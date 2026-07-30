// Package api — клиент Cabinet API бота Bedolaga и загрузчик подписки.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/store"
)

// Client ходит в кабинет и следит за свежестью токена.
type Client struct {
	http  *http.Client
	store *store.Store

	// Обновление токена строго одиночное: Bedolaga ротирует refresh при
	// каждом обновлении, поэтому параллельные запросы затёрли бы сессию
	// друг друга и разлогинили пользователя.
	refreshMu sync.Mutex
}

// New создаёт клиента поверх состояния.
func New(st *store.Store) *Client {
	return &Client{
		http:  &http.Client{Timeout: 30 * time.Second},
		store: st,
	}
}

// Error — ответ сервера с кодом; по нему решают, что показать пользователю.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	switch {
	case e.Code == 401:
		return "требуется вход"
	case e.Code == 404:
		return "сервис не найден: проверьте адрес кабинета"
	case e.Code == 429:
		return "слишком много попыток, подождите"
	case e.Code >= 500:
		return "сервер временно недоступен"
	}
	return fmt.Sprintf("ошибка сервера (%d)", e.Code)
}

// do выполняет запрос к кабинету. Токен обновляется дважды по разным
// поводам: заранее, когда истекает срок, и вынужденно, если сервер отозвал
// ещё не истёкший токен и ответил 401.
func (c *Client) do(ctx context.Context, method, path string, body, out any, authorized bool) error {
	var token string
	if authorized {
		if err := c.refreshIfExpired(ctx); err != nil {
			return err
		}
		if token = c.store.Snapshot().AccessToken; token == "" {
			return &Error{Code: 401}
		}
	}

	err := c.request(ctx, method, path, body, out, token)
	var apiErr *Error
	if !authorized || !asError(err, &apiErr) || apiErr.Code != 401 {
		return err
	}

	// сервер не принял токен, хотя по времени тот был годен
	if refreshErr := c.refreshRevoked(ctx, token); refreshErr != nil {
		return err
	}
	return c.request(ctx, method, path, body, out, c.store.Snapshot().AccessToken)
}

// request отправляет один запрос. Пустой token означает обращение без
// авторизации — так ходят вход и обновление токена.
func (c *Client) request(ctx context.Context, method, path string, body, out any, token string) error {
	state := c.store.Snapshot()
	endpoint := strings.TrimRight(state.BaseURL, "/") + "/api/" + strings.TrimLeft(path, "/")

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("нет связи с кабинетом: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("ответ кабинета не читается: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &Error{Code: response.StatusCode, Message: serverMessage(payload)}
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("кабинет вернул неожиданный ответ: %w", err)
	}
	return nil
}

// serverMessage вытаскивает человеческое описание ошибки, если оно есть.
func serverMessage(payload []byte) string {
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		return ""
	}
	for _, key := range []string{"detail", "message", "error"} {
		if text, ok := object[key].(string); ok && text != "" {
			return text
		}
	}
	return ""
}

// refreshIfExpired обновляет токен, у которого вышел срок. Повторную работу
// отсекаем по времени: если под мьютексом токен уже свеж, его обновил
// другой запрос.
func (c *Client) refreshIfExpired(ctx context.Context) error {
	state := c.store.Snapshot()
	if state.RefreshToken == "" || (state.AccessToken != "" && time.Until(state.AccessExpiresAt) > time.Minute) {
		return nil
	}
	return c.refresh(ctx, func(current store.State) bool {
		return current.AccessToken != "" && time.Until(current.AccessExpiresAt) > time.Minute
	})
}

// refreshRevoked обновляет токен, который сервер отверг раньше срока. Здесь
// проверять время бессмысленно — оно как раз выглядит годным, — поэтому
// повторную работу отсекаем по самому токену: если он уже не тот, которым мы
// получили отказ, значит обновление сделал другой запрос.
func (c *Client) refreshRevoked(ctx context.Context, rejected string) error {
	return c.refresh(ctx, func(current store.State) bool {
		return current.AccessToken != "" && current.AccessToken != rejected
	})
}

// Refresh обновляет пару токенов безусловно.
func (c *Client) Refresh(ctx context.Context) error {
	return c.refresh(ctx, func(store.State) bool { return false })
}

// refresh меняет пару токенов под мьютексом: Bedolaga ротирует refresh при
// каждом обновлении, поэтому параллельные попытки затёрли бы сессию.
// alreadyDone проверяется уже под замком и говорит, что работа не нужна.
func (c *Client) refresh(ctx context.Context, alreadyDone func(store.State) bool) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	state := c.store.Snapshot()
	if state.RefreshToken == "" {
		return &Error{Code: 401}
	}
	if alreadyDone(state) {
		return nil
	}

	var auth AuthResponse
	err := c.request(ctx, http.MethodPost, "cabinet/auth/refresh",
		refreshRequest{RefreshToken: state.RefreshToken}, &auth, "")
	if err != nil {
		var apiErr *Error
		// 4xx означает, что refresh-токен больше не примут — сессия мертва
		if asError(err, &apiErr) && apiErr.Code >= 400 && apiErr.Code < 500 {
			c.store.Update(func(s *store.State) {
				s.AccessToken, s.RefreshToken = "", ""
				s.AccessExpiresAt = time.Time{}
			})
		}
		return err
	}
	return c.saveSession(auth)
}

func (c *Client) saveSession(auth AuthResponse) error {
	if auth.AccessToken == "" {
		return fmt.Errorf("кабинет не вернул токен")
	}
	return c.store.Update(func(s *store.State) {
		s.AccessToken = auth.AccessToken
		if auth.RefreshToken != "" {
			s.RefreshToken = auth.RefreshToken
		}
		if auth.ExpiresIn > 0 {
			s.AccessExpiresAt = time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
		}
	})
}

func asError(err error, target **Error) bool {
	converted, ok := err.(*Error)
	if ok {
		*target = converted
	}
	return ok
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }
