package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/store"
)

// StartTelegramAuth запрашивает одноразовый токен и отдаёт ссылку на бота.
// Дальше вызывающий показывает ссылку пользователю и ждёт WaitTelegramAuth.
func (c *Client) StartTelegramAuth(ctx context.Context) (DeepLinkRequest, string, error) {
	var request DeepLinkRequest
	err := c.do(ctx, http.MethodPost, "cabinet/auth/deeplink/request", nil, &request, false)
	if err != nil {
		return DeepLinkRequest{}, "", err
	}
	if request.BotUsername == "" {
		return DeepLinkRequest{}, "", fmt.Errorf("кабинет не вернул имя бота")
	}
	if request.ExpiresIn <= 0 {
		request.ExpiresIn = 300
	}
	link := fmt.Sprintf("https://t.me/%s?start=webauth_%s", request.BotUsername, request.Token)
	return request, link, nil
}

// WaitTelegramAuth опрашивает кабинет, пока пользователь не нажмёт Start в
// боте. 202 — ещё ждём, 410 — токен протух.
func (c *Client) WaitTelegramAuth(ctx context.Context, request DeepLinkRequest) (*User, error) {
	deadline := time.Now().Add(time.Duration(request.ExpiresIn) * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}

		var auth AuthResponse
		err := c.request(ctx, http.MethodPost, "cabinet/auth/deeplink/poll",
			deepLinkPoll{Token: request.Token}, &auth, "")
		if err != nil {
			var apiErr *Error
			if asError(err, &apiErr) {
				switch {
				case apiErr.Code == 202:
					continue // подтверждения ещё нет
				case apiErr.Code == 410:
					return nil, fmt.Errorf("время авторизации истекло, попробуйте ещё раз")
				case apiErr.Code >= 500:
					continue // временная ошибка сервера — продолжаем ждать
				}
			}
			continue // сетевые перебои не должны обрывать ожидание
		}
		if auth.AccessToken == "" {
			continue // 202 без тела: кабинет ещё ждёт подтверждения
		}
		if err := c.saveSession(auth); err != nil {
			return nil, err
		}
		return auth.User, nil
	}
	return nil, fmt.Errorf("время авторизации истекло, попробуйте ещё раз")
}

// LoginEmail — вход по почте.
func (c *Client) LoginEmail(ctx context.Context, email, password string) (*User, error) {
	var auth AuthResponse
	err := c.do(ctx, http.MethodPost, "cabinet/auth/email/login",
		emailLogin{Email: email, Password: password}, &auth, false)
	if err != nil {
		return nil, err
	}
	if auth.AccessToken == "" {
		if auth.Message != "" {
			return nil, fmt.Errorf("%s", auth.Message)
		}
		return nil, fmt.Errorf("не удалось войти")
	}
	if err := c.saveSession(auth); err != nil {
		return nil, err
	}
	return auth.User, nil
}

// Me — профиль текущего пользователя.
func (c *Client) Me(ctx context.Context) (*User, error) {
	var user User
	if err := c.do(ctx, http.MethodGet, "cabinet/auth/me", nil, &user, true); err != nil {
		return nil, err
	}
	return &user, nil
}

// Logout гасит сессию на сервере и стирает её локально. Локальную часть
// делаем в любом случае: даже если сервер недоступен, пользователь, нажавший
// «выйти», не должен остаться с рабочими токенами на диске.
func (c *Client) Logout(ctx context.Context) error {
	state := c.store.Snapshot()
	var serverErr error
	if state.RefreshToken != "" {
		serverErr = c.do(ctx, http.MethodPost, "cabinet/auth/logout",
			refreshRequest{RefreshToken: state.RefreshToken}, nil, true)
	}

	if err := c.store.Update(func(s *store.State) {
		s.AccessToken, s.RefreshToken = "", ""
		s.AccessExpiresAt = time.Time{}
		s.Subscriptions = nil
		s.SelectedServer = nil
		s.SelectedSubscription = nil
	}); err != nil {
		return err
	}
	return serverErr
}
