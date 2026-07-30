package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/darkprince922/darkprincevpnlinux/internal/store"
	"github.com/darkprince922/darkprincevpnlinux/internal/xray"
)

// Subscriptions — список подписок пользователя. Без аккаунта пусто: гость
// живёт по чужой ссылке и кабинета не видит.
func (c *Client) Subscriptions(ctx context.Context) ([]Subscription, error) {
	if !c.store.Snapshot().LoggedIn() {
		return nil, nil
	}
	var response subscriptionsResponse
	if err := c.do(ctx, http.MethodGet, "cabinet/subscriptions", nil, &response, true); err != nil {
		return nil, err
	}
	return response.Subscriptions, nil
}

// Status — состояние текущей подписки.
func (c *Client) Status(ctx context.Context) (*Subscription, error) {
	var subscription Subscription
	if err := c.do(ctx, http.MethodGet, "cabinet/subscription", nil, &subscription, true); err != nil {
		return nil, err
	}
	return &subscription, nil
}

// SubscriptionURL находит ссылку на подписку Remnawave.
//
// Гостевая ссылка — запасной вариант: пока у зарегистрировавшегося гостя нет
// своей подписки, он продолжает пользоваться той, которой с ним поделились.
func (c *Client) SubscriptionURL(ctx context.Context) (string, error) {
	state := c.store.Snapshot()
	if !state.LoggedIn() {
		if state.GuestSubURL == "" {
			return "", fmt.Errorf("нет подписки: войдите в кабинет или добавьте ссылку")
		}
		return state.GuestSubURL, nil
	}

	// при мультитарифе ссылка выбранной подписки приходит прямо в списке
	if state.SelectedSubscription != nil {
		if subscriptions, err := c.Subscriptions(ctx); err == nil {
			for _, subscription := range subscriptions {
				if subscription.ID == *state.SelectedSubscription && subscription.SubscriptionURL != "" {
					return subscription.SubscriptionURL, nil
				}
			}
		}
	}

	var link connectionLink
	if err := c.do(ctx, http.MethodGet, "cabinet/subscription/connection-link", nil, &link, true); err == nil {
		if link.SubscriptionURL != "" {
			return link.SubscriptionURL, nil
		}
	}
	if subscription, err := c.Status(ctx); err == nil && subscription.SubscriptionURL != "" {
		return subscription.SubscriptionURL, nil
	}
	if state.GuestSubURL != "" {
		return state.GuestSubURL, nil
	}
	return "", fmt.Errorf("кабинет не отдал ссылку на подписку")
}

// FetchServers скачивает подписку и разбирает узлы. Результат кладётся в
// кэш, чтобы следующий запуск обходился без сети.
func (c *Client) FetchServers(ctx context.Context) ([]xray.Profile, *UserInfo, error) {
	url, err := c.SubscriptionURL(ctx)
	if err != nil {
		return nil, nil, err
	}
	state := c.store.Snapshot()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	// Заголовки учёта устройств: без x-hwid панель с включённым лимитом
	// отдаёт 404, а в списке устройств этот компьютер не появляется.
	request.Header.Set("User-Agent", "v2rayNG/1.10.7")
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("x-hwid", state.HWID)
	request.Header.Set("x-device-os", "Linux")
	request.Header.Set("x-ver-os", runtime.GOARCH)
	request.Header.Set("x-device-model", deviceModel())

	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("подписка не скачалась: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("подписка недоступна (HTTP %d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("подписка не читается: %w", err)
	}

	profiles := xray.ParseSubscription(string(body))
	if len(profiles) == 0 {
		return nil, nil, fmt.Errorf("в подписке не нашлось серверов")
	}

	info := parseUserInfo(response.Header.Get("subscription-userinfo"))
	saveErr := c.store.Update(func(s *store.State) {
		s.SetSubscriptionBody(s.SelectedSubscription, string(body))
		// своя подписка заработала — чужую отпускаем, чтобы не занимать
		// место в лимите устройств владельца
		if s.GuestSubURL != "" && s.LoggedIn() && url != s.GuestSubURL {
			s.GuestSubURL = ""
		}
	})
	if saveErr != nil {
		return profiles, info, saveErr
	}
	return profiles, info, nil
}

// CachedServers отдаёт узлы из сохранённой копии подписки — для работы без сети.
func (c *Client) CachedServers() []xray.Profile {
	state := c.store.Snapshot()
	body := state.SubscriptionBody(state.SelectedSubscription)
	if body == "" {
		return nil
	}
	return xray.ParseSubscription(body)
}

// SetGuestSubscription включает работу по чужой ссылке.
func (c *Client) SetGuestSubscription(url string) error {
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("нужна ссылка на подписку, начинающаяся с http:// или https://")
	}
	return c.store.Update(func(s *store.State) { s.GuestSubURL = url })
}

// parseUserInfo разбирает заголовок вида "upload=1; download=2; total=3; expire=4".
func parseUserInfo(header string) *UserInfo {
	if header == "" {
		return nil
	}
	info := &UserInfo{}
	for _, part := range strings.Split(header, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(key) {
		case "upload":
			info.Upload = number
		case "download":
			info.Download = number
		case "total":
			info.Total = number
		case "expire":
			info.Expire = number
		}
	}
	return info
}

func deviceModel() string {
	host, err := osHostname()
	if err != nil || host == "" {
		return "Linux PC"
	}
	return host
}

// osHostname вынесен отдельно, чтобы тест мог подменить источник имени.
var osHostname = os.Hostname
