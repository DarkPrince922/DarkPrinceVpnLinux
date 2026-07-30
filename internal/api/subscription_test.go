package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/store"
)

func newTestClient(t *testing.T, baseURL string) (*Client, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *store.State) { s.BaseURL = baseURL }); err != nil {
		t.Fatal(err)
	}
	return New(st), st
}

func TestParseUserInfoHeader(t *testing.T) {
	info := parseUserInfo("upload=1024; download=2048; total=107374182400; expire=1767225600")
	if info == nil {
		t.Fatal("заголовок не разобрался")
	}
	if info.Upload != 1024 || info.Download != 2048 {
		t.Errorf("трафик разобран неверно: %+v", info)
	}
	if info.Total != 107374182400 || info.Expire != 1767225600 {
		t.Errorf("лимит или срок разобраны неверно: %+v", info)
	}
	if parseUserInfo("") != nil {
		t.Error("пустой заголовок должен давать nil")
	}
	// мусор не должен ронять разбор
	if got := parseUserInfo("upload=нет; download=5"); got == nil || got.Download != 5 {
		t.Errorf("мусор сломал разбор: %+v", got)
	}
}

// Панель считает устройства по заголовкам, и без x-hwid при включённом
// лимите отдаёт 404 — проверяем, что мы их действительно шлём.
func TestFetchServersSendsDeviceHeaders(t *testing.T) {
	var gotHWID, gotAgent, gotOS string
	subscription := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHWID = r.Header.Get("x-hwid")
		gotAgent = r.Header.Get("User-Agent")
		gotOS = r.Header.Get("x-device-os")
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3; expire=4")
		w.Write([]byte("vless://uuid-1@node.example:443?security=tls&sni=node.example#Узел"))
	}))
	defer subscription.Close()

	client, st := newTestClient(t, "http://unused.invalid")
	if err := client.SetGuestSubscription(subscription.URL); err != nil {
		t.Fatal(err)
	}

	profiles, info, err := client.FetchServers(context.Background())
	if err != nil {
		t.Fatalf("подписка не скачалась: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "Узел" {
		t.Fatalf("узлы разобраны неверно: %+v", profiles)
	}
	if info == nil || info.Total != 3 {
		t.Errorf("subscription-userinfo не подхватился: %+v", info)
	}

	want := st.Snapshot().HWID
	if gotHWID != want || gotHWID == "" {
		t.Errorf("x-hwid = %q, ожидался %q", gotHWID, want)
	}
	if gotAgent != "v2rayNG/1.10.7" {
		t.Errorf("User-Agent = %q: панель отдаёт base64-список только v2rayNG", gotAgent)
	}
	if gotOS != "Linux" {
		t.Errorf("x-device-os = %q", gotOS)
	}

	// тело подписки должно осесть в кэше, иначе запуск без сети невозможен
	if cached := client.CachedServers(); len(cached) != 1 {
		t.Errorf("подписка не закэшировалась: %d узлов", len(cached))
	}
}

func TestSetGuestSubscriptionRejectsGarbage(t *testing.T) {
	client, _ := newTestClient(t, "http://unused.invalid")
	if err := client.SetGuestSubscription("не ссылка"); err == nil {
		t.Error("мусор принят как ссылка на подписку")
	}
	if err := client.SetGuestSubscription("https://sub.example/abc"); err != nil {
		t.Errorf("нормальная ссылка отвергнута: %v", err)
	}
}

// cabinetWithRefresh — кабинет, принимающий только токен "новый".
func cabinetWithRefresh(protectedCalls, refreshCalls *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/cabinet/auth/refresh":
			*refreshCalls++
			w.Write([]byte(`{"access_token":"новый","refresh_token":"r2","expires_in":3600}`))
		case "/api/cabinet/subscriptions":
			*protectedCalls++
			if r.Header.Get("Authorization") == "Bearer новый" {
				w.Write([]byte(`{"subscriptions":[{"id":1,"status":"active","tariff_name":"Тариф"}]}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// Истёкший токен обновляется заранее, поэтому лишнего похода за 401 нет.
func TestExpiredTokenRefreshedBeforeRequest(t *testing.T) {
	var protectedCalls, refreshCalls int
	cabinet := cabinetWithRefresh(&protectedCalls, &refreshCalls)
	defer cabinet.Close()

	client, st := newTestClient(t, cabinet.URL)
	err := st.Update(func(s *store.State) {
		s.AccessToken = "протухший"
		s.RefreshToken = "r1"
		s.AccessExpiresAt = time.Now().Add(-time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}

	subscriptions, err := client.Subscriptions(context.Background())
	if err != nil {
		t.Fatalf("запрос не прошёл: %v", err)
	}
	if len(subscriptions) != 1 || subscriptions[0].Label() != "Тариф" {
		t.Errorf("подписки разобраны неверно: %+v", subscriptions)
	}
	if refreshCalls != 1 {
		t.Errorf("обновлений токена = %d, ожидалось 1", refreshCalls)
	}
	if protectedCalls != 1 {
		t.Errorf("обращений к защищённому пути = %d: токен обновляется заранее, "+
			"лишний 401 не нужен", protectedCalls)
	}
	if state := st.Snapshot(); state.AccessToken != "новый" || state.RefreshToken != "r2" {
		t.Errorf("токены не обновились: %+v", state)
	}
}

// Если сервер отозвал ещё не истёкший токен, клиент обязан обновиться по
// 401 и повторить запрос — ровно один раз, без цикла.
func TestRevokedTokenRetriedOnceAfterUnauthorized(t *testing.T) {
	var protectedCalls, refreshCalls int
	cabinet := cabinetWithRefresh(&protectedCalls, &refreshCalls)
	defer cabinet.Close()

	client, st := newTestClient(t, cabinet.URL)
	err := st.Update(func(s *store.State) {
		s.AccessToken = "отозванный"
		s.RefreshToken = "r1"
		// по времени токен ещё живой, значит упреждающее обновление не сработает
		s.AccessExpiresAt = time.Now().Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Subscriptions(context.Background()); err != nil {
		t.Fatalf("запрос не прошёл: %v", err)
	}
	if refreshCalls != 1 {
		t.Errorf("обновлений токена = %d, ожидалось 1", refreshCalls)
	}
	if protectedCalls != 2 {
		t.Errorf("обращений к защищённому пути = %d, ожидалось 2 (отказ и повтор)", protectedCalls)
	}
}

// Отказ обновления означает мёртвую сессию: токены надо стереть, иначе
// клиент будет вечно биться в 401.
func TestDeadRefreshClearsSession(t *testing.T) {
	cabinet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer cabinet.Close()

	client, st := newTestClient(t, cabinet.URL)
	err := st.Update(func(s *store.State) {
		s.AccessToken = "протухший"
		s.RefreshToken = "мёртвый"
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Refresh(context.Background()); err == nil {
		t.Fatal("обновление мёртвого токена должно возвращать ошибку")
	}
	if state := st.Snapshot(); state.RefreshToken != "" || state.AccessToken != "" {
		t.Errorf("мёртвая сессия не стёрта: %+v", state)
	}
}

func TestLogoutClearsSessionEvenIfServerFails(t *testing.T) {
	cabinet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cabinet.Close()

	client, st := newTestClient(t, cabinet.URL)
	err := st.Update(func(s *store.State) {
		s.AccessToken, s.RefreshToken = "a", "r"
		s.AccessExpiresAt = timeFuture()
		s.SetSubscriptionBody(nil, "узлы")
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = client.Logout(context.Background())

	state := st.Snapshot()
	if state.RefreshToken != "" || state.AccessToken != "" {
		t.Error("выход не стёр токены при недоступном сервере")
	}
	if state.SubscriptionBody(nil) != "" {
		t.Error("выход не стёр кэш подписки")
	}
}

func timeFuture() time.Time { return time.Now().Add(time.Hour) }
