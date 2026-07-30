// Package store хранит настройки, токены и кэш подписки на диске.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultBaseURL — адрес кабинета, тот же, что в мобильных приложениях.
const DefaultBaseURL = "https://cabinet.darkprincepanel.ru"

// Paths — где лежат состояние и управляющий сокет. Демон под root ставится
// системно, поэтому кладёт всё в /var; запущенный пользователем (это законно
// для режима «прокси», привилегий он не требует) — в свой каталог.
type Paths struct {
	StateDir string
	StateFile string
	Socket   string
	GeodataDir string
}

// ResolvePaths выбирает каталоги под текущего пользователя.
func ResolvePaths() Paths {
	if os.Geteuid() == 0 {
		return Paths{
			StateDir:   "/var/lib/darkprince-vpn",
			StateFile: "/var/lib/darkprince-vpn/state.json",
			Socket:     "/run/darkprince-vpn.sock",
			GeodataDir: "/var/lib/darkprince-vpn/geodata",
		}
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "darkprince-vpn")

	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		runtime = dir
	}
	return Paths{
		StateDir:   dir,
		StateFile: filepath.Join(dir, "state.json"),
		Socket:     filepath.Join(runtime, "darkprince-vpn.sock"),
		GeodataDir: filepath.Join(dir, "geodata"),
	}
}

// State — всё, что переживает перезапуск демона.
type State struct {
	BaseURL string `json:"base_url"`

	AccessToken     string    `json:"access_token,omitempty"`
	RefreshToken    string    `json:"refresh_token,omitempty"`
	AccessExpiresAt time.Time `json:"access_expires_at,omitempty"`

	// HWID нужен панели, чтобы считать устройства и применять лимит тарифа.
	// Генерируется один раз и дальше не меняется: иначе каждая перезапись
	// состояния выглядела бы для панели новым устройством.
	HWID string `json:"hwid"`

	SelectedSubscription *int64 `json:"selected_subscription,omitempty"`

	// Подписка, которой поделились по ссылке; работает без входа в кабинет.
	GuestSubURL string `json:"guest_sub_url,omitempty"`

	// Кэш тела подписки по её id — чтобы стартовать без сети.
	Subscriptions map[string]string `json:"subscriptions,omitempty"`
	// Выбранный узел внутри каждой подписки.
	SelectedServer map[string]int `json:"selected_server,omitempty"`

	// Последние параметры подключения — их же использует автозапуск.
	Mode      string `json:"mode,omitempty"`
	SocksAddr string `json:"socks_addr,omitempty"`
	HTTPAddr  string `json:"http_addr,omitempty"`
}

// Store — состояние на диске с сериализацией доступа.
type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

// Open читает состояние; отсутствующий файл — это первый запуск, не ошибка.
func Open(path string) (*Store, error) {
	s := &Store{path: path, state: State{BaseURL: DefaultBaseURL}}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("состояние %s повреждено: %w", path, err)
		}
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("состояние %s не читается: %w", path, err)
	}

	if s.state.BaseURL == "" {
		s.state.BaseURL = DefaultBaseURL
	}
	if s.state.HWID == "" {
		s.state.HWID = uuid.NewString()
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Snapshot отдаёт копию состояния.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.clone()
}

// Update меняет состояние под замком и сразу пишет на диск.
func (s *Store) Update(mutate func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutate(&s.state)
	return s.saveLocked()
}

// saveLocked пишет через временный файл: обрыв записи не должен оставить
// пользователя с обрезанным состоянием и потерянными токенами.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("каталог состояния недоступен: %w", err)
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}

	temp := s.path + ".tmp"
	// 0600: внутри токены доступа к кабинету
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return fmt.Errorf("состояние не записалось: %w", err)
	}
	if err := os.Rename(temp, s.path); err != nil {
		os.Remove(temp)
		return fmt.Errorf("состояние не сохранилось: %w", err)
	}
	return nil
}

// --- удобные обёртки над картами, ключ которых — id подписки ---

// SubKey превращает id подписки в ключ карты. Отдельная подписка может быть
// без id (мультитариф выключен) — тогда ключ общий.
func SubKey(id *int64) string {
	if id == nil {
		return "default"
	}
	return strconv.FormatInt(*id, 10)
}

func (s State) SubscriptionBody(id *int64) string {
	if s.Subscriptions == nil {
		return ""
	}
	return s.Subscriptions[SubKey(id)]
}

func (s *State) SetSubscriptionBody(id *int64, body string) {
	if s.Subscriptions == nil {
		s.Subscriptions = map[string]string{}
	}
	s.Subscriptions[SubKey(id)] = body
}

func (s State) ServerIndex(id *int64) int {
	if s.SelectedServer == nil {
		return 0
	}
	return s.SelectedServer[SubKey(id)]
}

func (s *State) SetServerIndex(id *int64, index int) {
	if s.SelectedServer == nil {
		s.SelectedServer = map[string]int{}
	}
	s.SelectedServer[SubKey(id)] = index
}

// LoggedIn — есть ли аккаунт кабинета. Гость живёт только по чужой ссылке.
func (s State) LoggedIn() bool { return s.RefreshToken != "" }

func (s State) clone() State {
	copied := s
	if s.Subscriptions != nil {
		copied.Subscriptions = make(map[string]string, len(s.Subscriptions))
		for key, value := range s.Subscriptions {
			copied.Subscriptions[key] = value
		}
	}
	if s.SelectedServer != nil {
		copied.SelectedServer = make(map[string]int, len(s.SelectedServer))
		for key, value := range s.SelectedServer {
			copied.SelectedServer[key] = value
		}
	}
	if s.SelectedSubscription != nil {
		id := *s.SelectedSubscription
		copied.SelectedSubscription = &id
	}
	return copied
}
