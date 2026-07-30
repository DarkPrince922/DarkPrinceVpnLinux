// Package daemon — служба, которая держит туннель и обслуживает CLI.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/api"
	"github.com/darkprince922/darkprincevpnlinux/internal/engine"
	"github.com/darkprince922/darkprincevpnlinux/internal/ipc"
	"github.com/darkprince922/darkprincevpnlinux/internal/store"
	"github.com/darkprince922/darkprincevpnlinux/internal/webui"
)

// Daemon держит всё состояние службы. CLI — тонкий клиент поверх него.
type Daemon struct {
	paths   store.Paths
	webAddr string
	store   *store.Store
	api     *api.Client
	engine  *engine.Engine

	web *webui.Server

	mu sync.Mutex
	// начатые входы через Telegram: между запросом ссылки и ожиданием
	// подтверждения проходит время, и CLI приходит за результатом отдельно
	pendingAuth map[string]api.DeepLinkRequest
}

// New поднимает службу и её состояние.
func New(paths store.Paths, webAddr string) (*Daemon, error) {
	st, err := store.Open(paths.StateFile)
	if err != nil {
		return nil, err
	}
	if missing, err := engine.SetupGeodata(paths.GeodataDir); err != nil {
		log.Printf("геоданные: %v", err)
	} else if len(missing) > 0 {
		// не ошибка, пока подписка не пользуется правилами geoip:/geosite:,
		// но если пользуется — ядро откажется стартовать целиком
		log.Printf("геоданных нет (%v) в %s: конфиги с правилами geoip:/geosite: не запустятся",
			missing, paths.GeodataDir)
	}
	return &Daemon{
		paths:       paths,
		webAddr:     webAddr,
		store:       st,
		api:         api.New(st),
		engine:      engine.New(),
		pendingAuth: map[string]api.DeepLinkRequest{},
	}, nil
}

// Run обслуживает сокет до сигнала завершения.
func (d *Daemon) Run() error {
	listener, err := ipc.Listen(d.paths.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(d.paths.Socket)

	// Интерфейс не обязателен: если порт занят, служба всё равно должна
	// работать — CLI от этого не зависит.
	if web, err := webui.Start(d.webAddr, Version, d.RunCommand); err != nil {
		log.Printf("интерфейс не поднялся: %v", err)
	} else {
		d.web = web
		defer web.Close()
		log.Printf("интерфейс: %s", web.URL())
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("останавливаюсь")
		// туннель гасим до закрытия сокета: маршруты и интерфейс должны
		// исчезнуть, даже если процесс убивают
		d.engine.Stop()
		listener.Close()
	}()

	log.Printf("слушаю %s", d.paths.Socket)
	err = ipc.Serve(listener, d.handle)
	d.engine.Stop()
	return err
}

// Version подставляется из main, чтобы интерфейс мог её показать.
var Version = "dev"

// RunCommand выполняет ту же команду, что приходит от CLI по сокету, —
// интерфейс не дублирует логику, а пользуется ею.
func (d *Daemon) RunCommand(command string, args json.RawMessage) (any, error) {
	return d.handle(ipc.Request{Command: command, Args: args})
}

// WebURL — адрес интерфейса вместе с токеном, пусто если он не поднялся.
func (d *Daemon) WebURL() string {
	if d.web == nil {
		return ""
	}
	return d.web.URL()
}

func (d *Daemon) handle(request ipc.Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	switch request.Command {
	case ipc.CmdStatus:
		return d.status(ctx), nil
	case ipc.CmdServers:
		return d.servers()
	case ipc.CmdRefresh:
		return d.refresh(ctx)
	case ipc.CmdSelectServer:
		return nil, d.selectServer(request)
	case ipc.CmdConnect:
		return d.connect(ctx, request)
	case ipc.CmdDisconnect:
		d.engine.Stop()
		return nil, nil
	case ipc.CmdLoginTelegram:
		return d.startTelegram(ctx)
	case ipc.CmdAwaitTelegram:
		return d.awaitTelegram(ctx, request)
	case ipc.CmdLoginEmail:
		return d.loginEmail(ctx, request)
	case ipc.CmdLogout:
		d.engine.Stop()
		return nil, d.api.Logout(ctx)
	case ipc.CmdSetSubscription:
		return nil, d.setSubscription(request)
	case ipc.CmdSubscriptions:
		return d.api.Subscriptions(ctx)
	case ipc.CmdSelectSub:
		return nil, d.selectSubscription(request)
	case ipc.CmdWebURL:
		url := d.WebURL()
		if url == "" {
			return nil, fmt.Errorf("интерфейс не запущен")
		}
		return map[string]string{"url": url}, nil
	}
	return nil, fmt.Errorf("неизвестная команда %q", request.Command)
}

// StatusView — то, что CLI печатает по команде status.
type StatusView struct {
	engine.Status
	LoggedIn      bool   `json:"logged_in"`
	Account       string `json:"account,omitempty"`
	ServerCount   int    `json:"server_count"`
	SelectedIndex int    `json:"selected_index"`
	UsingShared   bool   `json:"using_shared"`
}

func (d *Daemon) status(ctx context.Context) StatusView {
	state := d.store.Snapshot()
	view := StatusView{
		Status:        d.engine.Status(),
		LoggedIn:      state.LoggedIn(),
		ServerCount:   len(d.api.CachedServers()),
		SelectedIndex: state.ServerIndex(state.SelectedSubscription),
		UsingShared:   state.GuestSubURL != "",
	}
	if view.LoggedIn {
		// профиль показываем по возможности: без сети статус всё равно нужен
		if user, err := d.api.Me(ctx); err == nil && user != nil {
			view.Account = user.Label()
		}
	}
	return view
}

// ServerView — узел в списке.
type ServerView struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Selected bool   `json:"selected"`
}

// servers отдаёт узлы подписки. Пустой список — не ошибка, а обычное
// состояние до первой загрузки: подсказывать, что делать дальше, должен
// тот, кто показывает результат, а не служба.
func (d *Daemon) servers() ([]ServerView, error) {
	profiles := d.api.CachedServers()
	state := d.store.Snapshot()
	selected := state.ServerIndex(state.SelectedSubscription)

	views := make([]ServerView, 0, len(profiles))
	for i, profile := range profiles {
		views = append(views, ServerView{
			Index:    i,
			Name:     profile.Label(),
			Protocol: string(profile.Protocol),
			Address:  profile.Address,
			Selected: i == selected,
		})
	}
	return views, nil
}

func (d *Daemon) refresh(ctx context.Context) ([]ServerView, error) {
	if _, _, err := d.api.FetchServers(ctx); err != nil {
		return nil, err
	}
	return d.servers()
}

func (d *Daemon) selectServer(request ipc.Request) error {
	var args ipc.SelectServerArgs
	if err := json.Unmarshal(request.Args, &args); err != nil {
		return err
	}
	profiles := d.api.CachedServers()
	if args.Index < 0 || args.Index >= len(profiles) {
		return fmt.Errorf("сервера №%d нет: доступны 0..%d", args.Index, len(profiles)-1)
	}
	return d.store.Update(func(s *store.State) {
		s.SetServerIndex(s.SelectedSubscription, args.Index)
	})
}

func (d *Daemon) selectSubscription(request ipc.Request) error {
	var args ipc.SelectSubscriptionArgs
	if err := json.Unmarshal(request.Args, &args); err != nil {
		return err
	}
	return d.store.Update(func(s *store.State) {
		id := args.ID
		s.SelectedSubscription = &id
	})
}

func (d *Daemon) setSubscription(request ipc.Request) error {
	var args ipc.SetSubscriptionArgs
	if err := json.Unmarshal(request.Args, &args); err != nil {
		return err
	}
	return d.api.SetGuestSubscription(args.URL)
}

// connect поднимает туннель. Узлы берём из кэша, а если его нет — идём в
// сеть: первое подключение после установки иначе всегда падало бы.
func (d *Daemon) connect(ctx context.Context, request ipc.Request) (StatusView, error) {
	var args ipc.ConnectArgs
	if len(request.Args) > 0 {
		if err := json.Unmarshal(request.Args, &args); err != nil {
			return StatusView{}, err
		}
	}

	profiles := d.api.CachedServers()
	if len(profiles) == 0 {
		var err error
		if profiles, _, err = d.api.FetchServers(ctx); err != nil {
			return StatusView{}, fmt.Errorf("нет списка серверов: %w", err)
		}
	}

	state := d.store.Snapshot()
	index := state.ServerIndex(state.SelectedSubscription)
	if args.Server != nil {
		index = *args.Server
	}
	if index < 0 || index >= len(profiles) {
		index = 0
	}

	mode, err := resolveMode(args.Mode, state.Mode)
	if err != nil {
		return StatusView{}, err
	}
	if mode == engine.ModeTUN && os.Geteuid() != 0 {
		return StatusView{}, fmt.Errorf(
			"режим tun требует прав root: запустите демон через sudo либо " +
				"выберите режим proxy")
	}

	options := engine.Options{
		Mode:      mode,
		SocksAddr: firstNonEmpty(args.SocksAddr, state.SocksAddr, "127.0.0.1:10808"),
		HTTPAddr:  firstNonEmpty(args.HTTPAddr, state.HTTPAddr, "127.0.0.1:10809"),
		TUN:       engine.DefaultTUNOptions(),
	}
	// сервер подписки обязан ходить мимо туннеля, иначе туннель заворачивает
	// сам себя
	if address := profiles[index].Address; address != "" && address != "-" {
		options.TUN.Bypass = []string{address}
	}

	if err := d.engine.Start(profiles[index], options); err != nil {
		return StatusView{}, err
	}

	saveErr := d.store.Update(func(s *store.State) {
		s.SetServerIndex(s.SelectedSubscription, index)
		s.Mode = string(mode)
		s.SocksAddr = options.SocksAddr
		s.HTTPAddr = options.HTTPAddr
	})
	if saveErr != nil {
		log.Printf("состояние не сохранилось: %v", saveErr)
	}
	return d.status(ctx), nil
}

func (d *Daemon) startTelegram(ctx context.Context) (ipc.TelegramStart, error) {
	request, link, err := d.api.StartTelegramAuth(ctx)
	if err != nil {
		return ipc.TelegramStart{}, err
	}
	d.mu.Lock()
	d.pendingAuth[request.Token] = request
	d.mu.Unlock()

	return ipc.TelegramStart{
		Link:      link,
		Token:     request.Token,
		ExpiresIn: request.ExpiresIn,
	}, nil
}

func (d *Daemon) awaitTelegram(ctx context.Context, request ipc.Request) (*api.User, error) {
	var args ipc.AwaitTelegramArgs
	if err := json.Unmarshal(request.Args, &args); err != nil {
		return nil, err
	}

	d.mu.Lock()
	pending, ok := d.pendingAuth[args.Token]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("вход не начинался или уже завершён")
	}

	user, err := d.api.WaitTelegramAuth(ctx, pending)
	d.mu.Lock()
	delete(d.pendingAuth, args.Token)
	d.mu.Unlock()
	return user, err
}

func (d *Daemon) loginEmail(ctx context.Context, request ipc.Request) (*api.User, error) {
	var args ipc.EmailLoginArgs
	if err := json.Unmarshal(request.Args, &args); err != nil {
		return nil, err
	}
	return d.api.LoginEmail(ctx, args.Email, args.Password)
}

// resolveMode выбирает режим: явно заданный, затем прошлый, иначе прокси —
// он не требует привилегий и потому безопасен по умолчанию.
func resolveMode(requested, remembered string) (engine.Mode, error) {
	if requested != "" {
		return engine.ParseMode(requested)
	}
	if remembered != "" {
		return engine.ParseMode(remembered)
	}
	return engine.ModeProxy, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
