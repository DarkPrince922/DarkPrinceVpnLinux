// Package cli — команды darkprince, которые пользователь набирает руками.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/api"
	"github.com/darkprince922/darkprincevpnlinux/internal/daemon"
	"github.com/darkprince922/darkprincevpnlinux/internal/ipc"
	"github.com/darkprince922/darkprincevpnlinux/internal/store"
	"golang.org/x/term"
)

const usage = `darkprince — VPN-клиент DarkPrince для Linux

Использование:
  darkprince <команда> [аргументы]

Подключение:
  connect [--mode proxy|tun] [--server N]   поднять туннель
  disconnect                                остановить
  status                                    что происходит сейчас

Серверы:
  servers                    список узлов подписки
  use <N>                    выбрать узел
  refresh                    перечитать подписку из кабинета

Подписки:
  subscriptions              список подписок (мультитариф)
  subscription <ID>          выбрать подписку
  link <URL>                 работать по чужой ссылке, без кабинета

Аккаунт:
  login                      вход через Telegram
  login --email <адрес>      вход по почте
  logout                     выйти

Интерфейс:
  gui                        открыть графический интерфейс в браузере

Служба:
  daemon [--web АДРЕС]       запустить службу (в systemd делается само)
  version                    версия клиента

Режимы:
  proxy   ядро слушает SOCKS 127.0.0.1:10808 и HTTP 127.0.0.1:10809,
          приложения направляются туда вручную; прав не требует
  tun     весь трафик системы идёт через туннель; нужен root
`

// Version подставляется из main при сборке релиза.
var Version = "dev"

// Run разбирает аргументы и выполняет команду.
func Run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}

	paths := store.ResolvePaths()
	command, rest := args[0], args[1:]

	switch command {
	case "daemon":
		daemon.Version = Version
		service, err := daemon.New(paths, webAddr(rest))
		if err != nil {
			return err
		}
		return service.Run()
	case "gui":
		return openGUI(paths)
	case "status":
		return showStatus(paths)
	case "connect":
		return connect(paths, rest)
	case "disconnect":
		if err := ipc.Call(paths.Socket, ipc.CmdDisconnect, nil, nil, 30*time.Second); err != nil {
			return err
		}
		fmt.Println("Отключено.")
		return nil
	case "servers":
		return listServers(paths)
	case "refresh":
		return refresh(paths)
	case "use":
		return useServer(paths, rest)
	case "subscriptions":
		return listSubscriptions(paths)
	case "subscription":
		return selectSubscription(paths, rest)
	case "link":
		return setLink(paths, rest)
	case "login":
		return login(paths, rest)
	case "version", "--version", "-v":
		fmt.Printf("darkprince %s\n", Version)
		return nil
	case "logout":
		if err := ipc.Call(paths.Socket, ipc.CmdLogout, nil, nil, time.Minute); err != nil {
			return err
		}
		fmt.Println("Вы вышли из аккаунта.")
		return nil
	}
	return fmt.Errorf("неизвестная команда %q; darkprince help покажет список", command)
}

// webAddr разбирает --web у команды daemon. Значение по умолчанию — петля:
// через интерфейс управляют VPN, наружу его выставлять нельзя.
func webAddr(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--web" {
			return args[i+1]
		}
	}
	return "127.0.0.1:8765"
}

// openGUI спрашивает у демона адрес интерфейса и открывает браузер.
func openGUI(paths store.Paths) error {
	var response struct {
		URL string `json:"url"`
	}
	if err := ipc.Call(paths.Socket, ipc.CmdWebURL, nil, &response, 10*time.Second); err != nil {
		return err
	}

	fmt.Println("Интерфейс:", response.URL)
	if err := openBrowser(response.URL); err != nil {
		fmt.Println("Браузер не открылся сам — скопируйте ссылку выше.")
	}
	return nil
}

// openBrowser зовёт xdg-open от имени того, кто запустил sudo: браузер под
// root открывать нельзя — он полезет в чужой профиль и оставит там файлы
// с правами root.
func openBrowser(url string) error {
	if user := os.Getenv("SUDO_USER"); user != "" && os.Geteuid() == 0 {
		return exec.Command("runuser", "-u", user, "--", "xdg-open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

func showStatus(paths store.Paths) error {
	var view daemon.StatusView
	if err := ipc.Call(paths.Socket, ipc.CmdStatus, nil, &view, 30*time.Second); err != nil {
		return err
	}

	if view.Running {
		fmt.Printf("Состояние: подключено (%s)\n", view.Mode)
		fmt.Printf("Сервер: %s\n", view.Server)
		if view.Mode == "proxy" {
			fmt.Printf("SOCKS: %s\n", view.SocksAddr)
			if view.HTTPAddr != "" {
				fmt.Printf("HTTP:  %s\n", view.HTTPAddr)
			}
		}
		if !view.Since.IsZero() {
			fmt.Printf("Время: %s\n", time.Since(view.Since).Truncate(time.Second))
		}
		fmt.Printf("Трафик: ↑ %s  ↓ %s\n", humanBytes(view.Uplink), humanBytes(view.Downlink))
	} else {
		fmt.Println("Состояние: отключено")
	}

	switch {
	case view.LoggedIn && view.Account != "":
		fmt.Printf("Аккаунт: %s\n", view.Account)
	case view.LoggedIn:
		fmt.Println("Аккаунт: вход выполнен")
	case view.UsingShared:
		fmt.Println("Аккаунт: гостевой доступ по чужой ссылке")
	default:
		fmt.Println("Аккаунт: вход не выполнен")
	}
	fmt.Printf("Серверов в подписке: %d\n", view.ServerCount)
	return nil
}

func connect(paths store.Paths, args []string) error {
	var connectArgs ipc.ConnectArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--mode", "-m":
			value, err := nextArg(args, &i, "--mode")
			if err != nil {
				return err
			}
			connectArgs.Mode = value
		case "--server", "-s":
			value, err := nextArg(args, &i, "--server")
			if err != nil {
				return err
			}
			index, convErr := strconv.Atoi(value)
			if convErr != nil {
				return fmt.Errorf("номер сервера должен быть числом, а не %q", value)
			}
			connectArgs.Server = &index
		default:
			return fmt.Errorf("непонятный аргумент %q", args[i])
		}
	}

	var view daemon.StatusView
	// подключение включает скачивание подписки, поэтому ждём дольше обычного
	if err := ipc.Call(paths.Socket, ipc.CmdConnect, connectArgs, &view, 2*time.Minute); err != nil {
		return err
	}

	fmt.Printf("Подключено: %s (%s)\n", view.Server, view.Mode)
	if view.Mode == "proxy" {
		fmt.Printf("\nНаправьте приложения на прокси:\n")
		fmt.Printf("  SOCKS5: %s\n", view.SocksAddr)
		if view.HTTPAddr != "" {
			fmt.Printf("  HTTP:   %s\n", view.HTTPAddr)
			fmt.Printf("\nДля текущей оболочки:\n")
			fmt.Printf("  export http_proxy=http://%s https_proxy=http://%s\n",
				view.HTTPAddr, view.HTTPAddr)
		}
	}
	return nil
}

func listServers(paths store.Paths) error {
	var servers []daemon.ServerView
	if err := ipc.Call(paths.Socket, ipc.CmdServers, nil, &servers, 30*time.Second); err != nil {
		return err
	}
	printServers(servers)
	return nil
}

func refresh(paths store.Paths) error {
	var servers []daemon.ServerView
	if err := ipc.Call(paths.Socket, ipc.CmdRefresh, nil, &servers, time.Minute); err != nil {
		return err
	}
	fmt.Printf("Подписка обновлена, узлов: %d\n\n", len(servers))
	printServers(servers)
	return nil
}

func printServers(servers []daemon.ServerView) {
	if len(servers) == 0 {
		fmt.Println("Список серверов пуст. Загрузите подписку: darkprince refresh")
		return
	}
	for _, server := range servers {
		marker := " "
		if server.Selected {
			marker = "*"
		}
		fmt.Printf("%s %2d  %-28s %s %s\n",
			marker, server.Index, truncate(server.Name, 28), server.Protocol, server.Address)
	}
	if len(servers) > 0 {
		fmt.Println("\n* — выбранный узел; сменить: darkprince use <N>")
	}
}

func useServer(paths store.Paths, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("укажите номер узла: darkprince use 3")
	}
	index, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("номер узла должен быть числом, а не %q", args[0])
	}
	err = ipc.Call(paths.Socket, ipc.CmdSelectServer,
		ipc.SelectServerArgs{Index: index}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("Выбран узел №%d. Применить: darkprince connect\n", index)
	return nil
}

func listSubscriptions(paths store.Paths) error {
	var subscriptions []api.Subscription
	err := ipc.Call(paths.Socket, ipc.CmdSubscriptions, nil, &subscriptions, 30*time.Second)
	if err != nil {
		return err
	}
	if len(subscriptions) == 0 {
		fmt.Println("Подписок нет или мультитариф выключен.")
		return nil
	}
	for _, subscription := range subscriptions {
		state := "неактивна"
		if subscription.Active() {
			state = "активна"
		}
		fmt.Printf("  %d  %-24s %s", subscription.ID, truncate(subscription.Label(), 24), state)
		if subscription.EndDate != "" {
			fmt.Printf("  до %s", truncate(subscription.EndDate, 10))
		}
		fmt.Println()
	}
	fmt.Println("\nВыбрать: darkprince subscription <ID>")
	return nil
}

func selectSubscription(paths store.Paths, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("укажите номер подписки: darkprince subscription 12")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("номер подписки должен быть числом, а не %q", args[0])
	}
	err = ipc.Call(paths.Socket, ipc.CmdSelectSub,
		ipc.SelectSubscriptionArgs{ID: id}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	fmt.Println("Подписка выбрана. Обновить список узлов: darkprince refresh")
	return nil
}

func setLink(paths store.Paths, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("укажите ссылку на подписку: darkprince link https://...")
	}
	err := ipc.Call(paths.Socket, ipc.CmdSetSubscription,
		ipc.SetSubscriptionArgs{URL: args[0]}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	fmt.Println("Ссылка сохранена. Загрузить узлы: darkprince refresh")
	return nil
}

func login(paths store.Paths, args []string) error {
	if len(args) >= 1 && (args[0] == "--email" || args[0] == "-e") {
		email := ""
		if len(args) >= 2 {
			email = args[1]
		}
		return loginEmail(paths, email)
	}
	return loginTelegram(paths)
}

func loginTelegram(paths store.Paths) error {
	var start ipc.TelegramStart
	if err := ipc.Call(paths.Socket, ipc.CmdLoginTelegram, nil, &start, time.Minute); err != nil {
		return err
	}

	fmt.Println("Откройте ссылку и нажмите в боте «Start»:")
	fmt.Printf("\n  %s\n\n", start.Link)
	fmt.Println("Жду подтверждения…")

	var user api.User
	// ждать приходится столько же, сколько живёт одноразовый токен
	timeout := time.Duration(start.ExpiresIn+30) * time.Second
	err := ipc.Call(paths.Socket, ipc.CmdAwaitTelegram,
		ipc.AwaitTelegramArgs{Token: start.Token}, &user, timeout)
	if err != nil {
		return err
	}
	fmt.Printf("Готово, вы вошли: %s\n", user.Label())
	fmt.Println("Дальше: darkprince refresh")
	return nil
}

func loginEmail(paths store.Paths, email string) error {
	reader := bufio.NewReader(os.Stdin)
	if email == "" {
		fmt.Print("E-mail: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		email = strings.TrimSpace(line)
	}

	password, err := readPassword()
	if err != nil {
		return err
	}

	var user api.User
	err = ipc.Call(paths.Socket, ipc.CmdLoginEmail,
		ipc.EmailLoginArgs{Email: email, Password: password}, &user, time.Minute)
	if err != nil {
		return err
	}
	fmt.Printf("Готово, вы вошли: %s\n", user.Label())
	fmt.Println("Дальше: darkprince refresh")
	return nil
}

// readPassword не показывает вводимое, если ввод идёт с терминала.
func readPassword() (string, error) {
	fmt.Print("Пароль: ")
	if term.IsTerminal(syscall.Stdin) {
		data, err := term.ReadPassword(syscall.Stdin)
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func nextArg(args []string, i *int, name string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("после %s нужно значение", name)
	}
	*i++
	return args[*i], nil
}

func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	if limit <= 1 {
		return string(runes[:limit])
	}
	return string(runes[:limit-1]) + "…"
}

func humanBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d Б", bytes)
	}
	value, exponent := float64(bytes)/unit, 0
	for value >= unit && exponent < 3 {
		value /= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %s", value, [...]string{"КБ", "МБ", "ГБ", "ТБ"}[exponent])
}
