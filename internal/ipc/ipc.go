// Package ipc — обмен между CLI и демоном через unix-сокет.
//
// Протокол намеренно простой: на соединение приходит один JSON-запрос и
// уходит один JSON-ответ. Команды редкие и человеческие, гонять ради них
// что-то сложнее незачем.
package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Команды, которые понимает демон.
const (
	CmdStatus          = "status"
	CmdServers         = "servers"
	CmdRefresh         = "refresh"
	CmdSelectServer    = "select-server"
	CmdConnect         = "connect"
	CmdDisconnect      = "disconnect"
	CmdLoginTelegram   = "login-telegram"
	CmdAwaitTelegram   = "await-telegram"
	CmdLoginEmail      = "login-email"
	CmdLogout          = "logout"
	CmdSetSubscription = "set-subscription"
	CmdSubscriptions   = "subscriptions"
	CmdSelectSub       = "select-subscription"
	CmdWebURL          = "web-url"
)

// Request — что CLI просит сделать.
type Request struct {
	Command string          `json:"command"`
	Args    json.RawMessage `json:"args,omitempty"`
}

// Response — что демон ответил.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// --- аргументы отдельных команд ---

type ConnectArgs struct {
	Mode      string `json:"mode,omitempty"`
	Server    *int   `json:"server,omitempty"`
	SocksAddr string `json:"socks_addr,omitempty"`
	HTTPAddr  string `json:"http_addr,omitempty"`
}

type SelectServerArgs struct {
	Index int `json:"index"`
}

type SelectSubscriptionArgs struct {
	ID int64 `json:"id"`
}

type EmailLoginArgs struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SetSubscriptionArgs struct {
	URL string `json:"url"`
}

type TelegramStart struct {
	Link      string `json:"link"`
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

type AwaitTelegramArgs struct {
	Token string `json:"token"`
}

// Handler обрабатывает одну команду.
type Handler func(request Request) (any, error)

// Listen открывает сокет. Старый файл от упавшего демона удаляется, но
// только если по нему никто не отвечает — иначе мы бы отобрали сокет у
// живого процесса.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("каталог для сокета недоступен: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		if conn, dialErr := net.DialTimeout("unix", path, 300*time.Millisecond); dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("демон уже запущен (сокет %s занят)", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("остаток сокета %s не удаляется: %w", path, err)
		}
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("сокет %s не открылся: %w", path, err)
	}
	// 0660: через сокет управляют VPN, посторонним туда нельзя
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("права на сокет не выставились: %w", err)
	}
	return listener, nil
}

// Serve обслуживает соединения, пока слушатель не закроют.
func Serve(listener net.Listener, handle Handler) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleConn(conn, handle)
	}
}

func handleConn(conn net.Conn, handle Handler) {
	defer conn.Close()

	var request Request
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&request); err != nil {
		writeResponse(conn, Response{Error: "запрос не разобран: " + err.Error()})
		return
	}

	data, err := handle(request)
	if err != nil {
		writeResponse(conn, Response{Error: err.Error()})
		return
	}

	response := Response{OK: true}
	if data != nil {
		encoded, marshalErr := json.Marshal(data)
		if marshalErr != nil {
			writeResponse(conn, Response{Error: "ответ не сериализуется: " + marshalErr.Error()})
			return
		}
		response.Data = encoded
	}
	writeResponse(conn, response)
}

func writeResponse(conn net.Conn, response Response) {
	_ = json.NewEncoder(conn).Encode(response)
}

// Call отправляет команду демону и разбирает ответ в out.
//
// timeout нужен разный: ожидание подтверждения в Telegram длится минутами,
// а status обязан отвечать мгновенно.
func Call(path, command string, args any, out any, timeout time.Duration) error {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return fmt.Errorf("демон не отвечает (%s): запустите darkprince daemon", path)
	}
	defer conn.Close()

	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	request := Request{Command: command}
	if args != nil {
		encoded, err := json.Marshal(args)
		if err != nil {
			return err
		}
		request.Args = encoded
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return fmt.Errorf("команда не отправилась: %w", err)
	}

	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return fmt.Errorf("демон не ответил: %w", err)
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	if out != nil && len(response.Data) > 0 {
		return json.Unmarshal(response.Data, out)
	}
	return nil
}
