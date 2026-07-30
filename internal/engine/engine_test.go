package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/xray"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/proxy"
)

// directProfile — узел, у которого исходящий ходит напрямую. Позволяет
// проверить весь обвес движка (запуск ядра, ожидание инбаунда, статистика,
// остановка), не имея на руках настоящего VPN-сервера.
func directProfile() xray.Profile {
	return xray.Profile{
		Protocol: xray.VLESS,
		Name:     "Прямой выход",
		Address:  "-",
		RawConfig: `{"outbounds":[{"tag":"proxy","protocol":"freedom","settings":{}}]}`,
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("порт не занялся: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestProxyModeServesSocksAndHTTP(t *testing.T) {
	socksAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	// целевой сервер поднимаем сами: тест не должен зависеть от интернета
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	e := New()
	err := e.Start(directProfile(), Options{
		Mode: ModeProxy, SocksAddr: socksAddr, HTTPAddr: httpAddr,
	})
	if err != nil {
		t.Fatalf("движок не запустился: %v", err)
	}
	defer e.Stop()

	status := e.Status()
	if !status.Running || status.Mode != ModeProxy {
		t.Fatalf("статус после запуска: %+v", status)
	}
	if status.HTTPAddr != httpAddr {
		t.Errorf("HTTP-инбаунд = %q, ожидался %q", status.HTTPAddr, httpAddr)
	}

	// через SOCKS
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS-диалер: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}}
	assertGetsOK(t, client, target.URL, "SOCKS")

	// через HTTP-инбаунд
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: httpAddr}),
	}}
	assertGetsOK(t, httpClient, target.URL, "HTTP-инбаунд")

	// счётчики ядра должны увидеть прошедший трафик
	if status := e.Status(); status.Uplink <= 0 || status.Downlink <= 0 {
		t.Errorf("статистика не считается: uplink=%d downlink=%d", status.Uplink, status.Downlink)
	}
}

// В режиме TUN лишний HTTP-порт не открывается: трафик и так идёт через
// интерфейс, а открытый порт — только расширение поверхности атаки.
func TestTUNModeDropsHTTPInbound(t *testing.T) {
	requireRoot(t)

	socksAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	tunOpts := DefaultTUNOptions()
	tunOpts.Name = uniqueIfaceName()
	tunOpts.Routes = []string{"198.18.32.0/24"} // не трогаем маршруты хоста

	e := New()
	err := e.Start(directProfile(), Options{
		Mode: ModeTUN, SocksAddr: socksAddr, HTTPAddr: httpAddr, TUN: tunOpts,
	})
	if err != nil {
		t.Fatalf("движок не запустился: %v", err)
	}
	defer e.Stop()

	if status := e.Status(); status.HTTPAddr != "" {
		t.Errorf("в режиме TUN открыт HTTP-инбаунд %q", status.HTTPAddr)
	}
	if _, err := net.DialTimeout("tcp", httpAddr, 300*time.Millisecond); err == nil {
		t.Errorf("порт %s принимает соединения, хотя не должен", httpAddr)
	}
}

// Ключевая проверка режима TUN: пакет, отправленный в интерфейс, должен
// дойти до SOCKS с правильным адресом назначения. Вместо ядра подставляем
// свой SOCKS-сервер, который записывает, что у него запросили.
func TestTUNDeliversTrafficToSocks(t *testing.T) {
	requireRoot(t)

	requested := make(chan string, 4)
	socksAddr := startRecordingSocks(t, requested)

	opts := DefaultTUNOptions()
	opts.Name = uniqueIfaceName()
	opts.Address = "198.18.48.1/24"
	opts.Routes = []string{"198.18.49.0/24"} // изолированный кусок, маршруты хоста целы

	tun, err := startTunnel(socksAddr, opts)
	if err != nil {
		t.Fatalf("туннель не поднялся: %v", err)
	}
	defer tun.close()

	const target = "198.18.49.7:8080"
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		t.Fatalf("соединение через туннель не установилось: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-requested:
		if got != target {
			t.Errorf("SOCKS получил %q, ожидался %q", got, target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("пакет не дошёл из TUN до SOCKS")
	}
}

// Остановка обязана вернуть систему в исходное состояние: ни интерфейса,
// ни наших маршрутов остаться не должно.
func TestTUNCleanupLeavesNothingBehind(t *testing.T) {
	requireRoot(t)

	requested := make(chan string, 1)
	socksAddr := startRecordingSocks(t, requested)

	opts := DefaultTUNOptions()
	opts.Name = uniqueIfaceName()
	opts.Address = "198.18.50.1/24"
	opts.Routes = []string{"198.18.51.0/24"}

	routesBefore := routeCount(t)

	tun, err := startTunnel(socksAddr, opts)
	if err != nil {
		t.Fatalf("туннель не поднялся: %v", err)
	}
	if _, err := netlink.LinkByName(opts.Name); err != nil {
		t.Fatalf("интерфейс %s не появился: %v", opts.Name, err)
	}

	tun.close()

	if _, err := netlink.LinkByName(opts.Name); err == nil {
		t.Errorf("интерфейс %s остался после остановки", opts.Name)
	}
	if after := routeCount(t); after != routesBefore {
		t.Errorf("маршрутов было %d, стало %d — таблица не восстановлена", routesBefore, after)
	}
}

// --- вспомогательное ---

func assertGetsOK(t *testing.T, client *http.Client, targetURL, through string) {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("запрос через %s не прошёл: %v", through, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("тело ответа через %s не прочиталось: %v", through, err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("через %s получили %d %q", through, resp.StatusCode, body)
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("нужны права root и CAP_NET_ADMIN")
	}
}

var ifaceCounter int

func uniqueIfaceName() string {
	ifaceCounter++
	return fmt.Sprintf("dptest%d", ifaceCounter)
}

func routeCount(t *testing.T) int {
	t.Helper()
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("таблица маршрутов не читается: %v", err)
	}
	return len(routes)
}

// startRecordingSocks поднимает минимальный SOCKS5-сервер, который
// сообщает запрошенный адрес и сразу отвечает успехом.
func startRecordingSocks(t *testing.T, requested chan<- string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("SOCKS-заглушка не поднялась: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSocksHandshake(conn, requested)
		}
	}()
	return listener.Addr().String()
}

func serveSocksHandshake(conn net.Conn, requested chan<- string) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // без аутентификации
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	var host string
	switch request[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03: // домен
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		buf := make([]byte, length[0])
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = string(buf)
	default:
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	requested <- net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBuf)))

	// отвечаем «успех», тело соединения тесту не нужно
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	io.Copy(io.Discard, conn)
}
