// Package engine поднимает ядро Xray и, при необходимости, туннель поверх него.
package engine

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/darkprince922/darkprincevpnlinux/internal/xray"
	xcore "github.com/xtls/xray-core/core"
	xstats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// Mode — способ, которым трафик попадает в ядро.
type Mode string

const (
	// ModeProxy: ядро слушает локальные SOCKS и HTTP, приложения
	// направляются туда вручную. Привилегии не нужны.
	ModeProxy Mode = "proxy"
	// ModeTUN: поверх SOCKS поднимается TUN-интерфейс, и через него идёт
	// весь трафик системы. Нужен CAP_NET_ADMIN.
	ModeTUN Mode = "tun"
)

// ParseMode разбирает режим из строки.
func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "proxy", "прокси":
		return ModeProxy, nil
	case "tun", "тун":
		return ModeTUN, nil
	}
	return "", fmt.Errorf("неизвестный режим %q: допустимы proxy и tun", value)
}

// Options — параметры запуска туннеля.
type Options struct {
	Mode      Mode
	SocksAddr string // адрес локального SOCKS, например 127.0.0.1:10808
	HTTPAddr  string // адрес локального HTTP; только в режиме proxy
	TUN       TUNOptions
}

// Status — что движок делает прямо сейчас.
type Status struct {
	Running   bool      `json:"running"`
	Mode      Mode      `json:"mode,omitempty"`
	Server    string    `json:"server,omitempty"`
	SocksAddr string    `json:"socks_addr,omitempty"`
	HTTPAddr  string    `json:"http_addr,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	Uplink    int64     `json:"uplink"`
	Downlink  int64     `json:"downlink"`
}

// Engine владеет ядром и туннелем. Все переходы состояния сериализованы
// мьютексом: одновременные connect/disconnect не должны пересекаться.
type Engine struct {
	mu sync.Mutex

	instance  *xcore.Instance
	tunnel    *tunnel
	stats     xstats.Manager
	statsTags []string

	mode      Mode
	server    string
	socksAddr string
	httpAddr  string
	since     time.Time
}

// New создаёт остановленный движок.
func New() *Engine { return &Engine{} }

// Start поднимает ядро по профилю, а в режиме TUN — ещё и туннель.
// Повторный вызов на работающем движке означает смену сервера: старое
// хозяйство гасится и поднимается новое.
func (e *Engine) Start(profile xray.Profile, opts Options) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if opts.SocksAddr == "" {
		return fmt.Errorf("не задан адрес SOCKS")
	}
	if opts.Mode == ModeTUN && opts.HTTPAddr != "" {
		// в режиме TUN трафик уже идёт через интерфейс; лишний открытый
		// порт только расширяет поверхность атаки
		opts.HTTPAddr = ""
	}

	e.stopLocked()

	inbounds := xray.Inbounds{SocksAddr: opts.SocksAddr, HTTPAddr: opts.HTTPAddr}
	configJSON, err := xray.BuildConfig(profile, inbounds)
	if err != nil {
		return fmt.Errorf("конфиг ядра не собрался: %w", err)
	}

	parsed, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("ядро не приняло конфиг: %w", err)
	}
	instance, err := xcore.New(parsed)
	if err != nil {
		return fmt.Errorf("ядро не создалось: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return fmt.Errorf("ядро не запустилось: %w", err)
	}

	if err := waitForListener(opts.SocksAddr, 10*time.Second); err != nil {
		instance.Close()
		return fmt.Errorf("SOCKS не открылся на %s: %w", opts.SocksAddr, err)
	}

	e.instance = instance
	e.stats, _ = instance.GetFeature(xstats.ManagerType()).(xstats.Manager)
	if e.stats == nil {
		// не повод падать: туннель работает и без счётчиков, но молчаливый
		// ноль в статусе выглядит как поломка, поэтому говорим об этом вслух
		log.Printf("статистика недоступна: ядро не отдало менеджер счётчиков")
	}
	e.statsTags = xray.StatsTags(profile)
	e.mode = opts.Mode
	e.server = profile.Label()
	e.socksAddr = opts.SocksAddr
	e.httpAddr = opts.HTTPAddr
	e.since = time.Now()

	if opts.Mode == ModeTUN {
		tun, err := startTunnel(opts.SocksAddr, opts.TUN)
		if err != nil {
			e.stopLocked()
			return fmt.Errorf("туннель не поднялся: %w", err)
		}
		e.tunnel = tun
	}

	return nil
}

// Stop гасит туннель и ядро. Вызов на остановленном движке безвреден.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

// stopLocked разбирает состояние в порядке, обратном сборке: сначала
// туннель с маршрутами, потом ядро.
func (e *Engine) stopLocked() {
	if e.tunnel != nil {
		e.tunnel.close()
		e.tunnel = nil
	}
	if e.instance != nil {
		e.instance.Close()
		e.instance = nil
	}
	e.stats = nil
	e.statsTags = nil
	e.mode = ""
	e.server = ""
	e.socksAddr = ""
	e.httpAddr = ""
	e.since = time.Time{}
}

// Status отдаёт текущее состояние вместе со счётчиками трафика.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()

	status := Status{
		Running:   e.instance != nil,
		Mode:      e.mode,
		Server:    e.server,
		SocksAddr: e.socksAddr,
		HTTPAddr:  e.httpAddr,
		Since:     e.since,
	}
	if e.instance == nil {
		return status
	}
	status.Uplink, status.Downlink = e.trafficLocked()
	return status
}

// trafficLocked суммирует счётчики по всем прокси-аутбаундам конфига.
// Счётчики ядра кумулятивные, читаем без сброса.
func (e *Engine) trafficLocked() (up, down int64) {
	if e.stats == nil {
		return 0, 0
	}
	for _, tag := range e.statsTags {
		up += counterValue(e.stats, "outbound>>>"+tag+">>>traffic>>>uplink")
		down += counterValue(e.stats, "outbound>>>"+tag+">>>traffic>>>downlink")
	}
	return up, down
}

func counterValue(manager xstats.Manager, name string) int64 {
	counter := manager.GetCounter(name)
	if counter == nil {
		return 0
	}
	return counter.Value()
}

// waitForListener ждёт, пока инбаунд действительно начнёт принимать
// соединения. Xray стартует асинхронно, и без этой проверки мост TUN мог бы
// подняться раньше SOCKS и сразу упасть.
func waitForListener(addr string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}
