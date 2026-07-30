package engine

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/vishvananda/netlink"
	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	t2stunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	// протоколы регистрируются в init(); нам нужен только socks5, остальные
	// в бинарник не тащим
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
)

// TUNOptions описывает интерфейс, который поднимается в режиме TUN.
type TUNOptions struct {
	Name    string // имя интерфейса, например darkprince0
	MTU     int
	Address string // адрес интерфейса с маской, например 198.18.0.1/15

	// Routes — что заворачивать в туннель. Пусто означает «весь трафик»:
	// вместо подмены основного маршрута ставим 0.0.0.0/1 и 128.0.0.0/1 —
	// они длиннее дефолтного, поэтому выигрывают, и родной маршрут остаётся
	// нетронутым. Так при падении демона система не остаётся без сети.
	Routes []string

	// Bypass — адреса, которые обязаны идти мимо туннеля. Сюда попадают
	// серверы подписки: их трафик и есть сам туннель, завернуть его в себя
	// же означает петлю.
	Bypass []string
}

// DefaultTUNOptions — разумные значения по умолчанию.
func DefaultTUNOptions() TUNOptions {
	return TUNOptions{
		Name:    "darkprince0",
		MTU:     1500,
		Address: "198.18.0.1/15",
	}
}

type tunnel struct {
	device device.Device
	stack  *stack.Stack
	link   netlink.Link
	// маршруты, добавленные нами: снимаем их при остановке, чтобы не
	// оставить систему с мусором в таблице
	added []netlink.Route
}

func startTunnel(socksAddr string, opts TUNOptions) (*tunnel, error) {
	if opts.Name == "" || opts.MTU <= 0 || opts.Address == "" {
		return nil, fmt.Errorf("неполные параметры интерфейса")
	}

	proxyURL, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		return nil, fmt.Errorf("адрес SOCKS не разбирается: %w", err)
	}
	dialer, err := proxy.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("SOCKS-прокси не создался: %w", err)
	}

	dev, err := tun.Open(opts.Name, uint32(opts.MTU))
	if err != nil {
		return nil, fmt.Errorf("интерфейс %s не создался (нужен CAP_NET_ADMIN): %w", opts.Name, err)
	}

	t := &tunnel{device: dev}
	// дальше любая ошибка обязана разобрать уже поднятое
	defer func() {
		if err != nil {
			t.close()
		}
	}()

	if err = t.configureLink(opts); err != nil {
		return nil, err
	}

	t2stunnel.T().SetProxy(dialer)
	t.stack, err = t2score.CreateStack(&t2score.Config{
		LinkEndpoint:     dev,
		TransportHandler: t2stunnel.T(),
	})
	if err != nil {
		return nil, fmt.Errorf("сетевой стек не создался: %w", err)
	}

	if err = t.installRoutes(opts); err != nil {
		return nil, err
	}
	return t, nil
}

// configureLink вешает адрес на интерфейс и поднимает его.
func (t *tunnel) configureLink(opts TUNOptions) error {
	link, err := netlink.LinkByName(opts.Name)
	if err != nil {
		return fmt.Errorf("интерфейс %s не найден: %w", opts.Name, err)
	}
	t.link = link

	addr, err := netlink.ParseAddr(opts.Address)
	if err != nil {
		return fmt.Errorf("адрес %q не разбирается: %w", opts.Address, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("адрес %s не назначился: %w", opts.Address, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("интерфейс %s не поднялся: %w", opts.Name, err)
	}
	return nil
}

// installRoutes сначала уводит серверы подписки мимо туннеля, и только
// потом заворачивает в него остальное. Обратный порядок оставил бы окно, в
// котором ядро уже не может достучаться до своего сервера.
func (t *tunnel) installRoutes(opts TUNOptions) error {
	for _, host := range opts.Bypass {
		if err := t.addBypass(host); err != nil {
			return err
		}
	}

	destinations := opts.Routes
	if len(destinations) == 0 {
		destinations = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	for _, destination := range destinations {
		_, dst, err := net.ParseCIDR(destination)
		if err != nil {
			return fmt.Errorf("маршрут %q не разбирается: %w", destination, err)
		}
		route := netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: dst}
		if err := netlink.RouteAdd(&route); err != nil {
			return fmt.Errorf("маршрут %s не добавился: %w", destination, err)
		}
		t.added = append(t.added, route)
	}
	return nil
}

// addBypass прописывает адресу отдельный маршрут через тот шлюз, которым
// система пользовалась до туннеля.
func (t *tunnel) addBypass(host string) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// на вход мог прийти домен: резолвим до поднятия туннеля
		ips, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(ips) == 0 {
			return fmt.Errorf("адрес %q не разрешается: %v", host, lookupErr)
		}
		addr, _ = netip.AddrFromSlice(ips[0].To4())
		if !addr.IsValid() {
			return fmt.Errorf("у %q нет адреса IPv4", host)
		}
	}
	if !addr.Is4() {
		return nil // IPv6 в обход пока не заворачиваем
	}

	ip := net.ParseIP(addr.String())
	existing, err := netlink.RouteGet(ip)
	if err != nil || len(existing) == 0 {
		return fmt.Errorf("не удалось узнать текущий маршрут до %s: %v", host, err)
	}
	current := existing[0]
	// если маршрут уже идёт через наш интерфейс, шлюз брать неоткуда
	if t.link != nil && current.LinkIndex == t.link.Attrs().Index {
		return fmt.Errorf("маршрут до %s уже ведёт в туннель", host)
	}

	route := netlink.Route{
		LinkIndex: current.LinkIndex,
		Gw:        current.Gw,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("обходной маршрут до %s не добавился: %w", host, err)
	}
	t.added = append(t.added, route)
	return nil
}

// close разбирает всё в обратном порядке. Каждый шаг независим: ошибка
// одного не должна помешать остальным освободить ресурсы.
func (t *tunnel) close() {
	for i := len(t.added) - 1; i >= 0; i-- {
		route := t.added[i]
		_ = netlink.RouteDel(&route)
	}
	t.added = nil

	if t.stack != nil {
		t.stack.Close()
		t.stack.Wait()
		t.stack = nil
	}
	if t.device != nil {
		t.device.Close()
		t.device = nil
	}
	// интерфейс исчезает вместе с закрытым устройством; если ядро его
	// почему-то оставило, убираем явно
	if t.link != nil {
		if link, err := netlink.LinkByName(t.link.Attrs().Name); err == nil {
			_ = netlink.LinkDel(link)
		}
		t.link = nil
	}
}
