// Package xray описывает узлы подписки Remnawave и собирает из них конфиг ядра.
package xray

// Protocol — транспортный протокол узла.
type Protocol string

const (
	VLESS       Protocol = "vless"
	VMess       Protocol = "vmess"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
)

// Profile — один сервер из подписки: либо разобранная ссылка vless:// и т.п.,
// либо целый конфиг панели в поле RawConfig.
type Profile struct {
	Protocol Protocol `json:"protocol"`
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	// UserID: uuid для vless/vmess, пароль для trojan/shadowsocks.
	UserID string `json:"user_id"`

	Flow       string `json:"flow,omitempty"`       // vless: xtls-rprx-vision
	Encryption string `json:"encryption,omitempty"` // vless: none; ss: метод шифрования
	Network    string `json:"network,omitempty"`    // tcp / ws / grpc / httpupgrade / xhttp
	Security   string `json:"security,omitempty"`   // none / tls / reality

	SNI           string `json:"sni,omitempty"`
	ALPN          string `json:"alpn,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	AllowInsecure bool   `json:"allow_insecure,omitempty"`

	PublicKey string `json:"public_key,omitempty"` // reality pbk
	ShortID   string `json:"short_id,omitempty"`   // reality sid
	SpiderX   string `json:"spider_x,omitempty"`   // reality spx

	Host          string `json:"host,omitempty"` // ws/httpupgrade/xhttp
	Path          string `json:"path,omitempty"`
	ServiceName   string `json:"service_name,omitempty"` // grpc
	GRPCMultiMode bool   `json:"grpc_multi_mode,omitempty"`
	HeaderType    string `json:"header_type,omitempty"` // tcp http-обфускация
	VMessSecurity string `json:"vmess_security,omitempty"`

	// RawConfig — полный конфиг Xray из подписки (формат Xray JSON / Happ).
	// Если задан, используется как есть: роутинг, правила и балансировщики
	// панели сохраняются, подменяется только inbounds.
	RawConfig string `json:"raw_config,omitempty"`
}

// Label — как узел показывается в списке.
func (p Profile) Label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Address
}
