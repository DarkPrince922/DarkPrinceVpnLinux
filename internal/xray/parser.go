package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseSubscription разбирает тело подписки Remnawave. Панель отдаёт его в
// одном из трёх видов: массив полных конфигов Xray, base64-список ссылок или
// те же ссылки построчно. Порядок проверок повторяет Android-клиент.
func ParseSubscription(content string) []Profile {
	text := strings.TrimSpace(content)
	if text == "" {
		return nil
	}

	if strings.HasPrefix(text, "[") || strings.HasPrefix(text, "{") {
		if profiles := parseXrayJSON(text); len(profiles) > 0 {
			return profiles
		}
	}

	decoded := text
	if !hasLinkPrefix(text) {
		if raw, ok := tryBase64(text); ok {
			decoded = raw
		}
	}

	trimmed := strings.TrimSpace(decoded)
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		if profiles := parseXrayJSON(trimmed); len(profiles) > 0 {
			return profiles
		}
	}

	var profiles []Profile
	for _, line := range strings.Split(decoded, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if p, err := ParseLink(line); err == nil {
			profiles = append(profiles, p)
		}
	}
	return profiles
}

func hasLinkPrefix(text string) bool {
	for _, prefix := range []string{"vless://", "vmess://", "trojan://", "ss://"} {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// parseXrayJSON разбирает подписку в формате Xray JSON: каждый элемент —
// целый конфиг с outbounds, routing и балансировщиками. Конфиг сохраняется
// целиком, а адрес и протокол вытаскиваются только для показа в списке.
func parseXrayJSON(text string) []Profile {
	var configs []map[string]json.RawMessage

	var asArray []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &asArray); err == nil {
		configs = asArray
	} else {
		var asObject map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &asObject); err != nil {
			return nil
		}
		if _, ok := asObject["outbounds"]; !ok {
			return nil
		}
		configs = []map[string]json.RawMessage{asObject}
	}

	var profiles []Profile
	for i, config := range configs {
		rawOutbounds, ok := config["outbounds"]
		if !ok {
			continue
		}
		var outbounds []map[string]json.RawMessage
		if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
			continue
		}

		profile := Profile{Protocol: VLESS, Port: 443}
		for _, outbound := range outbounds {
			proto := stringField(outbound, "protocol")
			parsed, ok := protocolFromName(proto)
			if !ok {
				continue
			}
			profile.Protocol = parsed
			address, port := serverEndpoint(outbound["settings"])
			if address != "" {
				profile.Address = address
			}
			if port > 0 {
				profile.Port = port
			}
			break
		}

		name := stringField(config, "remarks")
		if name == "" {
			name = profile.Address
		}
		if name == "" {
			name = fmt.Sprintf("Конфиг %d", i+1)
		}
		profile.Name = name
		if profile.Address == "" {
			profile.Address = "-"
		}

		encoded, err := json.Marshal(config)
		if err != nil {
			continue
		}
		profile.RawConfig = string(encoded)
		profiles = append(profiles, profile)
	}
	return profiles
}

func protocolFromName(name string) (Protocol, bool) {
	switch name {
	case "vless":
		return VLESS, true
	case "vmess":
		return VMess, true
	case "trojan":
		return Trojan, true
	case "shadowsocks":
		return Shadowsocks, true
	}
	return "", false
}

// serverEndpoint достаёт адрес и порт из settings.vnext[0] (vless/vmess) или
// settings.servers[0] (trojan/shadowsocks).
func serverEndpoint(rawSettings json.RawMessage) (string, int) {
	if len(rawSettings) == 0 {
		return "", 0
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(rawSettings, &settings); err != nil {
		return "", 0
	}
	for _, key := range []string{"vnext", "servers"} {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		var entries []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
			continue
		}
		return entries[0].Address, entries[0].Port
	}
	return "", 0
}

func stringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

// ParseLink разбирает одну ссылку из подписки.
func ParseLink(link string) (Profile, error) {
	switch {
	case strings.HasPrefix(link, "vless://"):
		return parseVLESS(link)
	case strings.HasPrefix(link, "trojan://"):
		return parseTrojan(link)
	case strings.HasPrefix(link, "vmess://"):
		return parseVMess(link)
	case strings.HasPrefix(link, "ss://"):
		return parseShadowsocks(link)
	}
	return Profile{}, fmt.Errorf("неизвестная схема ссылки")
}

// tryBase64 декодирует тело подписки. Панели отдают и обычный, и
// url-safe алфавит, и часто без выравнивающих '='.
func tryBase64(text string) (string, bool) {
	cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(text)
	if cleaned == "" {
		return "", false
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(cleaned); err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func fragmentName(u *url.URL, fallback string) string {
	if name := u.Fragment; name != "" {
		return name
	}
	return fallback
}

func portOr(u *url.URL, fallback int) int {
	if value := u.Port(); value != "" {
		if port, err := strconv.Atoi(value); err == nil && port > 0 {
			return port
		}
	}
	return fallback
}

func parseVLESS(link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, err
	}
	host := u.Hostname()
	if host == "" || u.User == nil {
		return Profile{}, fmt.Errorf("в ссылке vless нет адреса или идентификатора")
	}
	q := u.Query()
	return Profile{
		Protocol:      VLESS,
		Name:          fragmentName(u, host),
		Address:       host,
		Port:          portOr(u, 443),
		UserID:        u.User.Username(),
		Flow:          q.Get("flow"),
		Encryption:    orDefault(q.Get("encryption"), "none"),
		Network:       orDefault(q.Get("type"), "tcp"),
		Security:      orDefault(q.Get("security"), "none"),
		SNI:           q.Get("sni"),
		ALPN:          q.Get("alpn"),
		Fingerprint:   q.Get("fp"),
		AllowInsecure: isTruthy(q.Get("allowInsecure")),
		PublicKey:     q.Get("pbk"),
		ShortID:       q.Get("sid"),
		SpiderX:       q.Get("spx"),
		Host:          q.Get("host"),
		Path:          q.Get("path"),
		ServiceName:   q.Get("serviceName"),
		GRPCMultiMode: q.Get("mode") == "multi",
		HeaderType:    q.Get("headerType"),
	}, nil
}

func parseTrojan(link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, err
	}
	host := u.Hostname()
	if host == "" || u.User == nil {
		return Profile{}, fmt.Errorf("в ссылке trojan нет адреса или пароля")
	}
	q := u.Query()
	return Profile{
		Protocol:      Trojan,
		Name:          fragmentName(u, host),
		Address:       host,
		Port:          portOr(u, 443),
		UserID:        u.User.Username(),
		Network:       orDefault(q.Get("type"), "tcp"),
		Security:      orDefault(q.Get("security"), "tls"),
		SNI:           q.Get("sni"),
		ALPN:          q.Get("alpn"),
		Fingerprint:   q.Get("fp"),
		AllowInsecure: isTruthy(q.Get("allowInsecure")),
		Host:          q.Get("host"),
		Path:          q.Get("path"),
		ServiceName:   q.Get("serviceName"),
		GRPCMultiMode: q.Get("mode") == "multi",
	}, nil
}

// parseVMess: тело ссылки — base64 от JSON с однобуквенными ключами.
func parseVMess(link string) (Profile, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	decoded, ok := tryBase64(payload)
	if !ok {
		return Profile{}, fmt.Errorf("тело ссылки vmess не декодируется")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(decoded), &raw); err != nil {
		return Profile{}, err
	}

	field := func(key string) string {
		switch value := raw[key].(type) {
		case string:
			return value
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64)
		}
		return ""
	}

	address := field("add")
	userID := field("id")
	if address == "" || userID == "" {
		return Profile{}, fmt.Errorf("в ссылке vmess нет адреса или идентификатора")
	}

	port := 443
	if value, err := strconv.Atoi(field("port")); err == nil && value > 0 {
		port = value
	}

	network := orDefault(field("net"), "tcp")
	security := "none"
	if field("tls") == "tls" {
		security = "tls"
	}
	headerType := field("type")
	if headerType == "none" {
		headerType = ""
	}
	serviceName := ""
	if network == "grpc" {
		serviceName = field("path")
	}

	name := field("ps")
	if name == "" {
		name = address
	}

	return Profile{
		Protocol:      VMess,
		Name:          name,
		Address:       address,
		Port:          port,
		UserID:        userID,
		Network:       network,
		Security:      security,
		SNI:           field("sni"),
		ALPN:          field("alpn"),
		Fingerprint:   field("fp"),
		Host:          field("host"),
		Path:          field("path"),
		ServiceName:   serviceName,
		HeaderType:    headerType,
		VMessSecurity: orDefault(field("scy"), "auto"),
	}, nil
}

// parseShadowsocks поддерживает обе формы:
// ss://base64(method:password)@host:port#name и ss://base64(всё целиком)#name.
func parseShadowsocks(link string) (Profile, error) {
	if u, err := url.Parse(link); err == nil && u.Hostname() != "" && u.User != nil {
		userInfo := u.User.String()
		if decoded, ok := tryBase64(userInfo); ok {
			userInfo = decoded
		}
		if method, password, found := strings.Cut(userInfo, ":"); found {
			return Profile{
				Protocol:   Shadowsocks,
				Name:       fragmentName(u, u.Hostname()),
				Address:    u.Hostname(),
				Port:       portOr(u, 8388),
				UserID:     password,
				Encryption: method,
			}, nil
		}
	}

	body := strings.TrimPrefix(link, "ss://")
	name := ""
	if index := strings.Index(body, "#"); index >= 0 {
		name, _ = url.QueryUnescape(body[index+1:])
		body = body[:index]
	}
	decoded, ok := tryBase64(body)
	if !ok {
		return Profile{}, fmt.Errorf("тело ссылки ss не декодируется")
	}

	credentials, endpoint, found := strings.Cut(decoded, "@")
	if !found {
		return Profile{}, fmt.Errorf("в ссылке ss нет разделителя @")
	}
	method, password, found := strings.Cut(credentials, ":")
	if !found {
		return Profile{}, fmt.Errorf("в ссылке ss нет пароля")
	}
	host, portText, found := strings.Cut(endpoint, ":")
	if !found {
		return Profile{}, fmt.Errorf("в ссылке ss нет порта")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return Profile{}, fmt.Errorf("в ссылке ss некорректный порт")
	}
	if name == "" {
		name = host
	}

	return Profile{
		Protocol:   Shadowsocks,
		Name:       name,
		Address:    host,
		Port:       port,
		UserID:     password,
		Encryption: method,
	}, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func isTruthy(value string) bool {
	return value == "1" || value == "true"
}
