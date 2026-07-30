package xray

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Inbounds описывает, что ядро слушает локально. В режиме прокси на эти
// адреса пользователь направляет приложения сам; в режиме TUN на SOCKS
// садится мост tun2socks, а HTTP не поднимается.
type Inbounds struct {
	SocksAddr string // например 127.0.0.1:10808
	HTTPAddr  string // пусто — HTTP-инбаунд не создаётся
}

// BuildConfig собирает конфиг ядра под выбранный узел.
//
// Если узел пришёл из подписки в формате Xray JSON, конфиг панели берётся
// целиком — с её роутингом, правилами и балансировщиками, — и подменяется
// только inbounds. Иначе конфиг генерируется из разобранной ссылки.
func BuildConfig(profile Profile, in Inbounds) (string, error) {
	if profile.RawConfig != "" {
		return buildFromRaw(profile.RawConfig, in)
	}
	return buildFromProfile(profile, in)
}

func buildFromRaw(raw string, in Inbounds) (string, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return "", fmt.Errorf("конфиг из подписки не разбирается: %w", err)
	}

	inbounds, err := json.Marshal(buildInbounds(in))
	if err != nil {
		return "", err
	}
	config["inbounds"] = inbounds

	if _, ok := config["stats"]; !ok {
		config["stats"] = json.RawMessage(`{}`)
	}
	if _, ok := config["policy"]; !ok {
		config["policy"] = json.RawMessage(
			`{"system":{"statsInboundUplink":true,"statsInboundDownlink":true,` +
				`"statsOutboundUplink":true,"statsOutboundDownlink":true}}`)
	}
	if _, ok := config["log"]; !ok {
		config["log"] = json.RawMessage(`{"loglevel":"warning"}`)
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func buildFromProfile(p Profile, in Inbounds) (string, error) {
	outbound, err := buildOutbound(p)
	if err != nil {
		return "", err
	}

	config := map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"8": map[string]any{
					"handshake": 4, "connIdle": 300,
					"uplinkOnly": 1, "downlinkOnly": 1,
				},
			},
			"system": map[string]any{
				"statsInboundUplink": true, "statsInboundDownlink": true,
				"statsOutboundUplink": true, "statsOutboundDownlink": true,
			},
		},
		"dns": map[string]any{
			"servers": []any{"1.1.1.1", "8.8.8.8"},
		},
		"inbounds": buildInbounds(in),
		"outbounds": []any{
			outbound,
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
			map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				// частные сети мимо туннеля, иначе отваливается локальная сеть
				map[string]any{
					"type": "field",
					"ip": []any{
						"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
						"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
					},
					"outboundTag": "direct",
				},
			},
		},
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func buildInbounds(in Inbounds) []any {
	sniffing := map[string]any{
		"enabled":      true,
		"destOverride": []any{"http", "tls"},
		"routeOnly":    false,
	}

	inbounds := []any{}
	if in.SocksAddr != "" {
		host, port := splitHostPort(in.SocksAddr)
		inbounds = append(inbounds, map[string]any{
			"tag": "socks", "listen": host, "port": port, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
			"sniffing": sniffing,
		})
	}
	if in.HTTPAddr != "" {
		host, port := splitHostPort(in.HTTPAddr)
		inbounds = append(inbounds, map[string]any{
			"tag": "http", "listen": host, "port": port, "protocol": "http",
			"settings": map[string]any{},
			"sniffing": sniffing,
		})
	}
	return inbounds
}

func buildOutbound(p Profile) (map[string]any, error) {
	outbound := map[string]any{"tag": "proxy"}

	switch p.Protocol {
	case VLESS:
		user := map[string]any{
			"id": p.UserID, "encryption": orDefault(p.Encryption, "none"), "level": 8,
		}
		if p.Flow != "" {
			user["flow"] = p.Flow
		}
		outbound["protocol"] = "vless"
		outbound["settings"] = map[string]any{
			"vnext": []any{map[string]any{
				"address": p.Address, "port": p.Port, "users": []any{user},
			}},
		}
	case VMess:
		outbound["protocol"] = "vmess"
		outbound["settings"] = map[string]any{
			"vnext": []any{map[string]any{
				"address": p.Address, "port": p.Port,
				"users": []any{map[string]any{
					"id": p.UserID, "security": orDefault(p.VMessSecurity, "auto"),
					"alterId": 0, "level": 8,
				}},
			}},
		}
	case Trojan:
		outbound["protocol"] = "trojan"
		outbound["settings"] = map[string]any{
			"servers": []any{map[string]any{
				"address": p.Address, "port": p.Port, "password": p.UserID, "level": 8,
			}},
		}
	case Shadowsocks:
		outbound["protocol"] = "shadowsocks"
		outbound["settings"] = map[string]any{
			"servers": []any{map[string]any{
				"address": p.Address, "port": p.Port,
				"method":   orDefault(p.Encryption, "aes-256-gcm"),
				"password": p.UserID, "level": 8,
			}},
		}
	default:
		return nil, fmt.Errorf("протокол %q не поддерживается", p.Protocol)
	}

	outbound["streamSettings"] = buildStreamSettings(p)
	outbound["mux"] = map[string]any{"enabled": false}
	return outbound, nil
}

func buildStreamSettings(p Profile) map[string]any {
	network := orDefault(p.Network, "tcp")
	security := orDefault(p.Security, "none")
	stream := map[string]any{"network": network, "security": security}

	switch security {
	case "tls":
		tls := map[string]any{
			"serverName":    firstNonEmpty(p.SNI, p.Host, p.Address),
			"allowInsecure": p.AllowInsecure,
		}
		if p.Fingerprint != "" {
			tls["fingerprint"] = p.Fingerprint
		}
		if p.ALPN != "" {
			parts := strings.Split(p.ALPN, ",")
			alpn := make([]any, 0, len(parts))
			for _, part := range parts {
				alpn = append(alpn, strings.TrimSpace(part))
			}
			tls["alpn"] = alpn
		}
		stream["tlsSettings"] = tls
	case "reality":
		stream["realitySettings"] = map[string]any{
			"serverName":  p.SNI,
			"fingerprint": orDefault(p.Fingerprint, "chrome"),
			"publicKey":   p.PublicKey,
			"shortId":     p.ShortID,
			"spiderX":     p.SpiderX,
		}
	}

	switch network {
	case "ws":
		ws := map[string]any{"path": orDefault(p.Path, "/")}
		if p.Host != "" {
			ws["headers"] = map[string]any{"Host": p.Host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]any{
			"serviceName": p.ServiceName, "multiMode": p.GRPCMultiMode,
		}
	case "httpupgrade":
		settings := map[string]any{"path": orDefault(p.Path, "/")}
		if p.Host != "" {
			settings["host"] = p.Host
		}
		stream["httpupgradeSettings"] = settings
	case "xhttp":
		settings := map[string]any{"path": orDefault(p.Path, "/")}
		if p.Host != "" {
			settings["host"] = p.Host
		}
		stream["xhttpSettings"] = settings
	case "tcp":
		if p.HeaderType == "http" {
			stream["tcpSettings"] = map[string]any{
				"header": map[string]any{
					"type": "http",
					"request": map[string]any{
						"path":    []any{orDefault(p.Path, "/")},
						"headers": map[string]any{"Host": []any{p.Host}},
					},
				},
			}
		}
	}

	return stream
}

// StatsTags возвращает теги прокси-аутбаундов конфига — по ним опрашивается
// статистика трафика. У конфига панели тегов может быть несколько.
func StatsTags(p Profile) []string {
	if p.RawConfig == "" {
		return []string{"proxy"}
	}
	var config struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(p.RawConfig), &config); err != nil {
		return []string{"proxy"}
	}
	skip := map[string]bool{"freedom": true, "blackhole": true, "dns": true, "loopback": true}
	var tags []string
	for _, outbound := range config.Outbounds {
		if skip[outbound.Protocol] || outbound.Tag == "" {
			continue
		}
		tags = append(tags, outbound.Tag)
	}
	if len(tags) == 0 {
		return []string{"proxy"}
	}
	return tags
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func splitHostPort(addr string) (string, int) {
	host, portText, found := strings.Cut(addr, ":")
	if !found {
		return addr, 0
	}
	port := 0
	fmt.Sscanf(portText, "%d", &port)
	return host, port
}
