package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443" +
		"?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com" +
		"&fp=chrome&pbk=aGVsbG8&sid=ab12&spx=%2F#%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B"

	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	if p.Protocol != VLESS {
		t.Errorf("протокол = %q, ожидался vless", p.Protocol)
	}
	if p.Address != "example.com" || p.Port != 443 {
		t.Errorf("адрес = %s:%d", p.Address, p.Port)
	}
	if p.UserID != "d342d11e-d424-4583-b36e-524ab1f0afa4" {
		t.Errorf("uuid = %q", p.UserID)
	}
	if p.Security != "reality" || p.PublicKey != "aGVsbG8" || p.ShortID != "ab12" {
		t.Errorf("reality разобран неверно: %+v", p)
	}
	if p.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", p.Flow)
	}
	// имя узла приходит в percent-encoding и должно раскодироваться
	if p.Name != "Нидерланды" {
		t.Errorf("имя = %q, ожидалось «Нидерланды»", p.Name)
	}
}

func TestParseVLESSWebSocketTLS(t *testing.T) {
	link := "vless://uuid-1@host.example:8443?type=ws&security=tls&path=%2Fray&host=cdn.example&sni=cdn.example#WS"
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	if p.Network != "ws" || p.Path != "/ray" || p.Host != "cdn.example" {
		t.Errorf("транспорт разобран неверно: %+v", p)
	}
	if p.Port != 8443 {
		t.Errorf("порт = %d", p.Port)
	}
}

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"Токио","add":"jp.example","port":"443","id":"uuid-2",` +
		`"aid":"0","scy":"auto","net":"ws","type":"none","host":"jp.example","path":"/vm","tls":"tls"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	if p.Protocol != VMess || p.Name != "Токио" || p.Address != "jp.example" {
		t.Errorf("vmess разобран неверно: %+v", p)
	}
	if p.Port != 443 || p.Network != "ws" || p.Security != "tls" || p.Path != "/vm" {
		t.Errorf("параметры vmess неверны: %+v", p)
	}
	// "type":"none" не должен превратиться в http-обфускацию
	if p.HeaderType != "" {
		t.Errorf("headerType = %q, ожидалась пустая строка", p.HeaderType)
	}
}

func TestParseTrojan(t *testing.T) {
	p, err := ParseLink("trojan://secret@tr.example:443?security=tls&sni=tr.example#Trojan")
	if err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	if p.Protocol != Trojan || p.UserID != "secret" || p.Security != "tls" {
		t.Errorf("trojan разобран неверно: %+v", p)
	}
}

func TestParseShadowsocksBothForms(t *testing.T) {
	// форма 1: base64(method:password)@host:port
	creds := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass1"))
	p1, err := ParseLink("ss://" + creds + "@ss.example:8388#SS1")
	if err != nil {
		t.Fatalf("форма 1 не разобралась: %v", err)
	}
	if p1.Encryption != "aes-256-gcm" || p1.UserID != "pass1" || p1.Port != 8388 {
		t.Errorf("форма 1 разобрана неверно: %+v", p1)
	}

	// форма 2: base64(method:password@host:port)
	whole := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass2@ss2.example:9000"))
	p2, err := ParseLink("ss://" + whole + "#SS2")
	if err != nil {
		t.Fatalf("форма 2 не разобралась: %v", err)
	}
	if p2.Encryption != "chacha20-ietf-poly1305" || p2.UserID != "pass2" {
		t.Errorf("форма 2 разобрана неверно: %+v", p2)
	}
	if p2.Address != "ss2.example" || p2.Port != 9000 {
		t.Errorf("адрес формы 2 неверен: %+v", p2)
	}
	if p2.Name != "SS2" {
		t.Errorf("имя формы 2 = %q", p2.Name)
	}
}

func TestParseSubscriptionBase64List(t *testing.T) {
	links := strings.Join([]string{
		"vless://uuid-a@a.example:443?security=tls&sni=a.example#A",
		"trojan://pw@b.example:443?security=tls#B",
	}, "\n")
	body := base64.StdEncoding.EncodeToString([]byte(links))

	profiles := ParseSubscription(body)
	if len(profiles) != 2 {
		t.Fatalf("узлов = %d, ожидалось 2", len(profiles))
	}
	if profiles[0].Name != "A" || profiles[1].Name != "B" {
		t.Errorf("имена узлов: %q, %q", profiles[0].Name, profiles[1].Name)
	}
}

func TestParseSubscriptionPlainLines(t *testing.T) {
	body := "vless://uuid-c@c.example:443?security=tls#C\n\nvless://uuid-d@d.example:443?security=tls#D\n"
	profiles := ParseSubscription(body)
	if len(profiles) != 2 {
		t.Fatalf("узлов = %d, ожидалось 2", len(profiles))
	}
}

// Формат Xray JSON: конфиг панели должен сохраниться целиком, включая
// роутинг и балансировщики, — это главное, ради чего он поддерживается.
func TestParseSubscriptionXrayJSON(t *testing.T) {
	body := `[{
      "remarks": "Германия",
      "outbounds": [
        {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"de.example","port":443,
          "users":[{"id":"uuid-e","encryption":"none"}]}]}},
        {"tag":"direct","protocol":"freedom","settings":{}}
      ],
      "routing": {"rules":[{"type":"field","outboundTag":"direct","domain":["geosite:private"]}]},
      "observatory": {"subjectSelector":["proxy"]}
    }]`

	profiles := ParseSubscription(body)
	if len(profiles) != 1 {
		t.Fatalf("узлов = %d, ожидался 1", len(profiles))
	}
	p := profiles[0]
	if p.Name != "Германия" || p.Address != "de.example" || p.Port != 443 {
		t.Errorf("узел разобран неверно: %+v", p)
	}
	if p.RawConfig == "" {
		t.Fatal("конфиг панели не сохранён в RawConfig")
	}

	var saved map[string]json.RawMessage
	if err := json.Unmarshal([]byte(p.RawConfig), &saved); err != nil {
		t.Fatalf("RawConfig не разбирается: %v", err)
	}
	for _, key := range []string{"routing", "observatory", "outbounds"} {
		if _, ok := saved[key]; !ok {
			t.Errorf("из конфига панели потерян раздел %q", key)
		}
	}
}

func TestParseSubscriptionIgnoresGarbage(t *testing.T) {
	body := "vless://uuid-f@f.example:443?security=tls#F\nне ссылка вовсе\nhttp://example.com\n"
	profiles := ParseSubscription(body)
	if len(profiles) != 1 {
		t.Fatalf("узлов = %d, ожидался 1", len(profiles))
	}
}
