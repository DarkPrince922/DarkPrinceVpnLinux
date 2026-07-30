package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	testSocks = "127.0.0.1:10808"
	testHTTP  = "127.0.0.1:10809"
)

// acceptedByCore — главная проверка: конфиг скармливается настоящему ядру.
// Юнит-тесты на форму JSON не поймают несоответствие схеме Xray, а это ловит.
func acceptedByCore(t *testing.T, config string) {
	t.Helper()
	parsed, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatalf("ядро не приняло конфиг: %v\n%s", err, config)
	}
	instance, err := core.New(parsed)
	if err != nil {
		t.Fatalf("ядро не создалось: %v", err)
	}
	instance.Close()
}

func TestBuildConfigVLESSRealityAcceptedByCore(t *testing.T) {
	p, err := ParseLink("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443" +
		"?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com" +
		"&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179e30d4fc2#R")
	if err != nil {
		t.Fatal(err)
	}
	config, err := BuildConfig(p, Inbounds{SocksAddr: testSocks, HTTPAddr: testHTTP})
	if err != nil {
		t.Fatalf("конфиг не собрался: %v", err)
	}
	acceptedByCore(t, config)
}

func TestBuildConfigAllProtocolsAcceptedByCore(t *testing.T) {
	links := map[string]string{
		"vless-ws-tls": "vless://uuid-1@a.example:8443?type=ws&security=tls&path=%2Fx&host=a.example#A",
		"trojan":       "trojan://pw@b.example:443?security=tls&sni=b.example#B",
		"vmess-grpc":   "",
		"shadowsocks":  "ss://YWVzLTI1Ni1nY206cGFzcw==@c.example:8388#C",
	}
	// vmess собирается отдельно: тело ссылки — base64 от JSON
	links["vmess-grpc"] = "vmess://" + base64JSON(`{"ps":"D","add":"d.example","port":"443",
		"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"grpc","path":"svc","tls":"tls","scy":"auto"}`)

	for name, link := range links {
		t.Run(name, func(t *testing.T) {
			p, err := ParseLink(link)
			if err != nil {
				t.Fatalf("ссылка не разобралась: %v", err)
			}
			config, err := BuildConfig(p, Inbounds{SocksAddr: testSocks})
			if err != nil {
				t.Fatalf("конфиг не собрался: %v", err)
			}
			acceptedByCore(t, config)
		})
	}
}

// Режим TUN: HTTP-инбаунд не нужен, слушать должен только SOCKS.
func TestBuildConfigInboundsFollowMode(t *testing.T) {
	p, _ := ParseLink("vless://uuid-2@e.example:443?security=tls#E")

	tunConfig, err := BuildConfig(p, Inbounds{SocksAddr: testSocks})
	if err != nil {
		t.Fatal(err)
	}
	if tags := inboundTags(t, tunConfig); len(tags) != 1 || tags[0] != "socks" {
		t.Errorf("в режиме TUN инбаунды = %v, ожидался только socks", tags)
	}

	proxyConfig, err := BuildConfig(p, Inbounds{SocksAddr: testSocks, HTTPAddr: testHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if tags := inboundTags(t, proxyConfig); len(tags) != 2 {
		t.Errorf("в режиме прокси инбаунды = %v, ожидались socks и http", tags)
	}
	acceptedByCore(t, proxyConfig)
}

// Конфиг панели должен пережить подмену инбаундов без потерь.
func TestBuildConfigKeepsPanelRouting(t *testing.T) {
	raw := `{
      "remarks":"Панель",
      "outbounds":[
        {"tag":"proxy-a","protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443,
          "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
          "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example"}}},
        {"tag":"direct","protocol":"freedom","settings":{}},
        {"tag":"block","protocol":"blackhole","settings":{}}
      ],
      "routing":{"domainStrategy":"IPIfNonMatch","rules":[
        {"type":"field","outboundTag":"block","domain":["domain:ads.example"]}
      ]},
      "inbounds":[{"tag":"мусор","listen":"0.0.0.0","port":1080,"protocol":"socks",
        "settings":{"auth":"noauth"}}]
    }`
	profiles := ParseSubscription("[" + raw + "]")
	if len(profiles) != 1 {
		t.Fatalf("узлов = %d", len(profiles))
	}

	config, err := BuildConfig(profiles[0], Inbounds{SocksAddr: testSocks})
	if err != nil {
		t.Fatalf("конфиг не собрался: %v", err)
	}

	var built map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &built); err != nil {
		t.Fatal(err)
	}
	if _, ok := built["routing"]; !ok {
		t.Error("роутинг панели потерян")
	}
	// прежний инбаунд панели должен быть заменён нашим, а не добавлен к нему
	tags := inboundTags(t, config)
	if len(tags) != 1 || tags[0] != "socks" {
		t.Errorf("инбаунды = %v, ожидался только наш socks", tags)
	}
	acceptedByCore(t, config)
}

func TestStatsTagsFromPanelConfig(t *testing.T) {
	profiles := ParseSubscription(`[{"remarks":"П","outbounds":[
      {"tag":"proxy-a","protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443,
        "users":[{"id":"u","encryption":"none"}]}]}},
      {"tag":"proxy-b","protocol":"trojan","settings":{"servers":[{"address":"b.example","port":443,
        "password":"p"}]}},
      {"tag":"direct","protocol":"freedom","settings":{}},
      {"tag":"block","protocol":"blackhole","settings":{}}
    ]}]`)
	if len(profiles) != 1 {
		t.Fatalf("узлов = %d", len(profiles))
	}

	tags := StatsTags(profiles[0])
	if len(tags) != 2 {
		t.Fatalf("теги = %v, ожидались только прокси-аутбаунды", tags)
	}
	for _, tag := range tags {
		if tag == "direct" || tag == "block" {
			t.Errorf("в теги статистики попал служебный аутбаунд %q", tag)
		}
	}
}

func TestStatsTagsFromParsedLink(t *testing.T) {
	p, _ := ParseLink("vless://uuid-3@f.example:443?security=tls#F")
	tags := StatsTags(p)
	if len(tags) != 1 || tags[0] != "proxy" {
		t.Errorf("теги = %v, ожидался proxy", tags)
	}
}

func inboundTags(t *testing.T, config string) []string {
	t.Helper()
	var parsed struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("конфиг не разбирается: %v", err)
	}
	tags := make([]string, 0, len(parsed.Inbounds))
	for _, in := range parsed.Inbounds {
		tags = append(tags, in.Tag)
	}
	return tags
}

func base64JSON(text string) string {
	compact := strings.Join(strings.Fields(text), "")
	return base64.StdEncoding.EncodeToString([]byte(compact))
}
