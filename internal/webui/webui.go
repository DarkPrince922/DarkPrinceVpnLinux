// Package webui отдаёт графический интерфейс демона.
//
// Интерфейс — обычная страница, которую демон отдаёт на локальном адресе.
// Так у клиента остаётся один статический бинарник: настоящий тулкит
// потребовал бы cgo и системных библиотек, а с ними исчезла бы и простая
// кросс-компиляция, и независимость от версии libc.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed index.html
var assets embed.FS

// Command выполняет команду демона — ту же, что приходит от CLI по сокету.
type Command func(command string, args json.RawMessage) (any, error)

// Server — локальный веб-интерфейс.
type Server struct {
	listener net.Listener
	http     *http.Server
	token    string
	version  string
}

// Start поднимает интерфейс на 127.0.0.1.
//
// Слушаем только петлю: интерфейс управляет VPN, и открывать его наружу
// нельзя ни при каких настройках. Доступ дополнительно закрыт токеном —
// иначе любой процесс на машине, включая сайт в браузере через localhost,
// мог бы дёргать API.
func Start(addr string, version string, run Command) (*Server, error) {
	if addr == "" {
		addr = "127.0.0.1:8765"
	}
	if err := requireLoopback(addr); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("интерфейс не открылся на %s: %w", addr, err)
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		listener.Close()
		return nil, err
	}

	s := &Server{listener: listener, token: hex.EncodeToString(raw), version: version}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/api/", s.apiHandler(run))
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go s.http.Serve(listener)
	return s, nil
}

// requireLoopback не даёт случайно выставить панель управления VPN в сеть.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("адрес интерфейса %q неразборчив: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("интерфейс можно открывать только на петле, а не на %q", host)
	}
	return nil
}

// URL — адрес, который открывают в браузере; токен передаётся один раз в
// строке запроса, дальше страница держит его у себя.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?token=%s", s.listener.Addr().String(), s.token)
}

// Close останавливает интерфейс.
func (s *Server) Close() {
	if s.http == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.http.Shutdown(ctx)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, "страница не найдена", http.StatusInternalServerError)
		return
	}
	// страница управляет VPN и не должна оседать в кэше браузера
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) apiHandler(run Command) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "неверный токен")
			return
		}

		command := strings.TrimPrefix(r.URL.Path, "/api/")
		if command == "version" {
			writeJSON(w, map[string]string{"version": s.version})
			return
		}

		var args json.RawMessage
		if r.Body != nil {
			body, err := readLimited(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if len(body) > 0 {
				args = body
			}
		}

		data, err := run(command, args)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, data)
	}
}

// authorized принимает токен из заголовка или из строки запроса: первая
// загрузка страницы приходит со ссылкой, дальше — с заголовком.
func (s *Server) authorized(r *http.Request) bool {
	given := r.Header.Get("X-Token")
	if given == "" {
		given = r.URL.Query().Get("token")
	}
	// сравнение постоянного времени: токен короткий, и побитовый выход
	// раньше времени подсказывал бы перебору
	return subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) == 1
}

func readLimited(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for len(buf) < 64<<10 {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if data == nil {
		w.Write([]byte("null"))
		return
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
