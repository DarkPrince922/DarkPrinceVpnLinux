//! Режим «весь трафик»: TUN-интерфейс забирает трафик системы.
//!
//! Главная тонкость та же, что и на Windows, — не зациклить трафик. Ядро
//! ходит к серверу через обычную сеть, и если весь трафик уйдёт в туннель,
//! оно начнёт слать пакеты в собственный туннель. Поэтому до адресов серверов
//! прокладываются отдельные маршруты через физический шлюз, и делать это надо
//! ДО поднятия туннеля, пока DNS ещё отвечает напрямую.
//!
//! Про права. На Windows приложение перезапускало себя от администратора
//! целиком. На Linux так делать не принято и не нужно: интерфейс создаётся
//! **на имя текущего пользователя**, поэтому мост открывает его без всяких
//! прав и остаётся нашим обычным потомком — а значит, гибнет вместе с
//! приложением. Через `pkexec` выполняется только то, что действительно
//! требует прав: создание интерфейса и правка маршрутов. Пароль спрашивается
//! один раз на подключение, а не на каждую команду.

use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::sys;

pub const ADAPTER: &str = "dpvpn0";
const ADDRESS: &str = "198.18.0.1";
const MASK: &str = "24";

pub struct Tunnel {
    process: Option<Child>,
    server_routes: Vec<String>,
    up: bool,
}

impl Tunnel {
    pub fn new() -> Self {
        Self { process: None, server_routes: Vec::new(), up: false }
    }

    pub fn start(
        &mut self,
        bridge: &Path,
        servers: &[String],
        socks_port: u16,
        log_dir: &Path,
    ) -> Result<(), String> {
        if !bridge.exists() {
            return Err(format!(
                "не найден мост tun2socks: {}. Переустановите приложение.",
                bridge.display()
            ));
        }
        if !has_pkexec() {
            return Err("для режима «весь трафик» нужен polkit (программа pkexec). \
Установите пакет polkit и попробуйте снова."
                .into());
        }

        // Следы прошлого запуска, если его оборвали жёстко: пока они на
        // месте, трафик уходит в несуществующий туннель и сеть мертва.
        clear_stale_state(bridge.parent().unwrap_or(Path::new(".")));

        let gateway = default_route()
            .ok_or("не удалось определить основной шлюз — проверьте подключение к сети")?;
        sys::log(&format!("шлюз: {} через {}", gateway.via, gateway.dev));

        let addresses = resolve(servers);
        if addresses.is_empty() {
            return Err("не удалось определить адрес сервера. Без отдельного маршрута до него \
весь трафик, включая трафик самого ядра, ушёл бы в туннель и соединение зациклилось бы."
                .into());
        }

        // Всё, что требует прав, — одним заходом: один запрос пароля.
        let script = bring_up_script(&addresses, &gateway);
        if !elevated(&script) {
            return Err("не удалось поднять туннель: система отказала в правах. \
Если окно запроса пароля не появилось, проверьте, что служба polkit запущена."
                .into());
        }
        self.server_routes = addresses;
        self.up = true;

        // Мост открывает уже готовый интерфейс — прав ему не нужно.
        // Флаги строго с двумя дефисами: так их принимают обе разновидности
        // разбора аргументов, встречающиеся у сборок моста.
        let child = sys::command(&bridge.to_string_lossy())
            .args([
                "--device",
                &format!("tun://{ADAPTER}"),
                "--proxy",
                &format!("socks5://127.0.0.1:{socks_port}"),
                "--loglevel",
                "warning",
            ])
            .stdout(Stdio::null())
            .stderr(sys::log_file(&log_dir.join("tun2socks.log")))
            .spawn()
            .map_err(|error| format!("не удалось запустить мост: {error}"))?;
        self.process = Some(child);

        if !self.wait_for_bridge(Duration::from_secs(8)) {
            let tail = tail_of(&log_dir.join("tun2socks.log"));
            self.stop();
            return Err(format!("мост не смог открыть интерфейс.\n{tail}"));
        }

        sys::log("туннель поднят");
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.up {
            let script = tear_down_script(&self.server_routes);
            elevated(&script);
            self.up = false;
        }
        self.server_routes.clear();
    }

    /// Мост мог упасть на старте — тогда ждать нечего.
    fn wait_for_bridge(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(child) = self.process.as_mut() {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return false;
                }
            }
            if interface_is_up() {
                return true;
            }
            sleep(Duration::from_millis(250));
        }
        false
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct Gateway {
    pub via: String,
    pub dev: String,
}

/// Шлюз по умолчанию. Спрашиваем `ip -j` — он отдаёт JSON и не зависит ни от
/// языка системы, ни от версии iproute2, в отличие от обычного вывода.
pub fn default_route() -> Option<Gateway> {
    let routes = sys::json("ip", &["-j", "route", "show", "default"])?;
    let first = routes.as_array()?.iter().find(|route| {
        route.get("gateway").and_then(|value| value.as_str()).is_some()
    })?;
    Some(Gateway {
        via: first.get("gateway")?.as_str()?.to_string(),
        dev: first.get("dev")?.as_str()?.to_string(),
    })
}

/// Поднялся ли наш интерфейс.
fn interface_is_up() -> bool {
    sys::json("ip", &["-j", "link", "show", ADAPTER])
        .and_then(|links| {
            let state = links.as_array()?.first()?.get("operstate")?.as_str()?.to_string();
            Some(state != "DOWN")
        })
        .unwrap_or(false)
}

/// Есть ли чем спросить права.
pub fn has_pkexec() -> bool {
    sys::run("which", &["pkexec"])
}

/// Скрипт поднятия. Одной строкой, потому что `pkexec` спрашивает пароль на
/// каждый свой запуск: десять команд — десять запросов.
fn bring_up_script(servers: &[String], gateway: &Gateway) -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let mut lines = vec![
        "set -e".to_string(),
        // интерфейс создаётся на имя пользователя — мосту тогда не нужны права
        format!("ip tuntap add dev {ADAPTER} mode tun user {user}"),
        format!("ip addr add {ADDRESS}/{MASK} dev {ADAPTER}"),
        format!("ip link set dev {ADAPTER} up"),
    ];

    // 1. Маршруты до серверов мимо туннеля — обязательно раньше остальных
    for ip in servers {
        lines.push(format!("ip route replace {ip}/32 via {} dev {}", gateway.via, gateway.dev));
    }

    // 2. Две половинки вместо маршрута по умолчанию: исходный маршрут
    //    остаётся на месте, восстанавливать его потом не нужно.
    lines.push(format!("ip route replace 0.0.0.0/1 dev {ADAPTER}"));
    lines.push(format!("ip route replace 128.0.0.0/1 dev {ADAPTER}"));

    lines.join("\n")
}

fn tear_down_script(servers: &[String]) -> String {
    let mut lines = vec![
        // без set -e: если чего-то уже нет, уборка должна идти дальше
        "ip route del 0.0.0.0/1 2>/dev/null || true".to_string(),
        "ip route del 128.0.0.0/1 2>/dev/null || true".to_string(),
    ];
    for ip in servers {
        lines.push(format!("ip route del {ip}/32 2>/dev/null || true"));
    }
    lines.push(format!("ip link del {ADAPTER} 2>/dev/null || true"));
    lines.join("\n")
}

/// Выполняет скрипт с правами. Отдельным процессом `sh`, а не строкой в
/// `pkexec`: так аргументы не разбираются оболочкой дважды.
fn elevated(script: &str) -> bool {
    sys::command("pkexec")
        .args(["/bin/sh", "-c", script])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Следы предыдущего запуска, оборванного не по-хорошему.
pub fn clear_stale_state(core_dir: &Path) {
    sys::kill_our(&core_dir.join("tun2socks"));
    if sys::json("ip", &["-j", "link", "show", ADAPTER]).is_some() && has_pkexec() {
        sys::log("остался интерфейс от прошлого запуска — убираю");
        elevated(&format!(
            "ip route del 0.0.0.0/1 2>/dev/null || true\n\
             ip route del 128.0.0.0/1 2>/dev/null || true\n\
             ip link del {ADAPTER} 2>/dev/null || true"
        ));
    }
}

fn tail_of(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    lines.iter().rev().take(4).rev().cloned().collect::<Vec<_>>().join("\n")
}

/// Адреса серверов, приведённые к IPv4. В конфиге с балансировщиком
/// серверов несколько — маршрут нужен до каждого.
fn resolve(servers: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for address in servers {
        if let Ok(addresses) = (address.as_str(), 443u16).to_socket_addrs() {
            for socket in addresses {
                if socket.is_ipv4() {
                    let ip = socket.ip().to_string();
                    if !result.contains(&ip) {
                        result.push(ip);
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> Gateway {
        Gateway { via: "192.168.1.1".into(), dev: "wlan0".into() }
    }

    #[test]
    fn server_routes_come_before_the_tunnel_takes_over() {
        let script = bring_up_script(&["203.0.113.7".into()], &gateway());
        let server = script.find("203.0.113.7").expect("нет маршрута до сервера");
        let default = script.find("0.0.0.0/1").expect("нет маршрута по умолчанию");
        assert!(
            server < default,
            "маршрут до сервера обязан лечь раньше перехвата, иначе трафик ядра зациклится"
        );
    }

    #[test]
    fn tunnel_takes_traffic_in_two_halves() {
        let script = bring_up_script(&["203.0.113.7".into()], &gateway());
        assert!(script.contains("0.0.0.0/1"));
        assert!(script.contains("128.0.0.0/1"));
        assert!(
            !script.contains("default dev"),
            "исходный маршрут по умолчанию трогать нельзя — его потом нечем вернуть"
        );
    }

    #[test]
    fn interface_belongs_to_the_user_so_the_bridge_needs_no_rights() {
        let script = bring_up_script(&[], &gateway());
        assert!(script.contains("mode tun user "), "интерфейс должен создаваться на пользователя");
    }

    #[test]
    fn teardown_survives_missing_pieces() {
        let script = tear_down_script(&["203.0.113.7".into()]);
        assert!(!script.contains("set -e"), "уборка не должна падать на первом же отсутствии");
        assert!(script.contains("203.0.113.7"));
        assert!(script.contains("ip link del"));
    }
}
