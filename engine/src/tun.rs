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
//!
//! Про маршруты. Маршрут по умолчанию из основной таблицы не трогаем вовсе:
//! трафик в туннель уводится отдельной таблицей и правилами (как делает
//! wg-quick), а адреса серверов правилом отправляются в основную таблицу —
//! то есть по живому маршруту системы, каким бы он ни был сейчас. Раньше до
//! сервера прокладывался маршрут через конкретный шлюз, и при смене сети
//! (другой Wi-Fi, кабель) он пропадал: трафик ядра уходил в собственный
//! туннель, интернет пропадал до переподключения. Теперь смена сети
//! подхватывается сама — без нового запроса пароля.
//!
//! IPv6 уводится в туннель так же, если он в системе есть. Без этого
//! сайты с IPv6 открывались мимо VPN, с настоящим адресом.

use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::sys;

pub const ADAPTER: &str = "dpvpn0";
const ADDRESS: &str = "198.18.0.1";
const MASK: &str = "24";
/// Адрес туннеля в IPv6 — из частного диапазона, наружу не виден.
const ADDRESS6: &str = "fd66:6470:7276::1";
/// Таблица маршрутов туннеля и приоритеты правил. Номера свои, чтобы не
/// задеть чужие правила; по ним же правила и убираются.
const TABLE: &str = "7276";
const PREF_SERVERS: u32 = 7270;
const PREF_LOCAL: u32 = 7271;
const PREF_TUNNEL: u32 = 7272;

pub struct Tunnel {
    process: Option<Child>,
    up: bool,
}

impl Tunnel {
    pub fn new() -> Self {
        Self { process: None, up: false }
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

        let (v4, v6) = resolve(servers);
        if v4.is_empty() && v6.is_empty() {
            return Err("не удалось определить адрес сервера. Без отдельного маршрута до него \
весь трафик, включая трафик самого ядра, ушёл бы в туннель и соединение зациклилось бы."
                .into());
        }
        let ipv6 = has_ipv6_route();
        sys::log(&format!(
            "серверы: {v4:?} {v6:?}; IPv6 {}",
            if ipv6 { "есть — тоже в туннель" } else { "в системе не настроен" }
        ));

        // Всё, что требует прав, — одним заходом: один запрос пароля.
        let script = bring_up_script(&v4, &v6, ipv6);
        if !elevated(&script) {
            // мог успеть подняться интерфейс или часть правил — убираем
            elevated(&tear_down_script());
            return Err("не удалось поднять туннель: система отказала в правах. \
Если окно запроса пароля не появилось, проверьте, что служба polkit запущена."
                .into());
        }
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
            elevated(&tear_down_script());
            self.up = false;
        }
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

/// Есть ли в системе IPv6 с выходом наружу. Нет маршрута по умолчанию —
/// нет и утечки: уводить в туннель нечего.
fn has_ipv6_route() -> bool {
    sys::json("ip", &["-j", "-6", "route", "show", "default"])
        .and_then(|routes| routes.as_array().map(|list| !list.is_empty()))
        .unwrap_or(false)
}

/// Скрипт поднятия. Одной строкой, потому что `pkexec` спрашивает пароль на
/// каждый свой запуск: десять команд — десять запросов.
fn bring_up_script(servers: &[String], servers6: &[String], ipv6: bool) -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let mut lines = vec![
        "set -e".to_string(),
        // интерфейс создаётся на имя пользователя — мосту тогда не нужны права
        format!("ip tuntap add dev {ADAPTER} mode tun user {user}"),
        format!("ip addr add {ADDRESS}/{MASK} dev {ADAPTER}"),
        format!("ip link set dev {ADAPTER} up"),
    ];

    // 1. Серверы — по основной таблице, то есть по живому маршруту системы.
    //    Обязательно раньше правила туннеля. Чёрная дыра в таблице туннеля —
    //    на случай, когда сети нет вовсе: тогда пакеты ядра к серверу
    //    пропадут, а не уйдут по кругу в собственный туннель.
    for ip in servers {
        lines.push(format!("ip rule add to {ip}/32 lookup main pref {PREF_SERVERS}"));
        lines.push(format!("ip route replace blackhole {ip}/32 table {TABLE}"));
    }
    // 2. Локальная сеть и точные маршруты системы — как были: основная
    //    таблица, но без её маршрута по умолчанию.
    lines.push(format!("ip rule add lookup main suppress_prefixlength 0 pref {PREF_LOCAL}"));
    // 3. Всё остальное — в туннель.
    lines.push(format!("ip route replace default dev {ADAPTER} table {TABLE}"));
    lines.push(format!("ip rule add lookup {TABLE} pref {PREF_TUNNEL}"));

    // IPv6 — тем же порядком. Каждая команда отдельно прощает отказ: IPv6
    // бывает выключен в ядре, и это не повод оставить человека без IPv4.
    if ipv6 {
        let soft = |command: String| format!("{command} 2>/dev/null || true");
        lines.push(soft(format!("ip -6 addr add {ADDRESS6}/64 dev {ADAPTER} nodad")));
        for ip in servers6 {
            lines.push(soft(format!("ip -6 rule add to {ip}/128 lookup main pref {PREF_SERVERS}")));
            lines.push(soft(format!("ip -6 route replace blackhole {ip}/128 table {TABLE}")));
        }
        lines.push(soft(format!(
            "ip -6 rule add lookup main suppress_prefixlength 0 pref {PREF_LOCAL}"
        )));
        lines.push(soft(format!("ip -6 route replace default dev {ADAPTER} table {TABLE}")));
        lines.push(soft(format!("ip -6 rule add lookup {TABLE} pref {PREF_TUNNEL}")));
    }

    lines.join("\n")
}

/// Уборка. Правила снимаем по своим приоритетам все до одного — их могло
/// остаться несколько от оборванных запусков.
fn tear_down_script() -> String {
    let mut lines = Vec::new();
    for family in ["", "-6 "] {
        for pref in [PREF_TUNNEL, PREF_LOCAL, PREF_SERVERS] {
            lines.push(format!("while ip {family}rule del pref {pref} 2>/dev/null; do :; done"));
        }
        lines.push(format!("ip {family}route flush table {TABLE} 2>/dev/null || true"));
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
        elevated(&tear_down_script());
    }
}

fn tail_of(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    lines.iter().rev().take(4).rev().cloned().collect::<Vec<_>>().join("\n")
}

/// Адреса серверов: отдельно IPv4 и IPv6. В конфиге с балансировщиком
/// серверов несколько — правило нужно для каждого. IPv6 тоже: ядро вправе
/// пойти к серверу по нему, и без правила такой путь ушёл бы в туннель.
fn resolve(servers: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = Vec::new();
    let mut v6: Vec<String> = Vec::new();
    for address in servers {
        if let Ok(addresses) = (address.as_str(), 443u16).to_socket_addrs() {
            for socket in addresses {
                let ip = socket.ip().to_string();
                let list = if socket.is_ipv4() { &mut v4 } else { &mut v6 };
                if !list.contains(&ip) {
                    list.push(ip);
                }
            }
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(ipv6: bool) -> String {
        bring_up_script(&["203.0.113.7".into()], &["2001:db8::7".into()], ipv6)
    }

    #[test]
    fn servers_go_by_the_live_route_before_the_tunnel_takes_over() {
        let script = script(false);
        let server = script.find("to 203.0.113.7/32 lookup main").expect("нет правила до сервера");
        let tunnel = script.find(&format!("lookup {TABLE} pref")).expect("нет правила туннеля");
        assert!(
            server < tunnel,
            "правило до сервера обязано лечь раньше перехвата, иначе трафик ядра зациклится"
        );
        assert!(script.contains("blackhole 203.0.113.7/32"), "без сети пакеты к серверу не должны уходить в туннель");
    }

    #[test]
    fn main_default_route_is_left_alone() {
        let script = script(true);
        for line in script.lines().filter(|line| line.contains("default dev")) {
            assert!(
                line.contains(&format!("table {TABLE}")),
                "маршрут по умолчанию основной таблицы трогать нельзя: {line}"
            );
        }
        assert!(script.contains("suppress_prefixlength 0"), "локальная сеть должна остаться локальной");
    }

    #[test]
    fn ipv6_goes_into_the_tunnel_only_when_present() {
        let with = script(true);
        assert!(with.contains("ip -6 rule add to 2001:db8::7/128 lookup main"));
        assert!(with.contains(&format!("ip -6 rule add lookup {TABLE}")));
        // IPv6 может быть выключен в ядре — это не повод ломать IPv4
        for line in with.lines().filter(|line| line.starts_with("ip -6")) {
            assert!(line.ends_with("|| true"), "команда IPv6 должна прощать отказ: {line}");
        }
        assert!(!script(false).contains("ip -6"));
    }

    #[test]
    fn interface_belongs_to_the_user_so_the_bridge_needs_no_rights() {
        assert!(script(false).contains("mode tun user "), "интерфейс должен создаваться на пользователя");
    }

    #[test]
    fn teardown_survives_missing_pieces_and_removes_every_rule() {
        let script = tear_down_script();
        assert!(!script.contains("set -e"), "уборка не должна падать на первом же отсутствии");
        for pref in [PREF_SERVERS, PREF_LOCAL, PREF_TUNNEL] {
            assert!(script.contains(&format!("while ip rule del pref {pref}")));
            assert!(script.contains(&format!("while ip -6 rule del pref {pref}")));
        }
        assert!(script.contains("ip link del"));
    }
}
