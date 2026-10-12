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
//! требует прав: создание интерфейса и правка маршрутов.
//!
//! Это делает помощник `dp-tun-helper` (packaging/), и правило polkit
//! разрешает его активному пользователю без пароля — как у Happ и других
//! клиентов. Пакеты .deb и pacman ставят помощника сами. Если его нет
//! (AppImage), пароль спросят один раз: заодно с туннелем помощник и правило
//! поставятся в систему, и дальше подключение пойдёт без пароля.
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
#[cfg(test)]
const ADDRESS: &str = "198.18.0.1";
#[cfg(test)]
const MASK: &str = "24";
/// Адрес туннеля в IPv6 — из частного диапазона, наружу не виден.
#[cfg(test)]
const ADDRESS6: &str = "fd66:6470:7276::1";
/// Таблица маршрутов туннеля и приоритеты правил. Номера свои, чтобы не
/// задеть чужие правила; по ним же правила и убираются. Сами команды — в
/// помощнике (packaging/dp-tun-helper); здесь значения для сверки в тестах.
#[cfg(test)]
const TABLE: &str = "7276";
#[cfg(test)]
const PREF_SERVERS: u32 = 7270;
#[cfg(test)]
const PREF_LOCAL: u32 = 7271;
#[cfg(test)]
const PREF_TUNNEL: u32 = 7272;

/// Помощник с правами и правило polkit к нему — те же файлы, что кладут пакеты.
const HELPER: &str = include_str!("../../packaging/dp-tun-helper");
const POLICY: &str = include_str!("../../packaging/ru.dprince.vpn.policy");
const HELPER_PATH: &str = "/usr/lib/darkprince-vpn/dp-tun-helper";
const POLICY_PATH: &str = "/usr/share/polkit-1/actions/ru.dprince.vpn.policy";

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

        // Всё, что требует прав, — одним вызовом помощника.
        if !helper(&up_args(&v4, &v6, ipv6)) {
            // мог успеть подняться интерфейс или часть правил — убираем
            helper(&["down".to_string()]);
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
            helper(&["down".to_string()]);
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

/// Аргументы помощника: `up 0|1 4:адрес 6:адрес …`.
fn up_args(servers: &[String], servers6: &[String], ipv6: bool) -> Vec<String> {
    let mut args = vec!["up".to_string(), if ipv6 { "1" } else { "0" }.to_string()];
    args.extend(servers.iter().map(|ip| format!("4:{ip}")));
    args.extend(servers6.iter().map(|ip| format!("6:{ip}")));
    args
}

/// Стоит ли в системе помощник ровно этой версии вместе с правилом polkit.
fn helper_installed() -> bool {
    std::fs::read_to_string(HELPER_PATH).is_ok_and(|text| text == HELPER)
        && Path::new(POLICY_PATH).exists()
}

/// Скрипт для случая, когда помощника нет или он старый: поставить его и
/// правило в систему (тогда в следующий раз пароль не понадобится) и сразу
/// выполнить. Содержимое — внутри скрипта, а не во временных файлах
/// пользователя: подменить то, что root поставит в систему, некому.
/// Не вышло поставить (например, /usr только для чтения) — помощник всё
/// равно выполнится из закрытой временной папки root.
fn install_and_run_script() -> String {
    format!(
        r#"umask 022
t=$(mktemp -d) || exit 1
cat > "$t/helper" <<'DP_HELPER_EOF'
{HELPER}DP_HELPER_EOF
cat > "$t/policy" <<'DP_POLICY_EOF'
{POLICY}DP_POLICY_EOF
{{ install -Dm755 "$t/helper" {HELPER_PATH} && install -Dm644 "$t/policy" {POLICY_PATH}; }} 2>/dev/null || true
/bin/sh "$t/helper" "$@"
rc=$?
rm -rf "$t"
exit $rc"#
    )
}

/// Выполняет помощника с правами. Стоит — pkexec пускает его без пароля;
/// нет — один раз с паролем, заодно ставя его в систему.
fn helper(args: &[String]) -> bool {
    let status = if helper_installed() {
        sys::command("pkexec").arg(HELPER_PATH).args(args).status()
    } else {
        sys::command("pkexec")
            .args(["/bin/sh", "-c", &install_and_run_script(), "dp-tun-helper"])
            .args(args)
            .status()
    };
    status.map(|status| status.success()).unwrap_or(false)
}

/// Следы предыдущего запуска, оборванного не по-хорошему.
pub fn clear_stale_state(core_dir: &Path) {
    sys::kill_our(&core_dir.join("tun2socks"));
    if sys::json("ip", &["-j", "link", "show", ADAPTER]).is_some() && has_pkexec() {
        sys::log("остался интерфейс от прошлого запуска — убираю");
        helper(&["down".to_string()]);
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

    #[test]
    fn servers_go_by_the_live_route_before_the_tunnel_takes_over() {
        let server = HELPER.find("lookup main pref \"$PREF_SERVERS\"").expect("нет правила до сервера");
        let tunnel = HELPER.find("lookup \"$TABLE\" pref \"$PREF_TUNNEL\"").expect("нет правила туннеля");
        assert!(
            server < tunnel,
            "правило до сервера обязано лечь раньше перехвата, иначе трафик ядра зациклится"
        );
        assert!(HELPER.contains("blackhole \"$ip/32\""), "без сети пакеты к серверу не должны уходить в туннель");
    }

    #[test]
    fn helper_constants_match_the_engine() {
        assert!(HELPER.contains(&format!("ADAPTER={ADAPTER}\n")));
        assert!(HELPER.contains(&format!("ADDRESS={ADDRESS}/{MASK}\n")));
        assert!(HELPER.contains(&format!("ADDRESS6={ADDRESS6}/64\n")));
        assert!(HELPER.contains(&format!("TABLE={TABLE}\n")));
        assert!(HELPER.contains(&format!("PREF_SERVERS={PREF_SERVERS}\n")));
        assert!(HELPER.contains(&format!("PREF_LOCAL={PREF_LOCAL}\n")));
        assert!(HELPER.contains(&format!("PREF_TUNNEL={PREF_TUNNEL}\n")));
        assert!(POLICY.contains(HELPER_PATH), "правило polkit должно указывать на того же помощника");
    }

    #[test]
    fn main_default_route_is_left_alone() {
        for line in HELPER.lines().filter(|line| line.contains("default dev")) {
            assert!(line.contains("table \"$TABLE\""), "маршрут по умолчанию основной таблицы трогать нельзя: {line}");
        }
        assert!(HELPER.contains("suppress_prefixlength 0"), "локальная сеть должна остаться локальной");
    }

    #[test]
    fn ipv6_commands_forgive_failure() {
        for line in HELPER.lines().map(str::trim).filter(|line| line.starts_with("ip -6") && !line.contains("rule del")) {
            assert!(line.ends_with("|| true"), "команда IPv6 должна прощать отказ: {line}");
        }
    }

    #[test]
    fn interface_belongs_to_the_caller_not_to_an_argument() {
        assert!(HELPER.contains("mode tun user \"$owner\""));
        assert!(HELPER.contains("id -nu \"$PKEXEC_UID\""), "пользователя берём у pkexec, а не из аргументов");
    }

    #[test]
    fn up_args_tag_address_families() {
        let args = up_args(&["203.0.113.7".into()], &["2001:db8::7".into()], true);
        assert_eq!(args, ["up", "1", "4:203.0.113.7", "6:2001:db8::7"]);
    }

    #[test]
    fn install_script_embeds_both_files_intact() {
        let script = install_and_run_script();
        assert!(script.contains(HELPER));
        assert!(script.contains(POLICY));
        assert!(!HELPER.contains("DP_HELPER_EOF") && !POLICY.contains("DP_POLICY_EOF"));
        assert!(script.contains(&format!("install -Dm755 \"$t/helper\" {HELPER_PATH}")));
    }
}
