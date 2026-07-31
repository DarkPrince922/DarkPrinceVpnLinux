//! Режим системного прокси.
//!
//! На Windows такая настройка одна на всю систему — ветка реестра, которую
//! читают почти все программы. На Linux единой настройки **не существует**:
//! рабочие столы держат свои, а консольные программы смотрят на переменные
//! окружения и о настройках рабочего стола не знают.
//!
//! Поэтому здесь мы делаем ровно то, что можем сделать честно: правим
//! настройки GNOME и KDE. Этого хватает браузерам и большинству оконных
//! программ. Всё остальное — задача режима «весь трафик»; в интерфейсе так и
//! написано, чтобы человек не гадал, почему торрент-клиент идёт мимо.

use crate::sys;

const GNOME: &str = "org.gnome.system.proxy";

/// Включает прокси на localhost. Ошибку не возвращаем, если хотя бы один
/// рабочий стол принял настройку: на GNOME нет kwriteconfig, на KDE нет
/// gsettings, и отсутствие чужой утилиты — не отказ.
pub fn enable(http_port: u16, socks_port: u16) -> Result<(), String> {
    let mut applied = false;
    applied |= gnome_enable(http_port, socks_port);
    applied |= kde_enable(http_port);

    if applied {
        sys::log(&format!("системный прокси включён: http {http_port}, socks {socks_port}"));
        Ok(())
    } else {
        Err("не удалось настроить системный прокси: не нашлись ни gsettings, ни kwriteconfig. \
Воспользуйтесь режимом «весь трафик» либо укажите прокси 127.0.0.1 в программе вручную."
            .into())
    }
}

/// Выключает прокси. Вызывать только когда прокси действительно наш —
/// проверка в [`is_ours`].
pub fn disable() {
    sys::run("gsettings", &["set", GNOME, "mode", "'none'"]);
    for tool in kde_tools() {
        sys::run(&tool, &["--file", "kioslaverc", "--group", "Proxy Settings",
                          "--key", "ProxyType", "0"]);
    }
    sys::log("системный прокси выключен");
}

/// Наш ли сейчас прокси. Пользователь мог настроить собственный — затирать
/// его чужими руками нельзя, поэтому при отключении сверяемся с портом.
pub fn is_ours(http_port: u16) -> bool {
    let mode = sys::text("gsettings", &["get", GNOME, "mode"]).unwrap_or_default();
    if !mode.contains("manual") {
        return false;
    }
    let host = sys::text("gsettings", &["get", &format!("{GNOME}.http"), "host"]).unwrap_or_default();
    let port = sys::text("gsettings", &["get", &format!("{GNOME}.http"), "port"]).unwrap_or_default();
    host.contains("127.0.0.1") && port.trim() == http_port.to_string()
}

fn gnome_enable(http_port: u16, socks_port: u16) -> bool {
    let port = http_port.to_string();
    let socks = socks_port.to_string();
    let mut ok = sys::run("gsettings", &["set", GNOME, "mode", "'manual'"]);

    for scheme in ["http", "https"] {
        let key = format!("{GNOME}.{scheme}");
        ok &= sys::run("gsettings", &["set", &key, "host", "127.0.0.1"]);
        ok &= sys::run("gsettings", &["set", &key, "port", &port]);
    }
    let key = format!("{GNOME}.socks");
    sys::run("gsettings", &["set", &key, "host", "127.0.0.1"]);
    sys::run("gsettings", &["set", &key, "port", &socks]);

    // локальные адреса мимо прокси: иначе отвалятся принтеры и роутер
    sys::run("gsettings", &["set", GNOME, "ignore-hosts",
                            "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', \
                              '172.16.0.0/12', '192.168.0.0/16']"]);
    ok
}

fn kde_enable(http_port: u16) -> bool {
    let value = format!("http://127.0.0.1 {http_port}");
    let mut ok = false;
    for tool in kde_tools() {
        // ProxyType=1 — «настроить вручную»
        ok |= sys::run(&tool, &["--file", "kioslaverc", "--group", "Proxy Settings",
                                "--key", "ProxyType", "1"]);
        for key in ["httpProxy", "httpsProxy"] {
            sys::run(&tool, &["--file", "kioslaverc", "--group", "Proxy Settings",
                              "--key", key, &value]);
        }
    }
    ok
}

/// KDE переименовала утилиту при переходе на Qt6, а дистрибутивы держат обе.
fn kde_tools() -> Vec<String> {
    ["kwriteconfig6", "kwriteconfig5"]
        .iter()
        .filter(|tool| sys::run("which", &[tool]))
        .map(|tool| tool.to_string())
        .collect()
}
