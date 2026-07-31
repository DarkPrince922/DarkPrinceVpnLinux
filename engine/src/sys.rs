//! Работа с системой: запуск программ, порты, журнал.
//!
//! Linux-версия спрашивает систему её же утилитами, но там, где ответ нужен
//! разбором, просит **машинный формат**: `ip -j` отдаёт JSON и не зависит ни
//! от языка системы, ни от ширины колонок. На Windows ту же задачу решал
//! PowerShell — по той же причине.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};

/// Готовит команду. На Linux прятать консольное окно не нужно, но stdin
/// закрываем: иначе программа, решившая что-то спросить, повиснет молча.
pub fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.stdin(Stdio::null());
    command
}

/// Выполняет команду и ждёт её завершения. `true` — код возврата нулевой.
pub fn run(program: &str, args: &[&str]) -> bool {
    match output(program, args) {
        Some(result) => result.status.success(),
        None => false,
    }
}

pub fn output(program: &str, args: &[&str]) -> Option<Output> {
    command(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()
}

/// Вывод команды строкой. Пустой ответ считаем отсутствием ответа.
pub fn text(program: &str, args: &[&str]) -> Option<String> {
    let result = output(program, args)?;
    if !result.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&result.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// То же, но ответ разбирается как JSON. Нужен для `ip -j`: разбирать
/// человекочитаемый вывод нельзя — он меняется между версиями iproute2.
pub fn json(program: &str, args: &[&str]) -> Option<serde_json::Value> {
    serde_json::from_str(&text(program, args)?).ok()
}

/// Куда писать журнал. Задаётся один раз при запуске приложения.
static LOG_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

pub fn set_log_path(path: PathBuf) {
    let cell = LOG_PATH.get_or_init(|| Mutex::new(None));
    *cell.lock().unwrap() = Some(path);
}

/// Запись в журнал. Без него причина отказа видна только на машине
/// пользователя и только на словах — а слов обычно не хватает.
pub fn log(message: &str) {
    let cell = match LOG_PATH.get() {
        Some(cell) => cell,
        None => return,
    };
    let path = match cell.lock().unwrap().clone() {
        Some(path) => path,
        None => return,
    };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{message}");
    }
}

/// Файл для вывода запускаемой программы. Ядро и мост объясняют свои
/// отказы только в вывод, и без него отказ выглядит как молчание.
pub fn log_file(path: &std::path::Path) -> Stdio {
    match std::fs::File::create(path) {
        Ok(file) => Stdio::from(file),
        Err(_) => Stdio::null(),
    }
}

/// Ждёт, пока по адресу начнут принимать соединения.
pub fn wait_for_port(port: u16, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    false
}

/// Свободный порт: сначала пробуем желаемый, иначе просим систему выдать
/// любой. Занять наш порт мог другой VPN-клиент — это не повод ни падать,
/// ни убивать чужой процесс.
pub fn pick_port(preferred: u16) -> u16 {
    if std::net::TcpListener::bind(("127.0.0.1", preferred)).is_ok() {
        return preferred;
    }
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .unwrap_or(preferred)
}

/// Снимает только свои забытые процессы — по полному пути к файлу.
/// Снимать по имени нельзя: `xray` есть у половины VPN-клиентов, и чужой
/// процесс — не наша собственность. `pgrep -f` сверяет всю командную
/// строку, поэтому путь в ней и служит признаком «наше».
pub fn kill_our(path: &std::path::Path) {
    let full = path.to_string_lossy().to_string();
    if full.is_empty() {
        return;
    }
    let pids = match text("pgrep", &["-f", &format!("^{}", regex_escape(&full))]) {
        Some(text) => text,
        None => return,
    };
    for pid in pids.lines() {
        let pid = pid.trim();
        if pid.is_empty() || pid == std::process::id().to_string() {
            continue;
        }
        run("kill", &["-TERM", pid]);
    }
}

/// Экранирование для `pgrep -f`: путь попадает в регулярное выражение, и
/// точка в имени файла иначе совпала бы с любым символом.
fn regex_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if "\\.^$*+?()[]{}|/".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn free_port_is_taken_as_is() {
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port(); // слушателя тут же роняем — порт снова свободен
        assert_eq!(pick_port(port), port);
    }

    #[test]
    fn busy_port_sends_us_elsewhere() {
        let squatter = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let busy = squatter.local_addr().unwrap().port();
        let picked = pick_port(busy);
        assert_ne!(picked, busy, "занятый порт брать нельзя");
        assert!(TcpListener::bind(("127.0.0.1", picked)).is_ok(), "выданный порт занят");
    }

    #[test]
    fn path_is_escaped_for_pattern() {
        let escaped = regex_escape("/opt/dp/xray.bin");
        assert_eq!(escaped, "\\/opt\\/dp\\/xray\\.bin");
        assert!(!escaped.contains("y.b"), "точка должна перестать быть любым символом");
    }
}
