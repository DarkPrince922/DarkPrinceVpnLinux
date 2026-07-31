//! Движок клиента DarkPrince VPN для Linux.
//!
//! Здесь всё, что делает приложение приложением: разбор подписки, подготовка
//! конфига ядра, запуск ядра и моста, системный прокси и туннель. Интерфейс
//! сюда не заглядывает — он вызывает `Vpn` и читает состояние.
//!
//! Разбор подписки и сборка конфига — общие с Windows-версией слово в слово:
//! панель отдаёт один и тот же формат, и расходиться этим двум клиентам
//! нельзя. Различается только системная часть.

pub mod config;
pub mod proxy;
pub mod subscription;
pub mod sys;
pub mod tun;

use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

use serde::Serialize;
pub use subscription::Server;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Системный прокси: без прав, но не для всех программ.
    Proxy,
    /// TUN-интерфейс: весь трафик системы, права спрашиваются через polkit.
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub struct Vpn {
    core_dir: PathBuf,
    data_dir: PathBuf,
    xray: Option<Child>,
    tunnel: tun::Tunnel,
    state: State,
    mode: Mode,
    /// Порты выбираются при каждом подключении: желаемые может занять другой
    /// VPN-клиент. Помним выбранные, чтобы правильно погасить системный
    /// прокси при отключении.
    socks_port: u16,
    http_port: u16,
}

impl Vpn {
    pub fn new(core_dir: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            core_dir,
            data_dir,
            xray: None,
            tunnel: tun::Tunnel::new(),
            state: State::Disconnected,
            mode: Mode::Proxy,
            socks_port: config::SOCKS_PORT,
            http_port: config::HTTP_PORT,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Поднимает соединение. Всё внутри блокирующее: запуск процессов,
    /// разрешение имён, вызовы `ip` и запрос прав — вызывать только с
    /// фонового потока, иначе окно перестанет перерисовываться.
    pub fn connect(&mut self, server: &Server, mode: Mode) -> Result<(), String> {
        self.disconnect();
        self.state = State::Connecting;
        self.mode = mode;

        // Порты выбираем заново на каждое подключение: привычные могли
        // занять другим клиентом, пока мы стояли. Чужой процесс за это
        // снимать нельзя — просто уходим на свободный порт.
        self.socks_port = sys::pick_port(config::SOCKS_PORT);
        self.http_port = loop {
            let port = sys::pick_port(config::HTTP_PORT);
            if port != self.socks_port {
                break port;
            }
        };
        if (self.socks_port, self.http_port) != (config::SOCKS_PORT, config::HTTP_PORT) {
            sys::log(&format!(
                "привычные порты заняты, берём свои: socks {}, http {}",
                self.socks_port, self.http_port
            ));
        }

        sys::log(&format!(
            "подключение: сервер «{}», режим {}",
            server.name,
            if mode == Mode::Tun { "весь трафик" } else { "прокси" }
        ));
        let result = self.bring_up(server, mode);
        if let Err(error) = &result {
            sys::log(&format!("отказ: {error}"));
        }
        match result {
            Ok(()) => {
                self.state = State::Connected;
                Ok(())
            }
            Err(error) => {
                self.disconnect();
                Err(error)
            }
        }
    }

    fn bring_up(&mut self, server: &Server, mode: Mode) -> Result<(), String> {
        self.start_xray(server)?;
        match mode {
            Mode::Proxy => proxy::enable(self.http_port, self.socks_port)?,
            Mode::Tun => {
                let bridge = self.core_dir.join("tun2socks");
                self.tunnel.start(
                    &bridge,
                    &[server.address.clone()],
                    self.socks_port,
                    &self.data_dir,
                )?;
            }
        }
        Ok(())
    }

    fn start_xray(&mut self, server: &Server) -> Result<(), String> {
        let core = self.core_dir.join("xray");
        sys::log(&format!("ядро: {}", core.display()));
        if !core.exists() {
            return Err(format!(
                "не найдено ядро Xray: {}. Переустановите приложение.",
                core.display()
            ));
        }

        std::fs::create_dir_all(&self.data_dir).ok();
        let config_path = self.data_dir.join("xray-config.json");
        std::fs::write(
            &config_path,
            config::build(&server.raw_config, self.socks_port, self.http_port)?,
        )
        .map_err(|error| format!("не удалось сохранить конфиг ядра: {error}"))?;

        // вывод ядра — в файл: свои отказы оно объясняет только там
        let log_path = self.data_dir.join("xray.log");
        let child = sys::command(&core.to_string_lossy())
            .args(["run", "-c", &config_path.to_string_lossy()])
            .current_dir(&self.core_dir)
            .env("XRAY_LOCATION_ASSET", &self.core_dir)
            .stdout(sys::log_file(&log_path))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("не удалось запустить ядро: {error}"))?;
        self.xray = Some(child);

        // Мало запустить — надо дождаться, пока ядро начнёт принимать
        // соединения. Без этой проверки сломанный конфиг выглядел бы как
        // успешное подключение, у которого просто «не работает интернет».
        if !sys::wait_for_port(self.socks_port, Duration::from_secs(6)) {
            let tail = tail_of(&log_path);
            sys::log(&format!("ядро не открыло порт. Хвост журнала:\n{tail}"));
            return Err(format!("ядро не приняло конфиг сервера и не открыло порт.\n{tail}"));
        }
        sys::log("ядро слушает порт");
        Ok(())
    }

    pub fn disconnect(&mut self) {
        // системный прокси гасим только свой: пользователь мог настроить
        // собственный, и затирать его чужими руками нельзя
        if proxy::is_ours(self.http_port) {
            proxy::disable();
        }
        self.tunnel.stop();
        if let Some(mut child) = self.xray.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.state = State::Disconnected;
    }

    /// Уборка следов запуска, оборванного жёстко.
    pub fn clear_stale_state(core_dir: &Path) {
        sys::kill_our(&core_dir.join("xray"));
        tun::clear_stale_state(core_dir);
    }
}

impl Drop for Vpn {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn tail_of(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    lines.iter().rev().take(4).rev().cloned().collect::<Vec<_>>().join("\n")
}
