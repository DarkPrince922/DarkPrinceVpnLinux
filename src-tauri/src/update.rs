//! Обновление приложения.
//!
//! На Linux обновиться «на месте» может только AppImage — он лежит одним
//! файлом в домашнем каталоге и принадлежит самому пользователю. Пакет pacman
//! или .deb принадлежит пакетному менеджеру: запись в `/usr/bin` мимо него
//! рассогласует базу пакетов, а следующий `pacman -Syu` вернёт старый файл
//! обратно. Поэтому пакетным установкам мы показываем команду и не трогаем
//! ни одного файла.
//!
//! Подпись проверяет сам плагин: без неё скачанный файл — это чужой код,
//! запущенный с правами пользователя, и одного HTTPS тут мало.

use serde::Serialize;
use std::path::Path;
use tauri::Emitter;
use tauri_plugin_updater::UpdaterExt;

/// Сколько уже скачано. Уходит в окно событием `update-progress`.
#[derive(Serialize, Clone)]
struct Progress {
    downloaded: u64,
    /// Ноль означает «размер неизвестен» — полосу тогда не рисуем.
    total: u64,
}

/// Как приложение попало в систему.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum InstallKind {
    /// Один файл, запущенный пользователем: обновляем сами.
    AppImage,
    Pacman,
    Deb,
    /// Сборка из исходников или запуск из cargo — не трогаем.
    Unknown,
}

impl InstallKind {
    /// Команда, которой пользователь обновится сам.
    fn command(self) -> Option<&'static str> {
        match self {
            InstallKind::Pacman => Some("sudo pacman -Syu darkprince-vpn"),
            InstallKind::Deb => Some("sudo apt install ./DarkPrinceVPN.deb"),
            _ => None,
        }
    }
}

/// Определяет способ установки.
///
/// AppImage выставляет себе переменную `APPIMAGE` — это надёжнее любых догадок
/// по пути. Всё, что запущено не из `/usr`, считаем сборкой разработчика:
/// подсказывать там нечего.
pub fn install_kind() -> InstallKind {
    if std::env::var_os("APPIMAGE").is_some() {
        return InstallKind::AppImage;
    }

    let exe = std::env::current_exe().unwrap_or_default();
    if !exe.starts_with("/usr") {
        return InstallKind::Unknown;
    }

    if Path::new("/usr/bin/pacman").exists() {
        InstallKind::Pacman
    } else if Path::new("/usr/bin/dpkg").exists() {
        InstallKind::Deb
    } else {
        InstallKind::Unknown
    }
}

/// Что показать пользователю.
#[derive(Serialize, Default)]
pub struct UpdateInfo {
    /// Версия из манифеста, если она новее установленной.
    pub version: Option<String>,
    pub notes: Option<String>,
    /// Можно ли нажать кнопку «Обновить».
    pub can_install: bool,
    /// Чем обновиться руками, если сами не можем.
    pub command: Option<String>,
    /// Проверка не удалась — сети нет или сайт недоступен. Не ошибка:
    /// приложение работает, просто молчим об обновлениях.
    pub failed: bool,
}

/// Спрашивает манифест и сравнивает версии.
#[tauri::command]
pub async fn check_update(app: tauri::AppHandle) -> UpdateInfo {
    let kind = install_kind();

    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(error) => {
            dp_engine::sys::log(&format!("обновления: апдейтер недоступен: {error}"));
            return UpdateInfo {
                failed: true,
                ..Default::default()
            };
        }
    };

    match updater.check().await {
        // манифест отдал версию новее установленной
        Ok(Some(update)) => UpdateInfo {
            version: Some(update.version.clone()),
            notes: update.body.clone(),
            can_install: kind == InstallKind::AppImage,
            command: kind.command().map(str::to_owned),
            failed: false,
        },
        // установлена свежая версия
        Ok(None) => UpdateInfo::default(),
        Err(error) => {
            dp_engine::sys::log(&format!("обновления: проверка не удалась: {error}"));
            UpdateInfo {
                failed: true,
                ..Default::default()
            }
        }
    }
}

/// Скачивает и ставит обновление. Только для AppImage.
#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    let kind = install_kind();
    if kind != InstallKind::AppImage {
        // сюда можно попасть только в обход интерфейса, но лучше сказать прямо
        return Err(
            "так установлённое приложение обновляет пакетный менеджер, а не мы".into(),
        );
    }

    let update = app
        .updater()
        .map_err(|error| format!("апдейтер недоступен: {error}"))?
        .check()
        .await
        .map_err(|error| format!("не удалось проверить обновление: {error}"))?
        .ok_or("обновлений нет")?;

    dp_engine::sys::log(&format!("обновления: ставим {}", update.version));

    // Качаем сами и показываем, сколько уже скачано: файл на сотню мегабайт
    // без полосы выглядит как зависшее приложение.
    let window = app.clone();
    let mut downloaded: u64 = 0;

    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = window.emit(
                    "update-progress",
                    Progress {
                        downloaded,
                        // сервер не обязан говорить размер заранее
                        total: total.unwrap_or(0),
                    },
                );
            },
            || {},
        )
        .await
        .map_err(|error| format!("не удалось поставить обновление: {error}"))?;

    // AppImage заменён; перезапуск подхватит новый файл
    app.restart();
}
