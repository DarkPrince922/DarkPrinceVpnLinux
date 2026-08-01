// окно у приложения своё, консольное открываться не должно
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Оболочка приложения: тонкая прослойка между интерфейсом и движком.
//!
//! Здесь нет ни логики подписки, ни работы с сетью — всё это в `dp-engine`,
//! который проверяется тестами отдельно. Оболочка отвечает за три вещи:
//! отдать интерфейсу команды, увести долгую работу с потока окна и выполнить
//! сетевые запросы, которым мешало бы правило одного источника.
//!
//! Отличие от Windows-версии одно: там приложение перезапускало себя от
//! администратора целиком, здесь права спрашивает движок через polkit ровно
//! на те команды, которым они нужны. Поэтому команды перезапуска нет.

mod update;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dp_engine::{Mode, Server, State, Vpn};
use serde::{Deserialize, Serialize};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, State as TauriState, WindowEvent};

struct App {
    vpn: Arc<Mutex<Vpn>>,
    servers: Mutex<Vec<Server>>,
    /// Нужен при выходе: по этим путям добиваем свои процессы.
    core_dir: PathBuf,
}

/// Выход уже начат. Флаг разрывает круг: `exit` закрывает окно, окно снова
/// присылает «просят закрыть», а тот обработчик закрытие отменяет.
static QUITTING: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
struct ServerView {
    index: usize,
    name: String,
    transport: String,
}

#[derive(Serialize)]
struct Status {
    state: State,
    mode: Mode,
    /// Есть ли чем спросить права. Без polkit режим «весь трафик» невозможен,
    /// и честнее сказать это заранее, чем отказать в момент подключения.
    can_elevate: bool,
}

#[derive(Deserialize)]
struct Request {
    method: String,
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Serialize)]
struct Response {
    status: u16,
    body: String,
}

/// Загружает подписку и запоминает список серверов.
#[tauri::command]
async fn load_subscription(
    url: String,
    hwid: String,
    app: TauriState<'_, App>,
) -> Result<Vec<ServerView>, String> {
    let text = fetch_subscription(&url, &hwid).await?;
    let servers = dp_engine::subscription::parse(&text);
    if servers.is_empty() {
        return Err("подписка пуста или в незнакомом формате".into());
    }
    let view = servers
        .iter()
        .enumerate()
        .map(|(index, server)| ServerView {
            index,
            name: server.name.clone(),
            transport: server.transport_label(),
        })
        .collect();
    *app.servers.lock().unwrap() = servers;
    Ok(view)
}

/// Подключение. Работа долгая и блокирующая — уводим её с потока окна,
/// иначе интерфейс перестанет перерисовываться.
#[tauri::command]
async fn connect(index: usize, tun: bool, app: TauriState<'_, App>) -> Result<(), String> {
    let server = {
        let servers = app.servers.lock().unwrap();
        servers.get(index).cloned().ok_or("сервер не выбран")?
    };
    let mode = if tun { Mode::Tun } else { Mode::Proxy };
    let vpn = Arc::clone(&app.vpn);
    match tauri::async_runtime::spawn_blocking(move || vpn.lock().unwrap().connect(&server, mode)).await {
        Ok(result) => result,
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
async fn disconnect(app: TauriState<'_, App>) -> Result<(), String> {
    let vpn = Arc::clone(&app.vpn);
    tauri::async_runtime::spawn_blocking(move || vpn.lock().unwrap().disconnect())
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn status(app: TauriState<'_, App>) -> Status {
    let vpn = app.vpn.lock().unwrap();
    Status {
        state: vpn.state(),
        mode: vpn.mode(),
        can_elevate: dp_engine::tun::has_pkexec(),
    }
}

/// Где лежат ядро и мост.
///
/// Одного ответа тут нет: приложение живёт то распакованным рядом с собой,
/// то установленным пакетом, то внутри AppImage. Поэтому проверяем все
/// привычные места по очереди и берём первое, где ядро действительно есть.
/// Если не нашли — возвращаем самый вероятный путь: движок скажет о пропаже
/// понятнее, чем пустая папка.
fn find_core_dir(resources: Option<PathBuf>) -> PathBuf {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = resources {
        candidates.push(dir.join("core"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("core"));
        }
    }
    candidates.push(PathBuf::from("/usr/lib/darkprince-vpn/core"));

    for candidate in &candidates {
        if candidate.join("xray").exists() {
            return candidate.clone();
        }
    }
    candidates.into_iter().next().unwrap_or_else(|| PathBuf::from("core"))
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Полный выход по кнопке из окна.
#[tauri::command]
fn quit_app(app_handle: tauri::AppHandle) {
    quit(&app_handle);
}

#[tauri::command]
fn open_url(url: String) {
    // ссылку открываем в браузере по умолчанию
    dp_engine::sys::command("xdg-open").arg(&url).spawn().ok();
}

/// Запрос в кабинет. Идёт из Rust, а не из страницы: у окна свой источник,
/// и браузерное правило одного источника не пустило бы его наружу.
#[tauri::command]
async fn http(request: Request) -> Result<Response, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| error.to_string())?;

    let method = reqwest::Method::from_bytes(request.method.to_uppercase().as_bytes())
        .map_err(|_| "неизвестный метод запроса".to_string())?;
    let mut builder = client.request(method, &request.url);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    let response = builder
        .send()
        .await
        .map_err(|_| "нет соединения с сервером. Проверьте интернет.".to_string())?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Ok(Response { status, body })
}

/// Скачивание подписки. Заголовки здесь не украшение:
///
/// * панель отдаёт формат по клиенту — без `User-Agent` известного клиента
///   вместо конфига Xray приходит совсем другое, и разбирать нечего;
/// * по `x-hwid` и соседям панель ведёт учёт устройств. Без них компьютер не
///   появится в списке устройств кабинета, а лимит тарифа не сработает.
async fn fetch_subscription(url: &str, hwid: &str) -> Result<String, String> {
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "v2rayNG/1.10.7".to_string());
    headers.insert("Accept".to_string(), "text/plain".to_string());
    headers.insert("x-hwid".to_string(), hwid.to_string());
    headers.insert("x-device-os".to_string(), "Linux".to_string());
    headers.insert("x-ver-os".to_string(), os_version());
    headers.insert("x-device-model".to_string(), machine_name());

    let response = http(Request {
        method: "GET".into(),
        url: url.to_string(),
        headers,
        body: None,
    })
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(format!("сервер подписки ответил {}", response.status));
    }
    Ok(response.body)
}

fn machine_name() -> String {
    dp_engine::sys::text("hostname", &[]).unwrap_or_else(|| "Linux PC".to_string())
}

/// Название дистрибутива. Спрашивается один раз за запуск: ответ не меняется.
fn os_version() -> String {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| line.starts_with("PRETTY_NAME="))
                        .map(|line| line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
                })
                .unwrap_or_else(|| "Linux".to_string())
        })
        .clone()
}

/// Полный выход: снять соединение, вернуть системный прокси, убить свои
/// процессы и освободить порты — и только потом закрыться.
///
/// Всё это делается на отдельном потоке. На потоке окна нельзя: разбор
/// туннеля ходит в `ip` и может спросить пароль, а пока поток окна занят,
/// приложение выглядит зависшим.
fn quit(app: &tauri::AppHandle) {
    // второе нажатие «Выход», пока идёт первое, ничего не меняет
    if QUITTING.swap(true, Ordering::SeqCst) {
        return;
    }

    let handle = app.clone();
    let core_dir = app
        .try_state::<App>()
        .map(|state| state.core_dir.clone())
        .unwrap_or_default();

    // Страховка на случай, если замок занят долгим подключением: выйти
    // приложение обязано в любом случае, иначе значок останется висеть.
    let failsafe = core_dir.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        dp_engine::sys::log("выход затянулся — закрываемся принудительно");
        Vpn::clear_stale_state(&failsafe);
        std::process::exit(0);
    });

    std::thread::spawn(move || {
        if let Some(state) = handle.try_state::<App>() {
            if let Ok(mut vpn) = state.vpn.lock() {
                vpn.disconnect();
            }
        }
        Vpn::clear_stale_state(&core_dir);
        dp_engine::sys::log("--- выход ---");
        handle.exit(0);
    });
}

fn main() {
    tauri::Builder::default()
        // Второй запуск не поднимает второе приложение, а показывает уже
        // работающее. Без этого каждый повторный запуск вешал в трей ещё
        // один значок: приложение живёт с закрытым окном, ярлык об этом не
        // знает, и значки копились по числу запусков.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_window(app);
        }))
        // Обновления. Ставить их сами мы можем только у AppImage — почему,
        // написано в update.rs; проверять новую версию не мешает никому.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let core_dir = find_core_dir(app.path().resource_dir().ok());
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));

            std::fs::create_dir_all(&data_dir).ok();
            dp_engine::sys::set_log_path(data_dir.join("app.log"));
            dp_engine::sys::log(&format!(
                "--- запуск {} ---\nядро ищем в {}",
                env!("CARGO_PKG_VERSION"),
                core_dir.display()
            ));

            // следы прошлого запуска, если его завершили жёстко
            Vpn::clear_stale_state(&core_dir);

            app.manage(App {
                vpn: Arc::new(Mutex::new(Vpn::new(core_dir.clone(), data_dir))),
                servers: Mutex::new(Vec::new()),
                core_dir,
            });

            // Значок в трее. Приложение продолжает работать с закрытым
            // окном: соединение живёт, пока его не выключат явно.
            let open = MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", "Подключиться", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &connect, &disconnect, &quit_item])?;

            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().unwrap())
                .tooltip("DarkPrince VPN")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_window(app),
                    // подключением занимается страница: она знает выбранный
                    // сервер и режим, и делает это тем же путём, что и кнопка
                    "connect" => {
                        let _ = app.emit("tray", "connect");
                    }
                    "disconnect" => {
                        let _ = app.emit("tray", "disconnect");
                    }
                    "quit" => quit(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { button, .. } = event {
                        if button == tauri::tray::MouseButton::Left {
                            show_window(tray.app_handle());
                        }
                    }
                })
                .build(app)?;

            // Крестик сам по себе ничего не решает: закрыть окно и закрыть
            // приложение — разные вещи, а соединение переживает закрытое
            // окно. Спрашивает страница — своим окном, а не системным.
            if let Some(window) = app.get_webview_window("main") {
                let handle = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        if QUITTING.load(Ordering::SeqCst) {
                            return; // выход уже идёт — не мешаем
                        }
                        api.prevent_close();
                        let _ = handle.show();
                        let _ = handle.unminimize();
                        let _ = handle.set_focus();
                        let _ = handle.emit("close-requested", ());
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            load_subscription,
            connect,
            disconnect,
            status,
            open_url,
            quit_app,
            http,
            update::check_update,
            update::install_update
        ])
        .run(tauri::generate_context!())
        .expect("не удалось запустить приложение");
}
