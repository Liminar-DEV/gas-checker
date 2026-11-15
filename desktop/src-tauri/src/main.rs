// No console window behind the GUI in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
#[cfg(windows)]
mod memscan;
// Detection rules: private (decrypted by build.rs) or the open stub; see rules/README.md.
mod rules {
    include!(concat!(env!("OUT_DIR"), "/rules_active.rs"));
}
mod scanner;
#[cfg(windows)]
mod sstools;
#[cfg(windows)]
mod traces;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use scanner::{Progress, ScanReport};

/// Moderator PIN in the official build, relay code in standalone.
#[cfg(feature = "standalone")]
const PIN_LEN: usize = api::CODE_LEN;
#[cfg(not(feature = "standalone"))]
const PIN_LEN: usize = 6;

const BACKEND_PROGRESS_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
struct AppState {
    /// Set after a PIN is claimed; scanning requires it.
    session: Mutex<Option<api::Claim>>,
    /// Kept so a failed upload can be retried without rescanning.
    last_report: Mutex<Option<ScanReport>>,
    scanning: AtomicBool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanOutcome {
    report: ScanReport,
    /// Whether the result reached the moderator.
    upload_error: Option<String>,
    uploaded: bool,
}

#[derive(Serialize)]
struct ClaimInfo {
    label: String,
    server: String,
}

#[tauri::command]
async fn claim_pin(pin: String, state: State<'_, AppState>) -> Result<ClaimInfo, String> {
    let pin: String = pin.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_uppercase();
    if pin.len() != PIN_LEN {
        return Err(format!("Код состоит из {PIN_LEN} символов"));
    }
    let claim = tauri::async_runtime::spawn_blocking(move || api::claim(&pin)).await.map_err(|e| e.to_string())??;
    let info = ClaimInfo { label: claim.label.clone(), server: claim.server.clone() };
    *state.session.lock().unwrap() = Some(claim);
    Ok(info)
}

#[tauri::command]
fn is_standalone() -> bool {
    cfg!(feature = "standalone")
}

/// "full" when built with the private rules, "open" otherwise.
#[tauri::command]
fn rules_edition() -> &'static str {
    rules::EDITION
}

/// Standalone only: relay code passed as `GasChecker.exe <CODE>`; None if absent or malformed.
#[tauri::command]
fn cli_code() -> Option<String> {
    #[cfg(feature = "standalone")]
    return std::env::args().nth(1).and_then(|arg| api::normalize_code(&arg));
    #[cfg(not(feature = "standalone"))]
    None
}

#[tauri::command]
fn forget_session(state: State<'_, AppState>) {
    *state.session.lock().unwrap() = None;
}

#[tauri::command]
async fn start_scan(app: AppHandle, state: State<'_, AppState>) -> Result<ScanOutcome, String> {
    let Some(token) = state.session.lock().unwrap().as_ref().map(|claim| claim.token.clone()) else {
        return Err("Сначала введите код от модератора".into());
    };
    if state.scanning.swap(true, Ordering::AcqRel) {
        return Err("Сканирование уже идёт".into());
    }

    let scan = tauri::async_runtime::spawn_blocking(move || {
        let mut last_backend_update: Option<Instant> = None;
        let report = scanner::scan(|progress| {
            let _ = app.emit("scan-progress", progress);
            if last_backend_update.is_some_and(|at| at.elapsed() < BACKEND_PROGRESS_INTERVAL) {
                return;
            }
            last_backend_update = Some(Instant::now());
            let body = match progress {
                Progress::Walking { jars, .. } => api::ProgressBody { phase: "walking", checked: 0, total: jars },
                Progress::Checking { checked, total } => api::ProgressBody { phase: "checking", checked, total },
                Progress::Finalizing => api::ProgressBody { phase: "finalizing", checked: 0, total: 0 },
            };
            api::progress(&token, &body);
        });
        let upload = api::result(&token, &report);
        (report, upload)
    })
    .await;
    state.scanning.store(false, Ordering::Release);

    let (report, upload) = scan.map_err(|e| format!("Сканер остановился с ошибкой: {e}"))?;
    *state.last_report.lock().unwrap() = Some(report.clone());
    Ok(ScanOutcome {
        uploaded: upload.is_ok(),
        upload_error: upload.err(),
        report,
    })
}

/// Downloads the screen-share tools from their official sources and opens them.
#[tauri::command]
async fn open_ss_tools() -> Result<String, String> {
    #[cfg(windows)]
    {
        return tauri::async_runtime::spawn_blocking(sstools::run).await.map_err(|e| e.to_string());
    }
    #[cfg(not(windows))]
    Ok(String::new())
}

#[tauri::command]
async fn retry_upload(state: State<'_, AppState>) -> Result<(), String> {
    let token = state.session.lock().unwrap().as_ref().map(|claim| claim.token.clone());
    let report = state.last_report.lock().unwrap().clone();
    let (Some(token), Some(report)) = (token, report) else {
        return Err("Нечего отправлять".into());
    };
    tauri::async_runtime::spawn_blocking(move || api::result(&token, &report)).await.map_err(|e| e.to_string())?
}

/// A frameless window loses the Windows 11 rounded corners; ask DWM for them back.
/// DWM clips the acrylic backdrop too. Windows 10 ignores the attribute.
#[cfg(windows)]
fn round_corners(window: &tauri::WebviewWindow) {
    use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND};
    let Ok(hwnd) = window.hwnd() else { return };
    let preference = DWMWCP_ROUND;
    unsafe {
        DwmSetWindowAttribute(
            hwnd.0 as _,
            DWMWA_WINDOW_CORNER_PREFERENCE as _,
            (&preference as *const i32).cast(),
            std::mem::size_of_val(&preference) as u32,
        );
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            #[cfg(windows)]
            if let Some(window) = app.get_webview_window("main") {
                round_corners(&window);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rules_edition, is_standalone,cli_code, claim_pin, forget_session, start_scan, retry_upload, open_ss_tools])
        .build(tauri::generate_context!())
        .expect("error while running Gas Checker")
        .run(|_app, event| {
            let _ = &event; // only read by the self-delete below, which standalone omits
            // Remove the binary once the checker is closed, so copies aren't left behind.
            #[cfg(all(windows, not(feature = "standalone")))]
            if let tauri::RunEvent::Exit = event {
                delete_self_on_exit();
            }
        });
}

#[cfg(all(windows, not(feature = "standalone")))]
/// Spawns a detached shell that waits for this process to release the file, then deletes it.
fn delete_self_on_exit() {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = std::process::Command::new("cmd")
        .args(["/C", "ping", "-n", "2", "127.0.0.1", ">nul", "&", "del", "/f", "/q"])
        .arg(&exe)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn();
}
