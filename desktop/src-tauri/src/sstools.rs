//! Downloads the screen-share tools from their official sources and opens them.
//! User-requested: the checker fetches Everything (voidtools), JournalTrace (GitHub)
//! and Shellbag Analyzer (Privazer) into %TEMP% and launches them at scan start.
//! Best-effort — a tool that fails to download or run is skipped, never aborting the scan.

use std::fs;
use std::io::Cursor;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const EVERYTHING_ZIP: &str = "https://www.voidtools.com/Everything-1.4.1.1028.x64.zip";
const JOURNALTRACE_EXE: &str = "https://github.com/ponei/JournalTrace/releases/download/1.0/JournalTrace.exe";
const SHELLBAG_EXE: &str = "https://privazer.com/shellbag_analyzer_cleaner.exe";

const DETACHED_PROCESS: u32 = 0x0000_0008;

fn tools_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("GasCheckerTools");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("GasChecker/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    Ok(resp.bytes().map_err(|e| e.to_string())?.to_vec())
}

/// Launches a program detached so closing the checker doesn't close the tool.
fn launch(exe: &Path) {
    let mut cmd = Command::new(exe);
    if let Some(parent) = exe.parent() {
        cmd.current_dir(parent);
    }
    let _ = cmd.creation_flags(DETACHED_PROCESS).spawn();
}

fn download_and_run(url: &str, name: &str) -> bool {
    let Ok(bytes) = http_get(url) else { return false };
    let path = tools_dir().join(name);
    if fs::write(&path, &bytes).is_err() {
        return false;
    }
    launch(&path);
    true
}

fn extract_zip(bytes: &[u8], dest: &Path) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        // enclosed_name rejects path-traversal entries (../), keeping extraction inside dest.
        let Some(rel) = entry.enclosed_name() else { continue };
        let out = dest.join(rel);
        if entry.is_dir() {
            let _ = fs::create_dir_all(&out);
            continue;
        }
        if let Some(parent) = out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut file = fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut file).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn download_everything() -> bool {
    let Ok(bytes) = http_get(EVERYTHING_ZIP) else { return false };
    let dir = tools_dir().join("Everything");
    if extract_zip(&bytes, &dir).is_err() {
        return false;
    }
    let exe = dir.join("Everything.exe");
    if !exe.exists() {
        return false;
    }
    launch(&exe);
    true
}

/// Downloads and opens all three tools; returns the names that started, comma-joined.
pub fn run() -> String {
    let mut opened = Vec::new();
    if download_and_run(JOURNALTRACE_EXE, "JournalTrace.exe") {
        opened.push("JournalTrace");
    }
    if download_and_run(SHELLBAG_EXE, "shellbag_analyzer_cleaner.exe") {
        opened.push("Shellbag Analyzer");
    }
    if download_everything() {
        opened.push("Everything");
    }
    opened.join(", ")
}
