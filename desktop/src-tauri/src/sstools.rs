//! Downloads the screen-share tools from their official sources and opens them.
//! User-requested: the checker fetches Everything (voidtools), JournalTrace (GitHub)
//! and Shellbag Analyzer (Privazer) at scan start and launches them.
//! Best-effort — a tool that fails to download, verify or run is skipped, never aborting the scan.
//!
//! The checker runs elevated and starts these tools with the same rights, so they are staged
//! where a non-elevated process of the same user cannot touch them: every run uses a fresh,
//! randomly named directory under %TEMP% whose ACL is limited to Administrators and SYSTEM.
//! Everything and JournalTrace are pinned by SHA-256 and verified before anything is written.
//! shortcut: Shellbag Analyzer is not pinned (the vendor URL is unversioned), so it relies on
//! HTTPS and the protected directory only; pin it or verify its signature if the vendor versions it.

use std::fs;
use std::io::Cursor;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

const EVERYTHING_ZIP: &str = "https://www.voidtools.com/Everything-1.4.1.1028.x64.zip";
const EVERYTHING_ZIP_SHA256: &str = "4f4a9b9299b608d48b065f95fd80b9c095cdc7114cd467cd9b54944b23559dfe";
const JOURNALTRACE_EXE: &str = "https://github.com/ponei/JournalTrace/releases/download/1.0/JournalTrace.exe";
const JOURNALTRACE_SHA256: &str = "46873781a5c80ea676f0ed8024b31423f22918d9f4723aba49b22c8e597ec0e6";
const SHELLBAG_EXE: &str = "https://privazer.com/shellbag_analyzer_cleaner.exe";

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 128 random bits from the system CSPRNG, as hex.
fn random_hex() -> Option<String> {
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is valid for `buf.len()` bytes; a null algorithm handle is what the
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG flag requires.
    let status = unsafe {
        BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    (status >= 0).then(|| buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Creates a fresh, randomly named directory under %TEMP% and limits it to Administrators and
/// SYSTEM. `create_dir` (not `create_dir_all`) fails if the name already exists, and the directory
/// is discarded unless the ACL was applied, so nothing pre-planted or world-writable is ever used.
fn secure_tools_dir() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("GasCheckerTools-{}", random_hex()?));
    fs::create_dir(&dir).ok()?;
    // Absolute path: Command::new("icacls") would also look next to the checker's exe in %TEMP%.
    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let icacls = Path::new(&system_root).join("System32").join("icacls.exe");
    let restricted = Command::new(icacls)
        .arg(&dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !restricted {
        let _ = fs::remove_dir(&dir);
        return None;
    }
    Some(dir)
}

fn sha256_matches(bytes: &[u8], expected_hex: &str) -> bool {
    let actual: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
    actual == expected_hex
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

/// Downloads `url` into `dir` and runs it. With `sha256` set, a download that does not match is
/// dropped before it touches the disk.
fn download_and_run(dir: &Path, url: &str, name: &str, sha256: Option<&str>) -> bool {
    let Ok(bytes) = http_get(url) else { return false };
    if sha256.is_some_and(|expected| !sha256_matches(&bytes, expected)) {
        return false;
    }
    let path = dir.join(name);
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

fn download_everything(dir: &Path) -> bool {
    let Ok(bytes) = http_get(EVERYTHING_ZIP) else { return false };
    if !sha256_matches(&bytes, EVERYTHING_ZIP_SHA256) {
        return false;
    }
    let dir = dir.join("Everything");
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
/// Returns an empty string when no protected directory could be created.
pub fn run() -> String {
    let Some(dir) = secure_tools_dir() else { return String::new() };
    let mut opened = Vec::new();
    if download_and_run(&dir, JOURNALTRACE_EXE, "JournalTrace.exe", Some(JOURNALTRACE_SHA256)) {
        opened.push("JournalTrace");
    }
    if download_and_run(&dir, SHELLBAG_EXE, "shellbag_analyzer_cleaner.exe", None) {
        opened.push("Shellbag Analyzer");
    }
    if download_everything(&dir) {
        opened.push("Everything");
    }
    opened.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_only_the_exact_digest() {
        // SHA-256("abc"), the standard test vector.
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(sha256_matches(b"abc", abc));
        assert!(!sha256_matches(b"abd", abc));
        assert!(!sha256_matches(b"abc", ""));
    }

    #[test]
    fn tools_dirs_are_fresh_and_never_reused() {
        let a = secure_tools_dir().expect("first protected dir");
        let b = secure_tools_dir().expect("second protected dir");
        assert_ne!(a, b);
        assert!(a.is_dir() && b.is_dir());
        // An existing directory must be refused, not reused.
        assert!(fs::create_dir(&a).is_err());
        let _ = fs::remove_dir(&a);
        let _ = fs::remove_dir(&b);
    }
}
