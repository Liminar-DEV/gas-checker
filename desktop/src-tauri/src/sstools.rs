//! Downloads the screen-share tools from their official sources and opens them.
//! User-requested: the checker fetches Everything (voidtools), JournalTrace (GitHub)
//! and Shellbag Analyzer (Privazer) at scan start and launches them.
//! Best-effort — a tool that fails to download, verify or run is skipped, never aborting the scan.
//!
//! The checker runs elevated and starts these tools with the same rights, so they are staged
//! where a non-elevated process of the same user cannot touch them: every run uses a fresh,
//! randomly named directory under %TEMP% that is *created* with a DACL limited to Administrators
//! and SYSTEM (one CreateDirectoryW call, no window between creating and locking it).
//! Everything and JournalTrace are pinned by SHA-256 and verified before anything is written.
//! shortcut: Shellbag Analyzer is not pinned (the vendor URL is unversioned), so it relies on
//! HTTPS and the protected directory only; pin it or verify its signature if the vendor versions it.

use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

const EVERYTHING_ZIP: &str = "https://www.voidtools.com/Everything-1.4.1.1028.x64.zip";
const EVERYTHING_ZIP_SHA256: &str = "4f4a9b9299b608d48b065f95fd80b9c095cdc7114cd467cd9b54944b23559dfe";
const JOURNALTRACE_EXE: &str = "https://github.com/ponei/JournalTrace/releases/download/1.0/JournalTrace.exe";
const JOURNALTRACE_SHA256: &str = "46873781a5c80ea676f0ed8024b31423f22918d9f4723aba49b22c8e597ec0e6";
const SHELLBAG_EXE: &str = "https://privazer.com/shellbag_analyzer_cleaner.exe";

const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Protected DACL (P: nothing inherited from %TEMP%): full access for Administrators (BA) and
/// SYSTEM (SY) only, inherited by everything created inside (OICI).
const TOOLS_DIR_SDDL: &str = "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

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

/// Creates `dir` with `TOOLS_DIR_SDDL` already applied. Fails if `dir` exists, so a pre-planted
/// directory (or junction) is never reused.
fn create_protected_dir(dir: &Path) -> bool {
    let sddl: Vec<u16> = TOOLS_DIR_SDDL.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is a LocalAlloc'd block freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut())
    };
    if converted == 0 {
        return false;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path: Vec<u16> = OsStr::new(dir).encode_wide().chain(Some(0)).collect();
    // SAFETY: `path` is NUL-terminated and `attributes` outlives the call.
    let created = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0;
    // SAFETY: `descriptor` came from the conversion above and is not used afterwards.
    unsafe { LocalFree(descriptor) };
    created
}

/// A fresh, randomly named, protected directory under %TEMP%.
fn secure_tools_dir() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("GasCheckerTools-{}", random_hex()?));
    create_protected_dir(&dir).then_some(dir)
}

/// Writes a new file; refuses to touch one that already exists.
fn write_new(path: &Path, bytes: &[u8]) -> bool {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .is_ok()
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
    if !write_new(&path, &bytes) {
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
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&out).map_err(|e| e.to_string())?;
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
        // An existing directory must be refused, not reused or re-locked.
        assert!(!create_protected_dir(&a));
        let _ = fs::remove_dir(&a);
        let _ = fs::remove_dir(&b);
    }

    #[test]
    fn write_new_refuses_an_existing_file() {
        let dir = secure_tools_dir().expect("protected dir");
        let file = std::env::temp_dir().join(format!("gc-write-new-{}", random_hex().unwrap()));
        assert!(write_new(&file, b"first"));
        assert!(!write_new(&file, b"second"));
        assert_eq!(fs::read(&file).unwrap(), b"first");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir(&dir);
    }

    /// Reads the directory's real DACL back (SDDL, via `icacls /save`) instead of trusting the call.
    #[test]
    fn tools_dir_is_born_with_only_admin_and_system_access() {
        let dir = secure_tools_dir().expect("protected dir");
        let saved = std::env::temp_dir().join(format!("gc-acl-{}.txt", random_hex().unwrap()));
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let status = Command::new(Path::new(&system_root).join("System32").join("icacls.exe"))
            .arg(&dir)
            .arg("/save")
            .arg(&saved)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run icacls");
        assert!(status.success());
        let raw = fs::read(&saved).expect("saved acl");
        let units: Vec<u16> = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let sddl = String::from_utf16_lossy(&units);
        let _ = fs::remove_file(&saved);
        let _ = fs::remove_dir(&dir);
        assert!(sddl.contains("D:P"), "DACL must be protected (no inherited entries): {sddl}");
        assert!(sddl.contains("(A;OICI;FA;;;BA)") && sddl.contains("(A;OICI;FA;;;SY)"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 2, "only Administrators and SYSTEM may have access: {sddl}");
    }
}
