//! Programs that actually ran on this machine: running processes and the BAM execution
//! log. Their .exe files are handed to the rules, so a random file name does not hide them. Read-only: only queries and registry reads.

use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

/// BAM (Background Activity Moderator) keeps the full path of every program each user ran
/// in roughly the last week. The key moved in Windows 10 1809; both layouts are read.
const BAM_KEYS: [&str; 2] = [
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
];

/// Existing .exe files of running processes and BAM entries, outside the Windows folder.
pub fn executed_exes() -> Vec<PathBuf> {
    let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_ascii_lowercase() + "\\";
    let mut paths: Vec<String> =
        crate::memscan::processes().into_iter().filter_map(|(pid, _)| crate::memscan::process_image(pid)).collect();
    paths.extend(bam_exes());
    paths
        .into_iter()
        .filter(|path| {
            let lower = path.to_ascii_lowercase();
            lower.ends_with(".exe") && !lower.starts_with(&windows_dir)
        })
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .collect()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn open_key(parent: HKEY, path: &str) -> Option<HKEY> {
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(parent, wide(path).as_ptr(), 0, KEY_READ, &mut key) };
    (status == ERROR_SUCCESS).then_some(key)
}

fn subkey_names(key: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    for index in 0.. {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(key, index, buf.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if status != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
    }
    names
}

fn value_names(key: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    for index in 0.. {
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let status = unsafe {
            RegEnumValueW(key, index, buf.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        // Longer names (ERROR_MORE_DATA) are skipped; the index still advances.
        if status == ERROR_SUCCESS {
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
    }
    names
}

/// "\Device\HarddiskVolume3" -> "C:" for every mounted drive letter.
fn device_map() -> Vec<(String, String)> {
    (b'A'..=b'Z')
        .filter_map(|letter| {
            let drive = format!("{}:", letter as char);
            let mut buf = [0u16; 512];
            let len = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
            (len > 0 && end > 0).then(|| (String::from_utf16_lossy(&buf[..end]), drive))
        })
        .collect()
}

fn to_dos_path(device_path: &str, devices: &[(String, String)]) -> Option<String> {
    devices.iter().find_map(|(device, drive)| {
        let rest = device_path.strip_prefix(device.as_str())?;
        rest.starts_with('\\').then(|| format!("{drive}{rest}"))
    })
}

fn bam_exes() -> Vec<String> {
    let devices = device_map();
    let mut paths = Vec::new();
    for root_path in BAM_KEYS {
        let Some(root) = open_key(HKEY_LOCAL_MACHINE, root_path) else { continue };
        for sid in subkey_names(root) {
            if let Some(user) = open_key(root, &sid) {
                paths.extend(value_names(user).iter().filter_map(|name| to_dos_path(name, &devices)));
                unsafe { RegCloseKey(user) };
            }
        }
        unsafe { RegCloseKey(root) };
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_device_paths() {
        let devices = vec![(r"\Device\HarddiskVolume3".to_string(), "C:".to_string()), (r"\Device\HarddiskVolume30".to_string(), "D:".to_string())];
        assert_eq!(to_dos_path(r"\Device\HarddiskVolume3\Users\a\x.exe", &devices).as_deref(), Some(r"C:\Users\a\x.exe"));
        assert_eq!(to_dos_path(r"\Device\HarddiskVolume30\x.exe", &devices).as_deref(), Some(r"D:\x.exe"));
        assert_eq!(to_dos_path("Microsoft.Windows.Explorer", &devices), None);
    }

    // Real system path: this test binary is a running process outside the Windows folder.
    #[test]
    fn lists_running_test_binary() {
        let me = std::env::current_exe().unwrap().to_string_lossy().to_ascii_lowercase();
        assert!(executed_exes().iter().any(|path| path.to_string_lossy().to_ascii_lowercase() == me));
        assert!(device_map().iter().any(|(_, drive)| drive == "C:"));
    }
}
