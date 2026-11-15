//! Read-only scan of running Java process memory for cheat-client markers — the
//! automated form of the manual Process Hacker "Strings" check. Nothing is written
//! to the target process; only ReadProcessMemory is used, so this never modifies the
//! game. Matches are distinctive client names that do not occur in a clean game.

use std::collections::BTreeSet;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetClassNameW, GetWindowThreadProcessId};

use crate::rules::{HOST_SIGNATURES, MEMORY_MARKERS, WINDOW_SIGNATURES};
use crate::scanner::Finding;

/// Stop after this much memory so a huge heap never hangs the scan.
const MAX_TOTAL_BYTES: usize = 1536 * 1024 * 1024;
const CHUNK: usize = 1 << 20;
/// Overlap between chunks so a marker split across a read boundary still matches.
const OVERLAP: usize = 64;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Java stores text either as Latin-1 (one byte per char) or UTF-16LE (char + 0x00).
/// The haystack is already lower-cased, and markers are lower-case ASCII, so matching
/// both forms covers compact strings and char arrays alike.
fn found_in(hay_lower: &[u8], marker: &[u8]) -> bool {
    if contains(hay_lower, marker) {
        return true;
    }
    let mut utf16 = Vec::with_capacity(marker.len() * 2);
    for &b in marker {
        utf16.push(b);
        utf16.push(0);
    }
    contains(hay_lower, &utf16)
}

pub(crate) fn search_markers(hay: &[u8], markers: &[&'static str], found: &mut BTreeSet<&'static str>) {
    if found.len() == markers.len() {
        return;
    }
    let hay_lower: Vec<u8> = hay.iter().map(u8::to_ascii_lowercase).collect();
    for &marker in markers {
        if !found.contains(marker) && found_in(&hay_lower, marker.as_bytes()) {
            found.insert(marker);
        }
    }
}

fn wide_name(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Every running process as (PID, lower-cased exe file name).
pub(crate) fn processes() -> Vec<(u32, String)> {
    let mut list = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return list;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                list.push((entry.th32ProcessID, wide_name(&entry.szExeFile).to_ascii_lowercase()));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    list
}

fn java_pids() -> Vec<u32> {
    processes().into_iter().filter(|(_, name)| name == "javaw.exe" || name == "java.exe").map(|(pid, _)| pid).collect()
}

pub(crate) unsafe fn scan_process(handle: HANDLE, markers: &[&'static str]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    let mut addr: usize = 0;
    let mut read_total: usize = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    while read_total < MAX_TOTAL_BYTES && found.len() < markers.len() {
        if VirtualQueryEx(handle, addr as *const _, &mut mbi, mbi_size) == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let readable = mbi.State == MEM_COMMIT && mbi.Protect != 0 && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;

        if readable {
            let mut off = 0usize;
            let mut carry: Vec<u8> = Vec::new();
            while off < size && read_total < MAX_TOTAL_BYTES && found.len() < markers.len() {
                let want = CHUNK.min(size - off);
                let mut buf = vec![0u8; want];
                let mut got: usize = 0;
                let ok = ReadProcessMemory(handle, (base + off) as *const _, buf.as_mut_ptr().cast(), want, &mut got);
                if ok == 0 || got == 0 {
                    break; // sub-region not readable; move to the next region
                }
                buf.truncate(got);
                let mut hay = std::mem::take(&mut carry);
                hay.extend_from_slice(&buf);
                search_markers(&hay, markers, &mut found);
                let keep = hay.len().min(OVERLAP);
                carry = hay[hay.len() - keep..].to_vec();
                read_total += got;
                off += want;
            }
        }

        let next = base.wrapping_add(size);
        if next <= addr {
            break; // no forward progress: stop rather than loop
        }
        addr = next;
    }
    found
}

/// Scans every running `javaw.exe`/`java.exe` and returns a detection per matched marker.
/// Best-effort: a process that cannot be opened (elevated, protected, gone) is skipped.
pub fn scan_java_memory() -> Vec<Finding> {
    let mut findings = Vec::new();
    for pid in java_pids() {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() {
                continue;
            }
            let hits = scan_process(handle, MEMORY_MARKERS);
            CloseHandle(handle);
            for marker in hits {
                findings.push(Finding {
                    path: format!("java (PID {pid}) — память процесса"),
                    kind: "memory",
                    details: vec![marker.to_string()],
                });
            }
        }
    }
    findings
}

/// DLLs living in their host processes (`HOST_SIGNATURES`): read-only scan.
pub fn scan_host_signatures() -> Vec<Finding> {
    let mut findings = Vec::new();
    let running = processes();
    for &(kind, markers, hosts) in HOST_SIGNATURES {
        for (pid, name) in running.iter().filter(|(_, name)| hosts.contains(&name.as_str())) {
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, *pid);
                if handle.is_null() {
                    continue;
                }
                let hits = scan_process(handle, markers);
                CloseHandle(handle);
                if !hits.is_empty() {
                    findings.push(Finding {
                        path: format!("{name} (PID {pid}) — память процесса"),
                        kind,
                        details: hits.into_iter().map(str::to_string).collect(),
                    });
                }
            }
        }
    }
    findings
}

/// Full path of a process's .exe (needs only limited query access).
pub(crate) fn process_image(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// PIDs owning a top-level window (visible or hidden) of the given class.
fn window_class_pids(class: &str) -> Vec<u32> {
    struct Search<'a> {
        class: &'a str,
        pids: Vec<u32>,
    }
    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
        let search = &mut *(lparam as *mut Search);
        let mut name = [0u16; 128];
        let len = GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32);
        if len > 0 && String::from_utf16_lossy(&name[..len as usize]) == search.class {
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            search.pids.push(pid);
        }
        1 // keep enumerating
    }
    let mut search = Search { class, pids: Vec::new() };
    unsafe { EnumWindows(Some(visit), &mut search as *mut Search as LPARAM) };
    search.pids.sort_unstable();
    search.pids.dedup();
    search.pids
}

/// Programs running during the check, found by window class (`WINDOW_SIGNATURES`). Reports the
/// real path of the .exe, so a random file name does not hide it.
pub fn scan_window_signatures() -> Vec<Finding> {
    let mut findings = Vec::new();
    for &(kind, class) in WINDOW_SIGNATURES {
        findings.extend(window_class_pids(class).into_iter().map(|pid| Finding {
            path: process_image(pid).unwrap_or_else(|| format!("PID {pid}")),
            kind,
            details: vec![format!("окно {class} (PID {pid})")],
        }));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE: &[&str] = &["gc-probe-marker", "gc other marker"];

    #[test]
    fn matches_latin1_and_utf16() {
        let mut found = BTreeSet::new();
        // First marker as Latin-1 (upper-case), second as UTF-16LE.
        let mut hay: Vec<u8> = b"junk GC-PROBE-MARKER junk".to_vec();
        for b in b"gc other marker" {
            hay.push(*b);
            hay.push(0);
        }
        search_markers(&hay, PROBE, &mut found);
        assert_eq!(found.len(), 2);
        let mut none = BTreeSet::new();
        search_markers(b"nothing here", PROBE, &mut none);
        assert!(none.is_empty());
    }

    // Exercises the real WinAPI path (OpenProcess/VirtualQueryEx/ReadProcessMemory) by
    // reading this test process's own memory, where a marker is kept alive on the heap.
    #[test]
    fn reads_own_process_memory() {
        let probe = std::hint::black_box(b"xx gc-probe-marker xx".to_vec());
        unsafe {
            let pid = windows_sys::Win32::System::Threading::GetCurrentProcessId();
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            assert!(!handle.is_null());
            let found = scan_process(handle, PROBE);
            CloseHandle(handle);
            assert!(found.contains("gc-probe-marker"));
        }
        std::hint::black_box(probe);
    }

    // Real WinAPI path: a hidden window of a test-only class is found, and its owner
    // (this process) resolves to an .exe path.
    #[test]
    fn finds_window_owner_by_class() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, WNDCLASSW,
        };
        let class = format!("GasCheckerTestClass{}", std::process::id());
        let wide: Vec<u16> = class.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let instance = std::ptr::null_mut();
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(DefWindowProcW);
            wc.hInstance = instance;
            wc.lpszClassName = wide.as_ptr();
            assert_ne!(RegisterClassW(&wc), 0);
            let hwnd = CreateWindowExW(0, wide.as_ptr(), wide.as_ptr(), 0, 0, 0, 10, 10, std::ptr::null_mut(), std::ptr::null_mut(), instance, std::ptr::null());
            assert!(!hwnd.is_null());

            let me = windows_sys::Win32::System::Threading::GetCurrentProcessId();
            assert_eq!(window_class_pids(&class), [me]);
            assert!(window_class_pids("NoSuchClass-GasChecker").is_empty());
            assert!(process_image(me).is_some_and(|path| path.to_ascii_lowercase().ends_with(".exe")));
            DestroyWindow(hwnd);
        }
    }
}
