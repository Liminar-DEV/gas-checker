//! Read-only JAR scanner. Nothing is extracted, moved, edited or deleted:
//! archives are opened for reading and suspicious class files are read into memory.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::Serialize;

use crate::rules;

const MAX_CLASS_BYTES: u64 = 512_000;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

/// If no directory finishes listing for this long, the walk gives up on the
/// directories still being read (a hung cloud/network folder) and moves on.
const WALK_STALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Windows component store: hundreds of thousands of folders, writable only by TrustedInstaller.
const SKIPPED_DIRS: [&str; 1] = [r"\Windows\WinSxS"];

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    pub kind: &'static str,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub detections: Vec<Finding>,
    pub suspicious: Vec<Finding>,
    pub jars_checked: usize,
    pub jars_unreadable: usize,
    pub duration_ms: u64,
    pub roots: Vec<String>,
    /// Directories abandoned because listing them hung.
    pub stalled_dirs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase", tag = "phase")]
pub enum Progress {
    Walking { dirs: usize, jars: usize },
    Checking { checked: usize, total: usize },
    /// Post-JAR phases (memory, traces of runs) that report no per-item count.
    Finalizing,
}

/// All accessible fixed drives. Network and removable drives are skipped on purpose.
#[cfg(windows)]
pub fn scan_roots() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_FIXED: u32 = 3;

    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| format!("{}:\\", (b'A' + index) as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
            unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(windows))]
pub fn scan_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Case-insensitive ASCII extension check on a raw UTF-16 file name: `has_ext(name, b"jar")`.
pub(crate) fn has_ext(name: &[u16], ext: &[u8]) -> bool {
    let Some(dot) = name.len().checked_sub(ext.len() + 1) else { return false };
    dot > 0
        && name[dot] == b'.' as u16
        && name[dot + 1..].iter().zip(ext).all(|(&c, &want)| c < 128 && (c as u8).eq_ignore_ascii_case(&want))
}

fn is_jar_name(name: &[u16]) -> bool {
    has_ext(name, b"jar")
}

fn is_skipped_dir(path: &Path) -> bool {
    // Compare without the drive letter: "C:\Windows\WinSxS" -> "\Windows\WinSxS".
    let path = path.as_os_str().to_string_lossy();
    path.get(2..).is_some_and(|rest| SKIPPED_DIRS.iter().any(|skip| rest.eq_ignore_ascii_case(skip)))
}

/// Lists one directory with `FindFirstFileExW`: basic info (no 8.3 names) and large
/// fetches, so attributes and reparse tags come straight from the listing.
#[cfg(windows)]
fn list_dir(dir: &Path, subdirs: &mut Vec<PathBuf>, jars: &mut Vec<PathBuf>, trace_files: &mut Vec<PathBuf>) {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FIND_FIRST_EX_LARGE_FETCH, WIN32_FIND_DATAW,
    };
    /// Reparse tags with this bit are links (junctions, symlinks), not cloud/dedup storage.
    const NAME_SURROGATE: u32 = 0x2000_0000;
    /// Content that is not on the local disk; touching it would hit the network.
    const NOT_LOCAL: u32 = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    // The \\?\ prefix lifts the MAX_PATH limit.
    let mut pattern: Vec<u16> = r"\\?\".encode_utf16().chain(dir.as_os_str().encode_wide()).collect();
    if pattern.last() != Some(&(b'\\' as u16)) {
        pattern.push(b'\\' as u16);
    }
    pattern.extend([b'*' as u16, 0]);

    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let handle = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            (&mut data as *mut WIN32_FIND_DATAW).cast(),
            FindExSearchNameMatch,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return;
    }
    loop {
        let len = data.cFileName.iter().position(|&c| c == 0).unwrap_or(data.cFileName.len());
        let name = &data.cFileName[..len];
        let attributes = data.dwFileAttributes;
        let is_link = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && data.dwReserved0 & NAME_SURROGATE != 0;
        let is_dot = name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16];
        if !is_dot && !is_link && attributes & NOT_LOCAL == 0 {
            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                let path = dir.join(OsString::from_wide(name));
                if !is_skipped_dir(&path) {
                    subdirs.push(path);
                }
            } else if is_jar_name(name) {
                jars.push(dir.join(OsString::from_wide(name)));
            } else if rules::is_trace_candidate(name) {
                trace_files.push(dir.join(OsString::from_wide(name)));
            }
        }
        if unsafe { FindNextFileW(handle, &mut data) } == 0 {
            break;
        }
    }
    unsafe { FindClose(handle) };
}

#[cfg(not(windows))]
fn list_dir(dir: &Path, subdirs: &mut Vec<PathBuf>, jars: &mut Vec<PathBuf>, trace_files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let name: Vec<u16> = entry.file_name().to_string_lossy().encode_utf16().collect();
        if file_type.is_dir() {
            subdirs.push(entry.path());
        } else if file_type.is_file() && is_jar_name(&name) {
            jars.push(entry.path());
        } else if file_type.is_file() && rules::is_trace_candidate(&name) {
            trace_files.push(entry.path());
        }
    }
}

/// Shared state of the directory walk. Workers are detached threads, so a
/// worker stuck inside a hung syscall cannot block the scan from finishing.
struct Walk {
    queue: Mutex<Vec<PathBuf>>,
    ready: Condvar,
    /// Directories queued or being listed; the walk is done when it reaches zero.
    pending: AtomicUsize,
    dirs: AtomicUsize,
    jar_count: AtomicUsize,
    jars: Mutex<Vec<PathBuf>>,
    trace_files: Mutex<Vec<PathBuf>>,
    stop: AtomicBool,
    /// What each worker is listing right now, for stall reporting.
    busy: Mutex<Vec<Option<PathBuf>>>,
}

impl Walk {
    fn new() -> Arc<Self> {
        Arc::new(Walk {
        queue: Mutex::new(Vec::new()),
        ready: Condvar::new(),
        pending: AtomicUsize::new(0),
        dirs: AtomicUsize::new(0),
        jar_count: AtomicUsize::new(0),
        jars: Mutex::new(Vec::new()),
        trace_files: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        busy: Mutex::new(Vec::new()),
    })
    }

    fn worker(&self, slot: usize) {
        loop {
            let dir = {
                let mut queue = self.queue.lock().unwrap();
                loop {
                    if self.stop.load(Ordering::Acquire) || self.pending.load(Ordering::Acquire) == 0 {
                        return;
                    }
                    if let Some(dir) = queue.pop() {
                        break dir;
                    }
                    queue = self.ready.wait_timeout(queue, Duration::from_millis(50)).unwrap().0;
                }
            };
            self.busy.lock().unwrap()[slot] = Some(dir.clone());
            let (mut subdirs, mut jars, mut trace_files) = (Vec::new(), Vec::new(), Vec::new());
            list_dir(&dir, &mut subdirs, &mut jars, &mut trace_files);
            self.busy.lock().unwrap()[slot] = None;
            if self.stop.load(Ordering::Acquire) {
                return; // the scan already moved on without this directory
            }

            self.dirs.fetch_add(1, Ordering::Relaxed);
            if !jars.is_empty() {
                self.jar_count.fetch_add(jars.len(), Ordering::Relaxed);
                self.jars.lock().unwrap().extend(jars);
            }
            if !trace_files.is_empty() {
                self.trace_files.lock().unwrap().extend(trace_files);
            }
            if !subdirs.is_empty() {
                // Count children before releasing this directory so `pending` never hits zero early.
                self.pending.fetch_add(subdirs.len(), Ordering::AcqRel);
                self.queue.lock().unwrap().extend(subdirs);
                self.ready.notify_all();
            }
            if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.ready.notify_all();
            }
        }
    }
}

/// Listing directories and opening archives wait on the disk, not the CPU.
fn io_threads() -> usize {
    std::thread::available_parallelism().map_or(8, |n| n.get() * 2).clamp(8, 32)
}

/// Walks all roots in parallel. Returns the JARs found and any directories
/// that were abandoned because listing them never returned. Candidate files
/// are left in `walk.trace_files`.
fn walk(walk: &Arc<Walk>, roots: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>) {
    let threads = io_threads();
    walk.pending.store(roots.len(), Ordering::Release);
    walk.queue.lock().unwrap().extend(roots.iter().cloned());
    *walk.busy.lock().unwrap() = vec![None; threads];
    for slot in 0..threads {
        let walk = Arc::clone(walk);
        std::thread::spawn(move || walk.worker(slot));
    }

    let mut last_dirs = 0;
    let mut last_change = Instant::now();
    let mut stalled = Vec::new();
    while walk.pending.load(Ordering::Acquire) > 0 {
        std::thread::sleep(Duration::from_millis(50));
        let dirs = walk.dirs.load(Ordering::Relaxed);
        if dirs != last_dirs {
            (last_dirs, last_change) = (dirs, Instant::now());
        } else if last_change.elapsed() >= WALK_STALL_TIMEOUT {
            walk.stop.store(true, Ordering::Release);
            walk.ready.notify_all();
            stalled = walk.busy.lock().unwrap().iter().flatten().map(|dir| dir.display().to_string()).collect();
            break;
        }
    }
    let jars = std::mem::take(&mut *walk.jars.lock().unwrap());
    (jars, stalled)
}

fn read_entry(archive: &mut zip::ZipArchive<BufReader<File>>, index: usize) -> Option<Vec<u8>> {
    let entry = archive.by_index(index).ok()?;
    if entry.size() == 0 || entry.size() > MAX_CLASS_BYTES {
        return None;
    }
    let mut data = Vec::with_capacity(entry.size() as usize);
    entry.take(MAX_CLASS_BYTES).read_to_end(&mut data).ok()?;
    Some(data)
}

/// What the central directory alone says about an archive.
pub(crate) enum QuickScan {
    /// Names settle it: these are the findings (possibly none).
    Done(Vec<Finding>),
    /// Some entry calls for reading class bytes, so the full reader is needed.
    NeedsContent,
}

const MAX_CENTRAL_DIRECTORY: u64 = 64 * 1024 * 1024;

fn le16(bytes: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as u32
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Reads only the end record and the central directory (two reads) and checks
/// entry names in place. Returns `None` for anything unusual (ZIP64, prefixed
/// archives, damage) so the caller falls back to the full ZIP reader.
pub(crate) fn quick_scan(file: &mut File, path: &Path) -> Option<QuickScan> {
    const EOCD: u32 = 0x0605_4b50;
    const ENTRY: u32 = 0x0201_4b50;

    let len = file.seek(SeekFrom::End(0)).ok()?;
    let tail_len = len.min(22 + 65_535);
    let mut tail = vec![0u8; tail_len as usize];
    file.seek(SeekFrom::Start(len - tail_len)).ok()?;
    file.read_exact(&mut tail).ok()?;
    let eocd = (0..tail.len().checked_sub(22)? + 1).rev().find(|&at| le32(&tail, at) == EOCD)?;
    let entries = le16(&tail, eocd + 10);
    let cd_size = le32(&tail, eocd + 12) as u64;
    let cd_offset = le32(&tail, eocd + 16) as u64;
    if entries == 0xFFFF || cd_offset == 0xFFFF_FFFF || cd_size > MAX_CENTRAL_DIRECTORY || cd_offset + cd_size > len {
        return None;
    }

    let mut cd = vec![0u8; cd_size as usize];
    file.seek(SeekFrom::Start(cd_offset)).ok()?;
    file.read_exact(&mut cd).ok()?;

    let mut names = rules::NameScan::new();
    let mut at = 0;
    for _ in 0..entries {
        if at + 46 > cd.len() || le32(&cd, at) != ENTRY {
            return None;
        }
        let name_len = le16(&cd, at + 28) as usize;
        let skip = name_len + le16(&cd, at + 30) as usize + le16(&cd, at + 32) as usize;
        let name = cd.get(at + 46..at + 46 + name_len)?;
        at += 46 + skip;
        if names.feed(name) {
            return Some(QuickScan::NeedsContent);
        }
    }
    Some(QuickScan::Done(names.findings(&path.display().to_string())))
}

/// Returns `None` when the archive cannot be opened (locked, corrupt, not a ZIP).
pub(crate) fn check_jar(path: &Path) -> Option<Vec<Finding>> {
    let mut file = File::open(path).ok()?;
    // Fast path: almost every JAR is settled by its entry names alone.
    if let Some(QuickScan::Done(findings)) = quick_scan(&mut file, path) {
        return Some(findings);
    }
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).ok()?;
    let display = path.display().to_string();

    // Lower-cased name -> (original name, index), built from the central directory only.
    let names: HashMap<String, (String, usize)> = (0..archive.len())
        .filter_map(|index| {
            let name = archive.name_for_index(index)?.ok()?;
            Some((name.to_ascii_lowercase(), (name.to_string(), index)))
        })
        .collect();

    let mut scan = rules::NameScan::new();
    for (name, _) in names.values() {
        scan.feed(name.as_bytes());
    }
    let mut findings = scan.findings(&display);
    findings.extend(rules::content_findings(&display, &names, &mut |index| read_entry(&mut archive, index)));
    Some(findings)
}

/// JARs whose file name looks like a known cheat, excluding ones already detected by
/// content. Suspicion only — a renamed-back cheat is caught by its classes, not its name.
fn name_suspicions(jars: &[PathBuf], detected: &std::collections::HashSet<String>) -> Vec<Finding> {
    jars.iter()
        .filter_map(|jar| {
            let path = jar.display().to_string();
            if detected.contains(&path) {
                return None;
            }
            let name = jar.file_name()?.to_string_lossy().to_ascii_lowercase();
            let token = rules::CHEAT_NAME_TOKENS.iter().find(|t| name.contains(**t))?;
            Some(Finding { path, kind: "cheat-name", details: vec![(*token).to_string()] })
        })
        .collect()
}


const PHASE_WALKING: u8 = 0;
const PHASE_CHECKING: u8 = 1;
const PHASE_DONE: u8 = 2;

/// Runs a full scan. `on_progress` is called from a single reporter thread
/// roughly every 150 ms, plus once at the end of each phase.
pub fn scan(mut on_progress: impl FnMut(Progress) + Send) -> ScanReport {
    let started = Instant::now();
    let roots = scan_roots();
    let walk_state = Walk::new();
    let phase = AtomicU8::new(PHASE_WALKING);
    let checked = AtomicUsize::new(0);
    let total = AtomicUsize::new(0);
    let unreadable = AtomicUsize::new(0);
    let finished = AtomicBool::new(false);

    let mut detections = Vec::new();
    let mut stalled_dirs = Vec::new();
    let mut all_jars = Vec::new();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            let snapshot = || match phase.load(Ordering::Acquire) {
                PHASE_WALKING => Progress::Walking {
                    dirs: walk_state.dirs.load(Ordering::Relaxed),
                    jars: walk_state.jar_count.load(Ordering::Relaxed),
                },
                _ => Progress::Checking { checked: checked.load(Ordering::Relaxed), total: total.load(Ordering::Relaxed) },
            };
            while !finished.load(Ordering::Acquire) {
                on_progress(snapshot());
                std::thread::sleep(PROGRESS_INTERVAL);
            }
            on_progress(snapshot());
        });

        let (mut jars, stalled) = walk(&walk_state, &roots);
        stalled_dirs = stalled;
        jars.sort();
        total.store(jars.len(), Ordering::Relaxed);
        phase.store(PHASE_CHECKING, Ordering::Release);

        // Opening archives is disk-bound, so use more threads than cores.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(io_threads()).build().expect("thread pool");
        detections = pool.install(|| {
            jars.par_iter()
                .flat_map_iter(|jar| {
                    // A malformed archive must never abort the whole scan.
                    let result = catch_unwind(AssertUnwindSafe(|| check_jar(jar))).ok().flatten();
                    if result.is_none() {
                        unreadable.fetch_add(1, Ordering::Relaxed);
                    }
                    checked.fetch_add(1, Ordering::Relaxed);
                    result.unwrap_or_default()
                })
                .collect()
        });

        all_jars = jars;
        phase.store(PHASE_DONE, Ordering::Release);
        finished.store(true, Ordering::Release);
    });

    // Post-JAR phases (traces, memory) are slow and emit no per-item progress.
    // A heartbeat keeps the UI and panel on a live "finalizing" phase instead of a frozen
    // 100% — which the panel would otherwise flag as a lost connection after STALL_MS.
    let mut suspicious = Vec::new();
    let finalizing_done = AtomicBool::new(false);
    std::thread::scope(|threads| {
        threads.spawn(|| {
            while !finalizing_done.load(Ordering::Acquire) {
                on_progress(Progress::Finalizing);
                std::thread::sleep(PROGRESS_INTERVAL);
            }
        });

        // Candidate files: name-matched ones from the walk, plus every program that actually ran.
        let mut trace_files = std::mem::take(&mut *walk_state.trace_files.lock().unwrap());
        #[cfg(windows)]
        trace_files.extend(crate::traces::executed_exes());
        let mut seen = std::collections::HashSet::new();
        trace_files.retain(|path| seen.insert(path.to_string_lossy().to_ascii_lowercase()));
        // This binary contains the rules themselves; never flag the checker.
        let own_exe = std::env::current_exe().ok().and_then(|exe| exe.canonicalize().ok());
        trace_files.retain(|path| own_exe.is_none() || path.canonicalize().ok() != own_exe);
        let trace_results: Vec<(Finding, bool)> = trace_files
            .par_iter()
            .filter_map(|path| catch_unwind(AssertUnwindSafe(|| rules::check_trace(path))).ok().flatten())
            .collect();
        let mut trace_suspicions = Vec::new();
        for (finding, detected) in trace_results {
            if detected {
                detections.push(finding);
            } else {
                trace_suspicions.push(finding);
            }
        }

        // In-memory cheats that leave nothing on disk: read-only scan of the Java process.
        #[cfg(windows)]
        detections.extend(crate::memscan::scan_java_memory());
        #[cfg(windows)]
        detections.extend(crate::memscan::scan_window_signatures());
        #[cfg(windows)]
        detections.extend(crate::memscan::scan_host_signatures());

        let detected: std::collections::HashSet<String> = detections.iter().map(|f| f.path.clone()).collect();
        suspicious = name_suspicions(&all_jars, &detected);
        suspicious.extend(trace_suspicions);
        suspicious.extend(rules::profile_traces());
        #[cfg(windows)]
        suspicious.extend(rules::dns_traces());

        finalizing_done.store(true, Ordering::Release);
    });

    ScanReport {
        detections,
        suspicious,
        jars_checked: total.load(Ordering::Relaxed),
        jars_unreadable: unreadable.load(Ordering::Relaxed),
        duration_ms: started.elapsed().as_millis() as u64,
        roots: roots.iter().map(|root| root.display().to_string()).collect(),
        stalled_dirs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_jar(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join(name);
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        for (entry, data) in entries {
            writer.start_file(*entry, zip::write::SimpleFileOptions::default()).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    fn kinds(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|finding| finding.kind).collect()
    }

    #[test]
    fn detects_open_source_clients() {
        let dir = std::env::temp_dir().join(format!("gc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let clean = make_jar(&dir, "clean.jar", &[("net/example/Mod.class", b"hello")]);
        assert_eq!(kinds(&check_jar(&clean).unwrap()), Vec::<&str>::new());

        // Open-source clients by package path (fast path, names only).
        let meteor = make_jar(&dir, "meteor.jar", &[("meteordevelopment/meteorclient/MeteorClient.class", b"x"), ("net/example/Other.class", b"y")]);
        assert_eq!(kinds(&check_jar(&meteor).unwrap()), ["meteor"]);
        assert!(matches!(quick_scan(&mut File::open(&meteor).unwrap(), &meteor), Some(QuickScan::Done(f)) if kinds(&f) == ["meteor"]));

        let broken = dir.join("broken.jar");
        std::fs::write(&broken, b"not a zip").unwrap();
        assert!(check_jar(&broken).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Scans this machine's real drives: `cargo test --release -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn full_scan_of_this_machine() {
        let mut updates = 0;
        let started = Instant::now();
        let mut last_print = Instant::now();
        let report = scan(|progress| {
            updates += 1;
            if last_print.elapsed() >= Duration::from_secs(1) {
                last_print = Instant::now();
                println!("{:>5.1}s {progress:?}", started.elapsed().as_secs_f32());
            }
        });
        println!(
            "roots {:?}: {} JARs, {} unreadable, {} detections, {} suspicious, {} ms, {updates} progress updates",
            report.roots,
            report.jars_checked,
            report.jars_unreadable,
            report.detections.len(),
            report.suspicious.len(),
            report.duration_ms,
        );
        for finding in report.detections.iter().chain(&report.suspicious) {
            println!("  {} {} {:?}", finding.kind, finding.path, finding.details);
        }
        assert!(updates > 0);
    }

    #[test]
    fn jar_extension_is_case_insensitive() {
        let wide = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert!(is_jar_name(&wide("Mod.JAR")));
        assert!(is_jar_name(&wide("a.jar")));
        assert!(!is_jar_name(&wide(".jar")));
        assert!(!is_jar_name(&wide("jar")));
        assert!(!is_jar_name(&wide("mod.jar.txt")));
        assert!(!is_jar_name(&wide("modxjar")));
    }

    #[test]
    fn skips_component_store_only() {
        assert!(is_skipped_dir(Path::new(r"C:\Windows\WinSxS")));
        assert!(is_skipped_dir(Path::new(r"D:\windows\winsxs")));
        assert!(!is_skipped_dir(Path::new(r"C:\Windows")));
        assert!(!is_skipped_dir(Path::new(r"C:\Windows\WinSxS\x")));
    }

    #[test]
    fn walk_finds_nested_jars() {
        let dir = std::env::temp_dir().join(format!("gc-walk-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(r"a\b\c")).unwrap();
        std::fs::write(dir.join("top.jar"), b"x").unwrap();
        std::fs::write(dir.join(r"a\b\c\deep.JAR"), b"x").unwrap();
        std::fs::write(dir.join(r"a\notes.txt"), b"x").unwrap();
        let state = Walk::new();
        let (mut jars, stalled) = walk(&state, &[dir.clone()]);
        jars.sort();
        assert_eq!(jars, [dir.join(r"a\b\c\deep.JAR"), dir.join("top.jar")]);
        assert!(stalled.is_empty());
        assert_eq!(state.dirs.load(Ordering::Relaxed), 4);
        std::fs::remove_dir_all(&dir).ok();
    }
}
