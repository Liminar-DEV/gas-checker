// Open rules: used when the build has no private rules key. Only open-source clients with
// public package names are detected here. Included by build.rs into `mod rules`, so this file
// may not use inner doc comments. The interface mirrors the private rules exactly.

use std::collections::HashMap;
use std::path::Path;

use crate::scanner::Finding;

pub const EDITION: &str = "open";

/// (kind, lower-case package path): matched as a substring of lower-cased entry names.
const CLIENT_SIGNATURES: [(&str, &str); 4] = [
    ("meteor", "meteordevelopment/meteorclient/"),
    ("wurst", "net/wurstclient/"),
    ("liquidbounce", "net/ccbluex/liquidbounce/"),
    ("baritone", "baritone/api/"),
];

/// A JAR whose file name contains one of these is only a suspicion, never a detection.
pub const CHEAT_NAME_TOKENS: &[&str] = &["meteorclient", "wurstclient", "liquidbounce"];

/// Lower-case strings looked for in Java process memory.
pub const MEMORY_MARKERS: &[&str] = &[];

/// (kind, markers, host process names) for DLLs injected into other programs.
pub const HOST_SIGNATURES: &[(&str, &[&str], &[&str])] = &[];

/// (kind, window class) of programs that must not be running during the check.
pub const WINDOW_SIGNATURES: &[(&str, &str)] = &[];

/// Entry-name matching, fed one archive entry at a time (so the fast path never builds a map).
pub struct NameScan {
    clients: [bool; CLIENT_SIGNATURES.len()],
    lower: Vec<u8>,
}

impl NameScan {
    pub fn new() -> Self {
        NameScan { clients: [false; CLIENT_SIGNATURES.len()], lower: Vec::new() }
    }

    /// Takes an entry name in its original case. Returns true when this entry means the
    /// archive's content has to be read as well (never, in the open rules).
    pub fn feed(&mut self, name: &[u8]) -> bool {
        self.lower.clear();
        self.lower.extend(name.iter().map(u8::to_ascii_lowercase));
        for (hit, (_, sub)) in self.clients.iter_mut().zip(CLIENT_SIGNATURES) {
            if !*hit && self.lower.windows(sub.len()).any(|window| window == sub.as_bytes()) {
                *hit = true;
            }
        }
        false
    }

    /// Findings settled by names alone.
    pub fn findings(&self, path: &str) -> Vec<Finding> {
        CLIENT_SIGNATURES
            .iter()
            .zip(&self.clients)
            .filter(|(_, &hit)| hit)
            .map(|((kind, sub), _)| Finding { path: path.to_string(), kind, details: vec![sub.to_string()] })
            .collect()
    }
}

/// Findings that need class bytes. `names` maps lower-cased entry name -> (original name, index);
/// `read` returns the content of the entry with that index.
pub fn content_findings(
    _path: &str,
    _names: &HashMap<String, (String, usize)>,
    _read: &mut dyn FnMut(usize) -> Option<Vec<u8>>,
) -> Vec<Finding> {
    Vec::new()
}

/// Files outside JARs worth a closer look; chosen by name while the disk is walked.
pub fn is_trace_candidate(_name: &[u16]) -> bool {
    false
}

/// Checks one such file. Returns the finding and whether it is a detection or only a suspicion.
pub fn check_trace(_path: &Path) -> Option<(Finding, bool)> {
    None
}

/// Suspicion-level traces in the user profile.
pub fn profile_traces() -> Vec<Finding> {
    Vec::new()
}

/// Suspicion-level traces in the Windows DNS cache.
#[cfg(windows)]
pub fn dns_traces() -> Vec<Finding> {
    Vec::new()
}
