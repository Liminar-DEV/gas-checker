//! Standalone replacement for `api.rs`: same interface, but results go to a public ntfy.sh topic
//! named after the moderator's code instead of our backend. The code is the only secret.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;

use crate::scanner::{Finding, ScanReport};

/// Overridable at build time with `GASCHECKER_NTFY_URL` (self-hosted ntfy).
pub const API_URL: &str = match option_env!("GASCHECKER_NTFY_URL") {
    Some(url) => url,
    None => "https://ntfy.sh",
};

pub const CODE_LEN: usize = 12;
const ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// ntfy.sh allows ~1 message per 5 s after a burst; the body limit is 4096 bytes.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 3800;
const MAX_PATH_CHARS: usize = 160;

#[derive(Debug, Clone)]
pub struct Claim {
    pub token: String,
    pub label: String,
    pub server: String,
}

#[derive(Serialize)]
pub struct ProgressBody<'a> {
    pub phase: &'a str,
    pub checked: usize,
    pub total: usize,
}

/// Uppercases and strips separators; None unless the result is a valid code.
pub fn normalize_code(input: &str) -> Option<String> {
    let code: String = input.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_uppercase();
    (code.len() == CODE_LEN && code.chars().all(|c| ALPHABET.contains(c))).then_some(code)
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("GasChecker/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client")
}

/// POSTs one JSON line to the code's topic, retrying network errors, 429 and 5xx with backoff.
fn post(code: &str, body: String, tries: u32) -> Result<(), String> {
    let url = format!("{API_URL}/gaschecker-{}", code.to_ascii_lowercase());
    let mut delay = Duration::from_secs(2);
    for attempt in 0..tries {
        match client().post(&url).body(body.clone()).send() {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) if r.status().as_u16() != 429 && !r.status().is_server_error() => {
                return Err(format!("Ошибка сервера ({})", r.status()));
            }
            _ => {}
        }
        if attempt + 1 < tries {
            std::thread::sleep(delay);
            delay *= 3;
        }
    }
    Err("Нет связи с ntfy.sh".into())
}

pub fn claim(code: &str) -> Result<Claim, String> {
    let code = normalize_code(code)
        .ok_or_else(|| format!("Код состоит из {CODE_LEN} символов: буквы и цифры без 0, 1, O, I, L"))?;
    let hello = json!({ "v": 1, "t": "hello", "host": std::env::var("COMPUTERNAME").unwrap_or_default() }).to_string();
    let to = code.clone();
    std::thread::spawn(move || {
        let _ = post(&to, hello, 1); // best effort
    });
    Ok(Claim { token: code.clone(), label: code, server: String::new() })
}

static LAST_PROGRESS: Mutex<Option<Instant>> = Mutex::new(None);

/// Best effort, at most one POST per 5 s.
pub fn progress(code: &str, body: &ProgressBody) {
    let mut last = LAST_PROGRESS.lock().unwrap();
    if last.is_some_and(|at| at.elapsed() < PROGRESS_INTERVAL) {
        return;
    }
    *last = Some(Instant::now());
    drop(last);
    let msg = json!({ "v": 1, "t": "progress", "phase": body.phase, "checked": body.checked, "total": body.total });
    let _ = post(code, msg.to_string(), 1);
}

pub fn result(code: &str, report: &ScanReport) -> Result<(), String> {
    post(code, result_message(report), 3)
}

fn entry(finding: &Finding) -> serde_json::Value {
    json!({ "k": finding.kind, "p": finding.path.chars().take(MAX_PATH_CHARS).collect::<String>() })
}

/// Findings are added (detections first) while the JSON stays within `MAX_BODY`; the rest is counted in "more".
fn result_message(report: &ScanReport) -> String {
    let build = |det: &[serde_json::Value], sus: &[serde_json::Value], more: usize| {
        json!({
            "v": 1, "t": "result",
            "jars": report.jars_checked, "unreadable": report.jars_unreadable, "ms": report.duration_ms,
            "stalled": report.stalled_dirs.len(), "det": det, "sus": sus, "more": more,
        })
        .to_string()
    };
    let (mut det, mut sus) = (Vec::new(), Vec::new());
    let total = report.detections.len() + report.suspicious.len();
    let mut added = 0;
    let all = report.detections.iter().map(|f| (f, true)).chain(report.suspicious.iter().map(|f| (f, false)));
    for (finding, is_det) in all {
        let list = if is_det { &mut det } else { &mut sus };
        list.push(entry(finding));
        if build(&det, &sus, total).len() > MAX_BODY {
            if is_det { det.pop() } else { sus.pop() };
            break;
        }
        added += 1;
    }
    build(&det, &sus, total - added)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(i: usize) -> Finding {
        Finding { path: format!(r"C:\Users\{}\{i}", "я".repeat(300)), kind: "meteor", details: vec![] }
    }

    fn report(det: usize, sus: usize) -> ScanReport {
        ScanReport {
            detections: (0..det).map(finding).collect(),
            suspicious: (0..sus).map(finding).collect(),
            jars_checked: 10,
            jars_unreadable: 1,
            duration_ms: 5,
            roots: vec![],
            stalled_dirs: vec![],
        }
    }

    #[test]
    fn small_report_is_complete() {
        let v: serde_json::Value = serde_json::from_str(&result_message(&report(2, 1))).unwrap();
        assert_eq!(v["det"].as_array().unwrap().len(), 2);
        assert_eq!(v["sus"].as_array().unwrap().len(), 1);
        assert_eq!(v["more"].as_u64(), Some(0));
        assert_eq!(v["det"][0]["p"].as_str().unwrap().chars().count(), 160);
    }

    #[test]
    fn huge_report_fits_and_counts_rest() {
        let msg = result_message(&report(200, 50));
        assert!(msg.len() <= MAX_BODY && MAX_BODY < 4096);
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        let shown = v["det"].as_array().unwrap().len() + v["sus"].as_array().unwrap().len();
        assert!(shown > 0 && shown < 250);
        assert_eq!(shown as u64 + v["more"].as_u64().unwrap(), 250);
        assert!(v["sus"].as_array().unwrap().is_empty()); // detections have priority
    }

    #[test]
    fn code_validation() {
        assert_eq!(normalize_code("abcd-efgh-jkmn").as_deref(), Some("ABCDEFGHJKMN"));
        assert!(normalize_code("ABCDEFGHJKM").is_none()); // too short
        assert!(normalize_code("ABCDEFGHJKMNP").is_none()); // too long
        assert!(normalize_code("ABCDEFGHJKM0").is_none()); // 0 not in alphabet
        assert!(normalize_code("ABCDEFGHJKMO").is_none());
    }
}
