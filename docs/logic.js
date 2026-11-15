(function (root) {
  const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const CODE_RE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{12}$/;
  const LIMIT = 248; // 31 * 8: bytes >= 248 are dropped so the alphabet is unbiased

  function makeCode(getRandomValues) {
    let out = "";
    while (out.length < 12) {
      const bytes = getRandomValues(new Uint8Array(16));
      for (const b of bytes) {
        if (b < LIMIT && out.length < 12) out += ALPHABET[b % 31];
      }
    }
    return out;
  }

  const isPaths = (a) => Array.isArray(a) && a.every((x) => x && typeof x.k === "string" && typeof x.p === "string");
  const num = (n) => (Number.isFinite(n) && n >= 0 ? n : 0);

  // Returns a normalized message or null for anything unknown or malformed.
  function parseMessage(text) {
    let m;
    try { m = JSON.parse(text); } catch { return null; }
    if (!m || typeof m !== "object" || m.v !== 1) return null;
    if (m.t === "hello") return { t: "hello", host: String(m.host ?? "") };
    if (m.t === "progress") {
      if (!["walking", "checking", "finalizing"].includes(m.phase)) return null;
      return { t: "progress", phase: m.phase, checked: num(m.checked), total: num(m.total) };
    }
    if (m.t === "result") {
      const det = m.det ?? [], sus = m.sus ?? [];
      if (!isPaths(det) || !isPaths(sus)) return null;
      return { t: "result", jars: num(m.jars), unreadable: num(m.unreadable), ms: num(m.ms), stalled: num(m.stalled), det, sus, more: num(m.more) };
    }
    return null;
  }

  function verdict(result) {
    if (result.det.length) return "detected";
    if (result.sus.length) return "suspicious";
    return "clean";
  }

  function groupCode(code) {
    return code.match(/.{1,4}/g).join("-");
  }

  function plural(n, [one, few, many]) {
    const a = n % 100, b = n % 10;
    return a >= 11 && a <= 14 ? many : b === 1 ? one : b >= 2 && b <= 4 ? few : many;
  }

  // Number of matches behind the verdict: det for "detected", sus for "suspicious".
  function matchCount(result) {
    return result.det.length || result.sus.length;
  }

  function formatMs(ms) {
    const s = Math.round(ms / 1000);
    return s >= 60 ? `${Math.floor(s / 60)} мин ${s % 60} с` : `${s} с`;
  }

  const api = { makeCode, parseMessage, verdict, groupCode, plural, matchCount, formatMs, CODE_RE };
  root.GC = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
