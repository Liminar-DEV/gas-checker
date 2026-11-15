const NTFY = "https://ntfy.sh";
let REPO = "Liminar-DEV/gas-checker";
if (location.hostname.endsWith(".github.io")) {
  const seg = location.pathname.split("/")[1];
  if (seg) REPO = `${location.hostname.split(".")[0]}/${seg}`;
}
const STALE_MS = 20000;

const KIND_LABELS = {
  liminar: "Liminar",
  "liminar-loader": "Лоадер Liminar (бета)",
  "liminar-loader-run": "Запускался лоадер Liminar",
  "hitbox-mixin": "Скрытый хитбокс",
  "fake-appleskin": "Фейковый AppleSkin",
  downloader: "Встроенный загрузчик",
  "utorrent-backup": "uTorrent backup.json",
  meteor: "Meteor Client",
  wurst: "Wurst",
  liquidbounce: "LiquidBounce",
  baritone: "Baritone (авто-ходьба/майнинг)",
  doomsday: "Doomsday",
  aurora: "Aurora (инжект-чит)",
  systemdlc: "System DLC (инжект-чит)",
  "systemdlc-dns": "Обращение к серверу System DLC",
  memory: "Чит в памяти Java",
  "cheat-name": "Подозрительное имя файла",
};
const PHASES = { walking: "Поиск файлов", finalizing: "Проверка памяти и следов запусков" };
const VERDICTS = { detected: "Обнаружено", suspicious: "Подозрение", clean: "Чисто" };

const $ = (id) => document.getElementById(id);
let code, source, seen, scanning, lastMsgAt, staleTimer;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text; // client-controlled strings: textContent only
  return e;
}

function setSteps(upTo) {
  const order = ["created", "hello", "scan", "result"];
  document.querySelectorAll("#steps li").forEach((li) => {
    const i = order.indexOf(li.dataset.step);
    li.className = i < upTo ? "done" : i === upTo ? "active" : "";
  });
}

function setConn(state) {
  $("conn").className = "conn " + state;
  $("conn-text").textContent = state === "lost" ? "Соединение потеряно, переподключаюсь…" : state === "ok" ? "Подключено к ntfy.sh" : "Ожидаем игрока…";
}

function resetView() {
  seen = new Set();
  scanning = false;
  $("host").textContent = "";
  $("phase").textContent = "";
  $("bar").hidden = true;
  $("bar-fill").style.width = "0";
  $("stale").hidden = true;
  $("result").hidden = true;
  setSteps(1);
  setConn("");
}

function start(c) {
  if (source) source.close();
  code = c;
  resetView();
  $("code").textContent = GC.groupCode(code);
  $("cmd").textContent = `curl -fLo "%TEMP%\\GasChecker.exe" "https://github.com/${REPO}/releases/latest/download/GasChecker.exe" && start "" "%TEMP%\\GasChecker.exe" ${code}`;
  source = new EventSource(`${NTFY}/gaschecker-${code.toLowerCase()}/sse?since=all`);
  source.onopen = () => setConn("ok");
  source.onerror = () => setConn("lost"); // EventSource retries by itself
  source.addEventListener("message", (ev) => {
    let env;
    try { env = JSON.parse(ev.data); } catch { return; }
    if (!env || env.event !== "message" || seen.has(env.id)) return;
    const msg = GC.parseMessage(env.message);
    if (!msg) return;
    seen.add(env.id);
    handle(msg);
  });
}

function handle(msg) {
  lastMsgAt = Date.now();
  $("stale").hidden = true;
  if (msg.t === "hello") {
    $("host").textContent = msg.host;
    scanning = false;
    setSteps(2);
  } else if (msg.t === "progress") {
    scanning = true;
    setSteps(2);
    const bar = $("bar");
    bar.hidden = msg.phase !== "checking";
    if (msg.phase === "checking") {
      const pct = msg.total ? Math.min(100, Math.floor((msg.checked / msg.total) * 100)) : 0;
      $("bar-fill").style.width = pct + "%";
      $("phase").textContent = `${pct}% (${msg.checked} из ${msg.total})`;
    } else {
      $("phase").textContent = PHASES[msg.phase];
    }
  } else if (msg.t === "result") {
    scanning = false;
    $("bar").hidden = true;
    $("phase").textContent = "";
    setSteps(4);
    showResult(msg);
  }
}

function showResult(r) {
  const v = GC.verdict(r);
  $("verdict").className = "verdict " + v;
  $("v-title").textContent = VERDICTS[v];
  const n = GC.matchCount(r);
  $("v-sub").textContent = v === "clean" ? "" : `${n} ${GC.plural(n, ["совпадение", "совпадения", "совпадений"])}`;
  $("note").hidden = v !== "clean";
  $("note").textContent = "Чисто не гарантия: чекер ловит только известные сигнатуры";
  const box = $("findings");
  box.replaceChildren();
  const add = (items, cls) => items.forEach((it, i) => {
    const card = el("div", "finding " + cls);
    card.append(el("div", "kind", KIND_LABELS[it.k] ?? it.k), el("div", "path", it.p));
    card.style.animationDelay = box.children.length * 40 + "ms";
    box.append(card);
  });
  add(r.det, "detected");
  add(r.sus, "suspicious");
  $("more").hidden = r.more <= 0;
  $("more").textContent = `Не поместилось в сообщение: ещё ${r.more} ${GC.plural(r.more, ["находка", "находки", "находок"])}`;
  const stats = $("stats");
  stats.replaceChildren();
  [["Jar-файлов", r.jars], ["Не прочитано", r.unreadable], ["Время проверки", GC.formatMs(r.ms)], ["Зависших папок", r.stalled]].forEach(([k, val]) => {
    const s = el("div", "stat", k);
    s.prepend(el("b", null, String(val)));
    stats.append(s);
  });
  $("result").hidden = false;
}

function fromHash() {
  const h = location.hash.slice(1).toUpperCase();
  return GC.CODE_RE.test(h) ? h : null;
}

function fresh() {
  const c = GC.makeCode((a) => crypto.getRandomValues(a));
  history.replaceState(null, "", "#" + c);
  start(c);
}

$("new").addEventListener("click", fresh);
$("copy").addEventListener("click", async () => {
  const b = $("copy");
  try { await navigator.clipboard.writeText($("cmd").textContent); b.textContent = "Скопировано"; }
  catch { b.textContent = "Выделите и скопируйте вручную"; }
  setTimeout(() => (b.textContent = "Скопировать"), 1500);
});
addEventListener("hashchange", () => { const c = fromHash(); if (c && c !== code) start(c); });
setInterval(() => {
  if (scanning && Date.now() - lastMsgAt > STALE_MS) $("stale").hidden = false;
}, 1000);

const initial = fromHash();
if (initial) start(initial); else fresh();
