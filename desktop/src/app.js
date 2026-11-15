"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const appWindow = window.__TAURI__.window.getCurrentWindow();

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
const ICONS = {
  clean: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  suspicious: '<svg viewBox="0 0 24 24"><path d="M12 7v6M12 17h.01"/></svg>',
  detected: '<svg viewBox="0 0 24 24"><path d="M7 7l10 10M17 7L7 17"/></svg>',
};

const $ = (selector) => document.querySelector(selector);
let pinInputs = [...document.querySelectorAll("#pin-inputs input")];
let connected = false;
let checkingStartedAt = 0;

function show(screen) {
  document.querySelectorAll(".screen").forEach((el) => (el.hidden = el.id !== `screen-${screen}`));
}

function h(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text != null) el.textContent = text;
  return el;
}

const plural = (n, one, few, many) => {
  const mod10 = n % 10, mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
  return many;
};
const number = (n) => n.toLocaleString("ru-RU");

function formatDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} с`;
  if (s < 3600) return `${Math.floor(s / 60)} мин ${String(s % 60).padStart(2, "0")} с`;
  return `${Math.floor(s / 3600)} ч ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")} мин`;
}

// ------------------------------------------------------------ title bar

$("#btn-min").addEventListener("click", () => appWindow.minimize());
$("#btn-close").addEventListener("click", () => appWindow.close());
$("#result-close").addEventListener("click", () => appWindow.close());

// ------------------------------------------------------------------ PIN

const PIN_CHARS = /[A-HJKMNP-Z2-9]/i; // matches the backend alphabet: no 0/O/1/I/L

function readPin() {
  return pinInputs.map((input) => input.value).join("").toUpperCase();
}

function fillPin(text, from = 0) {
  const chars = [...text.toUpperCase()].filter((c) => PIN_CHARS.test(c));
  chars.slice(0, pinInputs.length - from).forEach((c, i) => {
    const input = pinInputs[from + i];
    input.value = c;
    input.classList.remove("filled");
    void input.offsetWidth;
    input.classList.add("filled");
  });
  const next = Math.min(from + chars.length, pinInputs.length - 1);
  pinInputs[next].focus();
  if (readPin().length === pinInputs.length) $("#pin-form").requestSubmit();
}

function setupPin() {
  pinInputs.forEach((input, index) => {
  input.addEventListener("input", () => {
    const value = input.value;
    input.value = "";
    fillPin(value, index);
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Backspace" && !input.value && index > 0) {
      pinInputs[index - 1].value = "";
      pinInputs[index - 1].focus();
      event.preventDefault();
    } else if (event.key === "ArrowLeft" && index > 0) pinInputs[index - 1].focus();
    else if (event.key === "ArrowRight" && index < pinInputs.length - 1) pinInputs[index + 1].focus();
  });
  input.addEventListener("paste", (event) => {
    event.preventDefault();
    fillPin(event.clipboardData.getData("text"), index);
  });
  input.addEventListener("focus", () => input.select());
  });
}

function pinError(message) {
  $("#pin-error").textContent = message;
  const box = $("#pin-inputs");
  box.classList.remove("shake");
  void box.offsetWidth;
  box.classList.add("shake");
}

$("#pin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const pin = readPin();
  if (pin.length !== pinInputs.length) return pinError(`Введите все ${pinInputs.length} символов кода`);
  const button = $("#pin-submit");
  button.disabled = true;
  button.textContent = "Подключение…";
  $("#pin-error").textContent = "";
  try {
    const { label, server } = await invoke("claim_pin", { pin });
    connected = true;
    $("#ready-title").textContent = server || "Подключено";
    $("#ready-subtitle").textContent = `Проверка игрока ${label}`;
    show("ready");
  } catch (error) {
    pinError(String(error));
    pinInputs.forEach((input) => (input.value = ""));
    pinInputs[0].focus();
  } finally {
    button.disabled = false;
    button.textContent = "Подключиться";
  }
});


// ----------------------------------------------------------------- scan

listen("scan-progress", ({ payload }) => {
  const bar = $("#scan-bar");
  if (payload.phase === "walking") {
    bar.classList.add("indeterminate");
    $("#scan-phase").textContent = "Поиск JAR-файлов на дисках…";
    $("#scan-count").textContent = `Папок: ${number(payload.dirs)} · JAR: ${number(payload.jars)}`;
    $("#scan-eta").textContent = "";
    return;
  }
  if (payload.phase === "finalizing") {
    bar.classList.add("indeterminate");
    $("#scan-phase").textContent = "Проверка памяти и следов запусков…";
    $("#scan-count").textContent = "";
    $("#scan-eta").textContent = "";
    return;
  }
  const { checked, total } = payload;
  if (!checkingStartedAt) checkingStartedAt = performance.now();
  bar.classList.remove("indeterminate");
  const ratio = total ? checked / total : 1;
  bar.firstElementChild.style.width = `${(ratio * 100).toFixed(1)}%`;
  $("#scan-phase").textContent = "Проверка JAR-файлов…";
  $("#scan-count").textContent = `${number(checked)} из ${number(total)} · ${Math.floor(ratio * 100)}%`;
  const elapsed = performance.now() - checkingStartedAt;
  const rate = checked / Math.max(elapsed, 1);
  $("#scan-eta").textContent = checked > 0 && checked < total ? `осталось ~${formatDuration((total - checked) / rate)}` : "";
});

// Ready-to-paste Everything search: ext filter + distinctive cheat names (no generic
// words that would flood the results). The moderator pastes this into Everything on SS.
const EVERYTHING_SEARCH =
  "ext:exe;jar;zip;rar regex:(impact|wurst|bleachhack|aristois|huzuni|skillclient|nodus|inertia|sigma|meteor|zamorozka|liquidbounce|nurik|nursultan|celestial|celka|expensive|neverhook|wexside|deadcode|akrien|dreampool|konas|zeusclient|rusherhack|thunderhack|moonhack|exire|doomsday|nightware|extazyy|troxill|dauntiblyat|xameleon|fuzeclient|rogalik|catlavan|fluger|newcode|britva|bushroot|novoline|cortex|noiseclient|forgehax|luminex|vape)";

$("#start-scan").addEventListener("click", async () => {
  checkingStartedAt = 0;
  $("#scan-bar").classList.add("indeterminate");
  $("#scan-bar").firstElementChild.style.width = "0";
  $("#scan-count").textContent = "";
  $("#scan-eta").textContent = "";
  $("#scan-phase").textContent = "Подготовка…";
  show("scan");
  // Download+open the SS tools and put the Everything search on the clipboard.
  const hint = $("#everything-hint");
  hint.hidden = false;
  hint.textContent = "Загружаю инструменты проверки (Everything, Shellbag Analyzer, JournalTrace)…";
  invoke("open_ss_tools")
    .then((opened) => {
      hint.textContent = opened
        ? `Открыты: ${opened}. Строка поиска для Everything — в буфере (Ctrl+V).`
        : "Не удалось загрузить инструменты. Откройте их вручную.";
    })
    .catch(() => (hint.textContent = "Не удалось загрузить инструменты."));
  navigator.clipboard.writeText(EVERYTHING_SEARCH).catch(() => {});
  try {
    renderResult(await invoke("start_scan"));
  } catch (error) {
    renderResult(null, String(error));
  }
});

function renderResult(outcome, scanError) {
  const verdictEl = $("#verdict");
  const findings = $("#findings");
  findings.replaceChildren();

  if (!outcome) {
    verdictEl.className = "verdict suspicious";
    $("#verdict-icon").innerHTML = ICONS.suspicious;
    $("#verdict-title").textContent = "Ошибка";
    $("#verdict-subtitle").textContent = scanError;
    $("#upload-status").hidden = true;
    show("result");
    return;
  }

  const { report } = outcome;
  const verdict = report.detections.length ? "detected" : report.suspicious.length ? "suspicious" : "clean";
  verdictEl.className = `verdict ${verdict}`;
  $("#verdict-icon").innerHTML = ICONS[verdict];
  $("#verdict-title").textContent = { clean: "Чисто", suspicious: "Подозрительно", detected: "Обнаружено" }[verdict];
  const n = report.detections.length;
  $("#verdict-subtitle").textContent = {
    clean: "Совпадений с сигнатурами не найдено",
    suspicious: "Есть подозрительные признаки, но не детект",
    detected: `${n} ${plural(n, "совпадение", "совпадения", "совпадений")} с сигнатурами`,
  }[verdict];

  const stats = h("div", "stat-row");
  for (const [label, value] of [
    ["Проверено JAR", number(report.jarsChecked)],
    ["Не открылись", number(report.jarsUnreadable)],
    ["Время", formatDuration(report.durationMs)],
  ]) {
    const stat = h("div", "stat");
    stat.append(h("span", null, label), h("b", null, value));
    stats.append(stat);
  }
  findings.append(stats);

  const addFinding = (item, cls) => {
    const card = h("div", `finding ${cls}`);
    card.append(h("div", "kind", KIND_LABELS[item.kind] ?? item.kind), h("div", "path", item.path));
    findings.append(card);
  };
  report.detections.forEach((item) => addFinding(item, "detected"));
  report.suspicious.forEach((item) => addFinding(item, "suspicious"));
  [...findings.children].forEach((el, i) => (el.style.animationDelay = `${120 + i * 50}ms`));

  renderUpload(outcome);
  show("result");
  if (verdict === "detected") playMogged();
}

// Red "MOGGED" stamp slams over the result and the verdict shakes, with sound.
function playMogged() {
  const screen = $("#screen-result");
  const stamp = h("div", "mogged-stamp", "mogged");
  screen.appendChild(stamp);
  const title = $("#verdict-title");
  title.classList.remove("mogged-hit");
  void title.offsetWidth;
  title.classList.add("mogged-hit");
  try {
    const a = new Audio("mogged.mp3");
    a.volume = 0.9;
    a.play().catch(() => {});
  } catch {}
  setTimeout(() => {
    stamp.classList.add("out");
    setTimeout(() => stamp.remove(), 420);
  }, 1600);
}

function renderUpload(outcome) {
  const box = $("#upload-status");
  box.hidden = !connected;
  if (!connected) return;
  if (outcome.uploaded) {
    box.className = "upload ok";
    box.replaceChildren(h("span", null, "✓ Результат отправлен модератору"));
    return;
  }
  box.className = "upload fail";
  const retry = h("button", "btn", "Повторить");
  retry.addEventListener("click", async () => {
    retry.disabled = true;
    try {
      await invoke("retry_upload");
      renderUpload({ uploaded: true });
    } catch (error) {
      renderUpload({ uploaded: false, uploadError: String(error) });
    }
  });
  box.replaceChildren(h("span", null, `Не отправлено: ${outcome.uploadError ?? "ошибка"}`), retry);
}

$("#result-new").addEventListener("click", async () => {
  await invoke("forget_session");
  connected = false;
  pinInputs.forEach((input) => (input.value = ""));
  $("#pin-error").textContent = "";
  show("start");
  pinInputs[0].focus();
});

// ------------------------------------------------------------------ boot

(async () => {
  const standalone = await invoke("is_standalone");
  if (standalone) {
    // 12-character relay code instead of the 6-character PIN, shown in three groups of four.
    const box = $("#pin-inputs");
    box.classList.add("long");
    box.replaceChildren(...Array.from({ length: 12 }, (_, i) => {
      const input = h("input");
      input.setAttribute("aria-label", `Символ ${i + 1}`);
      return i && i % 4 === 0 ? [h("span", "pin-dash"), input] : [input];
    }).flat());
    pinInputs = [...box.querySelectorAll("input")];
    $("#ready-upload-note").textContent =
      "Модератору по этому коду уходят вердикт, найденные файлы и их пути, имя ПК. Данные отправляются через публичный сервис ntfy.sh.";
  }
  if ((await invoke("rules_edition")) === "open") {
    document.querySelectorAll(".rules-note").forEach((el) => {
      el.textContent = "Сборка с открытыми правилами: проверка частичная, «чисто» ничего не гарантирует.";
      el.hidden = false;
    });
  }
  setupPin();
  pinInputs[0].focus();
  const code = standalone && (await invoke("cli_code"));
  if (code) fillPin(code);
})();
