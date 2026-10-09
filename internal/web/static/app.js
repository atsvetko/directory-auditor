/* Directory Auditor — local wizard. Talks only to the 127.0.0.1 server that
   served it; every API call carries the one-time token from the launch URL.
   All directory-sourced text is inserted with textContent or esc(). */
"use strict";
(function () {
const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let lang = "en", mode = "auto", scanMode = "fast", detected = null, result = null, conn = null, polling = null, info = null, library = null;

async function api(path, body) {
  const opt = {method: body === undefined ? "GET" : "POST", headers: {"X-DA-Token": TOKEN}, cache: "no-store"};
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({ok: false, error: "HTTP " + r.status}));
  if (!r.ok && j.ok === undefined) j.ok = false;
  return j;
}

/* ---------- text ---------- */
const T = {
 st1:["Connect","Подключение"], st2:["Scan","Сканирование"], st3:["Results","Результаты"],
 theme:["Theme","Тема"], quit:["Quit","Выход"],
 c_h:["Connect to a directory","Подключение к каталогу"],
 tagline:["What an attacker would find in your directory — read-only, in five minutes.","Что найдёт в вашем каталоге злоумышленник — только чтение, за пять минут."],
 tr1:["Read-only","Только чтение"], tr2:["Nothing leaves this machine","Ничего не покидает машину"], tr4:["Source public","Открытый код"],
 c_auto:["Use the detected domain","Использовать обнаруженный домен"], detecting:["Looking for a domain…","Поиск домена…"],
 auto_ok:["This computer is in {d}. Your current logon is used — no password.","Компьютер входит в домен {d}. Используется текущий вход — без пароля."],
 auto_none:["No domain detected on this computer — enter one below.","Домен на этом компьютере не обнаружен — укажите его ниже."],
 auto_nokrb:["{d} found, but there is no Kerberos ticket for the current logon — use an account below.","Найден домен {d}, но для текущего входа нет билета Kerberos — укажите учётную запись ниже."],
 d_dom:["Domain","Домен"], d_dc:["Domain controller","Контроллер домена"], d_dc_sub:["found via DNS SRV · LDAPS","найден через DNS SRV · LDAPS"],
 d_id:["Identity","Учётная запись"], d_id_sub:["your current logon · Kerberos (no password needed)","ваш текущий вход · Kerberos (пароль не нужен)"],
 d_smb:["This computer","Этот компьютер"], d_smb_v:["Samba AD DC — its configuration","Контроллер домена Samba — его конфигурация"], d_smb_sub:["will be audited too (tier 2)","тоже будет проверена (уровень 2)"],
 connok_smb:["Local smb.conf included.","Локальный smb.conf включён."],
 c_man:["Enter domain and credentials","Указать домен и учётные данные"],
 c_man_d:["Another domain, a non-joined machine, Samba AD DC, or a dedicated audit account.","Другой домен, компьютер вне домена, Samba AD DC или отдельная учётная запись для аудита."],
 f_dom:["Domain","Домен"], f_dc:["Domain controller or IP (optional)","Контроллер домена или IP (необязательно)"], f_user:["User","Пользователь"], f_pw:["Password","Пароль"],
 f_dcname:["DC name for the certificate (the IP above has no DNS name)","Имя КД для сертификата (у IP выше нет DNS-имени)"],
 f_tls:["Connection security","Защита подключения"], o_ldaps:["LDAPS (636)","LDAPS (636)"], o_starttls:["StartTLS (389)","StartTLS (389)"],
 f_pin:["Certificate fingerprint (only if the DC certificate is not trusted here)","Отпечаток сертификата (только если сертификат КД здесь не доверенный)"],
 f_hint:["A normal user account covers ~80% of checks. The password is used once in memory and never saved.","Обычной учётной записи достаточно для ~80% проверок. Пароль используется один раз в памяти и нигде не сохраняется."],
 demo:["Try with demo data","Попробовать на демо-данных"], connect:["Connect","Подключиться"], connecting:["Connecting…","Подключение…"],
 connok:["Connected to {s} as {i} · {k} · {t}.","Подключено к {s} как {i} · {k} · {t}."],
 unencrypted:["The connection is not encrypted (lab mode): directory data will cross the network in clear.","Подключение не зашифровано (режим стенда): данные каталога пойдут по сети в открытом виде."],
 o_auto:["Automatic — LDAPS, then StartTLS, then LDAP with Kerberos sealing (recommended)","Автоматически — LDAPS, затем StartTLS, затем LDAP с шифрованием Kerberos (рекомендуется)"],
 o_none:["Unencrypted LDAP (389) — lab only, sends the password in clear","LDAP без шифрования (389) — только стенд, пароль уходит открытым"],
 sc_h:["Choose a scan","Выберите сканирование"],
 fast:["Fast scan","Быстрое сканирование"], fast_d:["The highest-value checks · about a minute · best first look.","Самые ценные проверки · около минуты · для первого знакомства."],
 full:["Full scan","Полное сканирование"], full_d:["Every check your account can run · a few minutes.","Все проверки, доступные вашей учётной записи · несколько минут."],
 back:["Back","Назад"], start:["Start scan","Начать сканирование"], cancel:["Cancel","Отмена"], ro:["read-only","только чтение"],
 scanning:["Scanning {d}…","Сканирование {d}…"], done:["Done","Готово"],
 r_target:["Target","Цель"], pdf_sub:["Directory security assessment","Оценка защищённости каталога"],
 unsigned:["Unsigned check packs were loaded (development mode). Do not rely on this report.","Загружены неподписанные пакеты проверок (режим разработки). Не полагайтесь на этот отчёт."],
 nopacks:["No check packs are loaded yet: catalogue entries become checks only after human verification. The Tier-0 inventory below is complete.","Пакеты проверок пока не загружены: записи каталога становятся проверками только после проверки человеком. Инвентаризация нулевого уровня ниже — полная."],
 r_unenc:["The directory session was not encrypted — data crossed the network in clear (lab mode).","Подключение к каталогу не было зашифровано — данные прошли по сети в открытом виде (режим стенда)."],
 preview:["Preview checks: {n} catalogue entries were evaluated as checks. They are unsigned and not yet verified by a human (status draft). Treat their findings as leads to confirm, not as verified results.","Предварительные проверки: {n} записей каталога оценены как проверки. Они не подписаны и ещё не проверены человеком (статус «черновик»). Считайте их находки поводом для проверки, а не подтверждённым результатом."],
 checksinfo:["This run evaluates {p} signed check packs and {n} preview checks (unverified catalogue entries, unsigned). Start with --no-preview to run signed packs only.","Будут выполнены подписанные пакеты проверок: {p}, и предварительные проверки: {n} (записи каталога без подписи и без проверки человеком). Запуск с --no-preview выполняет только подписанные пакеты."],
 previewtag:["preview","preview"],
 c_checked:["checked","проверено"], c_passed:["passed","пройдено"], c_find:["with findings","с находками"], c_findings:["findings","находок"], c_skip:["skipped","пропущено"],
 dl_pdf:["Download PDF report","Скачать отчёт PDF"], dl_html:["HTML","HTML"], dl_json:["JSON","JSON"], dl_log:["Run log","Журнал запуска"], rescan:["New scan","Новое сканирование"],
 s_findings:["Findings","Находки"], nofind:["No findings from the checks that ran.","Выполненные проверки ничего не нашли."],
 s_tier0:["Tier 0 — who controls the domain, and why","Нулевой уровень — кто управляет доменом и почему"],
 h_obj:["Object","Объект"], h_path:["Why it is Tier 0","Почему это нулевой уровень"],
 t0more:["…and {n} more in report.json.","…и ещё {n} в report.json."],
 t0unres:["{n} members of Tier-0 groups live in other domains and were not resolved: {l}","{n} членов групп нулевого уровня находятся в других доменах и не разрешены: {l}"],
 s_skipped:["Skipped — and why","Пропущено — и почему"], noskip:["Nothing was skipped.","Ничего не пропущено."],
 aff:["Affected","Затронуто"], why:["Why it matters","Почему это важно"], abuse:["How it is abused","Как это используют"], fix:["Remediation","Как исправить"], verify:["How to verify","Как проверить"], refs:["References","Источники"], objs:["object(s)","объект(ов)"],
 skip_tier:["need a higher privilege tier","требуют более высокий уровень привилегий"], skip_provider:["do not apply to this directory type","не относятся к этому типу каталога"],
 skip_quick:["are not part of the fast scan","не входят в быстрое сканирование"], skip_error:["could not be evaluated","не удалось вычислить"],
 notread:["Not collected","Не собрано"],
 foot:["Generated read-only on this machine; nothing was sent anywhere. {n} objects, {q} LDAP searches, {t}. Snapshot SHA-256 {h}.","Создано в режиме только чтения на этой машине; ничего никуда не отправлялось. Объектов: {n}, LDAP-запросов: {q}, {t}. SHA-256 снимка {h}."],
 bye:["Directory Auditor has stopped. You can close this tab.","Directory Auditor остановлен. Вкладку можно закрыть."],
 library:["Library","Библиотека"],
 lib_title:["Check library","Библиотека проверок"],
 lib_sub:["{n} checks across {d} directory types, mapped to MITRE ATT&CK and ANSSI. Reference only — nothing is run.","{n} проверок для {d} типов каталогов с сопоставлением MITRE ATT&CK и ANSSI. Только справка — ничего не выполняется."],
 lib_close:["Close","Закрыть"],
 lib_search:["Search checks…","Поиск проверок…"],
 lib_allsev:["All severities","Все уровни"], lib_alldom:["All areas","Все области"], lib_allfw:["All frameworks","Все матрицы"],
 lib_count:["{n} of {all} checks","{n} из {all} проверок"],
 lib_obj:["Looks at","Проверяет"], lib_fix:["Remediation","Как исправить"], lib_fw:["Framework mapping","Сопоставление с матрицами"],
 lib_refs:["References","Источники"], lib_draft:["draft","черновик"], lib_planned:["planned","в плане"],
 lib_quick:["fast scan","быстрое"], lib_none:["No checks match.","Нет подходящих проверок."],
 sev_critical:["critical","критический"], sev_high:["high","высокий"], sev_medium:["medium","средний"], sev_low:["low","низкий"], sev_info:["info","инфо"]
};
const t = (k, v) => { let s = (T[k] || [k, k])[lang === "ru" ? 1 : 0]; for (const x in (v || {})) s = s.split("{" + x + "}").join(v[x]); return s; };
function applyLang() {
  document.querySelectorAll("[data-t]").forEach(el => { if (T[el.dataset.t]) el.textContent = t(el.dataset.t); });
  document.querySelectorAll("[data-ph]").forEach(el => { if (T[el.dataset.ph]) el.placeholder = t(el.dataset.ph); });
  $("lang").textContent = lang === "ru" ? "EN" : "RU";
  document.documentElement.lang = lang;
  renderDetect(); renderInfo(); if (conn) renderConn(); if (result) renderResult();
  if (library) { buildLibFilters(); renderLibrary(); }
}
function renderInfo() {
  if (!info) return;
  const n = info.preview || 0, p = info.packs || 0;
  $("checksinfo").classList.toggle("hidden", !(n > 0 || p > 0));
  $("checksinfo_t").textContent = t("checksinfo", {n: n, p: p});
}

/* ---------- navigation ---------- */
function show(v) {
  ["welcome","scan","report"].forEach(x => $(x).classList.toggle("hidden", x !== v));
  document.querySelectorAll("#tabs .ptab").forEach(b => b.setAttribute("aria-selected", b.dataset.go === v));
  window.scrollTo({top: 0, behavior: "smooth"});
}
document.addEventListener("click", e => {
  const g = e.target.closest("[data-go]"); if (g && !g.disabled) show(g.dataset.go);
  const c = e.target.closest(".copt"); if (!c) return;
  c.parentElement.querySelectorAll(":scope > .copt").forEach(x => { if (!!x.dataset.scan === !!c.dataset.scan) x.classList.toggle("sel", x === c); });
  if (c.dataset.scan) scanMode = c.dataset.scan;
  if (c.dataset.mode) { mode = c.dataset.mode; $("mform").classList.toggle("hidden", mode !== "manual"); $("detectbox").classList.toggle("hidden", mode !== "auto" || !detected || !detected.domain); }
});
function selectMode(m) { document.querySelector(`.copt[data-mode="${m}"]`).click(); }

/* ---------- 1 · connect ---------- */
function renderDetect() {
  const d = $("autodesc");
  if (!detected) return;
  if (detected.domain && detected.kerberos) d.textContent = t("auto_ok", {d: detected.domain});
  else if (detected.domain) d.textContent = t("auto_nokrb", {d: detected.domain});
  else d.textContent = t("auto_none");
  $("d_domain").textContent = detected.domain || "";
  $("d_server").textContent = detected.server || "—";
  $("d_identity").textContent = detected.identity || "—";
  $("smbrow").classList.toggle("hidden", !detected.smbconf);
  $("d_smbconf").textContent = detected.smbconf || "";
}
async function detect() {
  detected = await api("/api/detect");
  renderDetect();
  if (detected.domain && detected.kerberos && detected.server) { $("detectbox").classList.remove("hidden"); }
  else { selectMode("manual"); if (detected.domain) $("m_domain").value = detected.domain; if (detected.server) $("m_server").value = detected.server; }
}
function showErr(prefix, msg, fix) {
  $(prefix).classList.toggle("hidden", !msg);
  $(prefix + "_msg").textContent = msg || "";
  if ($(prefix + "_fix")) $(prefix + "_fix").textContent = fix || "";
}
function renderConn() {
  const k = {samba: "Samba AD DC", demo: "demo", freeipa: "FreeIPA / IdM", "389ds": "389 Directory Server"}[conn.kind] || "Active Directory";
  $("connok").textContent = "✓ " + t("connok", {s: conn.server, i: conn.identity, k: k, t: conn.transport || "—"}) + (conn.smbconf ? " " + t("connok_smb") : "")
    + (conn.transport && !conn.encrypted ? " " + t("unencrypted") : "");
  $("scantarget").textContent = conn.domain + " · " + conn.identity;
}
async function connect(kind) {
  showErr("connerr"); $("connok").classList.add("hidden");
  const btn = $("connect"); btn.disabled = true; $("demo").disabled = true; btn.textContent = t("connecting");
  let body = {mode: kind, smbconf: !!(detected && detected.smbconf)};
  if (kind === "manual") {
    body = {mode: "manual", domain: $("m_domain").value.trim(), server: $("m_server").value.trim(), server_name: $("m_servername").value.trim(),
      user: $("m_user").value.trim(),
      password: $("m_password").value, security: $("m_security").value, pin: $("m_pin").value.trim(), smbconf: !!(detected && detected.smbconf)};
  }
  const r = await api("/api/connect", body);
  $("m_password").value = "";   // the server holds it in memory until the scan ends; the page never keeps it
  btn.disabled = false; $("demo").disabled = false; btn.textContent = t("connect");
  if (!r.ok) { showErr("connerr", r.error, r.hint); return; }
  conn = r; renderConn(); document.body.classList.toggle("is-demo", r.kind === "demo"); $("connok").classList.remove("hidden");
  document.querySelector('.ptab[data-go="welcome"]').classList.add("done");
  document.querySelector('.ptab[data-go="scan"]').disabled = false;
  $("progress").classList.add("hidden");
  show("scan");
}
// Reveal the "DC name for the certificate" field only when the controller is
// given as an IP (so TLS/Kerberos can still be matched by name).
const isIP = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s.trim()) || s.trim().includes(":") && /^[0-9a-fA-F:]+$/.test(s.trim());
$("m_server").addEventListener("input", () => { $("servernamerow").classList.toggle("hidden", !isIP($("m_server").value)); });

$("connect").addEventListener("click", () => connect(mode));
$("demo").addEventListener("click", () => connect("demo"));

/* ---------- 2 · scan ---------- */
$("startscan").addEventListener("click", async () => {
  showErr("scanerr"); $("scanlog").textContent = ""; $("pbar").style.width = "2%";
  $("scanning").textContent = t("scanning", {d: conn ? conn.domain : ""});
  $("progress").classList.remove("hidden"); $("startscan").disabled = true;
  const r = await api("/api/scan", {quick: scanMode === "fast"});
  if (!r.ok) { $("startscan").disabled = false; showErr("scanerr", r.error); return; }
  poll();
});
$("cancelscan").addEventListener("click", () => api("/api/cancel", {}));
function poll() {
  clearTimeout(polling);
  polling = setTimeout(async () => {
    const s = await api("/api/status");
    const log = $("scanlog"); log.textContent = "";
    (s.log || []).slice(-8).reverse().forEach(l => { const d = document.createElement("div"); d.textContent = "· " + l; log.appendChild(d); });
    $("pphase").textContent = s.phase || "";
    $("pbar").style.width = Math.max(2, s.percent || 0) + "%";
    if (s.state === "running") return poll();
    $("startscan").disabled = false;
    if (s.state === "error" || s.state === "cancelled") { showErr("scanerr", s.error || s.state); return; }
    if (s.state === "done") {
      $("pphase").textContent = t("done");
      result = await api("/api/result");
      renderResult();
      document.querySelector('.ptab[data-go="scan"]').classList.add("done");
      document.querySelector('.ptab[data-go="report"]').disabled = false;
      show("report");
    }
  }, 600);
}

/* ---------- 3 · results ---------- */
const sevOrder = {critical: 0, high: 1, medium: 2, low: 3, info: 4};
const sevColor = {critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--info)"};
const safeURL = u => /^https:\/\//i.test(u || "") ? u : "#";
function renderResult() {
  const r = result, inv = r.inventory || {}, c = r.counts || {};
  const worst = ["critical", "high", "medium", "low"].find(s => (c.by_severity || {})[s] > 0);
  $("gauge").style.cssText = `--v:${r.score};--sevcol:${worst ? sevColor[worst] : "var(--ok)"}`;
  $("score").textContent = r.score;
  $("r_target").textContent = inv.domain || r.target;
  const when = (inv.collected_at || r.analysed_at || "").replace("T", " ").slice(0, 16) + " UTC";
  const kind = {samba: "Samba AD DC", freeipa: "FreeIPA / IdM", "389ds": "389 Directory Server"}[r.dialect] || "Active Directory";
  $("r_sub").textContent = [kind, (lang === "ru" ? "уровень " : "tier ") + r.tier, when, (inv.identity || ""), (inv.transport || "")].filter(Boolean).join(" · ");
  $("r_unenc").classList.toggle("hidden", !inv.unencrypted);
  $("pc_meta").innerHTML = esc(inv.domain || r.target) + "<br>" + esc(when) + "<br>" + esc(inv.identity || "");
  $("unsigned").classList.toggle("hidden", !r.unsigned_packs);
  $("nopacks").classList.toggle("hidden", (r.checks || []).length > 0);
  $("preview").classList.toggle("hidden", !(r.preview_checks > 0));
  $("preview_t").textContent = t("preview", {n: r.preview_checks || 0});
  $("n_checked").textContent = c.checked || 0; $("n_passed").textContent = c.passed || 0; $("n_failed").textContent = c.failed || 0;
  $("n_findings").textContent = c.findings || 0; $("n_skipped").textContent = c.skipped || 0;
  $("dlhtml").href = "/api/report.html?lang=" + lang + "&t=" + encodeURIComponent(TOKEN);
  $("dljson").href = "/api/report.json?t=" + encodeURIComponent(TOKEN);
  $("dllog").href = "/api/run.log?t=" + encodeURIComponent(TOKEN);

  const host = $("findings"); host.innerHTML = "";
  const failed = (r.checks || []).filter(x => x.status === "fail").sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);
  if (!failed.length) host.innerHTML = `<p class="hint">${esc(t("nofind"))}</p>`;
  failed.forEach(f => {
    const rem = (f.remediation || {})[lang] || (f.remediation || {}).en || {};
    const title = (f.title || {})[lang] || (f.title || {}).en || f.id;
    const items = (f.findings || []).map(x => `<li><span>${esc(x.dn)}</span><span class="ev">${esc(Object.entries(x.evidence || {}).map(([k, v]) => k + ": " + v).join(" · "))}</span></li>`).join("");
    const sec = (k, v) => v ? `<h4>${esc(t(k))}</h4><p>${esc(v)}</p>` : "";
    const d = document.createElement("details"); d.className = "finding";
    d.innerHTML = `<summary><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span><span class="fid">${esc(f.id)}${f.preview ? `<span class="ptag">${esc(t("previewtag"))}</span>` : ""}</span>
      <span class="ftitle">${esc(title)}</span><span class="fcount">${(f.findings || []).length} ${esc(t("objs"))} · ${esc(f.domain)}</span><span class="chev">▸</span></summary>
      <div class="fbody"><h4>${esc(t("aff"))}</h4><ul class="affected">${items}</ul>
      ${sec("why", rem.why)}${sec("abuse", rem.abuse)}${sec("fix", rem.fix)}${sec("verify", rem.verify)}
      ${(f.attack || []).length ? `<h4>MITRE ATT&amp;CK</h4><div class="chips">${f.attack.map(a => `<a class="chip" target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/techniques/${esc(String(a).replace(".", "/"))}/">${esc(a)}</a>`).join("")}</div>` : ""}
      ${(f.references || []).length ? `<h4>${esc(t("refs"))}</h4><ul class="refs">${f.references.map(x => `<li><a target="_blank" rel="noopener noreferrer" href="${esc(safeURL(x.url))}">${esc(x.title)}</a></li>`).join("")}</ul>` : ""}</div>`;
    host.appendChild(d);
  });

  const t0 = inv.tier0 || [], rows = $("t0rows"); rows.innerHTML = "";
  $("t0count").textContent = t0.length;
  t0.slice(0, 200).forEach(e => { const tr = document.createElement("tr"); tr.innerHTML = `<td class="mono">${esc(e.dn)}</td><td>${esc(e.reason)}</td>`; rows.appendChild(tr); });
  $("t0more").classList.toggle("hidden", t0.length <= 200); $("t0more").textContent = t("t0more", {n: t0.length - 200});
  const un = inv.tier0_unresolved || [];
  $("t0unres").classList.toggle("hidden", !un.length); $("t0unres").textContent = t("t0unres", {n: un.length, l: un.slice(0, 5).join("; ")});

  const sk = $("skipbox"); sk.innerHTML = "";
  const by = c.by_skip_reason || {};
  Object.keys(by).forEach(k => { const p = document.createElement("div"); p.innerHTML = `<b>${by[k]}</b> ${esc(t("skip_" + k))}`; sk.appendChild(p); });
  (inv.not_collected || []).forEach(n => { const p = document.createElement("div"); p.textContent = t("notread") + ": " + n.query + " (" + n.reason + ") " + (n.detail || ""); sk.appendChild(p); });
  if (!sk.childNodes.length) sk.textContent = t("noskip");
  $("foot").textContent = t("foot", {n: inv.objects || 0, q: inv.searches || 0, t: inv.collection_duration || "—", h: (r.snapshot_hash || "").slice(0, 16) + "…"});
}
function openAll() { document.querySelectorAll("details.finding").forEach(d => d.open = true); }
window.addEventListener("beforeprint", openAll);
$("pdfbtn").addEventListener("click", () => { openAll(); window.print(); });

/* ---------- library ---------- */
const SEVORD = {critical:0, high:1, medium:2, low:3, info:4};
function openLibrary() {
  $("library").classList.remove("hidden");
  if (library) { renderLibrary(); return; }
  $("lib_rows").innerHTML = `<p class="hint">…</p>`;
  api("/api/library").then(r => {
    library = (r && r.ok) ? r.items : [];
    buildLibFilters();
    renderLibrary();
  });
}
function closeLibrary() { $("library").classList.add("hidden"); }
function buildLibFilters() {
  const doms = [...new Set(library.map(x => x.domain))].sort();
  const fws = [...new Set(library.flatMap(x => Object.keys(x.frameworks || {})))].sort();
  const opt = (v, label) => `<option value="${esc(v)}">${esc(label)}</option>`;
  const fill = (id, html) => { const el = $(id), v = el.value; el.innerHTML = html; el.value = v; };
  fill("lib_sev", opt("", t("lib_allsev")) + ["critical","high","medium","low","info"].map(s => opt(s, t("sev_" + s))).join(""));
  fill("lib_dom", opt("", t("lib_alldom")) + doms.map(d => opt(d, d)).join(""));
  fill("lib_fw", opt("", t("lib_allfw")) + fws.map(f => opt(f, f)).join(""));
}
function renderLibrary() {
  if (!library) return;
  const q = ($("lib_q").value || "").toLowerCase().trim();
  const fsev = $("lib_sev").value, fdom = $("lib_dom").value, ffw = $("lib_fw").value;
  const doms = new Set(library.map(x => x.domain));
  $("lib_sub").textContent = t("lib_sub", {n: library.length, d: doms.size});
  const rows = library.filter(x => {
    if (fsev && x.severity !== fsev) return false;
    if (fdom && x.domain !== fdom) return false;
    if (ffw && !(x.frameworks && x.frameworks[ffw])) return false;
    if (q) {
      const hay = (x.id + " " + (x.title.en || "") + " " + (x.title.ru || "") + " " + x.object + " " +
        Object.values(x.frameworks || {}).flat().map(m => m.id + " " + (m.title || "")).join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => SEVORD[a.severity] - SEVORD[b.severity] || a.id.localeCompare(b.id));
  $("lib_count").textContent = t("lib_count", {n: rows.length, all: library.length});
  if (!rows.length) { $("lib_rows").innerHTML = `<p class="hint">${esc(t("lib_none"))}</p>`; return; }
  const L = lang === "ru" ? "ru" : "en";
  $("lib_rows").innerHTML = rows.map(x => {
    const title = esc(x.title[L] || x.title.en || x.id);
    const tags = [];
    if (x.quick) tags.push(`<span class="tag">${esc(t("lib_quick"))}</span>`);
    if (x.status === "draft") tags.push(`<span class="tag">${esc(t("lib_draft"))}</span>`);
    if (!x.implemented) tags.push(`<span class="tag">${esc(t("lib_planned"))}</span>`);
    const fwchips = Object.entries(x.frameworks || {}).map(([name, ms]) =>
      `<div class="fwrow"><span class="fwname">${esc(name)}</span>${ms.map(m =>
        `<a class="chip" href="${esc(m.url || "#")}" target="_blank" rel="noreferrer noopener" title="${esc(m.title || "")}">${esc(m.id)}${m.title ? " · " + esc(m.title) : ""}</a>`).join("")}</div>`).join("");
    const refs = (x.references || []).map(r =>
      `<a href="${esc(r.url)}" target="_blank" rel="noreferrer noopener">${esc(r.title)}</a>`).join(" · ");
    return `<details class="libitem sev-${esc(x.severity)}">
      <summary><span class="sevdot"></span><code>${esc(x.id)}</code><span class="libttl">${title}</span>
        <span class="sevlbl">${esc(t("sev_" + x.severity))}</span>${tags.join("")}</summary>
      <div class="libdet">
        <p><b>${esc(t("lib_obj"))}:</b> ${esc(x.object)}</p>
        <p><b>${esc(t("lib_fix"))}:</b> ${esc(x.remediation[L] || x.remediation.en || "")}</p>
        ${fwchips ? `<div class="fwbox"><div class="fwh">${esc(t("lib_fw"))}</div>${fwchips}</div>` : ""}
        ${refs ? `<p class="librefs"><b>${esc(t("lib_refs"))}:</b> ${refs}</p>` : ""}
      </div></details>`;
  }).join("");
}
$("librarybtn").addEventListener("click", openLibrary);
$("lib_close").addEventListener("click", closeLibrary);
$("library").addEventListener("click", e => { if (e.target === $("library")) closeLibrary(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeLibrary(); });
["lib_q","lib_sev","lib_dom","lib_fw"].forEach(id => $(id).addEventListener("input", renderLibrary));

/* ---------- chrome ---------- */
$("lang").addEventListener("click", () => { lang = lang === "ru" ? "en" : "ru"; try { localStorage.setItem("da-lang", lang); } catch (e) {} applyLang(); });
const root = document.documentElement;
$("theme").addEventListener("click", () => {
  const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next); try { localStorage.setItem("da-theme", next); } catch (e) {}
});
$("quit").addEventListener("click", async () => {
  await api("/api/quit", {}).catch(() => {});
  document.body.innerHTML = `<p style="padding:40px;font:16px Segoe UI,system-ui,sans-serif">${esc(t("bye"))}</p>`;
});
let savedLang = null;
try { const th = localStorage.getItem("da-theme"); if (th) root.setAttribute("data-theme", th); savedLang = localStorage.getItem("da-lang"); } catch (e) {}
lang = savedLang || (/^ru\b/i.test(navigator.language || "") ? "ru" : "en");
api("/api/info").then(i => {
  $("ver").textContent = i.version || "";
  info = i;
  renderInfo();
});
applyLang(); detect();
})();
