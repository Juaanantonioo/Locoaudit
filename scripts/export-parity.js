"use strict";

/**
 * export-parity.js — PASO 3: el export NO puede divergir del dashboard.
 *
 *   A) CABLEADO — cada ui_template usa el cuerpo snapshot compartido
 *      (lib/snapshot-body.txt), tiene sentinel + report-root, conserva el
 *      fallback y NO deja código global (que rompería Dashboard 2.0).
 *   B) SNAPSHOT (smoke) — se ejecuta el MISMO cuerpo contra un DOM falso y se
 *      comprueba que quita IA + descargas, reabre grupos, abre detalles y
 *      produce un documento autocontenido.
 *
 * Sin navegador ni dependencias. `node scripts/export-parity.js`.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const BODY = fs.readFileSync(path.join(ROOT, "lib", "snapshot-body.txt"), "utf8");
const TEMPLATES = {
  host: "examples/dashboard-host-template.html",
  network: "examples/dashboard-network-template.html",
  image: "examples/dashboard-image-template.html",
};

let fails = 0;
function ok(cond, msg) { if (!cond) { fails++; console.log("    ✗ " + msg); } }

// ── A) Cableado ──────────────────────────────────────────────────────────────
console.log("A) Cableado de los ui_template");
for (const [node, rel] of Object.entries(TEMPLATES)) {
  const t = fs.readFileSync(path.join(ROOT, rel), "utf8");
  const before = fails;
  ok(t.includes("LCA-STYLE-DASH:" + node), `[${node}] falta sentinel LCA-STYLE-DASH:${node}`);
  ok(t.includes("lca-report-root"), `[${node}] falta clase lca-report-root`);
  ok(t.includes("LCA:SNAPSHOT:START"), `[${node}] falta el cuerpo snapshot`);
  ok(t.includes("_buildHtmlReportFallback"), `[${node}] falta el fallback`);
  ok(t.indexOf("LCA:SNAPSHOT:START") < t.indexOf("_buildHtmlReportFallback"), `[${node}] snapshot no es primario`);
  // Dashboard 2.0 no admite código a nivel superior: el <script> arranca en export default.
  ok(/<script>\nexport default \{/.test(t), `[${node}] el <script> no arranca en export default`);
  ok(!t.includes("window.LCA_EXPORT") && !t.includes("LCA:EXPORT-LIB"), `[${node}] hay código global (rompe Dashboard 2.0)`);
  if (fails === before) console.log(`  ✓ ${node}`);
}

// ── B) Smoke del cuerpo snapshot contra DOM falso ────────────────────────────
console.log("B) Snapshot (DOM falso, mismo cuerpo que el navegador)");

function El(tag, cls, opts) {
  opts = opts || {};
  const e = { tagName: tag.toUpperCase(), _class: cls || "", children: [], style: { display: opts.display || "" }, _text: opts.text || "", _attrs: {} };
  e.className = e._class; e.textContent = opts.text || "";
  e.classList = {
    add(c) { if (!(" " + e._class + " ").includes(" " + c + " ")) { e._class = (e._class + " " + c).trim(); e.className = e._class; } },
    remove(c) { e._class = (" " + e._class + " ").replace(" " + c + " ", " ").trim(); e.className = e._class; },
    toggle(c, on) { on ? e.classList.add(c) : e.classList.remove(c); },
    contains(c) { return (" " + e._class + " ").includes(" " + c + " "); },
  };
  e.setAttribute = function (k, v) { e._attrs[k] = String(v); };
  e.getAttribute = function (k) { return k in e._attrs ? e._attrs[k] : null; };
  e.append = function (c) { c._parent = e; e.children.push(c); return c; };
  e.remove = function () { if (e._parent) e._parent.children = e._parent.children.filter((x) => x !== e); };
  Object.defineProperty(e, "nextElementSibling", { get() {
    if (!e._parent) return null; const s = e._parent.children; const i = s.indexOf(e); return i >= 0 && i + 1 < s.length ? s[i + 1] : null;
  } });
  const walk = (n, out) => { n.children.forEach((c) => { c._parent = n; out.push(c); walk(c, out); }); return out; };
  const matches = (n, sel) => sel.split(",").some((raw) => {
    const s = raw.trim(); let m;
    if ((m = s.match(/^\[class\*="(.+)"\]$/)) || (m = s.match(/^\[class\*=([a-z0-9-]+)\]$/i))) return n._class.includes(m[1]);
    if ((m = s.match(/^\[(.+)\]$/))) return m[1] in n._attrs;
    if ((m = s.match(/^\.(.+)$/))) return (" " + n._class + " ").includes(" " + m[1] + " ");
    if (/^[a-z]+$/i.test(s)) return n.tagName === s.toUpperCase();
    return false;
  });
  e.querySelector = function (sel) { return walk(e, []).find((n) => matches(n, sel)) || null; };
  e.querySelectorAll = function (sel) { return walk(e, []).filter((n) => matches(n, sel)); };
  e.cloneNode = function () {
    const c = El(tag, e._class, { display: e.style.display, text: e._text });
    Object.keys(e._attrs).forEach((k) => (c._attrs[k] = e._attrs[k]));
    e.children.forEach((ch) => c.append(ch.cloneNode(true)));
    return c;
  };
  Object.defineProperty(e, "innerHTML", { get() {
    return e.children.map((c) => {
      const cls = c._class ? ` class="${c._class}"` : "";
      const st = c.style.display === "none" ? ' style="display: none;"' : "";
      const at = Object.keys(c._attrs).map((k) => ` ${k}="${c._attrs[k]}"`).join("");
      return `<${c.tagName.toLowerCase()}${cls}${st}${at}>${c.innerHTML}${c._text}</${c.tagName.toLowerCase()}>`;
    }).join("");
  } });
  return e;
}

// Dashboard falso representativo (grupo colapsable + hallazgo con comando).
const reportRoot = El("div", "lca-report-root");
reportRoot.append(El("span", "dl-group")).append(El("button", "dl-btn", { text: "HTML" }));
const gh = reportRoot.append(El("div", "group-header"));
gh.append(El("span", "group-chevron", { text: "v" }));
const gbody = reportRoot.append(El("div", "group-findings", { display: "none" }));
const item = gbody.append(El("div", "finding-item"));
item.append(El("div", "finding-row", { text: "Fila" }));           // cabecera del hallazgo
const det = item.append(El("div", "finding-detail"));               // detalle (hermano de la fila)
const chat = det.append(El("div", "lca-chat-wrap"));
chat.append(El("button", "ai-ask-btn", { text: "Preguntar a la IA" }));
chat.append(El("div", "lca-chat", { text: "conversacion" }));
const cbox = det.append(El("div", "command-box"));
cbox.append(El("code", "command-text", { text: "sudo cosa" }));
cbox.append(El("button", "command-btn", { text: "Copiar" }));
det.append(El("div", "cmd-warn", { text: "LoCoAudit no ejecuta el comando" }));

const $el = El("div");
$el.append(reportRoot);

const styleEl = { textContent: "/*LCA-STYLE-DASH:host*/ .header-card{}--accent:#0EA5E9" };
const fakeDoc = {
  querySelectorAll: (sel) => (sel === "style" ? [styleEl] : $el.querySelectorAll(sel)),
  querySelector: (sel) => $el.querySelector(sel),
};

const thisObj = { $el, auditData: { auditType: "host", host: { hostname: "mac.local", platform: "darwin" } } };
const run = new Function("document", BODY);
const html = run.call(thisObj, fakeDoc);
const body = html.slice(html.indexOf("</style>"));

const before = fails;
ok(typeof html === "string" && html.startsWith("<!DOCTYPE html>"), "no es documento HTML completo");
ok(html.includes("<title>LoCoAudit"), "sin <title>");
ok(!/https?:\/\//i.test(html), "contiene URL externa (no autocontenido)");
ok(!/<link\b/i.test(html) && !/src=["']http/i.test(html), "enlaza recurso externo");
ok(!body.includes("ai-ask-btn"), "no eliminó el botón de IA");
ok(!body.includes("lca-chat"), "no eliminó el chat");
ok(!body.includes("Preguntar a la IA"), "quedó texto de IA");
ok(!body.includes('class="dl-group"'), "no eliminó los botones de descarga");
ok(!/group-findings" style="display: none;"/.test(body), "no reabrió el grupo (debe iniciar abierto)");
ok(/group-header[^>]*data-lca-acc/.test(body), "el grupo no es interactivo (sin data-lca-acc)");
ok(/finding-row[^>]*data-lca-acc/.test(body), "el hallazgo no es interactivo (sin data-lca-acc)");
ok(body.includes('data-lca-open="0"'), "el detalle no inicia cerrado (como el dashboard)");
ok(html.includes("data-lca-open"), "falta el toggle vanilla del acordeón");
ok(body.includes("command-btn"), "eliminó el botón Copiar (debe conservarse)");
ok(body.includes("sudo cosa"), "perdió el comando del hallazgo");
// PASO 3: el export conserva el aviso inline (comando + copiar + aviso) —
// la resolución vive en un solo sitio (inline), sin botón/modal redundante.
ok(body.includes("cmd-warn") && body.includes("no ejecuta"), "perdió el aviso inline en el export");
ok(html.includes("--accent"), "no embebió el CSS del dashboard");
if (fails === before) console.log("  ✓ prune IA/descargas · acordeón interactivo (grupos abiertos, detalles cerrados) · copiar conservado");

if (fails) { console.log(`\n${fails} fallo(s).`); process.exit(1); }
console.log("\nParidad/cableado OK.");
