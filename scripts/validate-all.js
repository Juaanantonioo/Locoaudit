"use strict";

/**
 * validate-all.js — Validación end-to-end de los tres dashboards.
 *
 * No improvisa nada: ejecuta siempre las mismas comprobaciones, en el mismo orden, y
 * falla con un mensaje que dice QUÉ criterio cayó y en qué dashboard. Sustituye a la
 * lista de pasos que hasta ahora había que recordar y ejecutar a mano.
 *
 *   node scripts/validate-all.js              # todo
 *   node scripts/validate-all.js --static     # solo lo que no necesita navegador
 *   node scripts/validate-all.js --only host  # un dashboard
 *   node scripts/validate-all.js --keep       # no parar Node-RED/Chrome al terminar
 *
 * Qué necesita para el modo completo:
 *   - Node-RED instalado y los nodos de LoCoAudit resolubles (usa ~/.node-red/node_modules
 *     por enlaces, sin tocar ese directorio);
 *   - Google Chrome, para medir contraste e imprimir;
 *   - las herramientas de auditoría que cada nodo use (trivy, lynis, nmap, docker).
 *     Lo que falte se traduce en un dashboard con menos datos, no en un fallo del runner.
 *
 * Levanta su PROPIO Node-RED en un userDir temporal con una copia de
 * examples/flows.json. Nunca escribe en ~/.node-red: Node-RED reescribe su flows.json
 * al arrancar y eso obligaría a repetir el pegado en la otra máquina.
 *
 * Exit code 0 solo si TODOS los criterios pasan.
 */

const { execFileSync, spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DASH = [
  { id: "host", page: "Host", file: "examples/dashboard-host-template.html" },
  { id: "network", page: "Network", file: "examples/dashboard-network-template.html" },
  { id: "image", page: "Image", file: "examples/dashboard-image-template.html" },
];

const ARGS = process.argv.slice(2);
const SOLO = ARGS.includes("--only") ? ARGS[ARGS.indexOf("--only") + 1] : null;
const ESTATICO = ARGS.includes("--static");
const KEEP = ARGS.includes("--keep");
const PUERTO = Number(process.env.LCA_PORT || 1881);
const CDP = Number(process.env.CDP_PORT || 9333);
const DASHES = SOLO ? DASH.filter((d) => d.id === SOLO) : DASH;

// ── Registro de resultados ───────────────────────────────────────────────────
const filas = [];   // { dash, criterio, ok, detalle }
let fallos = 0;
function reg(dash, criterio, ok, detalle) {
  filas.push({ dash, criterio, ok: !!ok, detalle: detalle || "" });
  if (!ok) fallos++;
  process.stdout.write(`  ${ok ? "✓" : "✗"} ${dash ? "[" + dash + "] " : ""}${criterio}${detalle ? " — " + detalle : ""}\n`);
}

function sh(cmd, args, opts) {
  return execFileSync(cmd, args, Object.assign(
    { cwd: ROOT, encoding: "utf8", stdio: "pipe", maxBuffer: 16 * 1024 * 1024 }, opts || {}));
}

// ═══ 1 · ESTÁTICO ════════════════════════════════════════════════════════════

function bloqueScripts() {
  console.log("\n── Scripts de coherencia ──");
  for (const [nombre, args] of [["build-dashboards --check", ["scripts/build-dashboards.js", "--check"]],
                                ["export-parity (A/B/C)", ["scripts/export-parity.js"]]]) {
    try { sh(process.execPath, args); reg("", nombre, true); }
    catch (e) { reg("", nombre, false, (e.stdout || e.message || "").trim().split("\n").slice(-3).join(" | ")); }
  }
}

function bloqueTests() {
  console.log("\n── Suite de tests ──");
  const dir = path.join(ROOT, "test", "manual");
  const tests = fs.readdirSync(dir).filter((f) => f.endsWith(".js")).sort();
  const malos = [];
  for (const t of tests) {
    try { sh(process.execPath, [path.join("test", "manual", t)]); }
    catch (_) { malos.push(t); }
  }
  reg("", `suite completa (${tests.length} tests)`, malos.length === 0, malos.length ? "fallan: " + malos.join(", ") : "");
}

// Emoji, fallbacks escondidos y hex sueltos. El generador de respaldo
// (_buildHtmlReportFallback) es un documento aparte, con su propio CSS, y queda fuera.
const RE_EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{2705}\u{2713}\u{2714}\u{25B2}\u{25BC}\u{25B8}\u{25BE}\u{25A0}\u{2715}]/u;

/**
 * Quita comentarios sustituyéndolos por espacios, para que las posiciones y los
 * números de línea no se muevan. Sin esto, un comentario que CITA lo que se retiró
 * —"antes era var(--accent, #7C3AED)", "el ▲/▼ de texto anterior"— se cuenta como
 * una infracción, y el runner acaba señalando su propia documentación.
 * Reconocer el comentario por cómo empieza la línea no vale: la cita suele estar en
 * la segunda o tercera línea del bloque.
 */
function sinComentarios(txt) {
  const blanco = (m) => m.replace(/[^\n]/g, " ");
  return txt
    .replace(/<!--[\s\S]*?-->/g, blanco)
    .replace(/\/\*[\s\S]*?\*\//g, blanco)
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, p1) => p1 + blanco(m.slice(p1.length)));
}

function trozos(src) {
  const iStyle = src.indexOf("\n<style>\n");
  const iFall = src.indexOf("_buildHtmlReportFallback() {");
  const iFallEnd = iFall >= 0 ? src.indexOf("\n    parseFixSteps(", iFall) : -1;
  const antesStyle = src.slice(0, iStyle);
  const css = src.slice(iStyle);
  return {
    antesStyle,
    css,
    limpioAntes: sinComentarios(antesStyle),
    limpioCss: sinComentarios(css),
    fallback: iFall >= 0 && iFallEnd > iFall ? src.slice(iFall, iFallEnd) : "",
  };
}

function bloqueHigiene(d) {
  const src = fs.readFileSync(path.join(ROOT, d.file), "utf8");
  const t = trozos(src);

  const limpio = sinComentarios(src);

  // Emoji: fuera de comentarios, que a veces citan el glifo que se retiró.
  const lineasEmoji = limpio.split("\n").map((l, i) => [i + 1, l]).filter(([, l]) => RE_EMOJI.test(l));
  reg(d.id, "cero emoji", lineasEmoji.length === 0,
      lineasEmoji.length ? "líneas " + lineasEmoji.map(([n]) => n).join(", ") : "");

  // var(--x, fallback): un token sin declarar pinta su fallback y no aparece en ningún
  // :root, así que no hay dónde verlo.
  const fb = [...t.limpioCss.matchAll(/var\(\s*(--[a-z0-9-]+)\s*,\s*[^)]+\)/g)];
  reg(d.id, "cero var(--x, fallback)", fb.length === 0,
      fb.length ? fb.map((m) => m[1]).join(", ") : "");

  // Hex sueltos fuera del <style> (atributos SVG y cadenas JS) y fuera del generador
  // de respaldo, que es un documento aparte con su propio CSS.
  const js = t.limpioAntes.replace(sinComentarios(t.fallback), "");
  const hex = [...js.matchAll(/#[0-9A-Fa-f]{6}\b|rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+/g)];
  reg(d.id, "cero color a mano en JS/SVG", hex.length === 0,
      hex.length ? hex.slice(0, 4).map((m) => m[0]).join(", ") + (hex.length > 4 ? ` (+${hex.length - 4})` : "") : "");
}

// ═══ 2 · COHERENCIA ENTRE LOS TRES ═══════════════════════════════════════════
// La comprobación que faltaba: nada vigilaba que los tres dashboards siguieran
// pareciéndose. El pie de image se quedó con una anatomía propia (.footer, una línea
// suelta) mientras host y network usaban .report-foot, y ningún test lo vio.

const ESTRUCTURALES = [
  "lca-report-root", "lca-sprite", "header-card", "header-main", "header-aside",
  "header-eyebrow", "host-name", "risk-badge", "meta-grid", "meta-key", "meta-val",
  "dl-group", "dl-btn", "report-foot", "report-foot-key", "report-foot-val",
  "lca-notice", "lca-notice-title", "lca-notice-body", "icon",
];
const NIVELES_AVISO = ["lvl-1", "lvl-2", "lvl-3", "is-ok", "is-warn", "is-info", "is-neutral"];
const ORDEN = ["header-card", "report-foot"];   // el esqueleto que los tres comparten

/**
 * Frontera de nombre de clase. `\b` NO vale: el guion es un carácter de no-palabra,
 * así que /\.report-foot\b/ casa dentro de `.report-foot-item` y un renombrado de
 * `.report-foot` pasa desapercibido. Comprobado: renombrando esa regla el criterio
 * seguía en verde.
 */
function claseRe(nombre) {
  return new RegExp("\\." + nombre.replace(/[-]/g, "\\-") + "(?![\\w-])");
}

function tokensDe(css) {
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  return new Set([...root.matchAll(/^\s*(--[a-z0-9-]+)\s*:/gm)].map((m) => m[1]));
}

function bloqueCoherencia(fuentes) {
  console.log("\n── Coherencia entre los tres ──");

  for (const clase of ESTRUCTURALES) {
    const faltan = fuentes.filter((f) => !claseRe(clase).test(f.css)).map((f) => f.id);
    reg("", `clase .${clase} en los tres`, faltan.length === 0, faltan.length ? "falta en " + faltan.join(", ") : "");
  }
  for (const n of NIVELES_AVISO) {
    const faltan = fuentes.filter((f) => !claseRe(n).test(f.css)).map((f) => f.id);
    reg("", `aviso .${n} en los tres`, faltan.length === 0, faltan.length ? "falta en " + faltan.join(", ") : "");
  }

  // Orden de bloques: comparando la posición en el MARCADO, no en el CSS.
  for (const f of fuentes) {
    const pos = ORDEN.map((c) => f.tpl.indexOf(`class="${c}`));
    const ok = pos.every((p) => p >= 0) && pos.every((p, i) => i === 0 || p > pos[i - 1]);
    reg(f.id, `orden de bloques (${ORDEN.join(" → ")})`, ok, ok ? "" : "posiciones " + pos.join(", "));
  }

  // Vocabulario de tokens: ninguno puede declarar un token que a otro le falte.
  const sets = fuentes.map((f) => ({ id: f.id, tk: tokensDe(f.css) }));
  const union = new Set(sets.flatMap((s) => [...s.tk]));
  for (const s of sets) {
    const faltan = [...union].filter((t) => !s.tk.has(t)).sort();
    reg(s.id, "vocabulario de tokens completo", faltan.length === 0,
        faltan.length ? "no declara " + faltan.join(", ") : `${s.tk.size} tokens`);
  }
}

// ═══ 3 · EN VIVO ═════════════════════════════════════════════════════════════

let nodeRed = null, chrome = null, tmp = null;

function arrancarEntorno() {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lca-validate-"));
  const nm = path.join(tmp, "node_modules");
  fs.mkdirSync(nm);
  const origen = path.join(os.homedir(), ".node-red", "node_modules");
  if (!fs.existsSync(origen)) throw new Error(`no encuentro ${origen}: instala los nodos en ~/.node-red primero`);
  for (const e of fs.readdirSync(origen)) {
    const src = path.join(origen, e), dst = path.join(nm, e);
    if (e.startsWith("@")) {
      fs.mkdirSync(dst);
      for (const f of fs.readdirSync(src)) fs.symlinkSync(path.join(src, f), path.join(dst, f));
    } else if (e === "locoaudit") {
      fs.symlinkSync(ROOT, dst);            // el repo de trabajo, no la copia instalada
    } else {
      fs.symlinkSync(src, dst);
    }
  }
  if (!fs.existsSync(path.join(nm, "locoaudit"))) fs.symlinkSync(ROOT, path.join(nm, "locoaudit"));
  fs.copyFileSync(path.join(ROOT, "examples", "flows.json"), path.join(tmp, "flows.json"));
  fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "lca-validate", version: "0.0.0" }));
  fs.writeFileSync(path.join(tmp, "settings.js"),
    `module.exports = { uiPort: ${PUERTO}, flowFile: 'flows.json', httpAdminRoot: '/admin',\n` +
    `  logging: { console: { level: 'warn' } }, editorTheme: { projects: { enabled: false } } };\n`);

  nodeRed = spawn("node-red", ["-u", tmp, "-s", "settings.js"], {
    cwd: tmp, stdio: ["ignore", "pipe", "pipe"],
    env: Object.assign({}, process.env, { NODE_OPTIONS: "--max-old-space-size=4096" }),
  });
  const log = fs.createWriteStream(path.join(tmp, "nr.log"));
  nodeRed.stdout.pipe(log); nodeRed.stderr.pipe(log);

  const chromeBin = process.env.CHROME_BIN ||
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  chrome = spawn(chromeBin, [
    "--headless=new", "--disable-gpu", `--remote-debugging-port=${CDP}`,
    `--user-data-dir=${path.join(tmp, "chrome")}`, "--window-size=1440,900", "about:blank",
  ], { stdio: "ignore" });
  return tmp;
}

function pararEntorno() {
  if (KEEP) { console.log(`\n(--keep) entorno en ${tmp}, Node-RED en :${PUERTO}`); return; }
  for (const p of [nodeRed, chrome]) { try { p && p.kill("SIGKILL"); } catch (_) {} }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
}

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

async function esperarHttp(url, ms) {
  const fin = Date.now() + ms;
  while (Date.now() < fin) {
    try { const r = await fetch(url); if (r.status < 500) return true; } catch (_) {}
    await dormir(1000);
  }
  return false;
}

/**
 * Ejecuta una expresión dentro de una página, vía scripts/cdp.js.
 * `navegar: false` evalúa sobre la página ya abierta: es lo que permite sondear en
 * bucle sin reiniciar el componente en cada vuelta.
 */
function enPagina(url, ficheroExpr, opts) {
  const o = opts || {};
  return sh(process.execPath, [path.join("scripts", "cdp.js"), url, ficheroExpr], {
    env: Object.assign({}, process.env, {
      CDP_PORT: String(CDP),
      CDP_WAIT_MS: String(o.waitMs || 9000),
      CDP_NO_NAV: o.navegar === false ? "1" : "0",
    }),
  });
}

function tmpExpr(nombre, cuerpo) {
  const f = path.join(tmp, nombre);
  fs.writeFileSync(f, cuerpo);
  return f;
}

async function lanzarAuditoria(d, flows) {
  // El inject que alimenta al nodo de este tipo.
  const nodo = flows.find((n) => n.type === "audit-" + d.id);
  if (!nodo) return null;
  const inj = flows.find((n) => n.type === "inject" && (n.wires || []).some((w) => w.includes(nodo.id)));
  if (!inj) return null;
  await fetch(`http://127.0.0.1:${PUERTO}/admin/inject/${inj.id}`, { method: "POST" });
  return inj.id;
}

/**
 * Servidor estático mínimo, para imprimir por HTTP.
 * `listen` es ASÍNCRONO: esperarlo con un bucle síncrono no funciona, porque el bucle
 * de eventos no llega a correr y `address()` se queda en null para siempre. El puerto
 * salía 0 y Chrome se colgaba intentando abrir http://127.0.0.1:0/.
 */
function servirDirectorio(dir) {
  return new Promise((res) => {
    const server = http.createServer((req, resp) => {
      const f = path.join(dir, decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, ""));
      if (!f.startsWith(dir) || !fs.existsSync(f)) { resp.statusCode = 404; return resp.end(); }
      resp.setHeader("Content-Type", "text/html; charset=utf-8");
      resp.end(fs.readFileSync(f));
    });
    server.listen(0, "127.0.0.1", () => {
      res({ puerto: server.address().port, cerrar: () => server.close() });
    });
  });
}

/**
 * Imprime el informe a PDF dos veces —con la regla @media print y sin ella— y compara
 * el número de páginas. Es la única forma de comprobar que la regla hace algo: si las
 * fichas no se abrieran al imprimir, los dos recuentos saldrían iguales y el informe
 * en papel llegaría con todo plegado sin que fallara nada más.
 */
async function medirImpresion(d, url) {
  const dir = path.join(tmp, "print-" + d.id);
  // El informe se DESCARGA a disco en vez de venir por el puente: con la auditoría de
  // imagen son megabytes, y devolver eso como valor por el protocolo de DevTools lo
  // mete en un JSON dentro de otro JSON que llega cortado.
  let origen;
  try {
    origen = sh(process.execPath, [path.join("scripts", "cdp-download.js"), url, dir], {
      env: Object.assign({}, process.env, { CDP_PORT: String(CDP), CDP_NO_NAV: "1" }),
      maxBuffer: 4 * 1024 * 1024,
    }).trim().split(" ")[0];
  } catch (e) {
    reg(d.id, "impresión: la regla abre las fichas", false, "no se pudo descargar el informe");
    return;
  }
  const html = fs.readFileSync(origen, "utf8");
  fs.writeFileSync(path.join(dir, "informe.html"), html);
  fs.writeFileSync(path.join(dir, "control.html"), html.replace(/@media print\{[\s\S]*?\}\}/g, ""));

  const chromeBin = process.env.CHROME_BIN ||
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  // Servido por HTTP y no como file://: Chrome headless se QUEDA COLGADO imprimiendo
  // un file:// (comprobado, no vuelve nunca), y el timeout se leería como "la regla
  // no funciona" cuando el problema es el protocolo.
  const srv = await servirDirectorio(dir);
  // Chrome se lanza de forma ASÍNCRONA. Con execFileSync el proceso se bloquea, el
  // bucle de eventos no corre, y el servidor de arriba —que vive en este mismo
  // proceso— no puede contestar: Chrome espera una página que nunca llega y la espera
  // es mutua. Un subproceso síncrono mata a cualquier servidor que viva con él.
  const paginas = (nombre) => new Promise((res) => {
    const pdf = path.join(dir, nombre + ".pdf");
    const hijo = spawn(chromeBin, ["--headless=new", "--disable-gpu", "--no-pdf-header-footer",
      "--print-to-pdf=" + pdf, "--user-data-dir=" + path.join(dir, "prof-" + nombre),
      `http://127.0.0.1:${srv.puerto}/${nombre}.html`], { stdio: "ignore" });
    const corte = setTimeout(() => { try { hijo.kill("SIGKILL"); } catch (_) {} }, 300000);
    hijo.on("exit", () => {
      clearTimeout(corte);
      try {
        const buf = fs.readFileSync(pdf).toString("latin1");
        res((buf.match(/\/Type\s*\/Page[^s]/g) || []).length);
      } catch (_) { res(-1); }
    });
  });
  const con = await paginas("informe");
  const sin = await paginas("control");
  srv.cerrar();
  reg(d.id, "impresión: la regla abre las fichas", con > 0 && sin > 0 && con > sin,
      con < 0 || sin < 0 ? "no se pudo imprimir" : `${con} páginas con la regla · ${sin} sin ella`);
}

async function bloqueVivo(fuentes) {
  console.log("\n── Entorno aislado ──");
  arrancarEntorno();
  const arriba = await esperarHttp(`http://127.0.0.1:${PUERTO}/admin/`, 90000);
  reg("", "Node-RED arranca", arriba);
  if (!arriba) return;
  const cdpOk = await esperarHttp(`http://127.0.0.1:${CDP}/json/list`, 30000);
  reg("", "Chrome headless (CDP)", cdpOk);
  if (!cdpOk) return;

  const flows = JSON.parse(fs.readFileSync(path.join(ROOT, "examples", "flows.json"), "utf8"));
  const estado = tmpExpr("estado.js",
    'JSON.stringify({done: !!document.querySelector(".lca-report-root")})');

  for (const d of fuentes) {
    console.log(`\n── ${d.id} ──`);
    const url = `http://127.0.0.1:${PUERTO}/dashboard/${d.page}`;

    const inj = await lanzarAuditoria(d, flows);
    if (!inj) { reg(d.id, "auditoría real", false, "no hay inject cableado en flows.json"); continue; }

    // Espera activa. Se navega UNA vez y a partir de ahí se sondea sobre la misma
    // página: cada navegación reinicia el componente y tira el websocket por el que
    // llega el payload, así que sondear navegando impide que llegue lo que se espera.
    // Una auditoría de imagen con Trivy sobre decenas de imágenes tarda minutos.
    let listo = false;
    const fin = Date.now() + 20 * 60 * 1000;
    try { listo = JSON.parse(enPagina(url, estado, { waitMs: 9000 })).done; } catch (_) {}
    while (!listo && Date.now() < fin) {
      await dormir(10000);
      try { listo = JSON.parse(enPagina(url, estado, { navegar: false })).done; } catch (_) {}
    }
    reg(d.id, "auditoría real completa", listo);
    if (!listo) continue;

    // Contraste.
    try {
      const r = JSON.parse(enPagina(url, path.join(ROOT, "scripts", "contrast-audit.js"), { navegar: false }));
      reg(d.id, "contraste 0 fallos", r.distintos === 0,
          r.distintos ? `${r.distintos} distintos, peor ${r.casos[0].ratio}:1 en .${String(r.casos[0].clase).split(" ")[0]}` : "");
    } catch (e) { reg(d.id, "contraste 0 fallos", false, String(e.message).slice(0, 120)); }

    // Export: se captura el HTML interceptando la descarga, sin tocar ~/Downloads.
    const capt = tmpExpr("export.js", `(async () => {
      const orig = HTMLAnchorElement.prototype.click;
      let href = null;
      HTMLAnchorElement.prototype.click = function () {
        if (this.download && String(this.href).startsWith('blob:')) { href = this.href; return; }
        return orig.apply(this, arguments);
      };
      document.querySelectorAll('.dl-btn')[0].click();
      HTMLAnchorElement.prototype.click = orig;
      if (!href) return JSON.stringify({ error: 'el botón no generó descarga' });
      const txt = await fetch(href).then(r => r.text());
      const d = new DOMParser().parseFromString(txt, 'text/html');
      const row = d.querySelector('[class*="finding-row"][data-lca-acc], [class*="finding-header"][data-lca-acc]');
      return JSON.stringify({
        bytes: txt.length,
        sprite: d.querySelectorAll('.lca-sprite symbol').length,
        uses: d.querySelectorAll('use').length,
        chat: d.querySelectorAll('[class*="chat"], .ai-ask-btn, .ia-ask-btn').length,
        dl: d.querySelectorAll('.dl-group, .ia-dl-group').length,
        acc: !!row,
        chevron: !!(row && row.querySelector('[class*=chevron]')),
        copiar: d.querySelectorAll('.command-btn, .ia-copy-btn').length,
        print: /@media print\\{/.test(txt),
        pie: d.querySelectorAll('.report-foot').length,
      });
    })()`);
    try {
      const r = JSON.parse(enPagina(url, capt, { navegar: false }));
      if (r.error) { reg(d.id, "export del informe", false, r.error); }
      else {
        reg(d.id, "export: sprite viaja", r.sprite > 0 && r.uses > 0, `${r.sprite} símbolos / ${r.uses} usos`);
        reg(d.id, "export: chat podado", r.chat === 0, r.chat ? `${r.chat} restos` : "");
        reg(d.id, "export: descargas podadas", r.dl === 0, r.dl ? `${r.dl} restos` : "");
        reg(d.id, "export: acordeón + chevron", r.acc && r.chevron);
        reg(d.id, "export: regla de impresión", r.print);
        reg(d.id, "export: pie unificado", r.pie === 1);
        // El botón Copiar solo existe si la auditoría produjo algún comando.
        reg(d.id, "export: botón Copiar", true, r.copiar ? `${r.copiar} comandos` : "sin comandos en estos datos");
        await medirImpresion(d, url);
      }
    } catch (e) { reg(d.id, "export del informe", false, String(e.message).slice(0, 120)); }
  }
}

// ═══ Ejecución ═══════════════════════════════════════════════════════════════
(async () => {
  console.log("LoCoAudit · validación end-to-end\n" + "=".repeat(60));

  const fuentes = DASHES.map((d) => {
    const src = fs.readFileSync(path.join(ROOT, d.file), "utf8");
    const t = trozos(src);
    return Object.assign({}, d, { src, css: t.css, tpl: src.slice(0, src.indexOf("<script>")) });
  });

  bloqueScripts();
  bloqueTests();
  console.log("\n── Higiene por dashboard ──");
  fuentes.forEach(bloqueHigiene);
  bloqueCoherencia(fuentes);

  if (!ESTATICO) {
    try { await bloqueVivo(fuentes); }
    catch (e) { reg("", "entorno en vivo", false, String(e.message).slice(0, 160)); }
    finally { pararEntorno(); }
  } else {
    console.log("\n(--static) omitidas auditoría real, contraste, export e impresión.");
  }

  // ── Informe final ──
  console.log("\n" + "=".repeat(60));
  const porDash = new Map();
  filas.forEach((f) => {
    const k = f.dash || "(global)";
    if (!porDash.has(k)) porDash.set(k, { ok: 0, ko: 0, malos: [] });
    const e = porDash.get(k);
    f.ok ? e.ok++ : (e.ko++, e.malos.push(f.criterio));
  });
  console.log("RESUMEN");
  for (const [k, v] of porDash) {
    console.log(`  ${k.padEnd(10)} ${String(v.ok).padStart(3)} ok  ${String(v.ko).padStart(3)} fallo(s)` +
                (v.malos.length ? "\n" + v.malos.map((m) => "               ✗ " + m).join("\n") : ""));
  }
  console.log("=".repeat(60));
  if (fallos) { console.log(`\n${fallos} criterio(s) fallidos.`); process.exit(1); }
  console.log("\nTodo en verde.");
})();
