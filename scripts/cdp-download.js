"use strict";

/**
 * cdp-download.js — Pulsa el botón de descarga de un dashboard, deja el fichero en un directorio e imprime ruta y tamaño.
 *   node scripts/cdp-download.js http://127.0.0.1:1881/dashboard/Host /tmp/salida
 * Va aparte de cdp.js porque un informe de megabytes llega cortado por DevTools.
 * Requiere Chrome headless con --remote-debugging-port (ver cdp.js). Variables: CDP_PORT, CDP_WAIT_MS, CDP_NO_NAV.
 */

const fs = require("fs");
const path = require("path");

const URL_ = process.argv[2];
const DIR = process.argv[3];
const PORT = process.env.CDP_PORT || 9333;
const WAIT = Number(process.env.CDP_WAIT_MS || 9000);

if (!URL_ || !DIR) {
  console.error("uso: node scripts/cdp-download.js <url> <directorio-destino>");
  process.exit(2);
}

(async () => {
  let targets = null;
  for (let i = 0; i < 60 && !targets; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); }
    catch (_) { await new Promise((r) => setTimeout(r, 500)); }
  }
  if (!targets) { console.error(`CDP no responde en ${PORT}`); process.exit(1); }

  const page = targets.find((t) => t.type === "page");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const pend = new Map();
  const send = (m, p) => new Promise((res, rej) => {
    const n = ++id; pend.set(n, { res, rej });
    ws.send(JSON.stringify({ id: n, method: m, params: p || {} }));
  });
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) {
      const { res, rej } = pend.get(m.id); pend.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    }
  };
  await new Promise((r) => { ws.onopen = r; });

  fs.mkdirSync(DIR, { recursive: true });
  for (const f of fs.readdirSync(DIR)) { try { fs.unlinkSync(path.join(DIR, f)); } catch (_) {} }

  await send("Page.enable");
  // El destino se fija antes de navegar para saber dónde cae la descarga.
  await send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: DIR, eventsEnabled: true });
  if (process.env.CDP_NO_NAV !== "1") {
    await send("Page.navigate", { url: URL_ });
    await new Promise((r) => setTimeout(r, WAIT));
  }

  await send("Runtime.evaluate", {
    expression: "document.querySelectorAll('.dl-btn')[0].click()",
    awaitPromise: true,
  });

  // Espera a un .html estable: mientras Chrome descarga deja un .crdownload al lado.
  let file = null;
  for (let i = 0; i < 120 && !file; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const todos = fs.readdirSync(DIR);
    const htmls = todos.filter((f) => f.endsWith(".html"));
    if (htmls.length && !todos.some((f) => f.endsWith(".crdownload"))) file = htmls[0];
  }
  if (!file) { console.error("SIN DESCARGA"); ws.close(); process.exit(1); }

  const full = path.join(DIR, file);
  console.log(full + " " + fs.statSync(full).size);
  ws.close();
  process.exit(0);
})();
