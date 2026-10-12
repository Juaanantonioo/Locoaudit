"use strict";

/**
 * cdp.js — Ejecuta JavaScript dentro de un dashboard servido y devuelve el resultado.
 * Validar un dashboard exige mirarlo renderizado (color efectivo, orden de bloques en el DOM, sprite tras el export).
 * Sin dependencias: habla el protocolo de DevTools por WebSocket, que Node 22 trae de serie.
 *
 *   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --remote-debugging-port=9333 --user-data-dir=/tmp/lca-chrome about:blank &
 *   node scripts/cdp.js http://127.0.0.1:1881/dashboard/Host scripts/contrast-audit.js
 *
 * El segundo argumento es un FICHERO con una expresión JavaScript (no un script con `return`); se imprime lo que evalúe.
 * Variables: CDP_PORT (9333), CDP_WAIT_MS (9000, el dashboard recibe los datos por websocket y no con el load) y
 * CDP_NO_NAV=1 para no navegar y evaluar en la página ya abierta (cada navegación tira el websocket y un sondeo en bucle no termina).
 */

const fs = require("fs");

const URL_ = process.argv[2];
const EXPR_FILE = process.argv[3];
const PORT = process.env.CDP_PORT || 9333;
const WAIT = Number(process.env.CDP_WAIT_MS || 9000);

if (!URL_ || !EXPR_FILE) {
  console.error("uso: node scripts/cdp.js <url> <fichero-con-expresion-js>");
  process.exit(2);
}

const EXPR = fs.readFileSync(EXPR_FILE, "utf8");

(async () => {
  // El puerto puede tardar en levantar: se reintenta en vez de fallar a la primera.
  let targets = null;
  for (let i = 0; i < 60 && !targets; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
    } catch (_) {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  if (!targets) {
    console.error(`CDP no responde en el puerto ${PORT}. ¿Arrancaste Chrome con --remote-debugging-port=${PORT}?`);
    process.exit(1);
  }

  const page = targets.find((t) => t.type === "page");
  if (!page) { console.error("no hay ninguna pestaña a la que conectarse"); process.exit(1); }

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const pend = new Map();
  const send = (method, params) =>
    new Promise((res, rej) => {
      const n = ++id;
      pend.set(n, { res, rej });
      ws.send(JSON.stringify({ id: n, method, params: params || {} }));
    });

  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) {
      const { res, rej } = pend.get(m.id);
      pend.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    }
  };

  await new Promise((r) => { ws.onopen = r; });
  await send("Page.enable");
  await send("Runtime.enable");
  if (process.env.CDP_NO_NAV !== "1") {
    await send("Page.navigate", { url: URL_ });
    await new Promise((r) => setTimeout(r, WAIT));
  }

  const out = await send("Runtime.evaluate", {
    expression: EXPR,
    awaitPromise: true,
    returnByValue: true,
  });
  if (out.exceptionDetails) {
    console.error("EXCEPCIÓN en la página:", JSON.stringify(out.exceptionDetails.exception || out.exceptionDetails, null, 1));
    process.exit(1);
  }
  const v = out.result.value;
  console.log(typeof v === "string" ? v : JSON.stringify(v, null, 1));
  ws.close();
  process.exit(0);
})();
