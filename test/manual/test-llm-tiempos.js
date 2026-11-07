"use strict";

/**
 * test-llm-tiempos.js — Cuerpo y tiempos de la consulta a Ollama, consulta a /api/show y prefijo común de los prompts.
 * Sustituye global.fetch por uno falso: no se llama a Ollama.
 *
 * Uso:
 *   node test/manual/test-llm-tiempos.js
 */

const {
  conversarConLlm,
  modeloRazona,
  promptDeSistema,
  promptDeSeguimiento,
} = require("../../lib/llm-client");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

/** Respuesta mínima con la forma de la de fetch. */
function respuesta(data, status) {
  const codigo = status || 200;
  return {
    ok: codigo >= 200 && codigo < 300,
    status: codigo,
    statusText: "",
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

const URL_OLLAMA = "http://ollama.falso:11434";

(async () => {
  console.log("\n── 1 · think:false solo si el modelo razona ──────────────────────\n");

  const enviados = [];
  global.fetch = async (url, opts) => {
    enviados.push({ url, body: JSON.parse(opts.body) });
    return respuesta({ message: { content: "hola" } });
  };
  const base = { ollamaUrl: URL_OLLAMA, model: "m:1b", systemPrompt: "s", messages: [{ role: "user", content: "q" }] };

  await conversarConLlm(Object.assign({ razona: true }, base));
  ok(enviados[0].body.think === false, "razona → body con think:false", JSON.stringify(enviados[0].body));
  await conversarConLlm(Object.assign({ razona: false }, base));
  ok(!("think" in enviados[1].body), "no razona → body sin think", JSON.stringify(enviados[1].body));
  await conversarConLlm(base);
  ok(!("think" in enviados[2].body), "sin opción → body sin think", JSON.stringify(enviados[2].body));
  ok(enviados[0].url === URL_OLLAMA + "/api/chat" && enviados[0].body.stream === false,
     "el resto del body no cambia", JSON.stringify(enviados[0]));

  console.log("\n── 2 · tiempos del turno ─────────────────────────────────────────\n");

  global.fetch = async () => respuesta({
    message: { content: "hola" },
    load_duration: 2345678901,
    prompt_eval_count: 1459,
    prompt_eval_duration: 78049000000,
    eval_count: 532,
    eval_duration: 73260000000,
  });
  let r = await conversarConLlm(base);
  const esperado = { carga_s: 2.3, prompt_tok: 1459, prompt_s: 78, gen_tok: 532, gen_s: 73.3 };
  ok(r.ok && JSON.stringify(r.tiempos) === JSON.stringify(esperado),
     "segundos con un decimal y tokens tal cual", JSON.stringify(r.tiempos));

  global.fetch = async () => respuesta({ message: { content: "hola" }, eval_count: 10, eval_duration: 50000000 });
  r = await conversarConLlm(base);
  const parcial = { carga_s: null, prompt_tok: null, prompt_s: null, gen_tok: 10, gen_s: 0.1 };
  ok(r.ok && JSON.stringify(r.tiempos) === JSON.stringify(parcial),
     "campos ausentes → null", JSON.stringify(r.tiempos));

  global.fetch = async () => respuesta({
    message: { content: "hola" },
    load_duration: 0, prompt_eval_count: 0, prompt_eval_duration: 0, eval_count: 0, eval_duration: 0,
  });
  r = await conversarConLlm(base);
  const ceros = { carga_s: 0, prompt_tok: 0, prompt_s: 0, gen_tok: 0, gen_s: 0 };
  ok(r.ok && JSON.stringify(r.tiempos) === JSON.stringify(ceros), "ceros → 0, no null", JSON.stringify(r.tiempos));

  global.fetch = async () => respuesta({
    message: { content: "hola" },
    load_duration: "123", prompt_eval_count: "10", prompt_eval_duration: null, eval_count: NaN, eval_duration: {},
  });
  r = await conversarConLlm(base);
  const raros = { carga_s: null, prompt_tok: null, prompt_s: null, gen_tok: null, gen_s: null };
  ok(r.ok && JSON.stringify(r.tiempos) === JSON.stringify(raros), "valores no numéricos → null", JSON.stringify(r.tiempos));

  global.fetch = async () => respuesta({ error: "x" }, 500);
  r = await conversarConLlm(base);
  ok(!r.ok && !("tiempos" in r), "con error no hay tiempos", JSON.stringify(r));

  console.log("\n── 3 · mensaje de timeout ────────────────────────────────────────\n");

  // fetch que no contesta nunca y respeta el AbortSignal, como el real.
  global.fetch = (url, opts) => new Promise((resolve, reject) => {
    opts.signal.addEventListener("abort", () => {
      const e = new Error("This operation was aborted");
      e.name = "AbortError";
      reject(e);
    });
  });
  r = await conversarConLlm(Object.assign({ timeoutMs: 30 }, base));
  ok(!r.ok && !/aumenta el timeout/i.test(r.error), "ya no pide aumentar el timeout", r.error);
  ok(/no respondió en 0 s/.test(r.error) && /GPU/.test(r.error), "da el límite en segundos y la causa", r.error);
  // Aborto inmediato: solo se mira el redondeo de 270000 ms.
  global.fetch = (url, opts) => Promise.reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
  r = await conversarConLlm(Object.assign({ timeoutMs: 270000 }, base));
  ok(/no respondió en 270 s/.test(r.error), "270000 ms → 270 s", r.error);

  console.log("\n── 4 · /api/show ─────────────────────────────────────────────────\n");

  let pedida = null;
  global.fetch = async (url, opts) => {
    pedida = { url, body: JSON.parse(opts.body), method: opts.method };
    return respuesta({ capabilities: ["completion", "thinking"] });
  };
  let e = await modeloRazona({ ollamaUrl: URL_OLLAMA + "/", model: "qwen3:8b" });
  ok(e === "razona", "capabilities con thinking → razona", e);
  ok(pedida.url === URL_OLLAMA + "/api/show" && pedida.method === "POST" && pedida.body.model === "qwen3:8b",
     "POST /api/show con {model}", JSON.stringify(pedida));

  global.fetch = async () => respuesta({ capabilities: ["completion", "tools"] });
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "qwen2.5:7b" });
  ok(e === "no-razona", "capabilities sin thinking → no-razona", e);

  global.fetch = async () => respuesta({ modelfile: "..." });
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "x" });
  ok(e === "desconocido", "sin capabilities → desconocido", e);

  global.fetch = async () => ({
    ok: true, status: 200, statusText: "",
    json: async () => { throw new SyntaxError("Unexpected token < in JSON"); },
  });
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "x" });
  ok(e === "desconocido", "JSON inválido → desconocido", e);

  global.fetch = async () => respuesta({ error: "model not found" }, 404);
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "x" });
  ok(e === "desconocido", "HTTP 404 → desconocido", e);

  global.fetch = async () => { throw new TypeError("fetch failed"); };
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "x" });
  ok(e === "desconocido", "fallo de conexión → desconocido", e);

  global.fetch = (url, opts) => new Promise((resolve, reject) => {
    opts.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  });
  e = await modeloRazona({ ollamaUrl: URL_OLLAMA, model: "x", timeoutMs: 20 });
  ok(e === "desconocido", "timeout → desconocido", e);

  console.log("\n── 5 · prefijo común de los dos prompts ──────────────────────────\n");

  /** Longitud del prefijo común de dos cadenas. */
  function prefijoComun(a, b) {
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    return i;
  }

  const CASOS = [
    ["host linux", { id: "HOST-1", title: "SSH", severity: "high" }, { auditType: "host", platform: "linux" }],
    ["network local", { id: "NET-1", title: "Puerto 22", severity: "medium" }, { auditType: "network", platform: "linux" }],
    ["network remoto", { id: "NET-2", title: "Puerto 80", severity: "high", isLocalTarget: false, target: "192.168.1.20" },
      { auditType: "network", platform: "darwin" }],
    ["image", { id: "IMG-1", title: "CVE-2024-0001", severity: "critical" }, { auditType: "image" }],
  ];
  for (const [nombre, f, ctx] of CASOS) {
    const primero = promptDeSistema(f, ctx);
    const seguimiento = promptDeSeguimiento(f, ctx);
    const reglas = primero.slice(0, primero.indexOf("===============================================") + 47);
    const comun = prefijoComun(primero, seguimiento);
    ok(primero.startsWith("=== CONTEXTO DEL ESCANEO") && seguimiento.startsWith("=== CONTEXTO DEL ESCANEO"),
       `[${nombre}] los dos empiezan por el bloque de reglas`);
    ok(comun >= reglas.length && reglas.length > 500,
       `[${nombre}] prefijo común (${comun}) ≥ bloque de reglas (${reglas.length})`);
  }
  const remoto = promptDeSistema(CASOS[2][1], CASOS[2][2]);
  ok(remoto.includes("REMOTO — no es el equipo") && remoto.includes("Dispositivo afectado: 192.168.1.20 (REMOTO)."),
     "[network remoto] el bloque remoto y el hallazgo siguen presentes");
  ok(remoto.indexOf("Eres un asistente") > remoto.indexOf("Reglas de FIABILIDAD") &&
     remoto.indexOf("=== HALLAZGO") > remoto.indexOf("Eres un asistente"),
     "orden: reglas, rol e instrucciones, hallazgo");

  console.log(`\n${passed} ok, ${failed} fallo(s)\n`);
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
