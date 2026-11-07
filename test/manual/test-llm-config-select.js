"use strict";

/**
 * test-llm-config-select.js — El chat usa el llm-config elegido en el nodo de auditoría.
 * Carga llm-config.js con un RED falso y sustituye comprobarModelo / conversarConLlm: no se llama a Ollama.
 * Comprueba también que los tres nodos de auditoría ponen llmConfigId en el payload y que los
 * dashboards reinician la conversación de un hallazgo cuando cambia el modelo.
 *
 * Uso:
 *   node test/manual/test-llm-config-select.js
 */

const fs = require("fs");
const path = require("path");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "..", "..");

// ── Sustitución de lib/llm-client ────────────────────────────────────────────
// Antes de cargar llm-config.js: desestructura las funciones al hacer require.
const CLIENT_PATH = require.resolve("../../lib/llm-client");
const clientReal = require(CLIENT_PATH);
const llamadas = { check: [], chat: [] };
require.cache[CLIENT_PATH].exports = Object.assign({}, clientReal, {
  comprobarModelo: async (opts) => { llamadas.check.push(opts); return { ok: true }; },
  conversarConLlm: async (opts) => { llamadas.chat.push(opts); return { ok: true, content: "respuesta de " + opts.model }; },
  // Sin red: el test no debe llamar a /api/show de un Ollama real.
  modeloRazona: async () => "desconocido",
});

// ── RED falso: lo que usa llm-config.js ──────────────────────────────────────
function crearRed() {
  const instancias = new Map();     // id → nodo
  const rutas = { get: {}, post: {} };
  const RED = {
    nodes: {
      createNode(node, config) {
        // Como el runtime real: id y type salen de la config.
        node.id = config.id;
        node.type = config.type;
        node.log = () => {};
        node.warn = () => {};
        node.error = () => {};
        instancias.set(config.id, node);
      },
      registerType(name, Ctor) { RED._tipos[name] = Ctor; },
      getNode: (id) => instancias.get(id) || null,
      eachNode(fn) { for (const n of instancias.values()) fn({ id: n.id, type: n.type }); },
    },
    _tipos: {},
    auth: { needsPermission: () => (req, res, next) => next() },
    httpAdmin: { get: () => {} },
    httpNode: {
      get: (ruta, h) => { rutas.get[ruta] = h; },
      post: (ruta, h) => { rutas.post[ruta] = h; },
    },
  };
  const llmPath = require.resolve("../../nodes/llm-config/llm-config");
  delete require.cache[llmPath];
  require(llmPath)(RED);
  return { RED, rutas, instancias };
}

/** Despliega un llm-config, o un nodo cualquiera de otro tipo con el mismo id. */
function desplegar(RED, instancias, id, model, type) {
  if (type && type !== "llm-config") {
    instancias.set(id, { id, type, model });
    return;
  }
  const n = {};
  RED._tipos["llm-config"].call(n, { id, type: "llm-config", model, ollamaUrl: "http://127.0.0.1:11434" });
}

/** Llama a un handler con un req mínimo y devuelve { status, body }. */
async function llamar(handler, req) {
  let status = 200;
  let body;
  const res = {
    status(c) { status = c; return res; },
    json(b) { body = b; return res; },
  };
  await handler(req, res);
  return { status, body };
}

async function esperar() {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
}

(async () => {
  console.log("\n── 1 · /locoaudit/chat/status y POST /locoaudit/chat ──────────────\n");

  const { RED, rutas, instancias } = crearRed();
  // Las rutas se registran con el primer llm-config; luego se retira, como en un redeploy que lo borra.
  desplegar(RED, instancias, "cfg-retirado", "x:1b");
  await esperar();
  instancias.delete("cfg-retirado");
  const status = rutas.get["/locoaudit/chat/status"];
  const chat = rutas.post["/locoaudit/chat"];
  ok(typeof status === "function" && typeof chat === "function", "las dos rutas quedan registradas");

  // Sin ningún llm-config desplegado.
  let r = await llamar(status, { query: {} });
  ok(r.body && r.body.available === false, "sin llm-config → available false", JSON.stringify(r.body));
  r = await llamar(chat, { body: { question: "hola", finding: {} } });
  ok(r.status === 503 && r.body && r.body.ok === false, "sin llm-config → POST da 503", JSON.stringify(r));

  // Viejo primero (con el modelo que se borró), nuevo después.
  desplegar(RED, instancias, "cfg-viejo", "viejo:1b");
  desplegar(RED, instancias, "cfg-nuevo", "nuevo:8b");
  desplegar(RED, instancias, "otro-nodo", "trampa:1b", "audit-host");
  await esperar();   // validarModelo() del constructor

  r = await llamar(status, { query: { llmConfigId: "cfg-nuevo" } });
  ok(r.body.available === true && r.body.model === "nuevo:8b", "status con id del nuevo → modelo nuevo", JSON.stringify(r.body));
  r = await llamar(status, { query: {} });
  ok(r.body.model === "viejo:1b", "status sin id → el primero (fallback)", JSON.stringify(r.body));
  r = await llamar(status, {});
  ok(r.body.model === "viejo:1b", "status sin query → el primero", JSON.stringify(r.body));
  r = await llamar(status, { query: { llmConfigId: "no-existe" } });
  ok(r.body.model === "viejo:1b", "status con id inexistente → el primero", JSON.stringify(r.body));
  r = await llamar(status, { query: { llmConfigId: "otro-nodo" } });
  ok(r.body.model === "viejo:1b", "status con id de un nodo que no es llm-config → el primero", JSON.stringify(r.body));
  r = await llamar(status, { query: { llmConfigId: ["cfg-nuevo"] } });
  ok(r.body.model === "viejo:1b", "status con id que no es cadena → el primero", JSON.stringify(r.body));

  /** POST con un body y devuelve el modelo con el que se comprobó y se conversó. */
  async function chatCon(extra) {
    llamadas.check.length = 0;
    llamadas.chat.length = 0;
    const res = await llamar(chat, { body: Object.assign({ question: "hola", finding: { id: "X" }, history: [] }, extra) });
    return {
      res,
      check: llamadas.check[0] && llamadas.check[0].model,
      chat: llamadas.chat[0] && llamadas.chat[0].model,
    };
  }

  let c = await chatCon({ llmConfigId: "cfg-nuevo" });
  ok(c.res.status === 200 && c.check === "nuevo:8b" && c.chat === "nuevo:8b",
     "POST con id del nuevo → comprueba y conversa con el nuevo", JSON.stringify(c));
  c = await chatCon({});
  ok(c.chat === "viejo:1b", "POST sin id → el primero", JSON.stringify(c));
  c = await chatCon({ llmConfigId: null });
  ok(c.chat === "viejo:1b", "POST con id null → el primero", JSON.stringify(c));
  c = await chatCon({ llmConfigId: "no-existe" });
  ok(c.chat === "viejo:1b", "POST con id inexistente → el primero", JSON.stringify(c));
  c = await chatCon({ llmConfigId: "otro-nodo" });
  ok(c.chat === "viejo:1b", "POST con id de un nodo que no es llm-config → el primero", JSON.stringify(c));
  c = await chatCon({ llmConfigId: { $ne: 1 } });
  ok(c.chat === "viejo:1b", "POST con id objeto → el primero", JSON.stringify(c));

  console.log("\n── 2 · Los nodos de auditoría mandan llmConfigId en el payload ────\n");

  /** Carga un nodo de auditoría con un RED falso; getNode solo conoce "cfg-nuevo". */
  function cargarAuditoria(rel) {
    const p = require.resolve(rel);
    delete require.cache[p];
    let Ctor = null;
    require(p)({
      nodes: {
        createNode(node) {
          node.on = (evt, fn) => { node._handler = fn; };
          node.status = () => {};
          node.warn = () => {};
          node.log = () => {};
          node.error = () => {};
        },
        getNode: (id) => (id === "cfg-nuevo" ? { id: "cfg-nuevo", type: "llm-config" } : null),
        registerType: (_n, fn) => { Ctor = fn; },
      },
      util: { evaluateNodeProperty: (v) => v },
    });
    return Ctor;
  }

  async function ejecutar(rel, config) {
    const Ctor = cargarAuditoria(rel);
    const node = {};
    Ctor.call(node, config);
    let enviado = null;
    let err = null;
    await new Promise((resolve) => {
      node._handler({}, (m) => { enviado = m; }, (e) => { err = e || null; resolve(); });
    });
    return { msg: enviado, err };
  }

  const CASOS = [
    // Todo apagado: el nodo emite sin lanzar herramientas.
    ["audit-host", "../../nodes/audit-host/audit-host", {
      enableCpu: false, enableDisk: false, enableSw: false, enableLynis: false,
      enableTrivy: false, securityEvents: false, trivySystemPkgs: false, enableSecrets: false,
    }],
    // Objetivo inválido: NET-CFG-ERR sin llegar a nmap.
    ["audit-network", "../../nodes/audit-network/audit-network", { scanTarget: "custom", customTarget: "no-es-una-ip" }],
    // Modo específico sin imagen: IMG-IMAGE-NONE sin llegar a Trivy.
    ["audit-image", "../../nodes/audit-image/audit-image", { scanMode: "specific", imageRef: "" }],
  ];
  for (const [nombre, rel, base] of CASOS) {
    let e = await ejecutar(rel, Object.assign({ llmConfig: "cfg-nuevo" }, base));
    ok(e.msg && e.msg.payload && e.msg.payload.llmConfigId === "cfg-nuevo",
       `[${nombre}] con llm-config elegido → payload.llmConfigId = su id`,
       JSON.stringify({ err: e.err && e.err.message, id: e.msg && e.msg.payload && e.msg.payload.llmConfigId }));
    e = await ejecutar(rel, Object.assign({}, base));
    ok(e.msg && e.msg.payload && e.msg.payload.llmConfigId === null,
       `[${nombre}] sin llm-config elegido → payload.llmConfigId = null`,
       JSON.stringify({ err: e.err && e.err.message }));
    e = await ejecutar(rel, Object.assign({ llmConfig: "borrado" }, base));
    ok(e.msg && e.msg.payload && e.msg.payload.llmConfigId === null,
       `[${nombre}] llm-config elegido que ya no existe → null (el servidor usará el primero)`,
       JSON.stringify({ err: e.err && e.err.message }));
  }

  console.log("\n── 3 · Dashboards: la conversación se reinicia si cambia el modelo ─\n");

  /** Recorta `[async ]nombre() { … }` del template contando llaves. */
  function extraerMetodo(src, name) {
    let start = src.indexOf("\n    " + name + "(");
    if (start < 0) start = src.indexOf("\n    async " + name + "(");
    if (start < 0) throw new Error(`no encuentro ${name}() en el template`);
    const i = src.indexOf("{", src.indexOf(")", start));
    let depth = 0;
    for (let j = i; j < src.length; j++) {
      if (src[j] === "{") depth++;
      else if (src[j] === "}") { depth--; if (depth === 0) return src.slice(start + 1, j + 1); }
    }
    throw new Error(`llaves sin cerrar en ${name}()`);
  }

  for (const tipo of ["host", "network", "image"]) {
    const tpl = fs.readFileSync(path.join(ROOT, "examples", `dashboard-${tipo}-template.html`), "utf8");
    const nombres = ["reiniciarChats", "consultarEstadoLlm", "alternarChat", "enviarChat"];
    const metodos = new Function("fetch", "return {" + nombres.map((n) => extraerMetodo(tpl, n)).join(",") + "};");

    // fetch falso: el modelo que "devuelve" el servidor se cambia desde el test.
    let modeloServidor = "viejo:1b";
    const peticiones = [];
    let retenerChat = false;
    let soltarChat = null;
    async function fetchFalso(url, opts) {
      peticiones.push({ url, body: opts && opts.body ? JSON.parse(opts.body) : null });
      if (url.indexOf("/locoaudit/chat/status") === 0) {
        return { json: async () => ({ available: true, model: modeloServidor, modelOk: true }) };
      }
      const modelo = modeloServidor;
      if (retenerChat) await new Promise((r) => { soltarChat = r; });
      return { json: async () => ({ ok: true, content: "respuesta de " + modelo }) };
    }

    const vm = Object.assign({
      auditData: { auditType: tipo, host: { platform: "linux" }, llmConfigId: "cfg-nuevo" },
      chatOpen: {}, chatMessages: {}, chatInput: {}, chatLoading: {}, chatEpoch: 0, chatModel: {},
      llmAvailable: null, llmModel: null,
    }, metodos(fetchFalso));
    const K = "k1";
    const F = { id: "X", title: "hallazgo" };
    const posts = () => peticiones.filter((p) => p.url === "/locoaudit/chat");

    vm.alternarChat(K, F);
    await esperar();
    ok(peticiones[0] && peticiones[0].url === "/locoaudit/chat/status?llmConfigId=cfg-nuevo",
       `[${tipo}] al abrir consulta status con el id del resultado`, JSON.stringify(peticiones[0]));
    ok(posts().length === 1 && posts()[0].body.llmConfigId === "cfg-nuevo",
       `[${tipo}] la pregunta automática lleva llmConfigId`, JSON.stringify(posts()));
    ok(vm.chatMessages[K].length === 2 && vm.chatModel[K] === "viejo:1b" && vm.llmModel === "viejo:1b",
       `[${tipo}] la conversación guarda el modelo con el que empezó`, JSON.stringify({ m: vm.chatModel, l: vm.llmModel }));

    // Cerrar y abrir con el mismo modelo: se conserva, no se pregunta otra vez.
    vm.alternarChat(K, F);
    vm.alternarChat(K, F);
    await esperar();
    ok(posts().length === 1 && vm.chatMessages[K].length === 2,
       `[${tipo}] mismo modelo → se conserva la conversación`, JSON.stringify(vm.chatMessages[K]));

    // El usuario cambia de modelo: al reabrir, conversación nueva con el modelo actual.
    modeloServidor = "nuevo:8b";
    vm.alternarChat(K, F);
    vm.alternarChat(K, F);
    await esperar();
    const msgs = vm.chatMessages[K];
    ok(posts().length === 2 && msgs.length === 2 && msgs[1].content === "respuesta de nuevo:8b",
       `[${tipo}] modelo distinto → se borra y empieza otra con la pregunta automática`, JSON.stringify(msgs));
    ok(vm.chatModel[K] === "nuevo:8b" && vm.llmModel === "nuevo:8b",
       `[${tipo}] la cabecera y la conversación pasan al modelo actual`, JSON.stringify({ m: vm.chatModel, l: vm.llmModel }));

    // Respuesta en vuelo: cambiar de modelo y reabrir no borra lo que está llegando.
    retenerChat = true;
    vm.chatInput[K] = "otra pregunta";
    const enVuelo = vm.enviarChat(K, F);
    await esperar();
    modeloServidor = "otro:3b";
    vm.alternarChat(K, F);
    vm.alternarChat(K, F);
    await esperar();
    ok(vm.chatMessages[K].length === 3 && posts().length === 3,
       `[${tipo}] con una respuesta en vuelo no se borra ni se repregunta`, JSON.stringify(vm.chatMessages[K]));
    retenerChat = false;
    soltarChat();
    await enVuelo;
    ok(vm.chatMessages[K].length === 4 && vm.chatLoading[K] === false,
       `[${tipo}] la respuesta en vuelo llega a su conversación`, JSON.stringify(vm.chatMessages[K]));

    // Escaneo nuevo mientras se consultaba el estado: no se lanza nada.
    vm.chatOpen = {};
    const antes = posts().length;
    vm.alternarChat("k2", F);
    vm.reiniciarChats();
    await esperar();
    ok(posts().length === antes && !vm.chatMessages.k2 && Object.keys(vm.chatModel).length === 0,
       `[${tipo}] escaneo nuevo durante la consulta (chatEpoch) → no se pregunta`, JSON.stringify(vm.chatMessages));

    // Resultado sin llm-config elegido: status sin query y POST con null.
    vm.auditData = { auditType: tipo, host: { platform: "linux" }, llmConfigId: null };
    peticiones.length = 0;
    vm.alternarChat("k3", F);
    await esperar();
    ok(peticiones[0] && peticiones[0].url === "/locoaudit/chat/status",
       `[${tipo}] sin llmConfigId → status sin query`, JSON.stringify(peticiones[0]));
    ok(posts()[0] && posts()[0].body.llmConfigId === null,
       `[${tipo}] sin llmConfigId → POST con null`, JSON.stringify(posts()[0]));
  }

  console.log(`\n${passed} ok, ${failed} fallo(s)\n`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
