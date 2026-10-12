"use strict";

/**
 * Nodo de configuración: guarda la conexión con Ollama y registra /locoaudit/chat sobre el
 * servidor que ya tiene Node-RED, sin levantar otro. El endpoint solo conversa con el modelo,
 * nunca ejecuta comandos, y toma la conexión del primer llm-config desplegado.
 */

const {
  chatWithLLM,
  checkModel,
  listOllamaModels,
  buildSystemPrompt,
  buildFollowupSystemPrompt,
} = require("../../lib/llm-client");

/** Timeout de una consulta al modelo. Interno: no se expone en la UI del nodo. */
const CHAT_TIMEOUT_MS = 120000;

/** Topes del turno del chat: la ruta va sobre httpNode, que adminAuth no protege. */
const MAX_HISTORY = 40;
const MAX_QUESTION_CHARS = 8000;
const MAX_HISTORY_CHARS = 200000;

module.exports = function (RED) {
  function LlmConfigNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.name = config.name;
    node.ollamaUrl = (config.ollamaUrl || "http://127.0.0.1:11434").trim();
    node.model = (config.model || "qwen3:8b").trim();
    node.timeoutMs = CHAT_TIMEOUT_MS;

    // null mientras validateModel() no haya terminado: sin comprobar, no "sin modelo".
    node.modelCheck = null;

    // Mismo principio que commandExists(): el modelo no se da por disponible. Comprobarlo al
    // desplegar falla aquí, con un mensaje claro, y no en el primer chat del usuario.
    validateModel(node);

    // Una sola vez por proceso: cada deploy recrea los nodos y duplicaría la ruta.
    registerChatEndpoint(RED);
  }

  RED.nodes.registerType("llm-config", LlmConfigNode);

  // El botón "Probar conexión" del panel. Va sobre httpAdmin y pide permiso de lectura de flujos,
  // como cualquier utilidad del editor, y devuelve el mismo diagnóstico que usa el runtime.
  RED.httpAdmin.get(
    "/locoaudit/llm/check",
    RED.auth.needsPermission("flows.read"),
    async function (req, res) {
      const result = await checkModel({
        ollamaUrl: (req.query.url || "").trim(),
        model: (req.query.model || "").trim(),
      });
      res.json(result);
    }
  );

  // El selector del editor. Al contrario que /check no necesita modelo: sirve para descubrir
  // cuáles hay. Usa la URL de la query, la que está en el formulario en ese momento y no la del
  // nodo desplegado: si el usuario cambia de servidor, la lista tiene que ser la de ese.
  RED.httpAdmin.get(
    "/locoaudit/llm/models",
    RED.auth.needsPermission("flows.read"),
    async function (req, res) {
      const result = await listOllamaModels({ ollamaUrl: (req.query.url || "").trim() });
      res.json(result);
    }
  );
};

/**
 * Contra /api/tags, con el resultado al log de Node-RED. Los dos fallos van por separado a
 * propósito: "Ollama no responde" y "el modelo no está" se arreglan de forma distinta, y
 * confundirlos manda al usuario a depurar lo que no es.
 */
async function validateModel(node) {
  const result = await checkModel({ ollamaUrl: node.ollamaUrl, model: node.model });
  node.modelCheck = result;

  if (result.ok) {
    node.log(`[llm-config] Modelo "${node.model}" disponible en ${node.ollamaUrl}.`);
    return;
  }

  if (result.kind === "unreachable") {
    node.error(`[llm-config] Ollama no está accesible: ${result.error}`);
  } else if (result.kind === "missing") {
    node.error(`[llm-config] Modelo no instalado: ${result.error}`);
  } else {
    node.error(`[llm-config] No se pudo validar el modelo: ${result.error}`);
  }
}

/** Idempotente por un flag en RED: la ruta no se puede registrar dos veces. */
function registerChatEndpoint(RED) {
  if (RED.__locoauditChatEndpoint) {
    return;
  }
  RED.__locoauditChatEndpoint = true;

  // Con esto el frontend decide si enseña el botón de chat, que la IA es opcional. `available`
  // significa "hay un llm-config desplegado" y no se pone a false porque falte el modelo: al
  // ocultar el chat, el usuario se quedaría sin saber por qué. El diagnóstico viaja aparte.
  RED.httpNode.get("/locoaudit/chat/status", function (req, res) {
    const cfg = findLlmConfig(RED);
    if (!cfg) {
      res.json({ available: false });
      return;
    }
    const check = cfg.modelCheck;
    res.json({
      available: true,
      model: cfg.model,
      modelOk: check ? check.ok === true : null, // null mientras la validación sigue en curso
      modelError: check && !check.ok ? check.error : null,
    });
  });

  RED.httpNode.post("/locoaudit/chat", async function (req, res) {
    try {
      const body = req.body || {};
      const finding = body.finding || {};
      const question = body.question;
      const history = Array.isArray(body.history) ? body.history : [];
      // Sin saber si es imagen, host o red, y en host de qué SO, el modelo da soluciones que no
      // valen. Lo manda el cliente desde payload.auditType y payload.host.platform.
      const context = { auditType: body.auditType, platform: body.platform };

      if (!question || typeof question !== "string") {
        res.status(400).json({ ok: false, error: "Falta la pregunta (campo 'question')." });
        return;
      }
      const historyChars = history.reduce(
        (n, m) => n + (m && typeof m.content === "string" ? m.content.length : 0), 0);
      if (question.length > MAX_QUESTION_CHARS || history.length > MAX_HISTORY || historyChars > MAX_HISTORY_CHARS) {
        res.status(413).json({
          ok: false,
          error: "La conversación es demasiado larga para el asistente. Cierra el chat y empieza uno nuevo.",
        });
        return;
      }

      const cfg = findLlmConfig(RED);
      if (!cfg) {
        res.status(503).json({
          ok: false,
          error:
            "No hay ningún nodo de configuración 'llm-config' desplegado. " +
            "Añade y configura un nodo llm-config en tu flujo para activar el chat.",
        });
        return;
      }

      // Se revalida en cada turno, que es un GET local de milisegundos, en vez de fiarse del
      // despliegue: tras un `ollama pull` el chat debe funcionar sin redesplegar el flujo.
      const check = await checkModel({ ollamaUrl: cfg.ollamaUrl, model: cfg.model });
      if (!check.ok) {
        cfg.modelCheck = check;
        res.status(503).json({ ok: false, error: check.error });
        return;
      }
      cfg.modelCheck = check;

      // Primer turno o seguimiento lo decide el servidor por el historial recibido, no un flag
      // del cliente. El primero lleva plantilla y el finding entero; los siguientes, un prompt
      // conversacional sin repetir nada de eso, que ya está en el historial.
      const isFirstTurn = history.length === 0;
      const systemPrompt = isFirstTurn
        ? buildSystemPrompt(finding, context)
        : buildFollowupSystemPrompt(finding, context);
      const messages = [...history, { role: "user", content: question }];

      console.log(
        `[locoaudit/chat] turno=${isFirstTurn ? "1-apertura" : "seguimiento"} ` +
          `history=${history.length} auditType=${context.auditType || "(derivado)"} ` +
          `platform=${context.platform || "?"} · system(1ª línea)="${systemPrompt.split("\n")[0]}"`
      );

      const result = await chatWithLLM({
        ollamaUrl: cfg.ollamaUrl,
        model: cfg.model,
        timeoutMs: cfg.timeoutMs,
        systemPrompt,
        messages,
      });

      res.json(result);
    } catch (err) {
      res.status(500).json({
        ok: false,
        error: "Error interno al procesar la consulta: " + ((err && err.message) || String(err)),
      });
    }
  });
}

/** El primer llm-config del runtime, o null. */
function findLlmConfig(RED) {
  let found = null;
  RED.nodes.eachNode(function (n) {
    if (found) return;
    if (n.type === "llm-config") {
      const instance = RED.nodes.getNode(n.id);
      if (instance) found = instance;
    }
  });
  return found;
}
