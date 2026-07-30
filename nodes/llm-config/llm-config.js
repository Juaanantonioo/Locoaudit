"use strict";

/**
 * llm-config.js — Nodo de CONFIGURACIÓN de Node-RED para el chat con LLM local (Ollama).
 *
 * Este nodo no procesa mensajes de flujo: guarda la configuración de conexión al
 * modelo (URL de Ollama y modelo) y registra un único endpoint HTTP
 * '/locoaudit/chat' sobre RED.httpNode (el servidor de Node-RED, NO uno nuevo).
 *
 * El endpoint recibe { finding, question, history } y responde { ok, content }
 * o { ok:false, error }. Sólo conversa con el modelo — NO ejecuta comandos.
 *
 * El endpoint busca el primer nodo llm-config configurado para obtener la conexión.
 * Si no hay ninguno, devuelve un error claro.
 *
 * El timeout NO es configurable desde la UI: es un detalle interno (CHAT_TIMEOUT_MS).
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

module.exports = function (RED) {
  function LlmConfigNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.name = config.name;
    node.ollamaUrl = (config.ollamaUrl || "http://127.0.0.1:11434").trim();
    node.model = (config.model || "qwen3:8b").trim();
    node.timeoutMs = CHAT_TIMEOUT_MS;

    // Estado de validación del modelo. Lo rellena validateModel() de forma
    // asíncrona; hasta entonces null = "todavía sin comprobar".
    node.modelCheck = null;

    // Mismo principio que commandExists(): no se asume que el modelo esté
    // disponible. Se comprueba al desplegar para fallar aquí con un mensaje
    // claro, en vez de en el primer chat del usuario.
    validateModel(node);

    // Registrar el endpoint HTTP una sola vez por proceso. El guard evita
    // duplicar la ruta en cada redeploy (cada deploy recrea los nodos).
    registerChatEndpoint(RED);
  }

  RED.nodes.registerType("llm-config", LlmConfigNode);

  // Endpoint del EDITOR (botón "Probar conexión" del panel de configuración).
  // Va sobre httpAdmin y pide permiso de lectura de flujos, como cualquier
  // utilidad del editor. Devuelve el mismo diagnóstico que usa el runtime.
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

  // Listado de modelos para el selector del editor. A diferencia de /check, no
  // necesita un modelo: sirve para DESCUBRIR cuáles hay antes de escribir nada.
  // Usa siempre la URL que llega en la query (la que hay en el formulario en ese
  // momento), no la del nodo desplegado: si el usuario cambia el servidor, la
  // lista debe ser la de ese servidor.
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
 * Comprueba contra /api/tags que el modelo configurado existe y refleja el
 * resultado en el log de Node-RED.
 *
 * Los dos fallos posibles se reportan por separado a propósito: "Ollama no
 * responde" y "el modelo no existe" tienen soluciones distintas y confundirlos
 * manda al usuario a depurar lo que no es.
 *
 * @param {object} node  Instancia del nodo llm-config.
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

/**
 * Registra el endpoint POST /locoaudit/chat sobre el servidor HTTP de Node-RED.
 * Idempotente: usa un flag a nivel de RED para no registrar la ruta más de una vez.
 *
 * @param {object} RED  Runtime de Node-RED.
 */
function registerChatEndpoint(RED) {
  if (RED.__locoauditChatEndpoint) {
    return; // ya registrado en este proceso
  }
  RED.__locoauditChatEndpoint = true;

  // Estado: indica al frontend si hay un LLM configurado para mostrar (o no)
  // el botón de chat. La IA es opcional: si no hay nodo, available:false.
  //
  // `available` sigue significando "hay nodo llm-config desplegado" y NO se pone
  // a false cuando el modelo falta: si se ocultara el chat, el usuario no vería
  // ningún mensaje explicando por qué. El diagnóstico viaja aparte.
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
      modelOk: check ? check.ok === true : null, // null = validación aún en curso
      modelError: check && !check.ok ? check.error : null,
    });
  });

  RED.httpNode.post("/locoaudit/chat", async function (req, res) {
    try {
      const body = req.body || {};
      const finding = body.finding || {};
      const question = body.question;
      const history = Array.isArray(body.history) ? body.history : [];
      // Contexto del escaneo: imprescindible para dar soluciones válidas
      // (imagen vs host vs red; y en host, el SO). Lo envía el cliente desde
      // payload.auditType y payload.host.platform.
      const context = { auditType: body.auditType, platform: body.platform };

      if (!question || typeof question !== "string") {
        res.status(400).json({ ok: false, error: "Falta la pregunta (campo 'question')." });
        return;
      }

      // Localizar el primer nodo llm-config configurado.
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

      // Validar el modelo ANTES de chatear. Se revalida en cada turno (es un GET
      // local a /api/tags, milisegundos) en vez de fiarse del resultado del
      // despliegue: si el usuario hace `ollama pull` tras ver el error, el chat
      // debe funcionar sin necesidad de redesplegar el flujo.
      const check = await checkModel({ ollamaUrl: cfg.ollamaUrl, model: cfg.model });
      if (!check.ok) {
        cfg.modelCheck = check;
        res.status(503).json({ ok: false, error: check.error });
        return;
      }
      cfg.modelCheck = check;

      // Distinción PRIMER turno vs SEGUIMIENTO en SERVIDOR, según si el historial
      // recibido está vacío (no se confía en un flag del cliente).
      //   - Primer turno  → plantilla estructurada + contexto completo del finding.
      //   - Seguimientos  → prompt conversacional y directo, sin repetir plantilla
      //     ni reinyectar el finding entero (ya vive en el historial).
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

/**
 * Devuelve el primer nodo llm-config registrado en el runtime, o null si no hay.
 * @param {object} RED
 * @returns {object|null}
 */
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
