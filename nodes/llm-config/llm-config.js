"use strict";

/**
 * llm-config.js — Nodo de CONFIGURACIÓN de Node-RED para el chat con LLM local (Ollama).
 *
 * Este nodo no procesa mensajes de flujo: guarda la configuración de conexión al
 * modelo (URL de Ollama, modelo, timeout) y registra un único endpoint HTTP
 * '/locoaudit/chat' sobre RED.httpNode (el servidor de Node-RED, NO uno nuevo).
 *
 * El endpoint recibe { finding, question, history } y responde { ok, content }
 * o { ok:false, error }. Sólo conversa con el modelo — NO ejecuta comandos.
 *
 * El endpoint busca el primer nodo llm-config configurado para obtener la conexión.
 * Si no hay ninguno, devuelve un error claro.
 */

const { chatWithLLM, buildSystemPrompt } = require("../../lib/llm-client");

module.exports = function (RED) {
  function LlmConfigNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.name = config.name;
    node.ollamaUrl = (config.ollamaUrl || "http://127.0.0.1:11434").trim();
    node.model = (config.model || "qwen3:8b").trim();
    node.timeoutMs = parseInt(config.timeoutMs, 10) || 120000;

    // Registrar el endpoint HTTP una sola vez por proceso. El guard evita
    // duplicar la ruta en cada redeploy (cada deploy recrea los nodos).
    registerChatEndpoint(RED);
  }

  RED.nodes.registerType("llm-config", LlmConfigNode);
};

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
  RED.httpNode.get("/locoaudit/chat/status", function (req, res) {
    res.json({ available: !!findLlmConfig(RED) });
  });

  RED.httpNode.post("/locoaudit/chat", async function (req, res) {
    try {
      const body = req.body || {};
      const finding = body.finding || {};
      const question = body.question;
      const history = Array.isArray(body.history) ? body.history : [];

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

      const systemPrompt = buildSystemPrompt(finding);
      const messages = [...history, { role: "user", content: question }];

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
