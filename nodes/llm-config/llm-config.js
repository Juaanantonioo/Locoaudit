"use strict";

/** Nodo de configuración de Ollama. Registra /locoaudit/chat en el servidor de Node-RED; el chat solo conversa, nunca ejecuta comandos. */

const {
  conversarConLlm,
  comprobarModelo,
  modeloRazona,
  listarModelosOllama,
  promptDeSistema,
  promptDeSeguimiento,
} = require("../../lib/llm-client");

/** Timeout de una consulta al modelo, por debajo de los 300 s de headersTimeout del fetch de Node. */
const CHAT_TIMEOUT_MS = 270000;

/** Topes del turno del chat: la ruta va sobre httpNode, que adminAuth no protege. */
const MAX_HISTORY = 40;
const MAX_QUESTION_CHARS = 8000;
const MAX_HISTORY_CHARS = 200000;

module.exports = function (RED) {
  function NodoConfigLlm(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.name = config.name;
    node.ollamaUrl = (config.ollamaUrl || "http://127.0.0.1:11434").trim();
    node.model = (config.model || "qwen3:8b").trim();
    node.timeoutMs = CHAT_TIMEOUT_MS;

    // null mientras validarModelo() no haya terminado: sin comprobar, no "sin modelo".
    node.modelCheck = null;

    // Modelo → "razona" / "no-razona", para no preguntar a /api/show en cada turno.
    node.razonaPorModelo = {};

    // Como existeComando(): el modelo se comprueba al desplegar, no en el primer chat.
    validarModelo(node);

    // Una sola vez por proceso: cada deploy recrea los nodos y duplicaría la ruta.
    registrarChat(RED);
  }

  RED.nodes.registerType("llm-config", NodoConfigLlm);

  // Botón "Probar conexión" del editor, con permiso de lectura de flujos.
  RED.httpAdmin.get(
    "/locoaudit/llm/check",
    RED.auth.needsPermission("flows.read"),
    async function (req, res) {
      const result = await comprobarModelo({
        ollamaUrl: (req.query.url || "").trim(),
        model: (req.query.model || "").trim(),
      });
      res.json(result);
    }
  );

  // Selector de modelos del editor: usa la URL del formulario, no la del nodo desplegado.
  RED.httpAdmin.get(
    "/locoaudit/llm/models",
    RED.auth.needsPermission("flows.read"),
    async function (req, res) {
      const result = await listarModelosOllama({ ollamaUrl: (req.query.url || "").trim() });
      res.json(result);
    }
  );
};

/** Valida el modelo al desplegar. "Ollama no responde" y "el modelo no está" se avisan por separado. */
async function validarModelo(node) {
  const result = await comprobarModelo({ ollamaUrl: node.ollamaUrl, model: node.model });
  node.modelCheck = result;

  if (result.ok) {
    node.log(`[llm-config] Modelo "${node.model}" disponible en ${node.ollamaUrl}.`);
    await consultarRazona(node);
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

/** Lo que se sabe de si el modelo razona. Solo se cachea una respuesta clara; "desconocido" se reintenta. */
async function consultarRazona(cfg) {
  const guardado = cfg.razonaPorModelo[cfg.model];
  if (guardado) {
    return guardado;
  }
  const estado = await modeloRazona({ ollamaUrl: cfg.ollamaUrl, model: cfg.model });
  if (estado !== "desconocido") {
    cfg.razonaPorModelo[cfg.model] = estado;
  }
  return estado;
}

/** Valor para el log de tiempos: "?" si Ollama no lo dio. */
function valorLog(valor, unidad) {
  if (valor === null || valor === undefined) {
    return "?";
  }
  return `${valor}${unidad}`;
}

/** Idempotente por un flag en RED: la ruta no se puede registrar dos veces. */
function registrarChat(RED) {
  if (RED.__locoauditChatEndpoint) {
    return;
  }
  RED.__locoauditChatEndpoint = true;

  // El frontend decide aquí si muestra el chat. `available` no depende del modelo: el fallo va aparte.
  RED.httpNode.get("/locoaudit/chat/status", function (req, res) {
    const cfg = buscarConfigLlm(RED, req.query && req.query.llmConfigId);
    if (!cfg) {
      res.json({ available: false });
      return;
    }
    const check = cfg.modelCheck;
    let estadoModelo;
    if (check) {
      estadoModelo = check.ok === true;
    } else {
      estadoModelo = null;
    }
    let errorModelo;
    if (check && !check.ok) {
      errorModelo = check.error;
    } else {
      errorModelo = null;
    }
    res.json({
      available: true,
      model: cfg.model,
      modelOk: estadoModelo, // null mientras la validación sigue en curso
      modelError: errorModelo,
    });
  });

  RED.httpNode.post("/locoaudit/chat", async function (req, res) {
    try {
      const body = req.body || {};
      const finding = body.finding || {};
      const question = body.question;
      let history;
      if (Array.isArray(body.history)) {
        history = body.history;
      } else {
        history = [];
      }
      // Tipo de auditoría y plataforma, para que el modelo no proponga soluciones que no valen.
      const context = { auditType: body.auditType, platform: body.platform };

      if (!question || typeof question !== "string") {
        res.status(400).json({ ok: false, error: "Falta la pregunta (campo 'question')." });
        return;
      }
      const historyChars = history.reduce(
        (n, m) => {
          let longitud;
          if (m && typeof m.content === "string") {
            longitud = m.content.length;
          } else {
            longitud = 0;
          }
          return n + longitud;
        }, 0);
      if (question.length > MAX_QUESTION_CHARS || history.length > MAX_HISTORY || historyChars > MAX_HISTORY_CHARS) {
        res.status(413).json({
          ok: false,
          error: "La conversación es demasiado larga para el asistente. Cierra el chat y empieza uno nuevo.",
        });
        return;
      }

      const cfg = buscarConfigLlm(RED, body.llmConfigId);
      if (!cfg) {
        res.status(503).json({
          ok: false,
          error:
            "No hay ningún nodo de configuración 'llm-config' desplegado. " +
            "Añade y configura un nodo llm-config en tu flujo para activar el chat.",
        });
        return;
      }

      // Se revalida en cada turno: tras un `ollama pull` el chat funciona sin redesplegar.
      const check = await comprobarModelo({ ollamaUrl: cfg.ollamaUrl, model: cfg.model });
      if (!check.ok) {
        cfg.modelCheck = check;
        res.status(503).json({ ok: false, error: check.error });
        return;
      }
      cfg.modelCheck = check;

      // Primer turno mientras el modelo no haya respondido: un intento fallido no cuenta,
      // porque el hallazgo solo viaja en las instrucciones del primer turno.
      const isFirstTurn = !history.some((m) => m && m.role === "assistant");
      let systemPrompt;
      if (isFirstTurn) {
        systemPrompt = promptDeSistema(finding, context);
      } else {
        systemPrompt = promptDeSeguimiento(finding, context);
      }
      const messages = [...history, { role: "user", content: question }];

      let turno;
      if (isFirstTurn) {
        turno = "1-apertura";
      } else {
        turno = "seguimiento";
      }
      cfg.log(
        `[locoaudit/chat] turno=${turno} ` +
          `history=${history.length} auditType=${context.auditType || "(derivado)"} ` +
          `platform=${context.platform || "?"} · system(1ª línea)="${systemPrompt.split("\n")[0]}"`
      );

      const razona = await consultarRazona(cfg);

      const inicio = Date.now();
      const result = await conversarConLlm({
        ollamaUrl: cfg.ollamaUrl,
        model: cfg.model,
        timeoutMs: cfg.timeoutMs,
        systemPrompt,
        messages,
        razona: razona === "razona",
      });
      const segundos = Math.round((Date.now() - inicio) / 100) / 10;

      if (result.ok) {
        const t = result.tiempos || {};
        cfg.log(
          `[locoaudit/chat] turno=${turno} total=${segundos}s carga=${valorLog(t.carga_s, "s")} ` +
            `prompt=${valorLog(t.prompt_tok, " tok")}/${valorLog(t.prompt_s, "s")} ` +
            `gen=${valorLog(t.gen_tok, " tok")}/${valorLog(t.gen_s, "s")} razona=${razona}`
        );
      } else {
        cfg.warn(`[locoaudit/chat] turno=${turno} falló tras ${segundos}s: ${result.error}`);
      }

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
 * El llm-config elegido en el nodo de auditoría (id que trae el payload), o el primero del runtime.
 * El id llega sin autenticar: solo se acepta si es un llm-config desplegado; si no, se usa el primero.
 */
function buscarConfigLlm(RED, idElegido) {
  if (typeof idElegido === "string" && idElegido) {
    const elegido = RED.nodes.getNode(idElegido);
    if (elegido && elegido.type === "llm-config") return elegido;
  }
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
