"use strict";

/**
 * llm-client.js — Cliente para chatear con un LLM local vía Ollama.
 *
 * Expone:
 *   - chatWithLLM({ ollamaUrl, model, timeoutMs, systemPrompt, messages })
 *       → POST a `${ollamaUrl}/api/chat` con { model, messages, stream:false }.
 *         Devuelve { ok:true, content } o { ok:false, error }. Nunca lanza.
 *   - buildSystemPrompt(finding)
 *       → construye un system prompt en español a partir de un finding.
 *
 * Diseñado para usarse desde el endpoint /locoaudit/chat (ver llm-config.js).
 * NO ejecuta comandos del sistema — solo habla con el modelo.
 */

/**
 * Construye el system prompt en español a partir de un finding de auditoría.
 * El asistente debe explicar el hallazgo a usuarios NO expertos en ciberseguridad.
 *
 * @param {object} finding  Finding con { title, severity, evidence, fix, category }.
 * @returns {string} System prompt listo para enviar al modelo.
 */
function buildSystemPrompt(finding) {
  const f = finding || {};

  const SEV_LABEL = {
    critical: "crítica",
    high: "alta",
    medium: "media",
    low: "baja",
    info: "informativa",
  };

  const title = f.title || "(sin título)";
  const severity = SEV_LABEL[(f.severity || "").toLowerCase()] || f.severity || "desconocida";
  const category = f.category || "general";
  const evidence = formatField(f.evidence) || "(sin evidencia)";
  const fix = formatField(f.fix) || "(sin recomendación específica)";

  return [
    "Eres un asistente de ciberseguridad de LoCoAudit que ayuda a personas SIN conocimientos técnicos",
    "a entender y resolver los hallazgos de una auditoría de seguridad de su equipo.",
    "",
    "Tu objetivo es que el usuario comprenda QUÉ ha pasado, POR QUÉ le importa y CÓMO solucionarlo,",
    "con un tono cercano, claro y didáctico. Evita la jerga innecesaria; si usas un término técnico,",
    "explícalo en pocas palabras. No inventes datos: básate únicamente en la información del hallazgo.",
    "Responde siempre en español.",
    "",
    "Estructura recomendada de tu respuesta:",
    "1. Explicación en lenguaje llano de qué significa el hallazgo.",
    "2. Por qué importa (qué riesgo real supone para el usuario).",
    "3. Cómo resolverlo, paso a paso y de forma concreta.",
    "",
    "Si el usuario hace una pregunta concreta, respóndela directamente sin repetir todo el contexto.",
    "Sé conciso pero completo. No te inventes comandos peligrosos ni animes a ejecutar nada que no entienda.",
    "",
    "=== HALLAZGO DE LA AUDITORÍA ===",
    `Título: ${title}`,
    `Severidad: ${severity}`,
    `Categoría: ${category}`,
    `Evidencia (dato concreto detectado): ${evidence}`,
    `Recomendación de mitigación sugerida por la herramienta: ${fix}`,
    "================================",
  ].join("\n");
}

/**
 * Normaliza un campo del finding (string u objeto) a texto legible.
 * @param {*} value
 * @returns {string}
 */
function formatField(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (e) {
    return String(value);
  }
}

/**
 * Envía una conversación a Ollama y devuelve la respuesta del modelo.
 * Nunca lanza: cualquier error se captura y se devuelve como string legible.
 *
 * @param {object} opts
 * @param {string} opts.ollamaUrl     URL base de Ollama (p.ej. http://127.0.0.1:11434).
 * @param {string} opts.model         Modelo a usar (p.ej. qwen3:8b).
 * @param {number} [opts.timeoutMs]   Timeout en ms (default 120000).
 * @param {string} opts.systemPrompt  System prompt (se inserta como primer mensaje).
 * @param {Array}  [opts.messages]    Mensajes [{ role, content }, ...].
 * @returns {Promise<{ok:true,content:string}|{ok:false,error:string}>}
 */
async function chatWithLLM(opts) {
  const {
    ollamaUrl,
    model,
    timeoutMs = 120000,
    systemPrompt,
    messages = [],
  } = opts || {};

  if (!ollamaUrl) {
    return { ok: false, error: "No se ha configurado la URL de Ollama." };
  }
  if (!model) {
    return { ok: false, error: "No se ha configurado el modelo del LLM." };
  }

  const url = `${String(ollamaUrl).replace(/\/+$/, "")}/api/chat`;

  const fullMessages = [];
  if (systemPrompt) {
    fullMessages.push({ role: "system", content: systemPrompt });
  }
  for (const m of messages) {
    if (m && m.role && typeof m.content === "string") {
      fullMessages.push({ role: m.role, content: m.content });
    }
  }

  const body = JSON.stringify({
    model,
    messages: fullMessages,
    stream: false,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: controller.signal,
    });

    if (!res.ok) {
      let detail = "";
      try {
        detail = await res.text();
      } catch (e) {
        /* ignorar */
      }
      return {
        ok: false,
        error: `Ollama respondió con error HTTP ${res.status} ${res.statusText}.${
          detail ? " Detalle: " + truncate(detail, 500) : ""
        }`,
      };
    }

    let data;
    try {
      data = await res.json();
    } catch (e) {
      return { ok: false, error: "No se pudo interpretar la respuesta de Ollama (JSON inválido)." };
    }

    const content =
      (data && data.message && data.message.content) ||
      (data && data.response) ||
      "";

    if (!content) {
      return { ok: false, error: "Ollama devolvió una respuesta vacía." };
    }

    return { ok: true, content: String(content).trim() };
  } catch (err) {
    if (err && err.name === "AbortError") {
      return {
        ok: false,
        error: `La consulta al modelo superó el tiempo límite (${timeoutMs} ms). ` +
          "Prueba con un modelo más ligero o aumenta el timeout.",
      };
    }
    // Errores típicos de conexión (Ollama apagado, URL incorrecta, etc.)
    const msg = (err && err.message) || String(err);
    if (/ECONNREFUSED|fetch failed|ENOTFOUND|EAI_AGAIN/i.test(msg)) {
      return {
        ok: false,
        error: `No se pudo conectar con Ollama en ${ollamaUrl}. ` +
          "Comprueba que Ollama está en ejecución y que la URL es correcta. " +
          `(detalle: ${msg})`,
      };
    }
    return { ok: false, error: `Error inesperado al consultar el modelo: ${msg}` };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Recorta un texto a una longitud máxima añadiendo elipsis.
 * @param {string} str
 * @param {number} max
 * @returns {string}
 */
function truncate(str, max) {
  const s = String(str);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

module.exports = { chatWithLLM, buildSystemPrompt };
