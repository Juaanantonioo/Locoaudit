"use strict";

/**
 * Qué scripts NSE están instalados y, tras el escaneo, qué le pasó a cada uno en cada puerto.
 *
 * Hay que preguntar antes: un nombre inexistente en `--script` no degrada el escaneo, lo aborta
 * (nmap 7.99: "failed to initialize the script engine … QUITTING!", exit=1, <hosts up="0">). Una instalación sin
 * `vulners` daría "la red entera sin auditar". Si aun así se colara, parseNmapFatalError() lo recoge como NET-SCAN-WARN.
 */

const { execCommand }                        = require("../../../lib/executor");
const { NSE_SCRIPT_IDS, appliesTo, sourceKind } = require("./nse-catalog");
const { findScript }                         = require("./nmap-xml");

const HELP_TIMEOUT_MS = 15000;

/**
 * Los nombres que `nmap --script-help` reconoció. El ancla es la línea `Categories:` y no el nombre, porque la descripción
 * de un script puede citar a otro (ssl-cert cita ssl-enum-ciphers) y se daría por instalado algo solo mencionado.
 */
function parseScriptHelp(stdout) {
  const lines = String(stdout || "").split(/\r?\n/);
  const found = new Set();
  for (let i = 1; i < lines.length; i++) {
    if (!/^Categories:/.test(lines[i].trim())) continue;
    const name = lines[i - 1].trim();
    if (/^[\w][\w.-]*$/.test(name)) found.add(name);
  }
  return found;
}

/** El nombre que nmap señala en 'X' did not match a category, filename, or directory. */
function parseRejectedName(text) {
  const m = String(text || "").match(/'([^']+)' did not match a category, filename, or directory/);
  return m ? m[1] : null;
}

/**
 * Qué scripts de la lista están instalados, con UNA llamada. `--script-help` aborta en el primer nombre que no reconoce,
 * así que solo ese caso cuesta un reintento con el resto (una llamada por script AUSENTE).
 * Devuelve { checked, available:Set, missing:[], reason }. `checked:false` es comprobación no realizada, no "no hay scripts".
 */
async function scriptExists(nmapPath, ids = NSE_SCRIPT_IDS, timeoutMs = HELP_TIMEOUT_MS) {
  const available = new Set();
  const missing   = [];
  let   pending   = ids.slice();

  // Cota dura: cada vuelta descarta un nombre, así que no puede haber más vueltas que nombres.
  for (let vuelta = 0; vuelta <= ids.length && pending.length; vuelta++) {
    let stdout = "";
    let stderr = "";
    try {
      // execCommand resuelve con el stdout en crudo (una cadena) y solo trae stderr cuando falla.
      stdout = (await execCommand(`"${nmapPath}" --script-help ${pending.join(",")}`, timeoutMs)) || "";
    } catch (err) {
      stdout = (err && err.stdout) || "";
      stderr = (err && err.stderr) || String((err && err.message) || err);
    }

    // Lo que sí reconoció antes de abortar cuenta: nmap los imprime en orden.
    for (const n of parseScriptHelp(stdout)) if (pending.includes(n)) available.add(n);

    const rejected = parseRejectedName(stderr) || parseRejectedName(stdout);
    if (!rejected) {
      // Sin nombre rechazado: o salió todo bien, o falló por algo que no es un script ausente.
      const sinRespuesta = pending.filter((n) => !available.has(n));
      if (sinRespuesta.length && !parseScriptHelp(stdout).size) {
        return {
          checked: false,
          available,
          missing,
          reason: `nmap --script-help no devolvió una lista interpretable: ${
            (stderr || "sin stderr").trim().split(/\r?\n/)[0]}`,
        };
      }
      // Un nombre que nmap ni listó ni rechazó no se da por instalado.
      for (const n of sinRespuesta) missing.push(n);
      pending = [];
      break;
    }

    missing.push(rejected);
    pending = pending.filter((n) => n !== rejected && !available.has(n));
  }

  return { checked: true, available, missing, reason: null };
}

/**
 * Qué le pasó a cada script en un puerto, después del escaneo:
 *   found           salió en el XML de este puerto. Hay dato.
 *   not-applicable  no le tocaba (puerto no TLS, servicio sin versión…). Es alcance, no hueco, y lleva su motivo.
 *   not-run         le tocaba, o no se sabe, y no hay dato. Esto sí es un hueco.
 * No existe un estado "salió y estaba limpio": un script callado puede ser un handshake que no se completó, y leerlo
 * como limpio es el falso verde que el proyecto prohíbe. Para vulners se apoya en el canario.
 */
function scriptStates(p, availability) {
  const scripts = (p && p.nse) || [];
  const avail   = availability || { checked: false, available: new Set(), missing: [] };
  const states  = {};

  for (const id of NSE_SCRIPT_IDS) {
    if (findScript(scripts, id)) {
      states[id] = { state: "found", kind: null, reason: null };
      continue;
    }

    if (!avail.checked) {
      states[id] = {
        state: "not-run",
        kind: "nse-unavailable",
        reason: avail.reason || "No se pudo comprobar qué scripts NSE están instalados.",
      };
      continue;
    }

    if ((avail.missing || []).includes(id)) {
      states[id] = {
        state: "not-run",
        kind: "script-missing",
        reason: `El script '${id}' no está instalado en este nmap, así que se quitó del comando.`,
      };
      continue;
    }

    const { applies, reason } = appliesTo(id, p);
    if (!applies) {
      states[id] = { state: "not-applicable", kind: "not-applicable", reason };
      continue;
    }

    // Le tocaba y no salió. La causa depende de con quién hablaba el script.
    states[id] = {
      state: "not-run",
      kind: "no-output",
      reason: sourceKind(id) === "remote-api"
        ? `El script '${id}' no devolvió datos para este puerto; puede ser que la fuente ` +
          "externa no respondiera."
        : `El script '${id}' no devolvió datos para este puerto: el servicio no completó el ` +
          "diálogo que el script necesita, o nuestra estimación de que aplicaba era incorrecta.",
    };
  }

  return states;
}

module.exports = {
  scriptExists,
  scriptStates,
  parseScriptHelp,
  parseRejectedName,
  HELP_TIMEOUT_MS,
};
