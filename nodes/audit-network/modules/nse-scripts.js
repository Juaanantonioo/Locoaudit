"use strict";

/**
 * Qué scripts NSE están instalados y, después del escaneo, qué le pasó a cada uno en cada puerto.
 *
 * POR QUÉ HAY QUE PREGUNTAR ANTES. Un nombre que no exista no degrada el escaneo: lo ABORTA.
 * Comprobado con nmap 7.99:
 *   nmap --script vulners,noexiste -p 22 127.0.0.1
 *   → NSE: failed to initialize the script engine … 'noexiste' did not match a category,
 *     filename, or directory  /  QUITTING!  /  exit=1, <hosts up="0">
 * O sea: una instalación de nmap sin `vulners` —que no viene en todas las distribuciones— no
 * daría "análisis NSE incompleto", daría "la red entera sin auditar". Podar la lista antes de
 * construir el comando no es una optimización, es lo que evita eso.
 *
 * (Y si aun así se colara: ese XML lo recoge parseNmapFatalError() y acaba en NET-SCAN-WARN, o
 * sea "no concluyente". Nunca en un falso verde. Esta poda es el primer cinturón, no el único.)
 */

const { execCommand }                        = require("../../../lib/executor");
const { NSE_SCRIPT_IDS, appliesTo, sourceKind } = require("./nse-catalog");
const { findScript }                         = require("./nmap-xml");

const HELP_TIMEOUT_MS = 15000;

/**
 * Los nombres que `nmap --script-help` reconoció.
 *
 * Formato real de la salida, por script:
 *   ssh2-enum-algos
 *   Categories: safe discovery
 *   https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html
 *   …descripción…
 *
 * El ancla es la línea `Categories:`, no el nombre: la descripción de un script puede contener
 * el nombre de otro (ssl-cert cita ssl-enum-ciphers), y buscar nombres sueltos daría por
 * instalado algo que solo estaba mencionado en un párrafo.
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
 * Qué scripts de la lista están instalados. UNA llamada, no una por script.
 *
 * `--script-help` con la lista completa aborta en el PRIMER nombre que no reconoce y no dice
 * nada de los siguientes, así que ese caso —y solo ese— cuesta un reintento con el resto: una
 * llamada más por script AUSENTE, que en una instalación normal son cero. Sondear uno a uno
 * serían cinco llamadas siempre, incluso cuando no falta ninguno.
 *
 * Devuelve { checked, available:Set, missing:[], reason }.
 * `checked:false` significa que no se pudo averiguar, y eso NO es "no hay scripts": el llamante
 * tiene que tratarlo como comprobación no realizada.
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
 * Qué le pasó a cada script en un puerto concreto, después del escaneo.
 *
 * Tres estados, y la diferencia entre ellos es la razón de ser del módulo:
 *
 *   found           el script salió en el XML de este puerto. Hay dato.
 *   not-applicable  no le tocaba (el puerto no es TLS, el servicio no anunció versión…).
 *                   No es un hueco: es el alcance real. Va con su motivo.
 *   not-run         le tocaba —o no sabemos si le tocaba— y no hay dato. ESTO SÍ ES UN HUECO.
 *
 * Lo que no existe a propósito es un cuarto estado "salió y estaba limpio". Un script que no
 * emite nada no está diciendo "todo bien": ssl-enum-ciphers callado puede ser un handshake que
 * no se completó, y leerlo como limpio es exactamente el falso verde que el proyecto prohíbe.
 * Quien afirme "limpio" tiene que apoyarse en otra cosa —para vulners, el canario—, no en el
 * silencio.
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
