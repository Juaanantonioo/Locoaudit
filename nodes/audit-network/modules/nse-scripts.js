"use strict";

// Qué scripts NSE hay instalados y qué pasó con cada uno en cada puerto.
// Se pregunta antes porque un nombre inexistente en --script aborta el escaneo entero.

const { ejecutar }                        = require("../../../lib/executor");
const { NSE_SCRIPT_IDS, aplicaA, tipoFuente } = require("./nse-catalog");
const { buscarScript }                         = require("./nmap-xml");

const HELP_TIMEOUT_MS = 15000;

// Se ancla en `Categories:` porque la descripción de un script puede citar a otro.
function leerAyudaScript(stdout) {
  const lines = String(stdout || "").split(/\r?\n/);
  const found = new Set();
  for (let i = 1; i < lines.length; i++) {
    if (!/^Categories:/.test(lines[i].trim())) continue;
    const name = lines[i - 1].trim();
    if (/^[\w][\w.-]*$/.test(name)) found.add(name);
  }
  return found;
}

// Nombre que nmap rechaza en "'X' did not match a category, filename, or directory".
function leerNombreRechazado(text) {
  const m = String(text || "").match(/'([^']+)' did not match a category, filename, or directory/);
  if (m) {
    return m[1];
  } else {
    return null;
  }
}

// --script-help aborta en el primer nombre desconocido: se reintenta sin él (una llamada por script ausente).
// checked:false significa que no se pudo comprobar, no que no haya scripts.
async function existeScript(nmapPath, ids = NSE_SCRIPT_IDS, timeoutMs = HELP_TIMEOUT_MS) {
  const available = new Set();
  const missing   = [];
  let   pending   = ids.slice();

  // Cada vuelta descarta un nombre, así que no hay más vueltas que nombres.
  for (let vuelta = 0; vuelta <= ids.length && pending.length; vuelta++) {
    let stdout = "";
    let stderr = "";
    try {
      // ejecutar solo da stderr cuando falla.
      stdout = (await ejecutar(`"${nmapPath}" --script-help ${pending.join(",")}`, timeoutMs)) || "";
    } catch (err) {
      stdout = (err && err.stdout) || "";
      stderr = (err && err.stderr) || String((err && err.message) || err);
    }

    // Lo reconocido antes de abortar también cuenta.
    for (const n of leerAyudaScript(stdout)) if (pending.includes(n)) available.add(n);

    const rejected = leerNombreRechazado(stderr) || leerNombreRechazado(stdout);
    if (!rejected) {
      // Sin nombre rechazado: o fue bien o falló por otra causa.
      const sinRespuesta = pending.filter((n) => !available.has(n));
      if (sinRespuesta.length && !leerAyudaScript(stdout).size) {
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

// Estado por script y puerto: found, not-applicable (fuera de alcance) o not-run (hueco).
// No existe "limpio": un script callado puede ser un diálogo que no terminó.
function estadoScripts(p, availability) {
  const scripts = (p && p.nse) || [];
  const avail   = availability || { checked: false, available: new Set(), missing: [] };
  const states  = {};

  for (const id of NSE_SCRIPT_IDS) {
    if (buscarScript(scripts, id)) {
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

    const { applies, reason } = aplicaA(id, p);
    if (!applies) {
      states[id] = { state: "not-applicable", kind: "not-applicable", reason };
      continue;
    }

    // Le tocaba y no salió; el motivo depende de con quién hablaba el script.
    let motivo;
    if (tipoFuente(id) === "remote-api") {
      motivo = `El script '${id}' no devolvió datos para este puerto; puede ser que la fuente ` +
          "externa no respondiera.";
    } else {
      motivo = `El script '${id}' no devolvió datos para este puerto: el servicio no completó el ` +
          "diálogo que el script necesita, o nuestra estimación de que aplicaba era incorrecta.";
    }
    states[id] = {
      state: "not-run",
      kind: "no-output",
      reason: motivo,
    };
  }

  return states;
}

module.exports = {
  existeScript,
  estadoScripts,
  leerAyudaScript,
  leerNombreRechazado,
  HELP_TIMEOUT_MS,
};
