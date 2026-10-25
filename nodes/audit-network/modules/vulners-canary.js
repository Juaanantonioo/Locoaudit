"use strict";

// Decide si vulners.com respondió: un puerto sin <script id="vulners"> puede ser "sin CVE" o "no se pudo preguntar".
// Si cualquier puerto trae ese nodo, la API respondió. No hay sonda propia: exigiría suplantar el User-Agent de vulners.nse.

// Solo `ok-inferred` permite leer un puerto como limpio; con los demás, los puertos con versión quedan sin comprobar.
const CANARY_DETAIL = {
  "ok-inferred":
    "La fuente de CVE respondió: al menos un puerto del escaneo recibió datos de vulners.com. " +
    "Los puertos con versión y sin CVE se pueden leer como 'sin vulnerabilidades conocidas'.",
  "unconfirmed":
    "No consta que la fuente de CVE respondiera: ningún puerto del escaneo recibió datos de " +
    "vulners.com. Eso ocurre en dos situaciones opuestas que desde aquí no se pueden " +
    "distinguir: que ninguna de las versiones detectadas tenga CVE publicados —o sea, un equipo " +
    "al día— o que la consulta no llegara a hacerse por falta de conexión, un proxy o un límite " +
    "de peticiones. Ante la duda no se da nada por limpio: los puertos con versión quedan SIN " +
    "COMPROBAR. Si mantienes el equipo actualizado, este es el resultado ESPERADO y no indica " +
    "ningún problema; LoCoAudit no lanza consultas propias a vulners.com para deshacer el empate.",
  "not-needed":
    "No hizo falta comprobar la fuente de CVE: ningún puerto abierto anunció versión, así que no " +
    "había nada que consultar.",
  "not-run":
    "No se comprobó la fuente de CVE porque el análisis NSE no se ejecutó.",
};

function canarioCorrecto(state) {
  return state === "ok-inferred";
}

// El script no emite ese nodo si no recibió respuesta.
function deducirDelEscaneo(ports) {
  return (ports || []).some((p) =>
    ((p && p.nse) || []).some((s) => s && s.id === "vulners")
  );
}

function algunoConVersion(ports, hasVersion) {
  return (ports || []).some((p) => hasVersion(p));
}

// Devuelve { state, detail, probed, evidence }; probed siempre es false porque LoCoAudit no consulta a terceros.
function ejecutarCanario(ports, opts = {}) {
  const { hasVersion, nseEnabled = true } = opts;

  if (!nseEnabled) {
    return { state: "not-run", detail: CANARY_DETAIL["not-run"], probed: false, evidence: null };
  }

  if (deducirDelEscaneo(ports)) {
    return {
      state: "ok-inferred",
      detail: CANARY_DETAIL["ok-inferred"],
      probed: false,
      evidence: "Al menos un puerto del escaneo trae resultados de vulners.",
    };
  }

  // Sin ningún puerto con versión no hay nada que afirmar ni que desmentir.
  if (typeof hasVersion === "function" && !algunoConVersion(ports, hasVersion)) {
    return {
      state: "not-needed", detail: CANARY_DETAIL["not-needed"], probed: false, evidence: null,
    };
  }

  // Caso ambiguo: lo conservador es dejar los puertos con versión sin comprobar.
  return {
    state: "unconfirmed",
    detail: CANARY_DETAIL.unconfirmed,
    probed: false,
    evidence: "Ningún puerto del escaneo recibió datos de vulners.",
  };
}

module.exports = {
  ejecutarCanario,
  deducirDelEscaneo,
  canarioCorrecto,
  CANARY_DETAIL,
};
