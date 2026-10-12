"use strict";

/**
 * ¿Respondió vulners.com en esta ejecución?
 *
 * El script `vulners` no distingue sus dos silencios: un puerto sin <script id="vulners"> puede ser "sin CVE publicados"
 * o "no pude preguntar" (sin red, API caída, rate limit). Nunca se afirma "sin vulnerabilidades" para un puerto con versión
 * salvo que conste que la fuente respondió, y este módulo es lo que lo hace constar.
 *
 * Mecanismo único, la inferencia: si CUALQUIER puerto produjo un <script id="vulners">, la API respondió, porque el script
 * no emite ese nodo sin datos. Un puerto con CVE certifica a los demás, sin peticiones ni datos que salgan del equipo.
 *
 * No hay sonda de respaldo. Se implementó y se midió contra vulners.com el 2026-09-13 (test/manual/test-nse-parse.js,
 * sección 11): sin User-Agent o con el de LoCoAudit da HTTP 403 (reto anti-bot) y solo con el de 'Vulners NMAP Plugin'
 * da 200. Funcionar exigía suplantar a vulners.nse, que es saltarse un control de acceso del tercero.
 *
 * Coste: vulners solo emite el nodo si encuentra CVE, así que un equipo bien mantenido sale siempre 'unconfirmed' y sus
 * puertos con versión como "sin comprobar". Es la lectura conservadora, pero contraintuitiva: CANARY_DETAIL.unconfirmed
 * lo explica y normalizer.js lo recoge en el hallazgo de omisión.
 *
 * Dependencia, anotada en las limitaciones del README: vulners.nse funciona porque Vulners mantiene su User-Agent en
 * lista blanca. Si lo cambian, el script morirá en silencio.
 */

/**
 * Los cuatro estados. Solo `ok-inferred` autoriza a leer un puerto como limpio; los otros tres
 * mandan todo puerto con versión a "sin comprobar", y se distinguen entre sí porque piden cosas
 * distintas a quien lee el informe.
 */
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

/** ¿Hay veredicto de que la fuente respondió? Uno solo de los cuatro estados lo da. */
function canaryIsOk(state) {
  return state === "ok-inferred";
}

/**
 * `true` si algún puerto trae un <script id="vulners">.
 *
 * Es una inferencia, no una suposición: el script no emite ese nodo si no recibió respuesta.
 */
function inferFromScan(ports) {
  return (ports || []).some((p) =>
    ((p && p.nse) || []).some((s) => s && s.id === "vulners")
  );
}

/** ¿Hay algún puerto cuya versión hubiera dado pie a una consulta? */
function anyVersioned(ports, hasVersion) {
  return (ports || []).some((p) => hasVersion(p));
}

/**
 * El veredicto. Devuelve { state, detail, probed, evidence }.
 * `probed` vale siempre false: el informe lo usa para decir que LoCoAudit no habló con ningún tercero. Síncrona porque no hay E/S.
 */
function runCanary(ports, opts = {}) {
  const { hasVersion, nseEnabled = true } = opts;

  if (!nseEnabled) {
    return { state: "not-run", detail: CANARY_DETAIL["not-run"], probed: false, evidence: null };
  }

  if (inferFromScan(ports)) {
    return {
      state: "ok-inferred",
      detail: CANARY_DETAIL["ok-inferred"],
      probed: false,
      evidence: "Al menos un puerto del escaneo trae resultados de vulners.",
    };
  }

  // Sin ningún puerto con versión no hay nada que afirmar ni que desmentir.
  if (typeof hasVersion === "function" && !anyVersioned(ports, hasVersion)) {
    return {
      state: "not-needed", detail: CANARY_DETAIL["not-needed"], probed: false, evidence: null,
    };
  }

  // El caso ambiguo se nombra tal cual: no se sabe. Manda todos los puertos con versión a "sin
  // comprobar", que es lo conservador.
  return {
    state: "unconfirmed",
    detail: CANARY_DETAIL.unconfirmed,
    probed: false,
    evidence: "Ningún puerto del escaneo recibió datos de vulners.",
  };
}

module.exports = {
  runCanary,
  inferFromScan,
  canaryIsOk,
  CANARY_DETAIL,
};
