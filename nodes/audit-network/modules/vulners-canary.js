"use strict";

/**
 * ¿Respondió vulners.com en esta ejecución?
 *
 * EL PROBLEMA QUE RESUELVE. El script `vulners` no distingue sus dos silencios: un puerto sin
 * <script id="vulners"> puede significar "esta versión no tiene CVE publicados" o "no pude
 * preguntar" (sin red, API caída, proxy que corta, rate limit). Son la misma ausencia en el XML
 * y significados opuestos. Sin resolver eso, el nodo tendría que elegir entre afirmar "sin
 * vulnerabilidades conocidas" sobre un fallo de red —el falso verde— o no afirmarlo nunca.
 *
 * LA RESTRICCIÓN. Nunca se afirma "sin vulnerabilidades" para un puerto que SÍ anunció versión,
 * salvo que conste que la fuente respondió. Este módulo es lo que hace que conste.
 *
 * UN SOLO MECANISMO: LA INFERENCIA. Si CUALQUIER puerto del escaneo produjo un
 * <script id="vulners">, la API respondió, porque el script no emite ese nodo sin haber recibido
 * datos. Un solo puerto con CVE certifica a todos los demás. Coste cero, ninguna petición a
 * nadie, ningún dato del equipo auditado sale de aquí.
 *
 * -------------------------------------------------------------------------------------------
 * POR QUÉ NO HAY UNA SONDA DE RESPALDO, Y QUÉ CUESTA NO TENERLA
 *
 * Se diseñó un segundo nivel para el caso ambiguo —ningún puerto recibió CVE pero sí había
 * versiones que consultar—: una petición a un CPE centinela cuya respuesta se conoce de
 * antemano. Se implementó, se midió contra vulners.com el 2026-09-13, y se retiró.
 *
 * Lo medido (los números están en test/manual/test-nse-parse.js, sección 11):
 *
 *   sin cabecera User-Agent            → HTTP 403, cuerpo "Just a moment..." (reto anti-bot)
 *   User-Agent 'LoCoAudit/1.0 (...)'   → HTTP 403, el mismo reto
 *   User-Agent 'Vulners NMAP Plugin 1.7' → HTTP 200, JSON con "result":"OK" (45.820 bytes)
 *
 * Idéntico en los tres endpoints probados: /api/v3/burp/software/, /api/v3/search/id/ y
 * /api/v3/burp/softwareapi/.
 *
 * O sea que la única forma de que la sonda funcionase era mandar la cadena de vulners.nse
 * haciéndose pasar por él. Eso es saltarse un control de acceso que el tercero ha puesto a
 * propósito. No se hace, y el código no se queda apagado "por si acaso": un camino que no se
 * ejecuta no se prueba, caduca sin que nadie lo note y sigue siendo la misma suplantación el día
 * que alguien le dé al interruptor.
 *
 * EL COSTE, que no se esconde. El script `vulners` solo emite su nodo cuando encuentra CVE. En
 * un equipo BIEN MANTENIDO no hay CVE en ninguna versión, así que no hay ningún nodo, así que la
 * inferencia no puede certificar nada: ese equipo sale siempre como 'unconfirmed', y sus puertos
 * con versión como "sin comprobar" en lugar de limpios. Es la lectura conservadora —nunca un
 * verde falso—, pero es contraintuitiva, así que TIENE QUE IR EXPLICADA EN EL INFORME y no solo
 * aquí: el texto de CANARY_DETAIL.unconfirmed lo dice con todas las letras, y de ahí lo recoge
 * el hallazgo de omisión que genera lib/normalizer.js.
 *
 * Y LA DEPENDENCIA QUE ESTO DESTAPA, apuntada en las limitaciones del README: vulners.nse
 * funciona porque se identifica con una cadena de User-Agent concreta que Vulners mantiene en
 * lista blanca. El día que la cambien, el script dejará de recibir datos y morirá EN SILENCIO
 * —su propio código descarta el fallo HTTP sin avisar—. La dependencia no es solo "requiere
 * internet": es "requiere seguir estando en la lista de otro".
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
 *
 * `probed` se queda en el contrato y vale SIEMPRE false: es lo que el informe usa para decir que
 * LoCoAudit no habló con ningún tercero durante la auditoría. Un campo que afirma algo cierto y
 * comprobable vale más que su ausencia.
 *
 * Síncrona: no hay E/S. Lo era `async` cuando existía la sonda, y dejarlo así insinuaría una
 * petición que ya no ocurre.
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
