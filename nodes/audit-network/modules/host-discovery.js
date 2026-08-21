"use strict";

/**
 * host-discovery.js — Comprobación previa de alcanzabilidad del objetivo.
 *
 * PROBLEMA QUE RESUELVE
 * ---------------------
 * El escaneo de puertos del nodo usa `-Pn` (omite el descubrimiento de host).
 * Con `-Pn`, nmap marca SIEMPRE `<hosts up="1" down="0">` y
 * `<status state="up" reason="user-set">`: "user-set" es nmap diciendo que no
 * ha comprobado nada, lo ha asumido porque se lo hemos pedido. Por eso un host
 * inexistente devolvía 0 puertos abiertos y el dashboard lo pintaba de verde
 * ("Sin puertos expuestos · SIN RIESGO"), que es información falsa: no es que
 * el equipo esté limpio, es que no hay equipo.
 *
 * Este módulo es la ÚNICA fuente de verdad sobre si el objetivo existe. Lanza
 * un descubrimiento explícito (`nmap -sn`) ANTES del escaneo de puertos.
 *
 * Además ahorra tiempo: medido en macOS contra 10.0.0.5 (IP sin host, ruta por
 * WireGuard), este descubrimiento tardó 3,0 s mientras que el escaneo de puertos
 * del nodo con `-p 1-1024` tardó 212,6 s — a 28 s de morir por el timeout de
 * 240 s del modo estándar. Ese 3,0 s es una MEDIDA de aquel caso, no un límite
 * configurado: los techos reales son --host-timeout 8s (nmap) y
 * DISCOVERY_TIMEOUT_MS = 15000 (executor).
 *
 * DECISIÓN (una sola señal: runstats/hosts del XML de -sn)
 *   <hosts up="N" …>  con N >= 1                 → reachable: true
 *   <hosts up="0" down="1" …> y <finished …>     → reachable: false
 *   <finished … exit="error">                    → reachable: null  (AMBIGUO)
 *   cualquier otra cosa (sin runstats, timeout,
 *   excepción, nmap ausente, XML ilegible)       → reachable: null  (AMBIGUO)
 *
 * Ante la duda (null) el llamante ESCANEA IGUAL y avisa: un falso "no
 * alcanzable" que cancela la auditoría es peor que un escaneo de más.
 *
 * `reason` (echo-reply / syn-ack / host-unreach / no-response…) NO decide nada:
 * solo afina el mensaje al usuario. Medido en macOS con escaneo `connect` sin
 * privilegios, los tres escenarios de host inalcanzable (subred VPN sin host,
 * IP libre de la LAN, link-local sin ruta) devuelven el mismo `no-response`.
 * `host-unreach` / `net-unreach` aparecen cuando el SO informa de EHOSTUNREACH
 * o llega un ICMP unreachable (típico en Linux con "No existe ninguna ruta
 * hasta el host"), y ahí sí cambia el consejo que se le da al usuario.
 *
 * Exporta:
 *   checkHostReachable(options)  → Promise<Discovery>   (ejecuta nmap -sn)
 *   parseDiscoveryXml(xml)       → { reachable, reason, error } (puro, para tests)
 *   buildDiscoveryCmd(target)    → string                (comando exacto)
 *
 * @typedef {Object} Discovery
 * @property {boolean|null} reachable  true | false | null (ambiguo)
 * @property {"nmap-sn"|"local"|"error"} method
 * @property {string|null} reason      Motivo de nmap (informativo)
 * @property {string|null} error       errormsg de nmap si abortó (diagnóstico)
 * @property {string} detail           Texto listo para la evidencia del finding
 * @property {number} durationMs
 * @property {string|null} cmd         Comando exacto ejecutado
 */

const { execCommand, commandExists } = require("../../../lib/executor");
const { findInterfaceForTarget, parseNmapFatalError } = require("./nmap-wrapper");

/** Timeout del executor para el descubrimiento. Techo duro: nunca es el cuello
 *  de botella (el --host-timeout de nmap corta antes, a los 8 s). */
const DISCOVERY_TIMEOUT_MS = 15000;

/**
 * Construye el comando de descubrimiento.
 *
 *   -sn                      solo descubrimiento, sin escaneo de puertos
 *   -n                       sin resolución DNS inversa (ahorra segundos)
 *   -PE                      ping ICMP echo
 *   -PS22,80,443,8080        sondas TCP SYN a puertos habituales: sin
 *                            privilegios nmap solo prueba 80 y 443, y un host
 *                            vivo que no sirva ninguno daría un falso "caído"
 *   --max-retries 1          un reintento basta para decidir vivo/no vivo
 *   --host-timeout 8s        techo por host
 *   -e <iface>               igual que el escaneo: en macOS con varias
 *                            interfaces en la misma subred, sin -e nmap falla.
 *                            En Windows NO se pasa: ver findInterfaceForTarget()
 *
 * @param {string} target
 * @returns {string}
 */
function buildDiscoveryCmd(target) {
  const iface     = findInterfaceForTarget(target);
  const ifaceFlag = iface ? `-e ${iface}` : "";
  return `nmap -sn -n -PE -PS22,80,443,8080 --max-retries 1 --host-timeout 8s ${ifaceFlag} -oX - ${target}`
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Interpreta el XML de `nmap -sn`. Función PURA: no ejecuta nada, para poder
 * fijarla con fixtures en los tests.
 *
 * @param {string} xml  Salida de nmap -sn -oX -
 * @returns {{ reachable: boolean|null, reason: string|null, error: string|null }}
 */
function parseDiscoveryXml(xml) {
  const text = xml || "";

  // nmap abortado (exit="error"): emite <runstats> y <hosts up="0" down="0"
  // total="0"/> igualmente. Esos ceros NO dicen que el host esté caído, dicen
  // que nmap no llegó a preguntárselo — ocurre, por ejemplo, con un -e que
  // apunta a una interfaz que no existe. Se comprueba ANTES que los <hosts>
  // porque esa etiqueta también casa aquí y daría un "no alcanzable" falso.
  const fatalError = parseNmapFatalError(text);
  if (fatalError) {
    return { reachable: null, reason: null, error: fatalError };
  }

  // Un descubrimiento VÁLIDO termina con <runstats><finished …><hosts …>.
  // Sin esos dos elementos el resultado no es interpretable → ambiguo.
  const hostsMatch = text.match(/<hosts\s+up="(\d+)"\s+down="(\d+)"/);
  const finished   = text.includes("<finished");
  if (!hostsMatch || !finished) {
    return { reachable: null, reason: null, error: null };
  }

  // reason del bloque <status state="…" reason="…">, solo informativo.
  const statusMatch = text.match(/<status\s+state="([^"]*)"\s+reason="([^"]*)"/);
  let reason = statusMatch ? statusMatch[2] : null;

  // Si el host está caído nmap no emite <status>; el motivo, cuando existe,
  // viaja en <extrareasons reason="…"> o directamente no hay ninguno.
  if (!reason) {
    const extraMatch = text.match(/<extrareasons\s+reason="([^"]*)"/);
    reason = extraMatch ? extraMatch[1] : null;
  }

  const up = parseInt(hostsMatch[1], 10);
  return { reachable: up > 0, reason: reason || null, error: null };
}

/**
 * Traduce el resultado a un texto llano para la evidencia del finding.
 *
 * @param {string} target
 * @param {boolean|null} reachable
 * @param {string|null} reason
 * @param {number} durationMs
 * @param {string|null} [error]  errormsg de nmap cuando abortó
 * @returns {string}
 */
function describe(target, reachable, reason, durationMs, error) {
  const secs = (durationMs / 1000).toFixed(1);
  if (reachable === true) {
    return `${target} respondió al descubrimiento de red en ${secs} s` +
           (reason ? ` (${reason}).` : ".");
  }
  if (reachable === false) {
    // host-unreach / net-unreach: el SO sabe que no hay ruta. El consejo al
    // usuario es distinto que cuando el host simplemente no contesta.
    if (reason === "host-unreach" || reason === "net-unreach") {
      return `El sistema informó de que no hay ruta hasta ${target} ` +
             `(${reason}, ${secs} s): no es que el equipo no conteste, es que ` +
             "este equipo no sabe por dónde llegar hasta él.";
    }
    return `${target} no respondió al descubrimiento de red (nmap -sn, ${secs} s).`;
  }
  if (error) {
    // Fallo de la herramienta, no del objetivo. Se dice tal cual: el equipo
    // puede estar perfectamente encendido.
    return `No se ha podido comprobar si ${target} está accesible (${secs} s): ` +
           `nmap terminó con error (${error}). No es un dato sobre el equipo, ` +
           "es que la comprobación no se pudo hacer.";
  }
  return `No se pudo determinar si ${target} está accesible (${secs} s): ` +
         "el descubrimiento no dio un resultado interpretable.";
}

/**
 * Comprueba si el objetivo está accesible antes de escanear sus puertos.
 *
 * Para objetivos locales NO ejecuta nada: este equipo siempre está accesible
 * para sí mismo, y `nmap -sn 127.0.0.1` solo añadiría latencia.
 *
 * @param {{ target?: string, isLocal?: boolean, timeout?: number }} [options]
 * @returns {Promise<Discovery>}
 */
async function checkHostReachable(options = {}) {
  const target  = options.target || "127.0.0.1";
  const timeout = options.timeout || DISCOVERY_TIMEOUT_MS;
  const started = Date.now();

  if (options.isLocal) {
    return {
      reachable:  true,
      method:     "local",
      reason:     "localhost",
      detail:     "El objetivo es este mismo equipo: no hace falta descubrimiento de red.",
      durationMs: 0,
      cmd:        null,
    };
  }

  // Sin nmap no hay descubrimiento posible. No es un fallo: es ambiguo, y el
  // llamante ya emite el finding NET-DEP-NMAP con las instrucciones de instalación.
  if (!(await commandExists("nmap"))) {
    return {
      reachable:  null,
      method:     "error",
      reason:     null,
      detail:     "Nmap no está instalado: no se ha podido comprobar si el equipo está accesible.",
      durationMs: Date.now() - started,
      cmd:        null,
    };
  }

  const cmd = buildDiscoveryCmd(target);
  let stdout;
  try {
    stdout = await execCommand(cmd, timeout);
  } catch (err) {
    // nmap puede salir con código != 0 y aun así haber emitido XML válido
    // (avisos de permisos en macOS sin sudo). Se intenta interpretar igual.
    stdout = err.stdout || "";
    if (!stdout.includes("<runstats")) {
      const durationMs = Date.now() - started;
      return {
        reachable:  null,
        method:     "error",
        reason:     null,
        detail:     `El descubrimiento de ${target} falló: ` +
                    `${(err.stderr || err.message || "timeout").trim()}. ` +
                    "No se puede afirmar si el equipo está accesible.",
        durationMs,
        cmd,
      };
    }
  }

  const { reachable, reason, error } = parseDiscoveryXml(stdout);
  const durationMs = Date.now() - started;

  return {
    reachable,
    method: "nmap-sn",
    reason,
    error: error || null,
    detail: describe(target, reachable, reason, durationMs, error),
    durationMs,
    cmd,
  };
}

/**
 * Traduce el resultado del descubrimiento al estado del objetivo que viaja en
 * el payload y que el dashboard usa para decidir si puede pintar verde.
 *
 * Vive aquí, junto a su única fuente de datos, para que el nodo no pueda
 * derivarlo de ninguna otra señal (en particular del "host up" del escaneo con
 * -Pn, que siempre dice que sí) y para poder fijarlo con tests.
 *
 * @param {Discovery|null} discovery
 * @returns {"reachable"|"unreachable"|"unknown"}
 */
function deriveTargetState(discovery) {
  if (!discovery) return "unknown";
  if (discovery.reachable === true)  return "reachable";
  if (discovery.reachable === false) return "unreachable";
  return "unknown";
}

module.exports = {
  checkHostReachable,
  parseDiscoveryXml,
  buildDiscoveryCmd,
  deriveTargetState,
};
