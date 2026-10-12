"use strict";

/**
 * Única fuente sobre si el objetivo existe, con un `nmap -sn` explícito antes del escaneo. El escaneo va con -Pn y ahí
 * nmap marca siempre up="1" reason="user-set" sin comprobar nada: un host inexistente daba 0 puertos y el dashboard lo
 * pintaba verde. Sale a cuenta: contra una IP sin host, 3,0 s de descubrimiento frente a 212,6 s del escaneo de 1-1024.
 *
 * Solo decide el bloque <hosts>: up >= 1 accesible, up=0 con <finished> no accesible, y todo lo demás (exit="error", sin
 * runstats, timeout, nmap ausente, XML ilegible) es null. Con null se escanea igual y se avisa, porque un falso
 * "no alcanzable" que cancela la auditoría es peor que un escaneo de más.
 * `reason` solo afina el mensaje (sin privilegios los casos inalcanzables dan el mismo `no-response`).
 */

const { execCommand, commandExists } = require("../../../lib/executor");
const { findInterfaceForTarget, parseNmapFatalError } = require("./nmap-wrapper");

/** Timeout del executor para el descubrimiento. Techo duro: nunca es el cuello
 *  de botella (el --host-timeout de nmap corta antes, a los 8 s). */
const DISCOVERY_TIMEOUT_MS = 15000;

/**
 * El -PS con cuatro puertos no es de adorno: sin privilegios nmap solo prueba 80 y 443, y un host
 * vivo que no sirva ninguno de los dos saldría como caído. El -e sale de findInterfaceForTarget,
 * el mismo que usa el escaneo, y en Windows no se pasa.
 */
function buildDiscoveryCmd(target) {
  const iface     = findInterfaceForTarget(target);
  const ifaceFlag = iface ? `-e ${iface}` : "";
  return `nmap -sn -n -PE -PS22,80,443,8080 --max-retries 1 --host-timeout 8s ${ifaceFlag} -oX - ${target}`
    .replace(/\s+/g, " ")
    .trim();
}

/** Pura, sin ejecutar nada, para poder fijarla con fixtures en los tests. */
function parseDiscoveryXml(xml) {
  const text = xml || "";

  // Un nmap abortado emite <runstats> y <hosts up="0" down="0" total="0"/> igual. Esos ceros no
  // dicen que el host esté caído, dicen que no llegó a preguntárselo; pasa, por ejemplo, con un
  // -e hacia una interfaz que no existe. Va antes que los <hosts>, que casarían y darían un
  // "no alcanzable" falso.
  const fatalError = parseNmapFatalError(text);
  if (fatalError) {
    return { reachable: null, reason: null, error: fatalError };
  }

  // Un descubrimiento válido termina en <runstats><finished><hosts>: sin los dos, ambiguo.
  const hostsMatch = text.match(/<hosts\s+up="(\d+)"\s+down="(\d+)"/);
  const finished   = text.includes("<finished");
  if (!hostsMatch || !finished) {
    return { reachable: null, reason: null, error: null };
  }

  // Del bloque <status>, y solo informativo.
  const statusMatch = text.match(/<status\s+state="([^"]*)"\s+reason="([^"]*)"/);
  let reason = statusMatch ? statusMatch[2] : null;

  // Con el host caído no hay <status>: el motivo, si lo hay, viene en <extrareasons>.
  if (!reason) {
    const extraMatch = text.match(/<extrareasons\s+reason="([^"]*)"/);
    reason = extraMatch ? extraMatch[1] : null;
  }

  const up = parseInt(hostsMatch[1], 10);
  return { reachable: up > 0, reason: reason || null, error: null };
}

/** El resultado en texto llano, listo para la evidencia del finding. */
function describe(target, reachable, reason, durationMs, error) {
  const secs = (durationMs / 1000).toFixed(1);
  if (reachable === true) {
    return `${target} respondió al descubrimiento de red en ${secs} s` +
           (reason ? ` (${reason}).` : ".");
  }
  if (reachable === false) {
    // Con host-unreach o net-unreach el SO sabe que no hay ruta, y el consejo es otro.
    if (reason === "host-unreach" || reason === "net-unreach") {
      return `El sistema informó de que no hay ruta hasta ${target} ` +
             `(${reason}, ${secs} s): no es que el equipo no conteste, es que ` +
             "este equipo no sabe por dónde llegar hasta él.";
    }
    return `${target} no respondió al descubrimiento de red (nmap -sn, ${secs} s).`;
  }
  if (error) {
    // Fallo de la herramienta y no del objetivo: el equipo puede estar perfectamente encendido.
    return `No se ha podido comprobar si ${target} está accesible (${secs} s): ` +
           `nmap terminó con error (${error}). No es un dato sobre el equipo, ` +
           "es que la comprobación no se pudo hacer.";
  }
  return `No se pudo determinar si ${target} está accesible (${secs} s): ` +
         "el descubrimiento no dio un resultado interpretable.";
}

/** Con un objetivo local no ejecuta nada: este equipo se alcanza siempre a sí mismo. */
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

  // Sin nmap no hay descubrimiento, pero tampoco es un fallo: es ambiguo, y del aviso ya se
  // encarga el NET-DEP-NMAP del llamante.
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
    // Puede salir con código distinto de cero y haber emitido XML válido, como con los avisos
    // de permisos de macOS sin sudo: se intenta interpretar igual.
    stdout = err.stdout || "";
    if (!stdout.includes("<runstats")) {
      const durationMs = Date.now() - started;
      // Cortado por el límite: el motivo es el tiempo, no lo que nmap llevase escrito en stderr.
      // Antes se mostraba el stderr también aquí, y en macOS sin root eso es el aviso "You are
      // not root -- using TCP pingscan", que aparece en TODAS las ejecuciones: el informe
      // atribuía el fallo a los permisos cuando lo que pasó es que se acabó el tiempo.
      // Mismo criterio que lynis.js: child_process marca killed y manda SIGTERM al cortar.
      const timedOut = err.killed || err.signal === "SIGTERM";
      return {
        reachable:  null,
        method:     "error",
        reason:     timedOut ? "timeout" : null,
        detail:     timedOut
          ? `El descubrimiento de ${target} no terminó en el límite de ${Math.round(timeout / 1000)} s ` +
            "y se interrumpió. No se puede afirmar si el equipo está accesible."
          : `El descubrimiento de ${target} falló: ` +
            `${(err.stderr || err.message || "sin detalle del sistema").trim()}. ` +
            "No se puede afirmar si el equipo está accesible.",
        durationMs,
        cmd,
      };
    }
  }

  const { reachable, reason, error } = parseDiscoveryXml(stdout);

  // Segunda opinión SOLO para el "no accesible" firme. El null ya se escanea igual, y un true no
  // necesita confirmación. Ver systemPing() para el porqué.
  if (reachable === false && !options.skipPing) {
    const ping = await systemPing(target, options.platform);
    if (ping.replied) {
      const durationMs = Date.now() - started;
      const secs = (durationMs / 1000).toFixed(1);
      return {
        reachable:   true,
        method:      "nmap-sn",
        reason:      "echo-reply",
        error:       null,
        detail:      `${target} no respondió a las sondas de Nmap, pero sí al ping del sistema ` +
                     `(${secs} s en total). Sin privilegios de administrador Nmap no puede usar ICMP ` +
                     "y solo prueba los puertos TCP 22, 80, 443 y 8080, que este equipo no atiende.",
        durationMs,
        cmd,
        confirmedBy: "ping",
        pingCmd:     ping.cmd,
      };
    }
    const durationMs = Date.now() - started;
    return {
      reachable,
      method: "nmap-sn",
      reason,
      error: error || null,
      // Solo se añade lo que se sabe: "tampoco respondió" cuando el ping se hizo, nada cuando no
      // se pudo hacer, para no afirmar una comprobación que no ocurrió.
      detail: describe(target, reachable, reason, durationMs, error) +
              (ping.ran ? " Tampoco respondió al ping del sistema." : ""),
      durationMs,
      cmd,
      pingCmd: ping.cmd || null,
    };
  }

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

/** Tiempo máximo del ping del sistema, con margen sobre los ~2 s que tardan dos paquetes. */
const PING_TIMEOUT_MS = 5000;

/**
 * El ping del sistema, para cuando Nmap da el equipo por caído. Sin root, nmap descarta -PE y solo le quedan cuatro
 * sondas TCP, así que un equipo que filtra todo salvo otros puertos sale "no accesible" aunque `ping` le responda
 * (comprobado el 2026-10-08 contra un equipo con solo 2222 y 5900 abiertos). El `ping` del sistema manda ICMP sin root.
 *
 * Cuenta como respuesta una línea con "ttl=": es lo que llevan los ecos reales y no el "destino inaccesible" de un router.
 * El código de salida no sirve (en Windows es 0 con ese mensaje) y "TTL=" no se traduce. Son dos paquetes porque en la
 * prueba real se perdieron los primeros.
 * Devuelve { ran, replied, cmd }; con ran=false no se afirma nada. El objetivo llega validado por validateTarget().
 */
async function systemPing(target, platform = process.platform) {
  const pingPath = await commandExists("ping");
  if (!pingPath) return { ran: false, replied: false, cmd: null };

  const cmd = platform === "win32"
    ? `"${pingPath}" -n 2 -w 1000 ${target}`
    : platform === "darwin"
    ? `"${pingPath}" -n -c 2 -W 1000 ${target}`   // -W en milisegundos en macOS
    : `"${pingPath}" -n -c 2 -W 1 ${target}`;     // -W en segundos en Linux

  let out;
  try {
    out = await execCommand(cmd, PING_TIMEOUT_MS);
  } catch (err) {
    // Sin respuesta, ping sale con código distinto de cero: eso es un "no", no un fallo. Fallo
    // es no haber podido ejecutarlo, y se distingue porque no deja salida ninguna.
    out = (err.stdout || "") + (err.stderr || "");
    if (!out.trim()) return { ran: false, replied: false, cmd };
  }
  return { ran: true, replied: /\bttl=\d+/i.test(out), cmd };
}

/**
 * El estado que viaja en el payload y con el que el dashboard decide si puede pintar verde. Vive
 * aquí, pegado a su única fuente, para que el nodo no pueda derivarlo de otra señal, en
 * particular del "host up" del escaneo con -Pn.
 */
function deriveTargetState(discovery) {
  if (!discovery) return "unknown";
  if (discovery.reachable === true)  return "reachable";
  if (discovery.reachable === false) return "unreachable";
  return "unknown";
}

module.exports = {
  checkHostReachable,
  systemPing,
  parseDiscoveryXml,
  buildDiscoveryCmd,
  deriveTargetState,
};
