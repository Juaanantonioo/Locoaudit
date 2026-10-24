"use strict";

// Decide si el objetivo existe con un `nmap -sn` previo, porque el escaneo con -Pn siempre dice "host up".
// Solo cuenta <hosts>: up>=1 accesible, up=0 terminado no accesible, y cualquier otra cosa null (ambiguo).

const { execCommand, commandExists } = require("../../../lib/executor");
const { findInterfaceForTarget, parseNmapFatalError } = require("./nmap-wrapper");

// Techo del executor; el --host-timeout de nmap corta antes, a los 8 s.
const DISCOVERY_TIMEOUT_MS = 15000;

// Cuatro puertos en -PS porque sin privilegios nmap solo probaría 80 y 443. El -e es el mismo del escaneo.
function buildDiscoveryCmd(target) {
  const iface     = findInterfaceForTarget(target);
  const ifaceFlag = iface ? `-e ${iface}` : "";
  return `nmap -sn -n -PE -PS22,80,443,8080 --max-retries 1 --host-timeout 8s ${ifaceFlag} -oX - ${target}`
    .replace(/\s+/g, " ")
    .trim();
}

// Pura, para poder probarla con fixtures.
function parseDiscoveryXml(xml) {
  const text = xml || "";

  // Un nmap abortado también emite <hosts up="0">: se mira antes para no dar un falso "no alcanzable".
  const fatalError = parseNmapFatalError(text);
  if (fatalError) {
    return { reachable: null, reason: null, error: fatalError };
  }

  // Sin <hosts> y <finished> el resultado es ambiguo.
  const hostsMatch = text.match(/<hosts\s+up="(\d+)"\s+down="(\d+)"/);
  const finished   = text.includes("<finished");
  if (!hostsMatch || !finished) {
    return { reachable: null, reason: null, error: null };
  }

  // El motivo solo afina el mensaje.
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

// Texto para la evidencia del hallazgo.
function describe(target, reachable, reason, durationMs, error) {
  const secs = (durationMs / 1000).toFixed(1);
  if (reachable === true) {
    return `${target} respondió al descubrimiento de red en ${secs} s` +
           (reason ? ` (${reason}).` : ".");
  }
  if (reachable === false) {
    // Sin ruta el problema es de este equipo, no de que el otro no conteste.
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

// Con objetivo local no ejecuta nada: siempre es accesible.
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

  // Sin nmap queda ambiguo; el aviso lo da NET-DEP-NMAP en el nodo.
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
    // Puede salir con error y aun así dejar XML válido (p. ej. macOS sin sudo).
    stdout = err.stdout || "";
    if (!stdout.includes("<runstats")) {
      const durationMs = Date.now() - started;
      // Si se cortó por tiempo no se muestra stderr: en macOS sin root siempre trae un aviso que confunde.
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

  // Segunda opinión con el ping del sistema solo para el "no accesible" firme.
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
      // Solo se menciona el ping si llegó a ejecutarse.
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

// Margen sobre los ~2 s que tardan dos paquetes.
const PING_TIMEOUT_MS = 5000;

// Sin root nmap no usa ICMP, pero `ping` sí. Se busca "ttl=" porque el código de salida no es fiable en Windows.
// Devuelve { ran, replied, cmd }; el objetivo ya llega validado por validateTarget().
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
    // Salir con error es un "no responde"; sin salida ninguna es que no se pudo ejecutar.
    out = (err.stdout || "") + (err.stderr || "");
    if (!out.trim()) return { ran: false, replied: false, cmd };
  }
  return { ran: true, replied: /\bttl=\d+/i.test(out), cmd };
}

// Vive aquí para que el estado salga solo del descubrimiento, nunca del "host up" del escaneo.
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
