"use strict";

/**
 * port-scanner.js — Escáner de puertos TCP del host local mediante net nativo.
 *
 * No utiliza dependencias externas: todo el escaneo se realiza con el módulo
 * "net" de Node.js intentando establecer conexiones TCP y observando si se
 * aceptan (puerto abierto) o se rechazan/expiran (puerto cerrado/filtrado).
 *
 * ── Criterio de severidad por puerto ─────────────────────────────────────────
 *
 * El criterio sigue la misma filosofía que LYNIS_PERSONAL_SEVERITY en
 * lib/severity-map.js: el target es un usuario doméstico sin conocimientos
 * de seguridad, no un administrador de sistemas.
 *
 * "high"   — El puerto expone un servicio con riesgo real e inmediato en un PC
 *            personal: protocolos sin cifrado que transmiten credenciales en
 *            claro (FTP, Telnet), acceso remoto de escritorio ampliamente
 *            atacado (RDP, VNC), o puertos directamente asociados a backdoors
 *            y herramientas de ataque (4444, 1337).  Un usuario doméstico
 *            no debería tener estos servicios activos bajo ningún uso normal.
 *
 * "medium" — El puerto corresponde a un servicio legítimo pero inusual o
 *            innecesariamente expuesto en un PC personal: bases de datos
 *            accesibles desde la red local (MySQL, PostgreSQL, Redis, MongoDB),
 *            servidores de correo (SMTP) o servidores web alternativos que
 *            podrían quedar olvidados activos.  Requieren atención pero no
 *            son tan urgentes como los "high".
 *
 * "info"   — Servicios habituales en PC de desarrollo o de uso doméstico:
 *            servidores web locales (HTTP/HTTPS), servidores de impresión
 *            (CUPS en macOS/Linux) o puertos típicos de entornos de desarrollo
 *            (3000, 5000, 8000, 9000).  Se informan para que el usuario sea
 *            consciente de lo que tiene activo, pero no implican riesgo.
 *
 * "low"    — Puerto abierto no reconocido en el catálogo.  Puede ser un
 *            servicio legítimo del sistema o una aplicación de usuario.
 *            Se muestra por trazabilidad sin alarmar innecesariamente.
 *
 * ── Nota de mantenimiento ─────────────────────────────────────────────────────
 *
 * PORT_CATALOG cubre los puertos más frecuentes en PCs personales.  Para
 * ampliar la cobertura a entornos servidor o añadir UDP, considerar integrar
 * nmap (audit-network ya tiene soporte opcional para él) y complementar este
 * escáner nativo con los resultados de nmap cuando esté disponible.
 *
 * Exporta:
 *   scanPorts(options?) → Promise<Array<PortResult>>
 *
 * @typedef {{ port: number, protocol: string, state: string, service: string, severity: string, fix: string|null }} PortResult
 */

const net = require("net");
const { getFixForPort } = require("./network-utils");

// ── Catálogo de puertos ───────────────────────────────────────────────────────

/**
 * Puertos conocidos con su metadato de severidad para PC personal.
 * Estructura: port → { service, severity, fix }
 *
 * ── Servicios propios de macOS clasificados como "info" ──────────────────────
 *
 * Los puertos 7000 (AirPlay), 5353 (mDNS/Bonjour) y 548 (AFP) aparecen
 * abiertos en cualquier Mac con la configuración por defecto del sistema.
 * No representan un riesgo en sí mismos: son funcionalidades del SO que el
 * usuario ha activado implícitamente al usar AirPlay, compartición de archivos
 * o la resolución de nombres en red local.  Se clasifican como "info" para que
 * el usuario sea consciente de que están activos, pero no se le alarma
 * innecesariamente.
 *
 * El usuario debería desactivarlos únicamente si no usa esas funcionalidades:
 *   - AirPlay receptor: Ajustes → General → AirDrop y Handoff → Receptor AirPlay
 *   - Bonjour/mDNS:    No se puede desactivar de forma granular en macOS sin
 *                      herramientas de terceros; forma parte de la red local.
 *   - AFP (548):       Ajustes → General → Compartir → Compartir archivos (desactivar)
 *
 * Nota sobre el puerto 8021:
 *   En macOS corresponde a un servicio interno del sistema (Control Center /
 *   daemon del sistema) y se clasifica como "info".  En Linux este puerto no
 *   tiene un uso estándar conocido y debería revisarse; si se amplía el soporte
 *   a perfiles de servidor, considerar elevarlo a "medium" en ese contexto.
 */
const PORT_CATALOG = {
  // ── HIGH — riesgo real e inmediato en PC personal ──────────────────────────
  21:    { service: "FTP",        severity: "high" },
  23:    { service: "Telnet",     severity: "high" },
  3389:  { service: "RDP",        severity: "high" },
  5900:  { service: "VNC",        severity: "high" },
  5901:  { service: "VNC-1",      severity: "high" },
  4444:  { service: "Metasploit", severity: "high" },
  1337:  { service: "Backdoor",   severity: "high" },

  // ── MEDIUM — servicio inusual o innecesariamente expuesto en PC personal ───
  22:    { service: "SSH",        severity: "medium" },
  25:    { service: "SMTP",       severity: "medium" },
  3306:  { service: "MySQL",      severity: "medium" },
  5432:  { service: "PostgreSQL", severity: "medium" },
  6379:  { service: "Redis",      severity: "medium" },
  27017: { service: "MongoDB",    severity: "medium" },
  8080:  { service: "HTTP-alt",   severity: "medium" },
  8443:  { service: "HTTPS-alt",  severity: "medium" },

  // ── INFO — habitual en PC de desarrollo o uso doméstico ───────────────────
  80:    { service: "HTTP",       severity: "info" },
  443:   { service: "HTTPS",      severity: "info" },
  631:   { service: "CUPS",       severity: "info" },
  3000:  { service: "Dev/Grafana", severity: "medium" },
  5000:  { service: "Dev-server", severity: "info" },
  8000:  { service: "Dev-server", severity: "info" },
  9000:  { service: "Dev-server", severity: "info" },

  // ── INFO — servicios propios de macOS, normales con configuración por defecto
  88:    { service: "Kerberos",   severity: "info" },
  548:   { service: "AFP",        severity: "info" },
  5353:  { service: "mDNS",       severity: "info" },
  7000:  { service: "AirPlay",    severity: "info" },
  8021:  { service: "macOS-svc",  severity: "info" },

  // ── MEDIUM — paneles de gestión de servidores/homelab expuestos en red ───────
  8006:  { service: "Proxmox-UI",  severity: "medium" },
  9090:  { service: "Cockpit",     severity: "medium" },
  10000: { service: "Webmin",      severity: "medium" },
  2375:  { service: "Docker-API",  severity: "high" },
  2376:  { service: "Docker-TLS",  severity: "medium" },
  9200:  { service: "Elasticsearch-HTTP", severity: "medium" },
  5601:  { service: "Kibana",      severity: "medium" },
  9093:  { service: "Prometheus",  severity: "medium" },
};

const ALL_PORTS = Object.keys(PORT_CATALOG).map(Number);

// ── Escáner ───────────────────────────────────────────────────────────────────

/**
 * Parsea un string de puertos personalizado a un array de números válidos.
 *
 * Formatos aceptados (combinables con comas):
 *   "22,80,443"       → puertos individuales
 *   "1-500"           → rango inclusivo
 *   "22,80,1000-1100" → combinación
 *
 * Tokens inválidos se ignoran silenciosamente. Si el resultado está vacío
 * lanza un Error con instrucciones de uso.
 *
 * @param {string} input
 * @returns {number[]}  Array ordenado de puertos únicos en rango 1-65535
 * @throws {Error} si no se encuentra ningún puerto válido
 */
function parsePortsInput(input) {
  const tokens = String(input).split(",").map((s) => s.trim()).filter(Boolean);
  const ports  = new Set();

  for (const token of tokens) {
    if (/^\d+$/.test(token)) {
      const n = parseInt(token, 10);
      if (n >= 1 && n <= 65535) ports.add(n);
    } else if (/^\d+-\d+$/.test(token)) {
      const [a, b] = token.split("-").map(Number);
      if (a >= 1 && b <= 65535 && a <= b) {
        for (let p = a; p <= b; p++) ports.add(p);
      }
    }
    // token inválido → ignorar
  }

  if (ports.size === 0) {
    throw new Error(
      "No se encontraron puertos válidos en la lista personalizada. " +
      "Usa formato: 22,80,443 o rangos como 1-1024."
    );
  }

  return Array.from(ports).sort((a, b) => a - b);
}

/**
 * Intenta conectar a host:port con un timeout dado.
 * @param {number} port
 * @param {number} timeout  ms
 * @param {string} [host="127.0.0.1"]
 * @returns {Promise<boolean>}  true si el puerto está abierto
 */
function probePort(port, timeout, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    const cleanup = (open) => {
      socket.destroy();
      resolve(open);
    };

    socket.setTimeout(timeout);
    socket.on("connect",  () => cleanup(true));
    socket.on("timeout",  () => cleanup(false));
    socket.on("error",    () => cleanup(false));  // ECONNREFUSED, EHOSTUNREACH, etc.

    socket.connect(port, host);
  });
}

/**
 * Ejecuta un array de funciones productoras de promesas respetando
 * un límite de concurrencia máxima.
 * @param {Array<() => Promise<any>>} tasks
 * @param {number} concurrency
 * @returns {Promise<any[]>}
 */
async function runWithConcurrency(tasks, concurrency) {
  const results = new Array(tasks.length);
  let index = 0;

  async function worker() {
    while (index < tasks.length) {
      const i = index++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, worker);
  await Promise.all(workers);
  return results;
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Escanea puertos TCP en el host indicado y devuelve los abiertos.
 *
 * @param {object}  [options]
 * @param {number}  [options.timeout=500]        ms por intento TCP
 * @param {number}  [options.concurrency=20]     workers paralelos
 * @param {string}  [options.host="127.0.0.1"]   IP o hostname objetivo
 * @param {string}  [options.mode="standard"]    modo de escaneo:
 *   - "standard" — solo los puertos del PORT_CATALOG (~27 puertos conocidos)
 *   - "full"     — puertos 1-1024 con concurrencia controlada
 *   - "custom"   — puertos definidos en options.customPorts
 * @param {string}  [options.customPorts=""]     lista de puertos para mode "custom".
 *   Formatos: "22,80,443" · "1-500" · "22,80,1000-1100"
 *   Los tokens inválidos se ignoran; si no hay ninguno válido lanza Error.
 * @returns {Promise<PortResult[]>}
 */
async function scanPorts(options = {}) {
  const timeout     = options.timeout     ?? 500;
  const concurrency = options.concurrency ?? 20;
  const host        = options.host        || "127.0.0.1";
  const mode        = options.mode        ?? "standard";

  let portsToScan;
  if (mode === "full") {
    portsToScan = Array.from({ length: 1024 }, (_, i) => i + 1);
  } else if (mode === "custom") {
    portsToScan = parsePortsInput(options.customPorts || "");
  } else {
    portsToScan = ALL_PORTS;
  }

  const tasks = portsToScan.map((port) => async () => {
    const open = await probePort(port, timeout, host);
    if (!open) return null;

    const meta = PORT_CATALOG[port] ?? {
      service:  "unknown",
      severity: "low",
    };

    return {
      port,
      protocol: "tcp",
      state:    "open",
      service:  meta.service,
      severity: meta.severity,
      fix:      getFixForPort(port, process.platform),
    };
  });

  const raw = await runWithConcurrency(tasks, concurrency);
  return raw.filter(Boolean);
}

module.exports = { scanPorts, parsePortsInput, PORT_CATALOG };
