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

// ── Catálogo de puertos ───────────────────────────────────────────────────────

/**
 * Puertos conocidos con su metadato de severidad para PC personal.
 * Estructura: port → { service, severity, fix }
 */
const PORT_CATALOG = {
  // ── HIGH — riesgo real e inmediato en PC personal ──────────────────────────
  21:    { service: "FTP",        severity: "high",   fix: "Desactiva el servicio FTP. Usa SFTP o SCP si necesitas transferencia de ficheros." },
  23:    { service: "Telnet",     severity: "high",   fix: "Desactiva Telnet. Usa SSH para acceso remoto cifrado." },
  3389:  { service: "RDP",        severity: "high",   fix: "Desactiva el escritorio remoto si no lo usas. Si lo necesitas, restringe el acceso por IP." },
  5900:  { service: "VNC",        severity: "high",   fix: "Desactiva VNC si no lo necesitas. Si lo usas, configura autenticación y cifra el canal con un túnel SSH." },
  5901:  { service: "VNC-1",      severity: "high",   fix: "Desactiva VNC si no lo necesitas. Si lo usas, configura autenticación y cifra el canal con un túnel SSH." },
  4444:  { service: "Metasploit", severity: "high",   fix: "Este puerto está asociado a herramientas de ataque y backdoors. Investiga qué proceso lo tiene abierto." },
  1337:  { service: "Backdoor",   severity: "high",   fix: "Este puerto está asociado a malware. Investiga qué proceso lo tiene abierto con 'lsof -i :1337'." },

  // ── MEDIUM — servicio inusual o innecesariamente expuesto en PC personal ───
  22:    { service: "SSH",        severity: "medium", fix: "Si no necesitas acceso SSH remoto, desactívalo. Si lo usas, deshabilita PermitRootLogin y usa claves." },
  25:    { service: "SMTP",       severity: "medium", fix: "Un servidor de correo en un PC personal es inusual. Desactívalo si no lo usas conscientemente." },
  3306:  { service: "MySQL",      severity: "medium", fix: "Restringe MySQL a localhost (bind-address = 127.0.0.1) para evitar exposición en red local." },
  5432:  { service: "PostgreSQL", severity: "medium", fix: "Restringe PostgreSQL a localhost en postgresql.conf (listen_addresses = 'localhost')." },
  6379:  { service: "Redis",      severity: "medium", fix: "Redis no tiene autenticación por defecto. Añade 'bind 127.0.0.1' y una contraseña en redis.conf." },
  27017: { service: "MongoDB",    severity: "medium", fix: "Activa la autenticación en MongoDB y restringe la escucha a localhost." },
  8080:  { service: "HTTP-alt",   severity: "medium", fix: "Comprueba qué servicio usa este puerto y ciérralo si no lo necesitas activamente." },
  8443:  { service: "HTTPS-alt",  severity: "medium", fix: "Comprueba qué servicio usa este puerto y ciérralo si no lo necesitas activamente." },

  // ── INFO — habitual en PC de desarrollo o uso doméstico ───────────────────
  80:    { service: "HTTP",       severity: "info",   fix: null },
  443:   { service: "HTTPS",      severity: "info",   fix: null },
  631:   { service: "CUPS",       severity: "info",   fix: null },
  3000:  { service: "Dev-server", severity: "info",   fix: null },
  5000:  { service: "Dev-server", severity: "info",   fix: null },
  8000:  { service: "Dev-server", severity: "info",   fix: null },
  9000:  { service: "Dev-server", severity: "info",   fix: null },
};

const ALL_PORTS = Object.keys(PORT_CATALOG).map(Number);

// ── Escáner ───────────────────────────────────────────────────────────────────

/**
 * Intenta conectar a 127.0.0.1:port con un timeout dado.
 * @param {number} port
 * @param {number} timeout  ms
 * @returns {Promise<boolean>}  true si el puerto está abierto
 */
function probePort(port, timeout) {
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

    socket.connect(port, "127.0.0.1");
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
 * Escanea los puertos TCP del catálogo en 127.0.0.1 y devuelve los abiertos.
 *
 * @param {{ timeout?: number, concurrency?: number }} [options]
 * @returns {Promise<PortResult[]>}
 */
async function scanPorts(options = {}) {
  const timeout     = options.timeout     ?? 500;
  const concurrency = options.concurrency ?? 20;

  const tasks = ALL_PORTS.map((port) => async () => {
    const open = await probePort(port, timeout);
    if (!open) return null;

    const meta = PORT_CATALOG[port] ?? {
      service:  "unknown",
      severity: "low",
      fix:      "Investiga qué proceso tiene abierto este puerto con 'lsof -i :<puerto>'.",
    };

    return {
      port,
      protocol: "tcp",
      state:    "open",
      service:  meta.service,
      severity: meta.severity,
      fix:      meta.fix,
    };
  });

  const raw = await runWithConcurrency(tasks, concurrency);
  return raw.filter(Boolean);
}

module.exports = { scanPorts, PORT_CATALOG };
