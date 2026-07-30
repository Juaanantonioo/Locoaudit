"use strict";

/**
 * service-detect.js — Enriquecimiento de puertos abiertos con información de proceso.
 *
 * Este módulo es complementario a nmap-wrapper.js: donde el escáner determina
 * qué puertos TCP están abiertos, service-detect añade el contexto humano
 * necesario para que un usuario sin conocimientos técnicos pueda interpretar
 * cada hallazgo.  Saber que el puerto 3306 está abierto es una alerta; saber
 * que lo tiene abierto "mysqld" (o peor, "python3") convierte el dato en una
 * acción concreta: detener ese proceso o revisar por qué está ahí.
 *
 * La información se obtiene con herramientas nativas del SO (lsof, netstat,
 * tasklist) sin dependencias externas.  Si el comando falla o el SO no
 * devuelve resultado, el puerto se devuelve sin enriquecer: el módulo nunca
 * bloquea ni lanza errores al nodo que lo invoca.
 *
 * Exporta:
 *   enrichPorts(openPorts) → Promise<Array<EnrichedPort>>
 *   detectFirewall()       → Promise<{ name: string|null, active: boolean }>
 *
 * @typedef {{ port: number, protocol: string, state: string, service: string, severity: string, fix: string|null }} PortResult
 * @typedef {{ pid?: number, process?: string, extra?: string, bind?: string, localOnly?: boolean }} Enrichment
 * @typedef {PortResult & Enrichment} EnrichedPort
 */

const { execCommand, commandExists } = require("../../../lib/executor");

const ENRICH_TIMEOUT_MS = 5000;

// ── Parsers por plataforma ────────────────────────────────────────────────────

/**
 * Parsea la salida de:
 *   lsof -i TCP:<port> -n -P -sTCP:LISTEN
 *
 * La primera línea es la cabecera (COMMAND PID USER …).
 * La segunda línea (índice 1) contiene el primer proceso en escucha.
 *
 * @param {string} stdout
 * @returns {{ pid: number|null, process: string|null }}
 */
function parseLsof(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  // lines[0] = cabecera, lines[1] = primer resultado
  if (lines.length < 2) return { pid: null, process: null, binds: [] };

  const parts = lines[1].trim().split(/\s+/);
  const processName = parts[0] || null;
  const pid = parts[1] ? parseInt(parts[1], 10) : null;

  // Direcciones de bind: la columna NAME de CADA línea LISTEN tiene la forma
  // "dirección:puerto (LISTEN)". La dirección distingue un servicio solo-local
  // ("localhost", "127.0.0.1", "[::1]") de uno expuesto a la red ("*", "0.0.0.0",
  // IP de la interfaz). Un mismo servicio puede escuchar en varias (IPv4+IPv6).
  const binds = [];
  for (const line of lines.slice(1)) {
    const m = line.match(/(\S+):(?:\d+|\w+)\s+\(LISTEN\)/);
    if (m && !binds.includes(m[1])) binds.push(m[1]);
  }

  return {
    pid:     isNaN(pid) ? null : pid,
    process: processName,
    binds,
  };
}

/**
 * ¿Es una dirección de bind exclusiva de loopback (solo accesible desde el
 * propio equipo)? Acepta las formas que emiten lsof y netstat.
 * @param {string} addr  "localhost" | "127.0.0.1" | "[::1]" | "*" | "0.0.0.0" | IP
 * @returns {boolean}
 */
function isLoopbackBind(addr) {
  const a = String(addr || "").replace(/^\[|\]$/g, "").toLowerCase();
  return a === "localhost" || a === "::1" || /^127\./.test(a);
}

/**
 * Parsea la salida de netstat -ano | findstr :<port> (Windows).
 * Devuelve el PID de la primera línea en estado LISTENING.
 *
 * Formato de línea: "  TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  1234"
 *
 * @param {string} stdout
 * @param {number} port
 * @returns {number|null}  PID o null si no se encuentra
 */
function parseNetstatPid(stdout, port) {
  const portStr = `:${port}`;
  for (const line of stdout.split("\n")) {
    const upper = line.toUpperCase();
    if (!upper.includes(portStr) || !upper.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const pid = parseInt(parts[parts.length - 1], 10);
    return isNaN(pid) ? null : pid;
  }
  return null;
}

/**
 * Extrae las direcciones locales de bind de las líneas LISTENING de netstat.
 * Formato de dirección local (parts[1]): "0.0.0.0:80" | "127.0.0.1:631" | "[::1]:631"
 *
 * @param {string} stdout
 * @param {number} port
 * @returns {string[]}  Direcciones sin el sufijo :puerto
 */
function parseNetstatBinds(stdout, port) {
  const portStr = `:${port}`;
  const binds = [];
  for (const line of stdout.split("\n")) {
    const upper = line.toUpperCase();
    if (!upper.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const local = parts[1] || "";
    if (!local.endsWith(portStr)) continue;
    const addr = local.slice(0, -portStr.length);
    if (addr && !binds.includes(addr)) binds.push(addr);
  }
  return binds;
}

/**
 * Parsea la salida de tasklist /FI "PID eq <pid>" /FO CSV (Windows).
 * La segunda línea (índice 1) es la primera fila de datos en formato CSV.
 * El primer campo es el nombre del proceso (entre comillas).
 *
 * @param {string} stdout
 * @returns {string|null}
 */
function parseTasklist(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return null;
  // CSV: "Image Name","PID","Session Name",...
  const firstField = lines[1].split(",")[0];
  return firstField ? firstField.replace(/"/g, "").trim() || null : null;
}

// ── Enriquecedores por plataforma ─────────────────────────────────────────────

/**
 * Obtiene PID y nombre de proceso en macOS / Linux mediante lsof.
 * @param {number} port
 * @returns {Promise<Enrichment>}
 */
async function enrichUnix(port) {
  try {
    const stdout = await execCommand(
      `lsof -i TCP:${port} -n -P -sTCP:LISTEN`,
      ENRICH_TIMEOUT_MS
    );
    const { pid, process: procName, binds } = parseLsof(stdout);
    if (!pid && !procName) return {};
    return {
      pid:       pid      ?? undefined,
      process:   procName ?? undefined,
      // localOnly solo se afirma si TODAS las direcciones de bind son loopback.
      // Sin datos de bind se deja undefined: no sabemos, no afirmamos.
      bind:      binds.length > 0 ? binds.join(", ") : undefined,
      localOnly: binds.length > 0 ? binds.every(isLoopbackBind) : undefined,
    };
  } catch (_) {
    return {};
  }
}

/**
 * Obtiene PID y nombre de proceso en Windows mediante netstat + tasklist.
 * @param {number} port
 * @returns {Promise<Enrichment>}
 */
async function enrichWindows(port) {
  try {
    const netstatOut = await execCommand(
      `netstat -ano | findstr :${port}`,
      ENRICH_TIMEOUT_MS
    );
    const pid = parseNetstatPid(netstatOut, port);
    if (!pid) return {};

    const binds = parseNetstatBinds(netstatOut, port);

    const taskOut = await execCommand(
      `tasklist /FI "PID eq ${pid}" /FO CSV`,
      ENRICH_TIMEOUT_MS
    );
    const procName = parseTasklist(taskOut);

    return {
      pid,
      process:   procName ?? undefined,
      bind:      binds.length > 0 ? binds.join(", ") : undefined,
      localOnly: binds.length > 0 ? binds.every(isLoopbackBind) : undefined,
    };
  } catch (_) {
    return {};
  }
}

// ── Detección del cortafuegos del sistema ─────────────────────────────────────

/**
 * Detecta qué cortafuegos hay en el sistema y si está ACTIVO, sin sudo.
 * Nunca lanza: ante cualquier fallo devuelve { name: null, active: false }.
 *
 * Métodos por plataforma (todos sin privilegios):
 *   linux  → ufw:       /etc/ufw/ufw.conf contiene "ENABLED=yes|no"
 *            firewalld: firewall-cmd --state → "running"
 *            nftables:  systemctl is-active nftables
 *   darwin → socketfilterfw --getglobalstate → "enabled"
 *   win32  → netsh advfirewall show currentprofile state → "ON"
 *
 * @param {string} [platform]  process.platform por defecto
 * @returns {Promise<{ name: string|null, active: boolean }>}
 */
async function detectFirewall(platform) {
  const plat = platform || process.platform;
  const FW_TIMEOUT_MS = 4000;

  try {
    if (plat === "linux") {
      if (await commandExists("ufw")) {
        try {
          const conf = await execCommand("grep -i '^ENABLED' /etc/ufw/ufw.conf", FW_TIMEOUT_MS);
          return { name: "ufw", active: /yes/i.test(conf) };
        } catch (_) {
          return { name: "ufw", active: false };
        }
      }
      if (await commandExists("firewall-cmd")) {
        try {
          const st = await execCommand("firewall-cmd --state", FW_TIMEOUT_MS);
          return { name: "firewalld", active: /running/i.test(st) };
        } catch (_) {
          return { name: "firewalld", active: false };
        }
      }
      if (await commandExists("nft")) {
        try {
          const st = await execCommand("systemctl is-active nftables", FW_TIMEOUT_MS);
          return { name: "nftables", active: st.trim() === "active" };
        } catch (_) {
          return { name: "nftables", active: false };
        }
      }
      return { name: null, active: false };
    }

    if (plat === "darwin") {
      try {
        const st = await execCommand(
          "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
          FW_TIMEOUT_MS
        );
        return { name: "alf", active: /enabled/i.test(st) };
      } catch (_) {
        return { name: "alf", active: false };
      }
    }

    if (plat === "win32") {
      try {
        const st = await execCommand("netsh advfirewall show currentprofile state", FW_TIMEOUT_MS);
        return { name: "windows", active: /\bON\b/i.test(st) || /activad/i.test(st) };
      } catch (_) {
        return { name: "windows", active: false };
      }
    }
  } catch (_) { /* nunca bloquear la auditoría por esto */ }

  return { name: null, active: false };
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Enriquece un array de puertos abiertos con información de proceso.
 * Los puertos se procesan en paralelo con Promise.allSettled; si un puerto
 * falla, el resto continúa y ese puerto se devuelve sin enriquecer.
 *
 * @param {PortResult[]} openPorts  Array de puertos devuelto por runNmap()
 * @returns {Promise<EnrichedPort[]>}
 */
async function enrichPorts(openPorts) {
  if (!Array.isArray(openPorts) || openPorts.length === 0) return [];

  const enrich = process.platform === "win32" ? enrichWindows : enrichUnix;

  const results = await Promise.allSettled(
    openPorts.map((p) => enrich(p.port))
  );

  return openPorts.map((p, i) => {
    const enrichment = results[i].status === "fulfilled" ? results[i].value : {};
    return { ...p, ...enrichment };
  });
}

module.exports = { enrichPorts, detectFirewall };
