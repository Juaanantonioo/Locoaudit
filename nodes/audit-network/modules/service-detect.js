"use strict";

/**
 * service-detect.js — Enriquecimiento de puertos abiertos con información de proceso.
 *
 * Este módulo es complementario a port-scanner.js: donde el escáner determina
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
 *
 * @typedef {{ port: number, protocol: string, state: string, service: string, severity: string, fix: string|null }} PortResult
 * @typedef {{ pid?: number, process?: string, extra?: string }} Enrichment
 * @typedef {PortResult & Enrichment} EnrichedPort
 */

const { execCommand } = require("../../../lib/executor");

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
  if (lines.length < 2) return { pid: null, process: null };

  const parts = lines[1].trim().split(/\s+/);
  const processName = parts[0] || null;
  const pid = parts[1] ? parseInt(parts[1], 10) : null;

  return {
    pid:     isNaN(pid) ? null : pid,
    process: processName,
  };
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
    const { pid, process: procName } = parseLsof(stdout);
    if (!pid && !procName) return {};
    return {
      pid:   pid    ?? undefined,
      process: procName ?? undefined,
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

    const taskOut = await execCommand(
      `tasklist /FI "PID eq ${pid}" /FO CSV`,
      ENRICH_TIMEOUT_MS
    );
    const procName = parseTasklist(taskOut);

    return {
      pid,
      process: procName ?? undefined,
    };
  } catch (_) {
    return {};
  }
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Enriquece un array de puertos abiertos con información de proceso.
 * Los puertos se procesan en paralelo con Promise.allSettled; si un puerto
 * falla, el resto continúa y ese puerto se devuelve sin enriquecer.
 *
 * @param {PortResult[]} openPorts  Array devuelto por scanPorts()
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

module.exports = { enrichPorts };
