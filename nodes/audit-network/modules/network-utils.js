"use strict";

/**
 * network-utils.js — Utilidades de parsing y validación para audit-network.
 *
 * Exporta:
 *   parsePortsList(input)             → number[] | null
 *   parseTargets(input)               → string[]
 *   isLocalTarget(target)             → boolean
 *   toBaseUrl(protocol, host, port)   → string
 */

/**
 * Parsea una cadena de puertos con rangos ("80,443,8000-8080") a un array
 * ordenado de números de puerto válidos.
 * Devuelve null si la cadena está vacía.
 *
 * @param {string} input
 * @returns {number[]|null}
 */
function parsePortsList(input) {
  const s = (input || "").trim();
  if (!s) return null;

  const ports = new Set();
  const parts = s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  for (const p of parts) {
    if (p.includes("-")) {
      const [a, b] = p.split("-").map((x) => parseInt(x.trim(), 10));
      if (!Number.isNaN(a) && !Number.isNaN(b) && a > 0 && b <= 65535 && a <= b) {
        for (let i = a; i <= b; i++) ports.add(i);
      }
    } else {
      const n = parseInt(p, 10);
      if (!Number.isNaN(n) && n > 0 && n <= 65535) ports.add(n);
    }
  }

  return Array.from(ports).sort((x, y) => x - y);
}

/**
 * Parsea una cadena de targets separados por coma, punto y coma o nueva línea.
 * Elimina duplicados y cadenas vacías.
 *
 * @param {string} input
 * @returns {string[]}
 */
function parseTargets(input) {
  const raw = String(input || "")
    .split(/[\n,;]/)
    .map((x) => x.trim())
    .filter(Boolean);
  return Array.from(new Set(raw));
}

/**
 * Comprueba si un target es localhost (127.0.0.1, localhost, ::1).
 * @param {string} target
 * @returns {boolean}
 */
function isLocalTarget(target) {
  const t = (target || "").trim().toLowerCase();
  return t === "127.0.0.1" || t === "localhost" || t === "::1";
}

/**
 * Construye una URL base a partir de protocolo, host y puerto,
 * omitiendo el puerto si coincide con el puerto por defecto del protocolo.
 *
 * @param {string} protocol   "http" | "https"
 * @param {string} host
 * @param {number} port
 * @returns {string}
 */
function toBaseUrl(protocol, host, port) {
  const defaultPort = protocol === "https" ? 443 : 80;
  const showPort = port !== defaultPort;
  return `${protocol}://${host}${showPort ? ":" + port : ""}`;
}

module.exports = { parsePortsList, parseTargets, isLocalTarget, toBaseUrl };
