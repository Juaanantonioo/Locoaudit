"use strict";

/**
 * utils.js — Utilidades genéricas compartidas por todos los nodos.
 *
 * Exporta:
 *   bytesToMiB(bytes)   → number
 *   bytesToGiB(bytes)   → number
 *   safeFileName(iso)   → string  (ISO 8601 → nombre de fichero seguro)
 *   escHtml(str)        → string  (escapa caracteres HTML especiales)
 */

/**
 * Convierte bytes a mebibytes, redondeando a 1 decimal.
 * @param {number} bytes
 * @returns {number}
 */
function bytesToMiB(bytes) {
  return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

/**
 * Convierte bytes a gibibytes, redondeando a 2 decimales.
 * @param {number} bytes
 * @returns {number}
 */
function bytesToGiB(bytes) {
  return Math.round((bytes / (1024 * 1024 * 1024)) * 100) / 100;
}

/**
 * Convierte una cadena ISO 8601 a un nombre de fichero seguro
 * reemplazando ':' y '.' por '-'.
 * @param {string} iso
 * @returns {string}
 */
function safeFileName(iso) {
  return iso.replace(/[:.]/g, "-");
}

/**
 * Escapa caracteres especiales HTML para evitar XSS en plantillas.
 * @param {*} str
 * @returns {string}
 */
function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

module.exports = { bytesToMiB, bytesToGiB, safeFileName, escHtml };
