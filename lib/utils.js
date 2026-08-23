"use strict";

/**
 * utils.js — Utilidades genéricas compartidas por todos los nodos.
 *
 * Exporta:
 *   bytesToMiB(bytes)   → number
 *   bytesToGiB(bytes)   → number
 *   safeFileName(iso)   → string  (ISO 8601 → nombre de fichero seguro)
 *   escHtml(str)        → string  (escapa caracteres HTML especiales)
 *   withTempFile(content, opts, fn) → Promise  (fichero temporal de un solo uso)
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

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

/**
 * Escribe `content` en un fichero temporal, se lo pasa a `fn`, y lo BORRA pase
 * lo que pase.
 *
 * API de callback y no "devuélveme la ruta" a propósito: el borrado va en un
 * finally que el llamante no puede olvidar. Si `fn` lanza, agota su timeout o
 * el proceso al que alimenta revienta, el fichero se borra igual y el error
 * sigue subiendo sin tocar.
 *
 * ── Nombre aleatorio, y por qué ─────────────────────────────────────────────
 * El directorio temporal es compartido y escribible por otros usuarios. Un
 * nombre predecible permitiría a un tercero crear ahí de antemano un enlace
 * simbólico apuntando a otro fichero, y nuestra escritura acabaría en el
 * destino del enlace, con nuestros permisos. Dos medidas contra eso:
 *
 *   - 12 bytes de crypto.randomBytes (96 bits, CSPRNG): no adivinable.
 *   - flag "wx" → open(2) con O_CREAT|O_EXCL: si la ruta ya existe, aunque sea
 *     como enlace, la llamada FALLA en vez de escribir a través de él.
 *
 * mode 0600 deja el contenido fuera del alcance de otros usuarios en Unix; en
 * Windows el bit no aplica y el ACL del temporal del usuario es lo que manda.
 *
 * @param {string} content         contenido del fichero
 * @param {Object} [opts]
 * @param {string} [opts.prefix]   prefijo del nombre (para reconocerlo en tmp)
 * @param {string} [opts.ext]      extensión, con punto (".ps1")
 * @param {boolean} [opts.bom]     antepone el BOM de UTF-8 (ver security-events.js)
 * @param {Function} fn            (rutaAbsoluta) → Promise<T> | T
 * @returns {Promise<T>} lo que devuelva `fn`
 */
async function withTempFile(content, opts, fn) {
  const { prefix = "lcaudit-", ext = "", bom = false } = opts || {};
  const name = `${prefix}${crypto.randomBytes(12).toString("hex")}${ext}`;
  const file = path.join(os.tmpdir(), name);
  const data = (bom ? "\uFEFF" : "") + String(content);

  await fs.promises.writeFile(file, data, { encoding: "utf8", mode: 0o600, flag: "wx" });
  try {
    return await fn(file);
  } finally {
    // El borrado nunca puede tapar el error real de `fn`: si falla, se ignora.
    await fs.promises.rm(file, { force: true }).catch(() => {});
  }
}

module.exports = { bytesToMiB, bytesToGiB, safeFileName, escHtml, withTempFile };
