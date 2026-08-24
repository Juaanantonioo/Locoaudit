"use strict";

/** Utilidades genéricas compartidas por los nodos. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

/** Bytes a MiB, con un decimal. */
function bytesToMiB(bytes) {
  return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

/** Bytes a GiB, con dos decimales. */
function bytesToGiB(bytes) {
  return Math.round((bytes / (1024 * 1024 * 1024)) * 100) / 100;
}

/** ISO 8601 a nombre de fichero: ':' y '.' pasan a '-'. */
function safeFileName(iso) {
  return iso.replace(/[:.]/g, "-");
}

/** Escapa el HTML del texto antes de meterlo en una plantilla. */
function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Escribe `content` en un temporal, se lo pasa a `fn` y lo borra pase lo que pase. Con callback
 * y no devolviendo la ruta a propósito: el borrado va en un finally que el llamante no puede
 * olvidar, aunque `fn` lance o agote su timeout.
 *
 * El nombre lleva 12 bytes de crypto.randomBytes y se abre con flag "wx" (O_CREAT|O_EXCL): el
 * directorio temporal es compartido, y con un nombre predecible otro usuario podría dejar ahí
 * un enlace simbólico y hacer que escribiéramos en su destino con nuestros permisos; con "wx"
 * la llamada falla en vez de seguir el enlace. mode 0600 en Unix; en Windows manda el ACL.
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
    // El borrado nunca puede tapar el error real de `fn`.
    await fs.promises.rm(file, { force: true }).catch(() => {});
  }
}

module.exports = { bytesToMiB, bytesToGiB, safeFileName, escHtml, withTempFile };
