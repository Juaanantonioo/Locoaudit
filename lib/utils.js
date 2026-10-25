"use strict";

/** Utilidades genéricas compartidas por los nodos. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

/** Bytes a MiB, con un decimal. */
function aMiB(bytes) {
  return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

/** Bytes a GiB, con dos decimales. */
function aGiB(bytes) {
  return Math.round((bytes / (1024 * 1024 * 1024)) * 100) / 100;
}

/** ISO 8601 a nombre de fichero: ':' y '.' pasan a '-'. */
function nombreFicheroSeguro(iso) {
  return iso.replace(/[:.]/g, "-");
}

/** Escapa el HTML del texto antes de meterlo en una plantilla. */
function escaparHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Escribe `content` en un temporal, se lo pasa a `fn` y lo borra siempre, aunque `fn` falle.
 *  Nombre aleatorio y flag "wx": en un /tmp compartido no se sigue un enlace simbólico ajeno. */
async function conFicheroTemporal(content, opts, fn) {
  const { prefix = "lcaudit-", ext = "", bom = false } = opts || {};
  const name = `${prefix}${crypto.randomBytes(12).toString("hex")}${ext}`;
  const file = path.join(os.tmpdir(), name);
  let prefijo;
  if (bom) {
    prefijo = "\uFEFF";
  } else {
    prefijo = "";
  }
  const data = prefijo + String(content);

  await fs.promises.writeFile(file, data, { encoding: "utf8", mode: 0o600, flag: "wx" });
  try {
    return await fn(file);
  } finally {
    // El borrado nunca puede tapar el error real de `fn`.
    await fs.promises.rm(file, { force: true }).catch(() => {});
  }
}

/** Salida de Trivy sin Results: ya va en los hallazgos y pesa megas en el mensaje del dashboard. */
function sinResultados(res) {
  if (!res || typeof res !== "object" || !Array.isArray(res.Results)) return res;
  const { Results, ...rest } = res;
  return { ...rest, resultsCount: Results.length };
}

module.exports = { aMiB, aGiB, nombreFicheroSeguro, escaparHtml, conFicheroTemporal, sinResultados };
