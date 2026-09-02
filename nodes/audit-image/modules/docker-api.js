"use strict";

/**
 * Inventario de imágenes y contenedores por CLI, no por el socket. El socket daría JSON sin
 * parsear, pero pide una librería con soporte de Unix sockets o un http.request con socketPath, y
 * con Docker Desktop en macOS y Windows el socket puede estar en rutas no estándar. La CLI se
 * comporta igual en los tres sistemas y con --format sale delimitada. Sin docker o sin daemon,
 * { skipped: true }: dentro de este nodo Docker es requisito, no herramienta opcional.
 */

const { execCommand, commandExists } = require("../../../lib/executor");

/** Docker escribe "45.2MB", "1.2GB", "512kB" o "1.024 kB"; lo que no se reconozca vale 0. */
function parseSizeBytes(sizeStr) {
  if (!sizeStr) return 0;
  const s = sizeStr.trim().replace(/\s+/g, "");
  const match = s.match(/^([\d.]+)(B|kB|KB|MB|GB|TB)$/i);
  if (!match) return 0;

  const value = parseFloat(match[1]);
  const unit  = match[2].toUpperCase();
  const multipliers = { B: 1, KB: 1000, MB: 1e6, GB: 1e9, TB: 1e12 };
  return Math.round(value * (multipliers[unit] ?? 0));
}

/** Salida de `docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"`. */
function parseImages(stdout) {
  const images = [];
  for (const line of stdout.trim().split("\n")) {
    if (!line.trim()) continue;
    const [id, repository, tag, size, created] = line.split("|");
    if (!id) continue;
    images.push({
      id:         (id         || "").trim(),
      repository: (repository || "").trim(),
      tag:        (tag        || "").trim(),
      sizeBytes:  parseSizeBytes((size || "").trim()),
      created:    (created    || "").trim(),
    });
  }
  return images;
}

/** Salida de `docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"`. */
function parseContainers(stdout) {
  const containers = [];
  for (const line of stdout.trim().split("\n")) {
    if (!line.trim()) continue;
    const [id, name, image, status, ports] = line.split("|");
    if (!id) continue;
    const statusStr = (status || "").trim();
    containers.push({
      id:      (id    || "").trim(),
      name:    (name  || "").trim(),
      image:   (image || "").trim(),
      status:  statusStr,
      running: statusStr.startsWith("Up"),
      ports:   (ports || "").trim(),
    });
  }
  return containers;
}

/** { skipped: true } si falta el CLI o el daemon no contesta: son dos fallos distintos. */
async function getDockerInfo() {
  const available = await commandExists("docker");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Docker no está instalado en este equipo" };
  }

  try {
    await execCommand('docker info --format "{{.ServerVersion}}"', 10000);
  } catch (_) {
    return { skipped: true, kind: "daemon-down", reason: "Docker está instalado pero su servicio no responde" };
  }

  let images = [];
  try {
    const imgOut = await execCommand(
      'docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"',
      15000
    );
    images = parseImages(imgOut);
  } catch (_) { /* devolver array vacío, no propagar */ }

  let containers = [];
  try {
    const psOut = await execCommand(
      'docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"',
      15000
    );
    containers = parseContainers(psOut);
  } catch (_) { /* devolver array vacío, no propagar */ }

  return { skipped: false, images, containers };
}

module.exports = { getDockerInfo, parseSizeBytes };
