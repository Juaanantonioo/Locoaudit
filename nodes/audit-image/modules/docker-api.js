"use strict";

// Inventario de imágenes y contenedores por la CLI: se comporta igual en los tres sistemas, el socket no.
// Sin docker o sin daemon devuelve { skipped, kind, reason }.

const { ejecutar, existeComando } = require("../../../lib/executor");

// "45.2MB", "1.2GB", "512kB"… a bytes; lo que no se reconozca vale 0.
function leerBytes(sizeStr) {
  if (!sizeStr) return 0;
  const s = sizeStr.trim().replace(/\s+/g, "");
  const match = s.match(/^([\d.]+)(B|kB|KB|MB|GB|TB)$/i);
  if (!match) return 0;

  const value = parseFloat(match[1]);
  const unit  = match[2].toUpperCase();
  const multipliers = { B: 1, KB: 1000, MB: 1e6, GB: 1e9, TB: 1e12 };
  return Math.round(value * (multipliers[unit] ?? 0));
}

// Salida de `docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"`.
function leerImagenes(stdout) {
  const images = [];
  for (const line of stdout.trim().split("\n")) {
    if (!line.trim()) continue;
    const [id, repository, tag, size, created] = line.split("|");
    if (!id) continue;
    images.push({
      id:         (id         || "").trim(),
      repository: (repository || "").trim(),
      tag:        (tag        || "").trim(),
      sizeBytes:  leerBytes((size || "").trim()),
      created:    (created    || "").trim(),
    });
  }
  return images;
}

// Salida de `docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"`.
function leerContenedores(stdout) {
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

// Distingue CLI ausente (not-installed) de daemon que no contesta (daemon-down).
async function infoDocker() {
  const available = await existeComando("docker");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Docker no está instalado en este equipo" };
  }

  // Sirve para saber si el daemon contesta y se guarda para poder reproducir el informe.
  let serverVersion = null;
  try {
    serverVersion = String(await ejecutar('docker info --format "{{.ServerVersion}}"', 10000)).trim() || null;
  } catch (_) {
    return { skipped: true, kind: "daemon-down", reason: "Docker está instalado pero su servicio no responde" };
  }

  // Si un listado falla se guarda el motivo: una lista vacía parecería "no hay nada".
  let images = [];
  let imagesError = null;
  try {
    const imgOut = await ejecutar(
      'docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"',
      15000
    );
    images = leerImagenes(imgOut);
  } catch (e) { imagesError = String((e && e.message) || e || "sin detalle"); }

  let containers = [];
  let containersError = null;
  try {
    const psOut = await ejecutar(
      'docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"',
      15000
    );
    containers = leerContenedores(psOut);
  } catch (e) { containersError = String((e && e.message) || e || "sin detalle"); }

  return { skipped: false, images, containers, serverVersion, imagesError, containersError };
}

module.exports = { infoDocker, leerBytes };
