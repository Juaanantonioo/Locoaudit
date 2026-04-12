"use strict";

/**
 * docker-api.js — Recolección de información de Docker vía CLI.
 *
 * Obtiene el inventario de imágenes y contenedores del daemon Docker local
 * usando exclusivamente comandos CLI (`docker images`, `docker ps`), sin
 * conectarse directamente al socket Unix `/var/run/docker.sock`.
 *
 * ── Por qué CLI y no el socket directo ───────────────────────────────────────
 *
 * La alternativa natural sería llamar a la API REST de Docker a través de
 * /var/run/docker.sock (o el named pipe en Windows), que ofrece respuestas
 * JSON estructuradas sin parsear.  Sin embargo, ese enfoque requiere una
 * librería HTTP con soporte de Unix sockets (ej: 'dockerode') o llamadas
 * manuales a `http.request` con socketPath, lo que añade complejidad y una
 * dependencia externa.
 *
 * Usar la CLI de Docker:
 *   - No requiere ninguna dependencia npm adicional.
 *   - Es totalmente compatible con Docker Desktop en macOS y Windows, que
 *     expone la CLI pero puede tener el socket en rutas no estándar.
 *   - El formato --format con plantillas Go produce salida estructurada y
 *     delimitada que es trivial de parsear con split("|").
 *   - El comportamiento es idéntico en Linux, macOS y Windows (WSL2).
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas requeridas:
 *   si docker no está instalado o el daemon no responde → { skipped: true }
 *
 * Exporta:
 *   getDockerInfo() → Promise<DockerInfo>
 *
 * @typedef {{ id: string, repository: string, tag: string, sizeBytes: number, created: string }} DockerImage
 * @typedef {{ id: string, name: string, image: string, status: string, running: boolean, ports: string }} DockerContainer
 * @typedef {{ skipped: true, reason: string } | { skipped: false, images: DockerImage[], containers: DockerContainer[] }} DockerInfo
 */

const { execCommand, commandExists } = require("../../../lib/executor");

// ── Parsers ───────────────────────────────────────────────────────────────────

/**
 * Convierte el string de tamaño de imagen de Docker a bytes.
 * Docker usa sufijos como "45.2MB", "1.2GB", "512kB", "1.024 kB".
 * Si el formato no es reconocible devuelve 0.
 *
 * @param {string} sizeStr  Cadena de tamaño (ej: "45.2MB", "1.2GB")
 * @returns {number}
 */
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

/**
 * Parsea la salida de:
 *   docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"
 *
 * @param {string} stdout
 * @returns {DockerImage[]}
 */
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

/**
 * Parsea la salida de:
 *   docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"
 *
 * @param {string} stdout
 * @returns {DockerContainer[]}
 */
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

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Recolecta información del daemon Docker local.
 * Devuelve { skipped: true } si Docker no está instalado o el daemon no responde.
 *
 * @returns {Promise<DockerInfo>}
 */
async function getDockerInfo() {
  // 1. Docker CLI disponible
  const available = await commandExists("docker");
  if (!available) {
    return { skipped: true, reason: "docker not installed" };
  }

  // 2. Daemon activo
  try {
    await execCommand('docker info --format "{{.ServerVersion}}"', 10000);
  } catch (_) {
    return { skipped: true, reason: "docker daemon not running" };
  }

  // 3. Imágenes
  let images = [];
  try {
    const imgOut = await execCommand(
      'docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"',
      15000
    );
    images = parseImages(imgOut);
  } catch (_) { /* devolver array vacío, no propagar */ }

  // 4. Contenedores
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
