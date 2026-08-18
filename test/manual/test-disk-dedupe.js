"use strict";

/**
 * test-disk-dedupe.js — Una entrada por SISTEMA DE FICHEROS, no por montaje.
 *
 * En btrfs el layout por defecto (CachyOS, Fedora, openSUSE) monta 6-8
 * subvolúmenes desde el mismo dispositivo. `df` repite la misma fila una vez
 * por montaje, así que `fromDisk()` generaba un HOST-DISK-* por subvolumen:
 * el mismo disco contado 7 veces en la cabecera y en el donut del dashboard.
 *
 * Comprueba, contra salidas reales de `df` (ver test/fixtures/df/README.md):
 *   1. btrfs real: 7 filas del mismo dispositivo → 1 entrada.
 *   2. CachyOS: recuento antes/después y desaparición de los tmpfs.
 *   3. macOS APFS: NO cambia nada (cada volumen tiene su propio dispositivo).
 *   4. ZFS: los datasets de un pool se agrupan por pool, y dos pools no se mezclan.
 *   5. Degradación sin columna Type (busybox): el deduplicado sigue funcionando.
 *   6. fromDisk() emite exactamente un finding por entrada.
 *
 * Uso:
 *   node test/manual/test-disk-dedupe.js
 */

const fs = require("fs");
const path = require("path");
const { parseDfOutput } = require("../../nodes/audit-host/modules/disk-storage");
const { normalizeHost } = require("../../lib/normalizer");

const FIX = path.join(__dirname, "..", "fixtures", "df");
const read = (f) => fs.readFileSync(path.join(FIX, f), "utf8");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const mounts = (d) => d.map((x) => x.mount).join(", ");

// ── 1 · btrfs real (contenedor privilegiado, mkfs.btrfs de verdad) ───────────
console.log("\n── 1 · btrfs real: 7 subvolúmenes, un solo dispositivo ───────────\n");

const real = parseDfOutput(read("linux-btrfs-real-container.txt"), true);
const btrfsReal = real.filter((d) => d.fsType === "btrfs");

ok(btrfsReal.length === 1, `7 filas btrfs → ${btrfsReal.length} entrada(s)`, "esperado 1");
ok(btrfsReal[0] && btrfsReal[0].mounts.length === 7,
   `conserva los 7 puntos de montaje (${btrfsReal[0] && btrfsReal[0].mounts.length})`);
ok(btrfsReal[0] && btrfsReal[0].mount === "/mnt/sys",
   `montaje representativo = el más corto ("${btrfsReal[0] && btrfsReal[0].mount}")`);
ok(!real.some((d) => d.fsType === "overlay" || d.fsType === "tmpfs"),
   "descarta overlay y tmpfs (no son almacenamiento)");
ok(!real.some((d) => d.totalGB < 1), "descarta volúmenes < 1 GB (el vfat de 511 MB)");

// ── 2 · CachyOS: el recuento que inflaba el dashboard ────────────────────────
console.log("\n── 2 · CachyOS (btrfs + tmpfs de systemd) ────────────────────────\n");

const cachy = parseDfOutput(read("linux-btrfs-cachyos.txt"), true);

// Recuento del comportamiento ANTERIOR: una entrada por montaje, sin filtrar
// pseudo-filesystems — exactamente lo que hacía el parser previo.
function countLegacy(stdout) {
  return stdout.trim().split("\n").slice(1).filter((line) => {
    const p = line.trim().split(/\s+/);
    if (p.length < 7) return false;
    const totalKB = parseInt(p[2], 10);
    const mount = p[p.length - 1];
    if (isNaN(totalKB) || totalKB === 0) return false;
    if (!mount.startsWith("/") || mount === "/dev") return false;
    // Mismo redondeo que el parser original antes de comparar con 1 GB.
    return Math.round((totalKB * 1024) / (1024 ** 3) * 100) / 100 >= 1;
  }).length;
}

const legacy = countLegacy(read("linux-btrfs-cachyos.txt"));
ok(legacy === 12, `antes: ${legacy} findings de disco`, "esperado 12");
ok(cachy.length === 2, `después: ${cachy.length} findings de disco (${mounts(cachy)})`, "esperado 2");
ok(cachy.some((d) => d.mount === "/" && d.mounts.length === 7),
   "los 7 subvolúmenes btrfs quedan bajo la entrada de /");
ok(!cachy.some((d) => ["/run", "/tmp", "/dev/shm", "/run/user/1000"].includes(d.mount)),
   "los tmpfs ya no son 'discos'");
ok(cachy.some((d) => d.mount === "/boot" && d.fsType === "ext4"),
   "/boot sigue siendo su propia entrada (partición distinta)");
ok(!cachy.some((d) => d.mount === "/efi"), "/efi (511 MB) sigue descartado por tamaño");

// ── 3 · macOS APFS: no-regresión ─────────────────────────────────────────────
console.log("\n── 3 · macOS APFS: el deduplicado no cambia nada ─────────────────\n");

const mac = parseDfOutput(read("macos-apfs-real.txt"), false);
ok(mac.length === 2, `${mac.length} entradas (${mounts(mac)})`, "esperado 2");
ok(mac.every((d) => d.mounts.length === 1), "ningún volumen APFS se agrupa con otro");
ok(mac[0].mount === "/" && mac[1].mount === "/System/Volumes/Data",
   "mismos montajes que antes del cambio");
ok(mac[0].usedPercent === 3 && mac[1].usedPercent === 76,
   `mismos porcentajes (${mac[0].usedPercent}%, ${mac[1].usedPercent}%)`);
ok(mac[0].totalGB === 460.43 && mac[1].usedGB === 351.64,
   "mismas cifras de capacidad");

// ── 4 · ZFS: agrupa por pool, no por dataset ─────────────────────────────────
console.log("\n── 4 · ZFS: los datasets comparten el espacio libre del pool ─────\n");

const zfs = parseDfOutput(read("linux-zfs.txt"), true);
const pools = zfs.filter((d) => d.fsType === "zfs");
ok(pools.length === 2, `2 pools → ${pools.length} entradas (${mounts(pools)})`, "esperado 2");

const rpool = pools.find((d) => d.device.startsWith("rpool"));
ok(rpool && rpool.mounts.length === 4,
   `rpool agrupa sus 4 datasets (${rpool && rpool.mounts.join(" ")})`);
// El usado se SUMA (cada dataset tiene datos propios); el libre es el del pool,
// idéntico en todas las filas, así que se toma una sola vez.
ok(rpool && rpool.usedGB === 82.07,
   `rpool usado = suma de los datasets (${rpool && rpool.usedGB} GB)`, "esperado 82.07");
ok(rpool && rpool.freeGB === 341.05,
   `rpool libre = el del pool, no la suma (${rpool && rpool.freeGB} GB)`, "esperado 341.05");
ok(pools.every((d) => !d.mounts.includes("/mnt/media") || d.device.startsWith("tank")),
   "tank no se mezcla con rpool");
ok(zfs.some((d) => d.mount === "/boot" && d.fsType === "ext4"),
   "el ext4 fuera del pool conserva su entrada");

// ── 5 · Sin columna Type (busybox): degradación ──────────────────────────────
console.log("\n── 5 · df sin -T (busybox): el deduplicado sigue vivo ────────────\n");

const bb = parseDfOutput(read("linux-btrfs-busybox-notype.txt"), false);
ok(bb.length === 2, `${bb.length} entradas (${mounts(bb)})`, "esperado 2: / y /boot");
ok(bb.some((d) => d.mount === "/" && d.mounts.length === 3),
   "los 3 montajes de /dev/nvme0n1p2 se agrupan sin conocer el tipo");
ok(bb.every((d) => d.fsType === null), "fsType es null cuando df no lo reporta");
ok(!bb.some((d) => ["/run", "/tmp", "/dev/shm"].includes(d.mount)),
   "los tmpfs se descartan por nombre de dispositivo");

// ── 6 · fromDisk(): un finding por entrada ───────────────────────────────────
console.log("\n── 6 · normalizeHost: un HOST-DISK-* por sistema de ficheros ─────\n");

const findings = normalizeHost({ disk: cachy }, "native")
  .filter((f) => f.category === "disk");
ok(findings.length === cachy.length,
   `${cachy.length} entradas → ${findings.length} findings HOST-DISK-*`);
ok(new Set(findings.map((f) => f.id)).size === findings.length, "los IDs no se repiten");

const raiz = findings.find((f) => f.evidence.startsWith("Montaje: /,"));
ok(!!raiz && /Compartido con:/.test(raiz.evidence),
   "la evidencia del disco compartido nombra los demás montajes",
   raiz && raiz.evidence);

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
