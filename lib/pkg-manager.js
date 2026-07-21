"use strict";

/**
 * pkg-manager.js — Gestor de paquetes REAL del sistema.
 *
 * Motivo: los fixes estáticos asumían apt en Linux y brew en macOS. En Arch
 * (pacman), openSUSE (zypper) o Alpine (apk) esos comandos no existen, así que
 * el paso de resolución era literalmente inejecutable en la máquina del usuario.
 *
 * Aquí NO se adivina: se comprueba qué binario existe realmente
 * (`commandExists`) y solo entonces se construye el comando. Si no se identifica
 * ninguno, las funciones devuelven null y quien llama debe emitir prosa —
 * nunca un comando inventado.
 *
 * API pública:
 *   detectPackageManager(platform)   → Promise<string|null>   'pacman'|'apt'|…
 *   upgradeCmd(mgr, pkg, ver)        → string|null
 *   removeCmd(mgr, pkg)              → string|null
 *   updateAllCmd(mgr)                → string|null
 *   managerLabel(mgr)                → string
 */

const { commandExists } = require("./executor");

// Orden de sondeo por plataforma. En Linux el primero que exista gana: un
// sistema con pacman NO tiene apt, así que no hay ambigüedad real.
const PROBE_ORDER = {
  linux:  ["pacman", "apt", "dnf", "yum", "zypper", "apk", "emerge"],
  darwin: ["brew", "port"],
  win32:  ["winget", "choco", "scoop"],
};

const LABELS = {
  pacman: "pacman (Arch)",
  apt:    "apt (Debian/Ubuntu)",
  dnf:    "dnf (Fedora/RHEL)",
  yum:    "yum (RHEL antiguo)",
  zypper: "zypper (openSUSE)",
  apk:    "apk (Alpine)",
  emerge: "emerge (Gentoo)",
  brew:   "Homebrew",
  port:   "MacPorts",
  winget: "winget",
  choco:  "Chocolatey",
  scoop:  "Scoop",
};

// Comandos por gestor. Cada entrada es UNA línea ejecutable: la nota explicativa
// nunca se concatena aquí (ver la regla de "comando ≠ nota" en finding-schema).
const COMMANDS = {
  pacman: {
    upgrade: (p)    => `sudo pacman -Syu ${p}`,
    remove:  (p)    => `sudo pacman -Rns ${p}`,
    all:     ()     => "sudo pacman -Syu",
  },
  apt: {
    upgrade: (p)    => `sudo apt update && sudo apt install --only-upgrade ${p}`,
    remove:  (p)    => `sudo apt remove --purge ${p}`,
    all:     ()     => "sudo apt update && sudo apt upgrade",
  },
  dnf: {
    upgrade: (p)    => `sudo dnf upgrade ${p}`,
    remove:  (p)    => `sudo dnf remove ${p}`,
    all:     ()     => "sudo dnf upgrade",
  },
  yum: {
    upgrade: (p)    => `sudo yum update ${p}`,
    remove:  (p)    => `sudo yum remove ${p}`,
    all:     ()     => "sudo yum update",
  },
  zypper: {
    upgrade: (p)    => `sudo zypper update ${p}`,
    remove:  (p)    => `sudo zypper remove ${p}`,
    all:     ()     => "sudo zypper update",
  },
  apk: {
    upgrade: (p)    => `sudo apk upgrade ${p}`,
    remove:  (p)    => `sudo apk del ${p}`,
    all:     ()     => "sudo apk upgrade",
  },
  emerge: {
    upgrade: (p)    => `sudo emerge --update ${p}`,
    remove:  (p)    => `sudo emerge --unmerge ${p}`,
    all:     ()     => "sudo emerge --update --deep @world",
  },
  brew: {
    upgrade: (p)    => `brew upgrade ${p}`,
    remove:  (p)    => `brew uninstall ${p}`,
    all:     ()     => "brew update && brew upgrade",
  },
  port: {
    upgrade: (p)    => `sudo port upgrade ${p}`,
    remove:  (p)    => `sudo port uninstall ${p}`,
    all:     ()     => "sudo port selfupdate && sudo port upgrade outdated",
  },
  winget: {
    upgrade: (p)    => `winget upgrade ${p}`,
    remove:  (p)    => `winget uninstall ${p}`,
    all:     ()     => "winget upgrade --all",
  },
  choco: {
    upgrade: (p)    => `choco upgrade ${p}`,
    remove:  (p)    => `choco uninstall ${p}`,
    all:     ()     => "choco upgrade all",
  },
  scoop: {
    upgrade: (p)    => `scoop update ${p}`,
    remove:  (p)    => `scoop uninstall ${p}`,
    all:     ()     => "scoop update *",
  },
};

// Type de Trivy (distribución del target escaneado) → gestor. Es un dato
// autoritativo del escaneo, así que aquí sí se puede mapear sin sondear.
const TRIVY_TYPE_TO_MANAGER = {
  debian: "apt", ubuntu: "apt",
  redhat: "dnf", centos: "dnf", rocky: "dnf", alma: "dnf", almalinux: "dnf",
  amazon: "dnf", oracle: "dnf", fedora: "dnf", photon: "dnf",
  mariner: "dnf", "cbl-mariner": "dnf", azurelinux: "dnf",
  suse: "zypper", opensuse: "zypper", "opensuse-leap": "zypper", "opensuse-tumbleweed": "zypper",
  alpine: "apk", wolfi: "apk", chainguard: "apk",
  arch: "pacman", archlinux: "pacman",
  gentoo: "emerge",
};

/**
 * Detecta el gestor de paquetes realmente instalado.
 * @param {string} [platform]  process.platform
 * @returns {Promise<string|null>}  id del gestor, o null si no se identificó
 */
async function detectPackageManager(platform) {
  const plat = platform || process.platform;
  const order = PROBE_ORDER[plat] || [];
  for (const mgr of order) {
    try {
      if (await commandExists(mgr)) return mgr;
    } catch (_) { /* un sondeo fallido no debe romper la auditoría */ }
  }
  return null;
}

/** Comando de actualización de UN paquete, o null si no hay gestor conocido. */
function upgradeCmd(mgr, pkg, ver) {
  if (!mgr || !COMMANDS[mgr] || !pkg) return null;
  const base = COMMANDS[mgr].upgrade(pkg);
  // La versión concreta no se fija en el comando: en gestores de SO se instala
  // la del repositorio. Indicarla como `pkg=ver` fallaría si el repo no la tiene.
  return ver ? base : base;
}

/** Comando de desinstalación, o null si no hay gestor conocido. */
function removeCmd(mgr, pkg) {
  if (!mgr || !COMMANDS[mgr] || !pkg) return null;
  return COMMANDS[mgr].remove(pkg);
}

/** Comando de actualización global del sistema, o null. */
function updateAllCmd(mgr) {
  if (!mgr || !COMMANDS[mgr]) return null;
  return COMMANDS[mgr].all();
}

/** Nombre legible del gestor ("pacman (Arch)"). */
function managerLabel(mgr) {
  return LABELS[mgr] || mgr || "el gestor de paquetes de tu sistema";
}

/** Gestor correspondiente a un Type de Trivy, o null si no se reconoce. */
function managerForTrivyType(type) {
  return TRIVY_TYPE_TO_MANAGER[String(type || "").toLowerCase()] || null;
}

module.exports = {
  detectPackageManager,
  upgradeCmd,
  removeCmd,
  updateAllCmd,
  managerLabel,
  managerForTrivyType,
  TRIVY_TYPE_TO_MANAGER,
};
