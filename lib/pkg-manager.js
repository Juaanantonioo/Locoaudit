"use strict";

/**
 * Gestor de paquetes real del sistema. Los fixes estáticos asumían apt en Linux y brew en macOS,
 * y en Arch, openSUSE o Alpine el paso de resolución quedaba inejecutable. Aquí no se adivina:
 * se comprueba el binario con commandExists, y sin gestor identificado se devuelve null para que
 * el llamante emita prosa en vez de un comando inventado.
 */

const { commandExists } = require("./executor");

// Orden de sondeo. En Linux gana el primero que exista: quien tiene pacman no tiene apt.
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

// Una línea ejecutable por entrada: la nota explicativa nunca se concatena aquí.
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

// El Type de Trivy es un dato del propio escaneo: aquí sí se mapea sin sondear nada.
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

/** Gestor de paquetes realmente instalado, o null si no se identifica ninguno. */
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
  // La versión no se fija: el gestor instala la del repo, y `pkg=ver` fallaría si no la tiene.
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
