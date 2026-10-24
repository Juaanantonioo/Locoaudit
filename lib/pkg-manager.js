"use strict";

/** Gestor de paquetes real del sistema, comprobado con commandExists. Sin gestor identificado
 *  se devuelve null y el llamante escribe prosa en vez de inventar un comando. */

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
    install: (p)    => `sudo pacman -S --noconfirm ${p}`,
    upgrade: (p)    => `sudo pacman -Syu ${p}`,
    remove:  (p)    => `sudo pacman -Rns ${p}`,
    all:     ()     => "sudo pacman -Syu",
  },
  apt: {
    install: (p)    => `sudo apt update && sudo apt install -y ${p}`,
    upgrade: (p)    => `sudo apt update && sudo apt install --only-upgrade ${p}`,
    remove:  (p)    => `sudo apt remove --purge ${p}`,
    all:     ()     => "sudo apt update && sudo apt upgrade",
  },
  dnf: {
    install: (p)    => `sudo dnf install -y ${p}`,
    upgrade: (p)    => `sudo dnf upgrade ${p}`,
    remove:  (p)    => `sudo dnf remove ${p}`,
    all:     ()     => "sudo dnf upgrade",
  },
  yum: {
    install: (p)    => `sudo yum install -y ${p}`,
    upgrade: (p)    => `sudo yum update ${p}`,
    remove:  (p)    => `sudo yum remove ${p}`,
    all:     ()     => "sudo yum update",
  },
  zypper: {
    install: (p)    => `sudo zypper install -y ${p}`,
    upgrade: (p)    => `sudo zypper update ${p}`,
    remove:  (p)    => `sudo zypper remove ${p}`,
    all:     ()     => "sudo zypper update",
  },
  apk: {
    install: (p)    => `sudo apk add ${p}`,
    upgrade: (p)    => `sudo apk upgrade ${p}`,
    remove:  (p)    => `sudo apk del ${p}`,
    all:     ()     => "sudo apk upgrade",
  },
  emerge: {
    install: (p)    => `sudo emerge ${p}`,
    upgrade: (p)    => `sudo emerge --update ${p}`,
    remove:  (p)    => `sudo emerge --unmerge ${p}`,
    all:     ()     => "sudo emerge --update --deep @world",
  },
  brew: {
    install: (p)    => `brew install ${p}`,
    upgrade: (p)    => `brew upgrade ${p}`,
    remove:  (p)    => `brew uninstall ${p}`,
    all:     ()     => "brew update && brew upgrade",
  },
  port: {
    install: (p)    => `sudo port install ${p}`,
    upgrade: (p)    => `sudo port upgrade ${p}`,
    remove:  (p)    => `sudo port uninstall ${p}`,
    all:     ()     => "sudo port selfupdate && sudo port upgrade outdated",
  },
  winget: {
    install: (p)    => `winget install ${p}`,
    upgrade: (p)    => `winget upgrade ${p}`,
    remove:  (p)    => `winget uninstall ${p}`,
    all:     ()     => "winget upgrade --all",
  },
  choco: {
    install: (p)    => `choco install ${p}`,
    upgrade: (p)    => `choco upgrade ${p}`,
    remove:  (p)    => `choco uninstall ${p}`,
    all:     ()     => "choco upgrade all",
  },
  scoop: {
    install: (p)    => `scoop install ${p}`,
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

/** Comando de instalación de un paquete, o null. Muchos controles de Lynis se resuelven instalando algo que falta. */
function installCmd(mgr, pkg) {
  if (!mgr || !COMMANDS[mgr] || !COMMANDS[mgr].install || !pkg) return null;
  return COMMANDS[mgr].install(pkg);
}

/** Comando de actualización de UN paquete, o null si no hay gestor conocido. */
function upgradeCmd(mgr, pkg) {
  if (!mgr || !COMMANDS[mgr] || !pkg) return null;
  // Sin fijar versión: `pkg=ver` fallaría si el repo no la tiene.
  return COMMANDS[mgr].upgrade(pkg);
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
  installCmd,
  upgradeCmd,
  removeCmd,
  updateAllCmd,
  managerLabel,
  managerForTrivyType,
  TRIVY_TYPE_TO_MANAGER,
};
