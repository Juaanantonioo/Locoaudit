# launcher/lcaudit_launcher.py

import subprocess
import sys
import shutil
import platform
import os

# ─────────────────────────────────────────────
#  Colores ANSI
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def info(msg): print(f"  {BLUE}→{RESET}  {msg}")
def sep():     print(f"  {'─' * 52}")

# ─────────────────────────────────────────────
#  Detección de plataforma
# ─────────────────────────────────────────────
OS = platform.system()  # 'Darwin' | 'Linux' | 'Windows'

# ─────────────────────────────────────────────
#  Instrucciones de instalación por herramienta y SO
# ─────────────────────────────────────────────
INSTALL_GUIDE = {
    "node": {
        "Darwin":  "brew install node",
        "Linux":   "sudo apt install nodejs npm   # o https://nodejs.org",
        "Windows": "Descarga el instalador en https://nodejs.org",
    },
    "npm": {
        "Darwin":  "Se instala junto con Node.js: brew install node",
        "Linux":   "sudo apt install npm",
        "Windows": "Se instala junto con Node.js desde https://nodejs.org",
    },
    "node-red": {
        "Darwin":  "npm install -g --unsafe-perm node-red",
        "Linux":   "sudo npm install -g --unsafe-perm node-red",
        "Windows": "npm install -g --unsafe-perm node-red",
    },
    "docker": {
        "Darwin":  "Descarga Docker Desktop en https://www.docker.com/products/docker-desktop",
        "Linux":   "sudo apt install docker.io && sudo systemctl start docker",
        "Windows": "Descarga Docker Desktop en https://www.docker.com/products/docker-desktop",
    },
    "nmap": {
        "Darwin":  "brew install nmap",
        "Linux":   "sudo apt install nmap",
        "Windows": "Descarga el instalador en https://nmap.org/download.html",
    },
    "lynis": {
        "Darwin":  "brew install lynis",
        "Linux":   "sudo apt install lynis",
        "Windows": "Lynis no está disponible en Windows sin WSL — instala WSL primero: https://learn.microsoft.com/en-us/windows/wsl/install",
    },
    "trivy": {
        "Darwin":  "brew install aquasecurity/trivy/trivy",
        "Linux":   "sudo apt install trivy   # o https://aquasecurity.github.io/trivy",
        "Windows": "Consulta https://aquasecurity.github.io/trivy/latest/getting-started/installation",
    },
}

# ─────────────────────────────────────────────
#  Qué audita cada herramienta opcional
# ─────────────────────────────────────────────
TOOL_DESCRIPTION = {
    "nmap":   "audit-network — escaneo avanzado de puertos y servicios",
    "lynis":  "audit-host   — configuración insegura del SO y hardening (no disponible en Windows sin WSL)",
    "trivy":  "audit-host + audit-image — CVEs en paquetes del SO e imágenes Docker",
    "docker": "audit-image  — auditoría de imágenes y contenedores Docker",
}

# ─────────────────────────────────────────────
#  Dependencias
#  (cmd, label, required, extra_check)
# ─────────────────────────────────────────────
DEPENDENCIES = [
    # — Requeridas —
    ("node",     "Node.js",   True,  lambda: check_min_version("node", "--version", 18)),
    ("npm",      "npm",       True,  None),
    ("node-red", "Node-RED",  True,  None),
    # — Requerida para audit-image —
    ("docker",   "Docker",    False, lambda: check_docker_running()),
    # — Opcionales —
    ("nmap",     "Nmap",      False, None),
    ("lynis",    "Lynis",     False, lambda: check_lynis_windows()),
    ("trivy",    "Trivy",     False, None),
]

# ─────────────────────────────────────────────
#  Funciones de comprobación
# ─────────────────────────────────────────────
def command_exists(cmd):
    return shutil.which(cmd) is not None

def check_min_version(cmd, flag, min_major):
    """Comprueba que la versión mayor sea >= min_major."""
    try:
        result = subprocess.run([cmd, flag], capture_output=True, text=True, timeout=5)
        version_str = result.stdout.strip().lstrip('v')
        major = int(version_str.split('.')[0])
        if major < min_major:
            return f"versión {version_str} detectada — se recomienda v{min_major} o superior"
        return None
    except Exception:
        return "no se pudo determinar la versión"

def check_docker_running():
    """Comprueba que el daemon de Docker esté activo."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return "Docker instalado pero el daemon no está en ejecución — ábrelo primero"
        return None
    except Exception:
        return "no se pudo conectar con Docker"

def check_lynis_windows():
    """Avisa si se intenta usar Lynis en Windows sin WSL."""
    if OS == "Windows":
        return "Lynis no es compatible con Windows de forma nativa — usa WSL"
    return None

def get_install_cmd(tool):
    return INSTALL_GUIDE.get(tool, {}).get(OS, "Consulta la documentación oficial")

# ─────────────────────────────────────────────
#  Comprobación principal
# ─────────────────────────────────────────────
def check_dependencies():
    print(f"\n{BOLD}  LoCoAudit — comprobación de dependencias{RESET}")
    print(f"  Sistema: {OS} ({platform.machine()})\n")

    sep()
    print(f"  {BOLD}Dependencias requeridas{RESET}")
    sep()

    all_required_ok = True
    missing_required = []
    optional_missing = []
    optional_warnings = []

    for cmd, label, required, extra_check in DEPENDENCIES:
        if not required:
            continue
        if not command_exists(cmd):
            fail(f"{label} no encontrado")
            info(f"Instálalo con: {BOLD}{get_install_cmd(cmd)}{RESET}")
            missing_required.append(label)
            all_required_ok = False
        else:
            warning = extra_check() if extra_check else None
            if warning:
                warn(f"{label} instalado — {warning}")
            else:
                ok(f"{label} instalado")

    print()
    sep()
    print(f"  {BOLD}Herramientas opcionales{RESET}")
    sep()

    for cmd, label, required, extra_check in DEPENDENCIES:
        if required:
            continue
        desc = TOOL_DESCRIPTION.get(cmd, "")
        if not command_exists(cmd):
            warn(f"{label} no encontrado — {desc}")
            info(f"Instálalo con: {BOLD}{get_install_cmd(cmd)}{RESET}")
            optional_missing.append(label)
        else:
            warning = extra_check() if extra_check else None
            if warning:
                warn(f"{label} instalado — {warning}")
                optional_warnings.append(label)
            else:
                ok(f"{label} instalado — {desc}")

    return all_required_ok, missing_required, optional_missing, optional_warnings

# ─────────────────────────────────────────────
#  Resumen
# ─────────────────────────────────────────────
def print_summary(all_required_ok, missing_required, optional_missing, optional_warnings):
    print()
    sep()

    if missing_required:
        print(f"  {RED}{BOLD}Faltan dependencias requeridas: {', '.join(missing_required)}{RESET}")
        print(f"  Node-RED no se iniciará hasta que estén instaladas.\n")
        return

    if optional_missing:
        print(f"  {YELLOW}Herramientas opcionales no disponibles: {', '.join(optional_missing)}{RESET}")
        print(f"  Algunos nodos tendrán funcionalidad limitada o desactivada.\n")

    if not optional_missing and not optional_warnings:
        print(f"  {GREEN}{BOLD}Todo listo. Iniciando Node-RED...{RESET}\n")
    else:
        print(f"  {YELLOW}{BOLD}Dependencias requeridas OK. Iniciando Node-RED con funcionalidad parcial...{RESET}\n")

# ─────────────────────────────────────────────
#  Arranque de Node-RED
# ─────────────────────────────────────────────
def launch_node_red():
    try:
        cmd = ["node-red.cmd"] if OS == "Windows" else ["node-red"]
        print(f"  {BLUE}Ejecutando:{RESET} {' '.join(cmd)}\n")
        sep()
        print()
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Node-RED detenido por el usuario.{RESET}\n")
    except FileNotFoundError:
        fail("No se pudo lanzar node-red. Comprueba que está en el PATH.")
        sys.exit(1)

# ─────────────────────────────────────────────
#  Punto de entrada
# ─────────────────────────────────────────────
if __name__ == "__main__":
    all_ok, missing_req, opt_missing, opt_warn = check_dependencies()
    print_summary(all_ok, missing_req, opt_missing, opt_warn)

    if not all_ok:
        sys.exit(1)

    launch_node_red()
