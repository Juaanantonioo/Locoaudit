#!/usr/bin/env python3
"""LoCoAudit — Asistente de onboarding y lanzador de Node-RED.

Pasos:
  1. Verifica dependencias requeridas (node ≥18, npm, node-red)
  2. Ofrece instalar herramientas opcionales (nmap, lynis, trivy, docker)
  3. Registra LoCoAudit en Node-RED
  4. Instala dependencias de Node-RED (@flowfuse/node-red-dashboard)
  5. Carga los flujos de demo si ~/.node-red/flows.json no existe
  6. Arranca Node-RED
"""

import subprocess
import sys
import shutil
import platform
import os
import signal
import tempfile
import json
import threading
import queue
import webbrowser

# ─────────────────────────────────────────────
#  Detección de entorno
# ─────────────────────────────────────────────
OS           = platform.system()          # 'Darwin' | 'Linux' | 'Windows'
ARCH         = platform.machine()
LAUNCHER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(LAUNCHER_DIR)
NODE_RED_DIR = os.path.expanduser("~/.node-red")
FLOWS_SRC    = os.path.join(PROJECT_ROOT, "examples", "flows.json")
FLOWS_DST    = os.path.join(NODE_RED_DIR, "flows.json")
NPM_CMD      = "npm.cmd"      if OS == "Windows" else "npm"
NODE_RED_CMD = "node-red.cmd" if OS == "Windows" else "node-red"
# Settings propios (loopback y guardián de origen); -u fija el userDir, que con --settings no se deduce.
NODE_RED_SETTINGS = os.path.join(LAUNCHER_DIR, "node-red-settings.js")
NODE_RED_ARGS = [NODE_RED_CMD, "--settings", NODE_RED_SETTINGS, "-u", NODE_RED_DIR]


def _read_version() -> str:
    try:
        with open(os.path.join(PROJECT_ROOT, "package.json")) as fh:
            return json.load(fh).get("version", "?")
    except Exception:
        return "?"

VERSION = _read_version()


# ─────────────────────────────────────────────
#  GUI detection
# ─────────────────────────────────────────────
HAS_GUI = False
try:
    import tkinter as _tk
    _t = _tk.Tk(); _t.withdraw(); _t.destroy()
    del _t, _tk
    import sys as _sys; _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); del _sys
    from lcaudit_gui import LoCoAuditGUI
    HAS_GUI = True
except Exception:
    HAS_GUI = False


# ─────────────────────────────────────────────
#  OUTPUT_QUEUE — None = modo terminal
# ─────────────────────────────────────────────
OUTPUT_QUEUE = None  # queue.Queue when GUI is active

# Card buffer para el modo GUI (agrupa los mensajes de cada paso en una tarjeta)
_gui_card_title = ""
_gui_card_items = []  # list of (icon, text, color)
_gui_step_label = ""  # texto del pie del paso actual, para restaurarlo tras instalar


def _gui_flush_card():
    if OUTPUT_QUEUE is not None and _gui_card_items:
        OUTPUT_QUEUE.put({"type": "card", "title": _gui_card_title,
                          "items": list(_gui_card_items)})
        _gui_card_items.clear()


# ─────────────────────────────────────────────
#  Auto-instalar rich si no está disponible
# ─────────────────────────────────────────────
def _ensure_rich() -> bool:
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        pass

    print("  Instalando rich (interfaz visual del launcher)...")

    install_cmds = [
        # Arch / CachyOS / Manjaro (no pip disponible)
        ["sudo", "pacman", "-S", "--noconfirm", "--needed", "python-rich"],
        # Sistemas con pip estándar
        [sys.executable, "-m", "pip", "install", "rich", "--quiet"],
        # Entorno externo (PEP 668: Debian/Ubuntu/Arch modernos)
        [sys.executable, "-m", "pip", "install", "rich", "--quiet", "--break-system-packages"],
    ]

    for cmd in install_cmds:
        try:
            r = subprocess.run(cmd, timeout=120)
            if r.returncode == 0:
                try:
                    import rich  # noqa: F401
                    return True
                except ImportError:
                    continue
        except Exception:
            continue

    print("  No se pudo instalar rich automáticamente.")
    print("  Instálalo manualmente:")
    print("    (Arch/CachyOS)  sudo pacman -S python-rich")
    print("    (Ubuntu/Debian) sudo apt install python3-rich")
    print("    (macOS/pip)     pip install rich")
    print("  El launcher funcionará en modo texto básico.\n")
    return False

RICH = _ensure_rich()

# ─────────────────────────────────────────────
#  Importaciones rich (condicionales)
# ─────────────────────────────────────────────
if RICH:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Confirm
    from rich import box as rbox
    console = Console(highlight=False)

# ─────────────────────────────────────────────
#  ANSI fallback (desactivado en Windows cmd.exe nativo)
# ─────────────────────────────────────────────
_color = OS != "Windows" or bool(os.environ.get("WT_SESSION") or os.environ.get("TERM"))
BO = "\033[1m"  if _color else ""
RS = "\033[0m"  if _color else ""
CY = "\033[96m" if _color else ""
YL = "\033[93m" if _color else ""

# ─────────────────────────────────────────────
#  Funciones de output — plain text (fallback)
# ─────────────────────────────────────────────
def _ok_p(msg):   print(f"  ✅  {msg}")
def _err_p(msg):  print(f"  ❌  {msg}")
def _warn_p(msg): print(f"  ⚠️   {msg}")
def _work_p(msg): print(f"  🔧  {msg}", flush=True)
def _tip_p(msg):  print(f"       {YL}↳ {msg}{RS}")
def _blank_p():   print()
def _sep_p():     print(f"  {'═' * 54}")

def _step_header_p(n: int, title: str):
    bar = "─" * max(1, 44 - len(title))
    print(f"\n  {BO}{CY}── Paso {n}/6 — {title} {bar}{RS}\n")

# ─────────────────────────────────────────────
#  Funciones de output — rich
# ─────────────────────────────────────────────
if RICH:
    def _ok_r(msg):   console.print(f"  [bold green]✅[/]  {msg}")
    def _err_r(msg):  console.print(f"  [bold red]❌[/]  {msg}")
    def _warn_r(msg): console.print(f"  [bold yellow]⚠️ [/]  {msg}")
    def _work_r(msg): console.print(f"  [bold blue]🔧[/]  [bold]{msg}[/bold]")
    def _tip_r(msg):  console.print(f"     [yellow]↳[/yellow] [dim]{msg}[/dim]")
    def _blank_r():   console.print()
    def _sep_r():     console.rule(style="dim white")

    def _step_header_r(n: int, title: str):
        console.print()
        console.rule(f"[bold cyan] Paso {n}/6 — {title} [/bold cyan]", style="cyan")
        console.print()


# ─────────────────────────────────────────────
#  Dispatch — wrappers que comprueban OUTPUT_QUEUE
# ─────────────────────────────────────────────
def ok(msg):
    if OUTPUT_QUEUE is not None:
        _gui_card_items.append(("✓", msg, "#a6e3a1"))
    elif RICH:
        _ok_r(msg)
    else:
        _ok_p(msg)

def err(msg):
    if OUTPUT_QUEUE is not None:
        _gui_card_items.append(("✗", msg, "#f38ba8"))
    elif RICH:
        _err_r(msg)
    else:
        _err_p(msg)

def warn(msg):
    if OUTPUT_QUEUE is not None:
        _gui_card_items.append(("⚠", msg, "#f9e2af"))
    elif RICH:
        _warn_r(msg)
    else:
        _warn_p(msg)

def work(msg):
    if OUTPUT_QUEUE is not None:
        _gui_card_items.append(("⟳", msg, "#89b4fa"))
    elif RICH:
        _work_r(msg)
    else:
        _work_p(msg)

def tip(msg):
    if OUTPUT_QUEUE is not None:
        _gui_card_items.append(("↳", msg, "#6c7086"))
    elif RICH:
        _tip_r(msg)
    else:
        _tip_p(msg)

def status(msg):
    """Texto vivo en el pie de la GUI para que una descarga larga muestre actividad."""
    if OUTPUT_QUEUE is not None:
        OUTPUT_QUEUE.put({"type": "status", "text": msg})

def blank():
    if OUTPUT_QUEUE is None:
        if RICH:
            _blank_r()
        else:
            _blank_p()

def sep():
    if OUTPUT_QUEUE is None:
        if RICH:
            _sep_r()
        else:
            _sep_p()

def step_header(n: int, title: str):
    global _gui_card_title, _gui_card_items, _gui_step_label
    if OUTPUT_QUEUE is not None:
        _gui_flush_card()
        _gui_card_title = title
        _gui_card_items = []
        _gui_step_label = f"Paso {n}/6 — {title}"
        OUTPUT_QUEUE.put({"type": "progress", "step": n, "label": _gui_step_label})
    elif RICH:
        _step_header_r(n, title)
    else:
        _step_header_p(n, title)


# ─────────────────────────────────────────────
#  Scripts de instalación reutilizables
# ─────────────────────────────────────────────
_TRIVY_SCRIPT = (
    "curl -sfL "
    "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"
    " | sudo sh -s -- -b /usr/local/bin"
)
_DOCKER_SCRIPT = "curl -fsSL https://get.docker.com | sudo sh"

# ─────────────────────────────────────────────
#  Instrucciones manuales por herramienta y SO
# ─────────────────────────────────────────────
MANUAL_INSTALL = {
    "node": {
        "Darwin":  "brew install node",
        "Linux":   "Instala Node.js LTS (>=18) desde https://nodejs.org/en/download/package-manager",
        "Windows": "winget install --id OpenJS.NodeJS.LTS --source winget -e",
    },
    "npm": {
        "Darwin":  "Se instala junto con Node.js; no se instala por separado.",
        "Linux":   "Se instala junto con Node.js; no se instala por separado.",
        "Windows": "Se instala junto con Node.js; no se instala por separado.",
    },
    "node-red": {
        "Darwin":  "npm install -g node-red",
        "Linux":   "sudo npm install -g node-red",
        "Windows": "npm install -g node-red",
    },
    "nmap": {
        "Darwin":  "brew install nmap",
        "Linux":   "(apt) sudo apt install nmap   |   (pacman) sudo pacman -S nmap   |   (dnf) sudo dnf install nmap",
        "Windows": "winget install -e --id Insecure.Nmap --source winget   o   https://nmap.org/download.html",
    },
    "lynis": {
        "Darwin":  "brew install lynis",
        "Linux":   "(apt) sudo apt install lynis   |   (pacman) sudo pacman -S lynis   |   (dnf) sudo dnf install lynis",
        "Windows": "Lynis no está disponible en Windows sin WSL",
    },
    "trivy": {
        "Darwin":  "brew install aquasecurity/trivy/trivy",
        "Linux":   _TRIVY_SCRIPT,
        "Windows": "winget install --id AquaSecurity.Trivy --source winget -e   o   "
                   "https://aquasecurity.github.io/trivy/latest/getting-started/installation",
    },
    "docker": {
        "Darwin":  "https://www.docker.com/products/docker-desktop",
        "Linux":   _DOCKER_SCRIPT,
        "Windows": "winget install -e --id Docker.DockerDesktop   o   https://www.docker.com/products/docker-desktop",
    },
}

TOOL_DESC = {
    "nmap":   "audit-network — escaneo avanzado de puertos y versiones de servicios",
    "lynis":  "audit-host   — análisis de hardening y +300 comprobaciones del sistema",
    "trivy":  "audit-host + audit-image — CVEs en paquetes del SO e imágenes Docker",
    "docker": "audit-image  — auditoría de imágenes y contenedores Docker",
}

# Avisos que se muestran junto a la pregunta de instalación, por herramienta.
_INSTALL_NOTES = {
    "docker": "Descarga considerable y requiere reiniciar el sistema al terminar.",
}

# Tiempo máximo de instalación por herramienta; Docker Desktop necesita más.
_INSTALL_TIMEOUT_DEFAULT = 600
_INSTALL_TIMEOUTS = {
    "docker": 1800,
}

# Códigos de Windows Installer que no son fallo: la instalación terminó y falta reiniciar.
_REBOOT_CODES = {
    3010: "hay un reinicio de Windows pendiente para completar la instalación",
    1641: "el instalador ha iniciado un reinicio de Windows",
}

# Instaladores que necesitan administrador: solo Nmap, que escribe en el PATH de sistema.
_NEEDS_ELEVATION = {"nmap"}

def _default_windows_tool_dirs() -> tuple:
    """Carpetas fijas donde acaban los binarios de las herramientas en Windows."""
    dirs = [
        # Instalador oficial de Nmap.
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
    ]
    # Carpeta de enlaces de winget: ahí registra los binarios de Docker y Trivy.
    local = os.environ.get("LOCALAPPDATA")
    if local:
        dirs.append(os.path.join(local, "Microsoft", "WinGet", "Links"))
    return tuple(dirs)


_WINDOWS_TOOL_DIRS = _default_windows_tool_dirs()

# Extensiones que se prueban al buscar una herramienta en esas carpetas.
_WINDOWS_EXEC_EXTS = (".exe", ".cmd", ".bat", "")

# Herramientas instaladas durante ESTA ejecución (para el consejo final).
_installed_this_run: list = []

_SE_ERR_ACCESSDENIED = 5     # ShellExecute: acceso denegado
_ERROR_CANCELLED     = 1223  # GetLastError: el usuario canceló el diálogo de UAC

# El aviso de que Windows va a pedir permisos se da una sola vez por ejecución.
_uac_notice_shown = False

# True si run_install() vio que la herramienta ya estaba; solo cambia el mensaje final.
_already_installed = False

# Estado de cada herramienta opcional ({"state", "reason"}); lo rellena el paso 2 y alimenta ambos resúmenes.
_tool_status: dict = {}

# Node-RED se instala en el mismo lote que las opcionales si ya hay Node.js y npm.
_node_red_pending_install = False

# "unknown": sin Node no se puede consultar lib/executor.js, así que no se afirma que falte.
TOOL_STATES = ("available", "not_operational", "unsupported", "unknown", "missing")


def _set_tool_state(cmd: str, state: str, reason: str = "") -> None:
    """Registra el estado de una herramienta y su motivo, si lo hay."""
    _tool_status[cmd] = {"state": state, "reason": reason}


def _tool_state(cmd: str) -> str:
    registro = _tool_status.get(cmd)
    return registro.get("state", "missing") if registro else "missing"


def _tool_groups() -> dict:
    """Agrupa las herramientas por estado. De aquí salen AMBOS resúmenes."""
    grupos = {estado: [] for estado in TOOL_STATES}
    for cmd, label in OPTIONAL_TOOLS:
        registro = _tool_status.get(cmd) or {}
        estado = registro.get("state", "missing")
        grupos.setdefault(estado, []).append(
            (label, TOOL_DESC.get(cmd, ""), registro.get("reason", ""))
        )
    return grupos


def _tool_summary_lines() -> list:
    """Líneas [(tipo, texto)] del resumen de herramientas, sin grupos vacíos."""
    g = _tool_groups()
    lineas = []
    if g["available"]:
        lineas.append(("ok", "Módulos activos: " +
                       ", ".join(l for l, _, _ in g["available"])))
    if g["not_operational"]:
        detalle = ", ".join(
            f"{l} ({_short_reason(r)})" if r else l for l, _, r in g["not_operational"]
        )
        lineas.append(("warn", "Requieren atención: " + detalle))
    if g["unsupported"]:
        lineas.append(("warn", "No disponibles en este sistema: " +
                       ", ".join(l for l, _, _ in g["unsupported"])))
    if g["unknown"]:
        # No se pudo comprobar: no se cuentan como instaladas ni como ausentes.
        lineas.append(("warn", "Sin comprobar: " +
                       ", ".join(l for l, _, _ in g["unknown"])))
    if g["missing"]:
        lineas.append(("warn", "No instaladas: " +
                       ", ".join(l for l, _, _ in g["missing"])))
    return lineas


def _short_reason(reason: str) -> str:
    """Quita el "instalado pero" del motivo: el grupo ya lo dice."""
    return reason.removeprefix("instalado pero ").strip()

OPTIONAL_TOOLS = [
    ("docker", "Docker"),
    ("nmap",   "Nmap"),
    ("lynis",  "Lynis"),
    ("trivy",  "Trivy"),
]


# ─────────────────────────────────────────────
#  Utilidades de plataforma
# ─────────────────────────────────────────────
def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def detect_pkg_manager() -> str | None:
    if OS != "Linux":
        return None
    for pm in ("apt-get", "dnf", "pacman", "zypper"):
        if shutil.which(pm):
            return pm
    return None


def is_wsl() -> bool:
    if OS != "Linux":
        return False
    try:
        with open("/proc/version") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def get_node_version() -> tuple:
    try:
        r = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
        ver = r.stdout.strip().lstrip("v")
        major = int(ver.split(".")[0])
        return (major >= 18), f"v{ver}"
    except Exception:
        return False, "no detectado"


def check_docker_daemon() -> str | None:
    # Ruta por la fuente única: en Windows docker puede no estar en el PATH de este proceso.
    exe = _tool_path("docker") or "docker"
    try:
        r = subprocess.run([exe, "info"], capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            return "instalado pero el daemon no está en ejecución — ábrelo primero"
        return None
    except Exception:
        return "no se pudo conectar con el daemon de Docker"


def get_auto_install_cmd(tool: str) -> str | None:
    if tool == "node-red":
        if OS == "Linux":
            return "sudo npm install -g node-red"
        return "npm install -g node-red"

    if OS == "Darwin":
        if not shutil.which("brew"):
            return None
        return {
            "nmap":  "brew install nmap",
            "lynis": "brew install lynis",
            "trivy": "brew install aquasecurity/trivy/trivy",
        }.get(tool)

    if OS == "Linux":
        pm = detect_pkg_manager()
        tables = {
            "apt-get": {
                "nmap":   "sudo apt-get install -y nmap",
                "lynis":  "sudo apt-get install -y lynis",
                "trivy":  _TRIVY_SCRIPT,
                "docker": _DOCKER_SCRIPT,
            },
            "pacman": {
                "nmap":   "sudo pacman -S --noconfirm nmap",
                "lynis":  "sudo pacman -S --noconfirm lynis",
                "trivy":  _TRIVY_SCRIPT,
                "docker": "sudo pacman -S --noconfirm docker && sudo systemctl start docker",
            },
            "dnf": {
                "nmap":   "sudo dnf install -y nmap",
                "lynis":  "sudo dnf install -y lynis",
                "trivy":  _TRIVY_SCRIPT,
                "docker": "sudo dnf install -y docker && sudo systemctl start docker",
            },
            "zypper": {
                "nmap":   "sudo zypper install -y nmap",
                "lynis":  "sudo zypper install -y lynis",
                "trivy":  _TRIVY_SCRIPT,
                "docker": "sudo zypper install -y docker && sudo systemctl start docker",
            },
        }
        if pm and pm in tables:
            return tables[pm].get(tool)
        return None

    if OS == "Windows":
        if shutil.which("winget"):
            # Acuerdos aceptados de antemano (en la GUI no hay consola); sin --silent a propósito.
            base = "winget install --id {} --source winget -e " \
                   "--accept-source-agreements --accept-package-agreements"
            return {
                "nmap":   base.format("Insecure.Nmap"),
                "docker": base.format("Docker.DockerDesktop"),
                "trivy":  base.format("AquaSecurity.Trivy"),
            }.get(tool)
        return None

    return None


def _is_windows_admin():
    """True/False en Windows, None en otros sistemas; ante un error, False."""
    if OS != "Windows":
        return None
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _shellexecuteinfo_type():
    """Construye SHELLEXECUTEINFOW con tipos de ancho fijo (layout igual en cualquier SO)."""
    import ctypes
    DWORD  = ctypes.c_uint32
    HANDLE = ctypes.c_void_p
    LPCWSTR = ctypes.c_wchar_p

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize",       DWORD),
            ("fMask",        DWORD),
            ("hwnd",         HANDLE),
            ("lpVerb",       LPCWSTR),
            ("lpFile",       LPCWSTR),
            ("lpParameters", LPCWSTR),
            ("lpDirectory",  LPCWSTR),
            ("nShow",        ctypes.c_int),
            ("hInstApp",     HANDLE),
            ("lpIDList",     ctypes.c_void_p),
            ("lpClass",      LPCWSTR),
            ("hkeyClass",    HANDLE),
            ("dwHotKey",     DWORD),
            ("hIcon",        HANDLE),
            ("hProcess",     HANDLE),
        ]

    return SHELLEXECUTEINFOW


def _run_elevated_windows(cmd: str, timeout: int):
    """Ejecuta `cmd` elevado vía UAC y devuelve (returncode, salida).

    returncode None significa que el usuario canceló el diálogo de UAC.
    Solo se eleva el comando de instalación, nunca el launcher (mínimo privilegio).
    """
    import ctypes

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SW_SHOWNORMAL = 1
    WAIT_TIMEOUT  = 0x00000102

    SHELLEXECUTEINFOW = _shellexecuteinfo_type()
    DWORD  = ctypes.c_uint32
    HANDLE = ctypes.c_void_p

    shell32  = ctypes.WinDLL("shell32",  use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype  = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [HANDLE, DWORD]
    kernel32.WaitForSingleObject.restype  = DWORD
    kernel32.GetExitCodeProcess.argtypes  = [HANDLE, ctypes.POINTER(DWORD)]
    kernel32.GetExitCodeProcess.restype   = ctypes.c_int
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype  = ctypes.c_int

    # El proceso elevado no hereda las tuberías: la salida va a un fichero temporal.
    fd, log_path = tempfile.mkstemp(prefix="lcaudit-install-", suffix=".log")
    os.close(fd)
    try:
        # Con /s, cmd solo quita la primera y la última comilla: la ruta temporal puede llevar espacios.
        params = f'/s /c "{cmd} > "{log_path}" 2>&1"'

        info = SHELLEXECUTEINFOW()
        info.cbSize       = ctypes.sizeof(info)
        info.fMask        = SEE_MASK_NOCLOSEPROCESS
        info.hwnd         = None
        info.lpVerb       = "runas"
        info.lpFile       = "cmd.exe"
        info.lpParameters = params
        info.lpDirectory  = None
        info.nShow        = SW_SHOWNORMAL

        if not shell32.ShellExecuteExW(ctypes.byref(info)):
            hinst = int(info.hInstApp or 0)
            last  = ctypes.get_last_error()
            # UAC cancelado: según la versión llega por una vía u otra.
            if hinst == _SE_ERR_ACCESSDENIED or last == _ERROR_CANCELLED:
                return None, ""
            raise OSError(
                f"ShellExecuteExW falló (hInstApp={hinst}, GetLastError={last})"
            )

        handle = info.hProcess
        if not handle:
            raise OSError("ShellExecuteExW no devolvió handle del proceso elevado")

        try:
            if kernel32.WaitForSingleObject(handle, max(1, int(timeout)) * 1000) == WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired(cmd, timeout)
            rc = DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(rc)):
                raise OSError("GetExitCodeProcess falló")
            code = int(rc.value)
        finally:
            kernel32.CloseHandle(handle)

        try:
            with open(log_path, "rb") as fh:
                output = _decode_output(fh.read()).strip()
        except OSError:
            output = ""
        return code, output
    finally:
        try:
            os.unlink(log_path)
        except OSError:
            pass


def _run_plain(cmd: str, timeout: int):
    """Ejecución normal, sin elevar. Devuelve (returncode, salida)."""
    result = subprocess.run(
        cmd, shell=True, timeout=timeout,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    salida = _decode_output(result.stderr).strip() or _decode_output(result.stdout).strip()
    return result.returncode, salida


def _tool_in_known_dirs(tool: str):
    """Carpeta conocida donde está el binario de `tool`, o None."""
    if OS != "Windows":
        return None
    for d in _WINDOWS_TOOL_DIRS:
        if not os.path.isdir(d):
            continue
        for ext in _WINDOWS_EXEC_EXTS:
            if os.path.isfile(os.path.join(d, tool + ext)):
                return d
    return None


# Caché de lib/executor.js ({tool: ruta|None}), rellenada con una sola llamada a Node.
_js_probe_cache: dict = {}
# ¿Pudo Node responder? None = todavía no se ha intentado.
_js_probe_ok: bool | None = None

# Detector en JS, pasado con -e para no dejar ficheros temporales.
_JS_PROBE = (
    "const {commandExists}=require(process.argv[1]);"
    "(async()=>{const o={};"
    "for(const t of process.argv.slice(2)) o[t]=(await commandExists(t))||null;"
    "process.stdout.write(JSON.stringify(o));})()"
)


def _probe_tools_with_node(tools: list) -> dict | None:
    """Consulta a lib/executor.js todas las herramientas en una llamada a Node.

    Devuelve {tool: ruta|None}, o None si Node no respondió ("no lo sé", no "falta").
    """
    executor = os.path.join(PROJECT_ROOT, "lib", "executor.js")
    if not os.path.isfile(executor):
        return None
    try:
        proc = subprocess.run(
            ["node", "-e", _JS_PROBE, executor] + list(tools),
            capture_output=True, text=True, timeout=20, env=_child_env(),
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        datos = json.loads(proc.stdout)
    except Exception:
        # Node ausente, roto o salida no JSON: "no lo sé", nunca "no está instalada".
        return None
    return {t: datos.get(t) or None for t in tools}


def _prime_tool_probe(tools: list = None) -> None:
    """Rellena la caché con una sola llamada a Node. Idempotente."""
    global _js_probe_ok
    if _js_probe_ok is not None:
        return
    lista = tools or [c for c, _ in OPTIONAL_TOOLS]
    datos = _probe_tools_with_node(lista)
    if datos is None:
        _js_probe_ok = False
        return
    _js_probe_cache.update(datos)
    _js_probe_ok = True


def _tool_path(tool: str):
    """Ruta del ejecutable de `tool`, o None. Fuente única de disponibilidad.

    Orden: lib/executor.js, el PATH de este proceso y _WINDOWS_TOOL_DIRS
    (los dos últimos solo como respaldo cuando aún no hay Node).
    """
    _prime_tool_probe()
    if _js_probe_ok and tool in _js_probe_cache:
        ruta = _js_probe_cache[tool]
        if ruta:
            return ruta

    ruta = shutil.which(tool)
    if ruta:
        return ruta
    carpeta = _tool_in_known_dirs(tool)
    if carpeta:
        for ext in _WINDOWS_EXEC_EXTS:
            candidato = os.path.join(carpeta, tool + ext)
            if os.path.isfile(candidato):
                return candidato
    return None


def _tool_available(tool: str) -> bool:
    """¿Puede LoCoAudit usar esta herramienta? Ver _tool_path()."""
    return _tool_path(tool) is not None


def _probe_is_conclusive() -> bool:
    """¿Se pudo consultar lib/executor.js? Si no, un "no la encuentro" no es concluyente."""
    _prime_tool_probe()
    return _js_probe_ok is True


# ─────────────────────────────────────────────
#  Permisos de instalación
# ─────────────────────────────────────────────
def _can_sudo() -> bool | None:
    """True: sudo sin contraseña; False: no está en sudoers; None: no se sabe (o pedirá contraseña)."""
    if OS == "Windows":
        return None
    if not shutil.which("sudo"):
        return False
    try:
        proc = subprocess.run(["sudo", "-n", "true"],
                              capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    if proc.returncode == 0:
        return True
    salida = ((proc.stderr or "") + (proc.stdout or "")).lower()
    # El usuario no puede usar sudo: ofrecer la instalación solo llevaría a un fallo.
    if "sudoers" in salida or "not allowed" in salida:
        return False
    # "a password is required": puede, pero hay que pedírsela.
    return None


def _needs_sudo(cmd: str) -> bool:
    """¿El comando de instalación necesita privilegios?"""
    return "sudo " in (cmd or "")


def _can_run_install(cmd: str) -> bool:
    """¿Se ofrece esta instalación? Solo se descarta si consta que va a fallar."""
    if not _needs_sudo(cmd):
        return True
    return _can_sudo() is not False


def _child_env() -> dict:
    """Copia en memoria del entorno con las carpetas de herramientas añadidas al PATH."""
    env = os.environ.copy()
    if OS != "Windows":
        return env
    extra = [d for d in _WINDOWS_TOOL_DIRS if os.path.isdir(d)]
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


def _decode_output(raw: bytes) -> str:
    """Decodifica la salida de un proceso sin lanzar nunca (la consola de Windows no es UTF-8)."""
    if not raw:
        return ""
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _format_rc(rc: int) -> str:
    """Código de salida en decimal y en hex de 32 bits sin signo, como lo documenta Windows."""
    return f"{rc} (0x{rc & 0xFFFFFFFF:08X})"


def _tail_lines(text: str, n: int = 8) -> list:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    return lines[-n:]


def run_install(cmd: str, label: str, tool: str = "", timeout: int = 0) -> bool:
    """Ejecuta una instalación y devuelve True si la herramienta quedó instalada.

    `tool` es la clave interna ("nmap", "docker"...); si falta, se deriva del label.
    """
    global _uac_notice_shown, _already_installed
    _already_installed = False
    tool = tool or label.lower()
    timeout = timeout or _INSTALL_TIMEOUTS.get(tool, _INSTALL_TIMEOUT_DEFAULT)

    # Se eleva solo en Windows, para herramientas de la lista y si no somos ya administrador.
    elevar = (
        OS == "Windows"
        and tool in _NEEDS_ELEVATION
        and _is_windows_admin() is False
    )

    work(f"Instalando {label}...")
    # El comando solo se muestra si falla, dentro del bloque de error.
    if elevar and not _uac_notice_shown:
        _uac_notice_shown = True
        # La justificación de la elevación está en README.md.
        warn(f"Windows va a pedirte permisos de administrador para instalar {label}")
        tip("Solo se usa para este paso — Node-RED seguirá sin privilegios de "
            "administrador")
        tip("Si rechazas el permiso, se salta la instalación y puedes hacerla a mano")
    status(f"Instalando {label} — puede tardar varios minutos, no cierres la ventana")
    blank()

    try:
        if elevar:
            try:
                rc, salida = _run_elevated_windows(cmd, timeout)
            except subprocess.TimeoutExpired:
                raise
            except Exception as exc:
                # Si la ruta elevada falla de forma imprevista, se sigue por la normal.
                warn(f"No se pudo lanzar la instalación elevada: {exc}")
                tip("Se reintenta sin permisos de administrador")
                rc, salida = _run_plain(cmd, timeout)
        else:
            rc, salida = _run_plain(cmd, timeout)
    except subprocess.TimeoutExpired:
        status(_gui_step_label)
        err(f"La instalación de {label} superó el tiempo límite ({timeout}s)")
        tip(f"Comando: {cmd}")
        tip(f"Intenta manualmente: {MANUAL_INSTALL.get(tool, {}).get(OS, '?')}")
        return False
    except Exception as exc:
        status(_gui_step_label)
        err(f"Error inesperado instalando {label}: {exc}")
        return False

    status(_gui_step_label)

    # UAC cancelado: es decisión del usuario, se avisa y se sigue con el resto.
    if rc is None:
        warn(f"Instalación de {label} cancelada: se necesitan permisos de administrador")
        tip(f"Puedes instalarlo manualmente: "
            f"{MANUAL_INSTALL.get(tool, {}).get(OS, 'Consulta la documentación oficial')}")
        return False

    if rc == 0:
        return True

    # Códigos estándar del instalador de Windows: terminó bien, falta reiniciar.
    if rc in _REBOOT_CODES:
        warn(f"{label}: {_REBOOT_CODES[rc]}")
        return True

    # Otro código no cero: si la herramienta ya está disponible, se da por buena.
    if _tool_available(tool):
        _already_installed = True
        return True

    err(f"La instalación de {label} falló — código de salida {_format_rc(rc)}")
    tip(f"Comando: {cmd}")
    if salida:
        for line in _tail_lines(salida):
            tip(line)
    else:
        tip("El comando no devolvió ningún mensaje de error.")
    tip(f"Intenta manualmente: {MANUAL_INSTALL.get(tool, {}).get(OS, 'Consulta la documentación oficial')}")
    return False


def _run_npm(cmd: str, label: str, timeout: int = 120) -> bool:
    """Run an npm command. Uses rich spinner + captured output when available."""
    if OUTPUT_QUEUE is not None:
        work(label + "...")
        try:
            result = subprocess.run(
                cmd, shell=True, timeout=timeout,
                capture_output=True, text=True,
            )
            if result.returncode != 0 and result.stderr.strip():
                err(result.stderr.strip()[:300])
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            err(f"Timeout ({timeout}s) instalando {label}")
            return False
        except Exception as exc:
            err(str(exc))
            return False

    if RICH:
        with console.status(f"[bold blue]🔧  {label}[/bold blue]", spinner="dots"):
            try:
                result = subprocess.run(
                    cmd, shell=True, timeout=timeout,
                    capture_output=True, text=True,
                )
                success  = result.returncode == 0
                out_text = result.stdout.strip()
                err_text = result.stderr.strip()
            except subprocess.TimeoutExpired:
                success  = False
                out_text = ""
                err_text = f"Timeout ({timeout}s)"
            except Exception as exc:
                success  = False
                out_text = ""
                err_text = str(exc)
        if not success:
            if out_text:
                console.print(f"[dim]{out_text}[/dim]")
            if err_text:
                console.print(f"[red]{err_text}[/red]")
        return success
    else:
        work(label + "...")
        blank()
        try:
            result = subprocess.run(cmd, shell=True, timeout=timeout)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False


def _ask_install_node_red(is_tty: bool) -> bool:
    """Pregunta si se debe instalar Node-RED con el npm ya disponible."""
    cmd = "npm install -g node-red"
    if OUTPUT_QUEUE is not None:
        evt = threading.Event()
        result = []
        OUTPUT_QUEUE.put({
            "type": "ask",
            "tool": "Node-RED",
            "desc": cmd,
            "note": "Si después no aparece el comando, reinicia el equipo para recargar el PATH.",
            "event": evt,
            "result": result,
        })
        evt.wait()
        return bool(result and result[0])

    if not is_tty:
        return False

    tip(f"Comando: {cmd}")
    tip("Si después no aparece el comando, reinicia el equipo para recargar el PATH.")
    if RICH:
        try:
            return bool(Confirm.ask(
                "  ¿Deseas instalar [bold]Node-RED[/bold] ahora?",
                default=False,
            ))
        except (EOFError, KeyboardInterrupt):
            blank()
            return False
    print(f"\n  ¿Deseas instalar {BO}Node-RED{RS} ahora? (s/n)")
    try:
        return input("  → ").strip().lower() in ("s", "si", "sí", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        blank()
        return False


# ─────────────────────────────────────────────
#  Pantalla de bienvenida
# ─────────────────────────────────────────────
def print_welcome():
    if not RICH:
        _blank_p()
        _sep_p()
        print(f"  {BO}  LoCoAudit — Asistente de configuración{RS}")
        wsl_note = "  (WSL)" if is_wsl() else ""
        print(f"  Sistema: {OS}{wsl_note} ({ARCH})   Python {platform.python_version()}")
        _sep_p()
        return

    wsl_note = "  [dim yellow](WSL)[/dim yellow]" if is_wsl() else ""

    content = Text()
    content.append("\n")
    content.append("   LoCoAudit", style="bold cyan")
    content.append(f"   v{VERSION}\n", style="dim cyan")
    content.append("   Node-RED Security Audit Suite\n", style="white")
    content.append("\n")
    content.append(f"   Sistema: {OS}", style="dim")
    if is_wsl():
        content.append("  (WSL)", style="dim yellow")
    content.append(f"  {ARCH}   Python {platform.python_version()}\n", style="dim")

    console.print(
        Panel(content, border_style="cyan", padding=(0, 1), expand=False)
    )
    console.print()


# ─────────────────────────────────────────────
#  Resumen final (antes de arrancar Node-RED)
# ─────────────────────────────────────────────
# Secciones del resumen final, compartidas por la salida plana y la tabla de rich.
_SUMMARY_SECTIONS = [
    ("available",       "Módulos activos",               "green"),
    ("not_operational", "Requieren atención",            "yellow"),
    ("unsupported",     "No disponibles en este sistema", "yellow"),
    # Mismo orden que _tool_summary_lines().
    ("unknown",         "Sin comprobar",                 "yellow"),
    ("missing",         "No instaladas",                 "yellow"),
]


def _print_summary():
    if OUTPUT_QUEUE is not None:
        for tipo, texto in _tool_summary_lines():
            (ok if tipo == "ok" else warn)(texto)
        return

    if not RICH:
        return

    grupos = _tool_groups()

    t = Table(box=rbox.SIMPLE, show_header=False, pad_edge=False, expand=True)
    t.add_column("icon", width=5,  no_wrap=True)
    t.add_column("name", width=18, no_wrap=True, style="bold")
    t.add_column("desc", style="dim")

    primera = True
    for estado, titulo, color in _SUMMARY_SECTIONS:
        filas = grupos.get(estado) or []
        if not filas:
            continue
        if not primera:
            t.add_row("", "", "")
        primera = False
        icono = "✅" if estado == "available" else "⚠️ "
        t.add_row("", f"[bold {color}]{titulo}[/bold {color}]", "")
        for label, desc, reason in filas:
            # Si hay motivo, se muestra en lugar de la descripción.
            detalle = _short_reason(reason) if reason else desc
            t.add_row(f"  [{color}]{icono}[/{color}]", f"[{color}]{label}[/{color}]", detalle)

    if primera:
        t.add_row("", "[dim]Sin herramientas opcionales[/dim]", "")

    url = Text()
    url.append("\n  Editor:    ", style="white")
    url.append("http://localhost:1880", style="bold cyan underline")
    url.append("\n  Dashboard: ", style="white")
    url.append("http://localhost:1880/dashboard\n", style="bold cyan underline")

    console.print(
        Panel(t, title="[bold white] Configuración completada [/bold white]",
              border_style="green", padding=(0, 1))
    )
    console.print(
        Panel(url, border_style="cyan", padding=(0, 0), expand=False)
    )
    console.print()


# ─────────────────────────────────────────────
#  Paso 1 — Dependencias requeridas
# ─────────────────────────────────────────────
def step1_required_deps() -> list:
    global _node_red_pending_install
    step_header(1, "Dependencias requeridas")
    missing = []
    node_red_missing = False

    if RICH and OUTPUT_QUEUE is None:
        table = Table(
            box=rbox.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=False,
        )
        table.add_column("Herramienta", style="bold white", width=12)
        table.add_column("Estado",      width=14)
        table.add_column("Detalle",     style="dim")

        # Node.js
        if not command_exists("node"):
            table.add_row(
                "Node.js",
                "[bold red]❌  falta[/bold red]",
                MANUAL_INSTALL["node"].get(OS, "https://nodejs.org"),
            )
            missing.append("Node.js")
        else:
            is_ok, label = get_node_version()
            if is_ok:
                table.add_row("Node.js", "[bold green]✅  ok[/bold green]", label)
            else:
                table.add_row(
                    "Node.js",
                    "[bold red]❌  versión[/bold red]",
                    f"{label} — requiere v18+",
                )
                missing.append("Node.js ≥ v18")

        # npm
        if not command_exists("npm"):
            table.add_row(
                "npm",
                "[bold red]❌  falta[/bold red]",
                MANUAL_INSTALL["npm"].get(OS, "https://nodejs.org"),
            )
            missing.append("npm")
        else:
            table.add_row("npm", "[bold green]✅  ok[/bold green]", "instalado")

        # Node-RED
        if not command_exists("node-red"):
            table.add_row(
                "Node-RED",
                "[bold red]❌  falta[/bold red]",
                MANUAL_INSTALL["node-red"].get(OS, "npm install -g node-red"),
            )
            missing.append("Node-RED")
            node_red_missing = True
        else:
            table.add_row("Node-RED", "[bold green]✅  ok[/bold green]", "instalado")

        console.print(table)
        console.print()

        if missing:
            for item in missing:
                _err_r(f"{item} — dependencia requerida no encontrada")
    else:
        # ── Node.js ──
        if not command_exists("node"):
            err("Node.js no encontrado")
            tip(f"Instálalo: {MANUAL_INSTALL['node'].get(OS, 'https://nodejs.org')}")
            missing.append("Node.js")
        else:
            is_ok, label = get_node_version()
            if is_ok:
                ok(f"Node.js {label}")
            else:
                err(f"Node.js {label} — se requiere v18 o superior")
                tip(f"Actualiza: {MANUAL_INSTALL['node'].get(OS)}")
                missing.append("Node.js ≥ v18")

        # ── npm ──
        if not command_exists("npm"):
            err("npm no encontrado")
            tip(f"Instálalo: {MANUAL_INSTALL['npm'].get(OS, 'https://nodejs.org')}")
            missing.append("npm")
        else:
            ok("npm instalado")

        # ── Node-RED ──
        if not command_exists("node-red"):
            err("Node-RED no encontrado")
            tip(f"Instálalo: {MANUAL_INSTALL['node-red'].get(OS)}")
            missing.append("Node-RED")
            node_red_missing = True
        else:
            ok("Node-RED instalado")

    if node_red_missing and "Node.js" not in missing and "Node.js ≥ v18" not in missing and "npm" not in missing:
        _node_red_pending_install = True
        missing.remove("Node-RED")
        tip("Node-RED se ofrecerá junto con las herramientas opcionales en el paso 2")

    return missing


# ─────────────────────────────────────────────
#  Paso 2 — Herramientas opcionales
# ─────────────────────────────────────────────
def _ask_install_all(pending: list, is_tty: bool) -> bool:
    """Ofrece instalar de golpe lo que falta y tiene instalación automática."""
    names = ", ".join(label for _, label in pending)
    note  = "  ".join(_INSTALL_NOTES[c] for c, _ in pending if c in _INSTALL_NOTES)

    if OUTPUT_QUEUE is not None:
        evt    = threading.Event()
        result = []
        OUTPUT_QUEUE.put({
            "type":     "ask",
            "title":    f"Faltan {len(pending)} herramientas recomendadas",
            "tool":     names,
            "desc":     names,
            "note":     note,
            "yes_text": "Sí, instalar todas",
            "no_text":  "No, preguntar una a una",
            "event":    evt,
            "result":   result,
        })
        evt.wait()
        return bool(result and result[0])

    if not is_tty:
        return False

    blank()
    tip(f"Faltan {len(pending)} herramientas recomendadas: {names}")
    if note:
        tip(note)
    if RICH:
        try:
            return bool(Confirm.ask("  ¿Instalarlas [bold]todas[/bold] ahora?", default=False))
        except (EOFError, KeyboardInterrupt):
            blank()
            return False
    print(f"\n  ¿Instalarlas {BO}todas{RS} ahora? (s/n)")
    try:
        return input("  → ").strip().lower() in ("s", "si", "sí", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        blank()
        return False


def _report_install_result(cmd: str, label: str) -> None:
    """Mensaje final tras una instalación que run_install() dio por buena."""
    if not _tool_available(cmd):
        # Instalada pero fuera del alcance de los nodos: no cuenta como disponible.
        _set_tool_state(cmd, "not_operational", "el sistema todavía no lo encuentra")
        warn(f"{label} se instaló, pero el sistema todavía no lo encuentra")
        tip("Abre una ventana de terminal nueva o reinicia el equipo "
            "para empezar a usarlo.")
        return

    _set_tool_state(cmd, "available")
    # Una sola línea, distinta si ya estaba instalada.
    if _already_installed:
        ok(f"{label} ya estaba instalado — listo para usar")
    else:
        ok(f"{label} instalado correctamente — listo para usar")

    if cmd == "docker":
        daemon_warn = check_docker_daemon()
        if daemon_warn:
            _set_tool_state(cmd, "not_operational", daemon_warn)
            warn(f"Docker {daemon_warn}")


def step2_optional_tools():
    global _node_red_pending_install
    step_header(2, "Herramientas opcionales")

    is_tty = sys.stdin.isatty()

    # Si falta más de una herramienta instalable, se ofrece instalarlas todas a la vez.
    # Antes se consulta a Node una sola vez para dejar la caché llena.
    _prime_tool_probe()

    # Mismo filtro que dentro del bucle.
    pending = [
        (c, l) for c, l in OPTIONAL_TOOLS
        if not _tool_available(c)
        and _probe_is_conclusive()
        and get_auto_install_cmd(c)
        and _can_run_install(get_auto_install_cmd(c))
    ]
    if _node_red_pending_install:
        node_red_cmd = get_auto_install_cmd("node-red")
        if node_red_cmd and _can_run_install(node_red_cmd):
            pending.insert(0, ("node-red", "Node-RED"))
    install_all = _ask_install_all(pending, is_tty) if len(pending) >= 2 else False
    if install_all:
        ok(f"Se instalarán sin preguntar: {', '.join(l for _, l in pending)}")
        blank()

        if _node_red_pending_install:
            node_red_cmd = get_auto_install_cmd("node-red")
            if node_red_cmd and _run_npm(node_red_cmd, "Instalando Node-RED"):
                if command_exists("node-red"):
                    ok("Node-RED instalado correctamente")
                    _node_red_pending_install = False
                else:
                    warn("Node-RED se instaló, pero el comando todavía no aparece en el PATH")
                    tip("Reinicia el equipo y vuelve a ejecutar el launcher para recargar el PATH")
            else:
                err("No se pudo instalar Node-RED automáticamente")
                tip(f"Instálalo manualmente: {MANUAL_INSTALL['node-red'].get(OS)}")

    elif _node_red_pending_install:
        node_red_cmd = get_auto_install_cmd("node-red")
        if node_red_cmd and not _can_run_install(node_red_cmd):
            tip("Tu usuario no tiene permisos para instalar Node-RED automáticamente")
            tip(f"Instálalo manualmente: {MANUAL_INSTALL['node-red'].get(OS)}")
        elif _ask_install_node_red(is_tty):
            node_red_cmd = get_auto_install_cmd("node-red")
            if node_red_cmd and _run_npm(node_red_cmd, "Instalando Node-RED"):
                if command_exists("node-red"):
                    ok("Node-RED instalado correctamente")
                    _node_red_pending_install = False
                else:
                    warn("Node-RED se instaló, pero el comando todavía no aparece en el PATH")
                    tip("Reinicia el equipo y vuelve a ejecutar el launcher para recargar el PATH")
            else:
                err("No se pudo instalar Node-RED automáticamente")
                tip(f"Instálalo manualmente: {MANUAL_INSTALL['node-red'].get(OS)}")

    for cmd, label in OPTIONAL_TOOLS:
        # Lynis is not available natively on Windows
        if cmd == "lynis" and OS == "Windows":
            # No existe para esta plataforma, que no es lo mismo que no estar instalada.
            _set_tool_state(cmd, "unsupported", "no existe versión para Windows sin WSL")
            warn(f"{label} — no disponible en Windows sin WSL")
            tip("Instala WSL: https://learn.microsoft.com/es-es/windows/wsl/install")
            blank()
            continue

        # Misma vara de medir que el resto: si LoCoAudit puede usarla, está.
        if _tool_available(cmd):
            if cmd == "docker":
                daemon_warn = check_docker_daemon()
                if daemon_warn:
                    _set_tool_state(cmd, "not_operational", daemon_warn)
                    warn(f"Docker {daemon_warn}")
                else:
                    _set_tool_state(cmd, "available")
                    ok("Docker instalado y daemon activo")
            else:
                _set_tool_state(cmd, "available")
                ok(f"{label} instalado — {TOOL_DESC.get(cmd, '')}")
            if not command_exists(cmd):
                tip("Está en el equipo, pero el sistema no la tiene registrada: "
                    "LoCoAudit la usará igualmente, y otros programas no la "
                    "encontrarán hasta que la reinstales desde su instalador oficial.")
            continue

        # ── No se ha encontrado ──
        # Con Node se puede afirmar que falta; sin Node solo que no se pudo comprobar.
        if not _probe_is_conclusive():
            _set_tool_state(cmd, "unknown", "no se ha podido comprobar desde el asistente")
            warn(f"{label} — no se ha podido comprobar si está instalado")
            tip("El asistente no ha podido consultarlo con Node. Si ya lo tienes, "
                "LoCoAudit lo usará igualmente.")
            tip(f"Para instalarlo: {MANUAL_INSTALL.get(cmd, {}).get(OS, 'Consulta la documentación oficial')}")
            blank()
            continue

        _set_tool_state(cmd, "missing")
        warn(f"{label} no encontrado — {TOOL_DESC.get(cmd, '')}")

        auto_cmd = get_auto_install_cmd(cmd)

        # Sin permisos no se ofrece la instalación: se da el comando para ejecutarlo a mano.
        if auto_cmd and not _can_run_install(auto_cmd):
            tip("Tu usuario no tiene permisos de administrador en este equipo, así "
                "que el asistente no puede instalarlo por ti.")
            tip(f"Pídeselo a quien administre el equipo, o ejecútalo tú con una cuenta que pueda: {auto_cmd}")
            blank()
            continue

        if auto_cmd and OUTPUT_QUEUE is not None:
            if install_all:
                answer = True
            else:
                # GUI mode: ask via queue, block until user responds
                evt    = threading.Event()
                result = []
                OUTPUT_QUEUE.put({
                    "type":   "ask",
                    "tool":   label,
                    "desc":   auto_cmd,
                    "note":   _INSTALL_NOTES.get(cmd, ""),
                    "event":  evt,
                    "result": result,
                })
                evt.wait()
                # result queda vacía si se cierra la ventana, o con False si se omite.
                answer = bool(result and result[0])
            if answer:
                blank()
                success = run_install(auto_cmd, label)
                if success:
                    # Si ya estaba, no cuenta para el aviso final de reinicio.
                    if not _already_installed:
                        _installed_this_run.append(label)
                    _report_install_result(cmd, label)
                # Si falla, run_install() ya ha mostrado el detalle.
            else:
                warn(f"Omitiendo {label} — el nodo correspondiente funcionará en modo reducido")

        elif auto_cmd and is_tty:
            if install_all:
                answer = True
            elif RICH:
                tip(f"Comando: {auto_cmd}")
                blank()
                try:
                    answer = Confirm.ask(
                        f"  ¿Deseas instalar [bold]{label}[/bold] ahora?",
                        default=False,
                    )
                except (EOFError, KeyboardInterrupt):
                    blank()
                    warn(f"Omitiendo {label}")
                    blank()
                    continue
            else:
                print(f"\n  ¿Deseas instalar {BO}{label}{RS} ahora? (s/n)")
                tip(f"Comando: {auto_cmd}")
                try:
                    answer = input("  → ").strip().lower() in ("s", "si", "sí", "y", "yes")
                except (EOFError, KeyboardInterrupt):
                    blank()
                    warn(f"Omitiendo {label}")
                    blank()
                    continue

            if answer:
                blank()
                success = run_install(auto_cmd, label)
                if success:
                    # Si ya estaba, no cuenta para el aviso final de reinicio.
                    if not _already_installed:
                        _installed_this_run.append(label)
                    _report_install_result(cmd, label)
                # Si falla, run_install() ya ha mostrado el detalle.
            else:
                warn(f"Omitiendo {label} — el nodo correspondiente funcionará en modo reducido")
        else:
            # No auto-install available or non-interactive shell
            tip(f"Para instalarlo: {MANUAL_INSTALL.get(cmd, {}).get(OS, 'Consulta la documentación oficial')}")

        blank()

    # Se deriva siempre de _tool_status.
    lineas = _tool_summary_lines()
    if len(lineas) == 1 and lineas[0][0] == "ok":
        ok("Todas las herramientas opcionales están disponibles")
    else:
        for tipo, texto in lineas:
            (ok if tipo == "ok" else warn)(texto)
        # Solo si alguna falta o no funciona de verdad.
        grupos = _tool_groups()
        if grupos["missing"] or grupos["not_operational"] or grupos["unsupported"]:
            tip("Los nodos que dependen de ellas seguirán funcionando en modo "
                "reducido: avisarán en el panel en vez de dar un resultado vacío.")
        if grupos["unknown"]:
            tip("No se ha podido comprobar su estado desde el asistente. Si están "
                "instaladas, los nodos las usarán igualmente: LoCoAudit las busca "
                "también fuera del PATH de esta ventana.")

    if _installed_this_run:
        blank()
        ok(f"Instaladas en esta sesión: {', '.join(_installed_this_run)}")
        tip("LoCoAudit ya puede usarlas. Puedes continuar sin reiniciar nada.")
        if OS == "Windows":
            tip("Cuando te venga bien, reinicia Windows para que queden disponibles "
                "también en cualquier otro programa o ventana de terminal. Es una "
                "recomendación, no un requisito para usar LoCoAudit.")

    return not _node_red_pending_install or command_exists("node-red")


# ─────────────────────────────────────────────
#  Paso 3 — Registrar LoCoAudit en Node-RED
# ─────────────────────────────────────────────
def step3_register_package():
    step_header(3, "Registrando LoCoAudit en Node-RED")

    os.makedirs(NODE_RED_DIR, exist_ok=True)
    cmd = f'{NPM_CMD} install "{PROJECT_ROOT}" --prefix "{NODE_RED_DIR}"'
    tip(cmd)

    success = _run_npm(cmd, "Registrando LoCoAudit en Node-RED")

    if success:
        ok(f"LoCoAudit registrado en {NODE_RED_DIR}")
    else:
        err("npm install terminó con error")
        warn("Los nodos de LoCoAudit podrían no aparecer en la paleta de Node-RED")
        tip(f"Intenta manualmente desde la carpeta del proyecto: {cmd}")


# ─────────────────────────────────────────────
#  Paso 4 — Instalar dependencias de Node-RED
# ─────────────────────────────────────────────
_DASHBOARD_PKG  = "@flowfuse/node-red-dashboard"
_DASHBOARD_PATH = os.path.join(NODE_RED_DIR, "node_modules", "@flowfuse", "node-red-dashboard")


def step4_install_dashboard():
    step_header(4, "Dependencias de Node-RED")

    if os.path.isdir(_DASHBOARD_PATH):
        ok(f"{_DASHBOARD_PKG} ya instalado")
        return

    cmd = f'{NPM_CMD} install {_DASHBOARD_PKG} --prefix "{NODE_RED_DIR}"'
    tip(cmd)

    success = _run_npm(cmd, f"Instalando {_DASHBOARD_PKG}")

    if success:
        ok(f"{_DASHBOARD_PKG} instalado correctamente")
    else:
        err(f"npm install {_DASHBOARD_PKG} terminó con error")
        tip(f"Instálalo manualmente: {cmd}")


# ─────────────────────────────────────────────
#  Paso 5 — Cargar flujos de demo
# ─────────────────────────────────────────────
def step5_copy_flows():
    step_header(5, "Flujos de demo")

    if not os.path.exists(FLOWS_SRC):
        warn(f"No se encontró {FLOWS_SRC} — omitiendo este paso")
        tip("Puedes importar flujos manualmente desde Node-RED → menú ≡ → Import")
        return

    if os.path.exists(FLOWS_DST):
        blank()
        warn("Ya tienes flujos en Node-RED. Para cargar los flujos de demo de LoCoAudit,")
        if RICH and OUTPUT_QUEUE is None:
            console.print("       importa manualmente el archivo [bold]examples/flows.json[/bold] desde el menú de Node-RED.")
        else:
            tip("importa manualmente el archivo examples/flows.json desde el menú de Node-RED.")
        tip("Node-RED → menú ≡ (esquina superior derecha) → Import → sube el archivo")
        tip(f"Ruta del archivo: {FLOWS_SRC}")
    else:
        os.makedirs(NODE_RED_DIR, exist_ok=True)
        import shutil as _sh
        try:
            _sh.copy2(FLOWS_SRC, FLOWS_DST)
            ok(f"Flujos de demo cargados en {FLOWS_DST}")
        except OSError as exc:
            err(f"No se pudo copiar flows.json: {exc}")
            tip(f"Cópialo manualmente: cp \"{FLOWS_SRC}\" \"{FLOWS_DST}\"")


# ─────────────────────────────────────────────
#  Proceso de Node-RED — referencia y parada
# ─────────────────────────────────────────────
NODE_RED_PROC = None   # subprocess.Popen mientras Node-RED corre en modo GUI


def _detached_popen_kwargs() -> dict:
    """Flags de arranque que permiten matar luego al hijo y a su descendencia."""
    if OS == "Windows":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def is_node_red_running() -> bool:
    """¿Está Node-RED corriendo? Fuente única para el estado de la ventana."""
    return NODE_RED_PROC is not None and NODE_RED_PROC.poll() is None


def start_node_red() -> bool:
    """Lanza Node-RED en segundo plano (sin repetir los pasos previos). True si arrancó."""
    global NODE_RED_PROC
    try:
        NODE_RED_PROC = subprocess.Popen(
            NODE_RED_ARGS, env=_child_env(), **_detached_popen_kwargs()
        )
    except FileNotFoundError:
        NODE_RED_PROC = None
        err(f"No se pudo lanzar '{NODE_RED_CMD}' — comprueba que está en el PATH")
        tip(f"Instálalo: {MANUAL_INSTALL['node-red'].get(OS)}")
        return False
    return True


def stop_node_red(timeout: int = 10) -> bool:
    """Detiene Node-RED y su descendencia. True si había algo que parar."""
    global NODE_RED_PROC
    proc = NODE_RED_PROC
    if proc is None or proc.poll() is not None:
        NODE_RED_PROC = None
        return False
    try:
        if OS == "Windows":
            # node-red.cmd lanza node.exe como hijo: /T mata el árbol completo
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=timeout)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=timeout)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    finally:
        NODE_RED_PROC = None
    return True


# ─────────────────────────────────────────────
#  Paso 6 — Arrancar Node-RED
# ─────────────────────────────────────────────
def step6_launch():
    step_header(6, "Iniciando Node-RED")
    _print_summary()
    ok("Todo listo. Arrancando Node-RED...")

    if OUTPUT_QUEUE is not None:
        # GUI mode: launch without blocking the background thread
        if start_node_red():
            blank()
            ok("Node-RED iniciado — abre http://localhost:1880 en tu navegador")
        return

    # Terminal mode: blocking
    if RICH:
        console.print()
        sep()
        console.print()
    else:
        tip(f"Abre tu navegador en: {BO}http://localhost:1880{RS}")
        blank()
        sep()
        blank()

    try:
        subprocess.run(NODE_RED_ARGS, env=_child_env())
    except KeyboardInterrupt:
        blank()
        warn("Node-RED detenido por el usuario")
        blank()
    except FileNotFoundError:
        err(f"No se pudo lanzar '{NODE_RED_CMD}' — comprueba que está en el PATH")
        tip(f"Instálalo: {MANUAL_INSTALL['node-red'].get(OS)}")
        sys.exit(1)


def _gui_start_node_red() -> bool:
    """Arranque desde el botón de la ventana; vuelca la tarjeta pendiente al terminar."""
    global _gui_card_title
    exito = start_node_red()
    if exito:
        ok("Node-RED iniciado — abre http://localhost:1880 en tu navegador")
    _gui_card_title = "Node-RED"
    _gui_flush_card()
    return exito


# ─────────────────────────────────────────────
#  run_all_steps — hilo de fondo para el modo GUI
# ─────────────────────────────────────────────
def run_all_steps():
    """Ejecuta los 6 pasos en el hilo de fondo y envía 'done' al terminar."""
    missing = step1_required_deps()
    if missing:
        err(f"Faltan dependencias requeridas: {', '.join(missing)}")
        tip("Instálalas y vuelve a ejecutar el launcher")
        _gui_flush_card()
        OUTPUT_QUEUE.put({"type": "done"})
        return
    if not step2_optional_tools():
        err("Node-RED sigue sin estar disponible")
        tip("Reinicia el equipo si acabas de instalarlo y vuelve a ejecutar el launcher")
        _gui_flush_card()
        OUTPUT_QUEUE.put({"type": "done"})
        return
    step3_register_package()
    step4_install_dashboard()
    step5_copy_flows()
    step6_launch()
    _gui_flush_card()
    OUTPUT_QUEUE.put({"type": "done", "node_red": NODE_RED_PROC is not None})


# ─────────────────────────────────────────────
#  Punto de entrada
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if HAS_GUI:
        gui = LoCoAuditGUI(VERSION, OS, platform.python_version(),
                           on_stop=stop_node_red,
                           on_start=_gui_start_node_red,
                           is_running=is_node_red_running)
        OUTPUT_QUEUE = gui.q
        threading.Thread(target=run_all_steps, daemon=True).start()
        gui.run()
    else:
        print_welcome()

        missing = step1_required_deps()
        if missing:
            blank()
            err(f"Faltan dependencias requeridas: {', '.join(missing)}")
            tip("Instálalas y vuelve a ejecutar: python3 launcher/lcaudit_launcher.py")
            blank()
            sys.exit(1)

        if not step2_optional_tools():
            blank()
            err("Node-RED sigue sin estar disponible")
            tip("Reinicia el equipo si acabas de instalarlo y vuelve a ejecutar el launcher")
            blank()
            sys.exit(1)
        step3_register_package()
        step4_install_dashboard()
        step5_copy_flows()
        step6_launch()
