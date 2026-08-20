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
    global _gui_card_title, _gui_card_items
    if OUTPUT_QUEUE is not None:
        _gui_flush_card()
        _gui_card_title = title
        _gui_card_items = []
        OUTPUT_QUEUE.put({"type": "progress", "step": n, "label": f"Paso {n}/6 — {title}"})
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
        "Linux":   "(apt) sudo apt install nodejs   |   (pacman) sudo pacman -S nodejs   |   (dnf) sudo dnf install nodejs",
        "Windows": "winget install -e --idOpenJS.NodeJS --source winget   o   https://nodejs.org",
    },
    "npm": {
        "Darwin":  "Se instala junto con Node.js: brew install node",
        "Linux":   "(apt) sudo apt install npm   |   (pacman) sudo pacman -S npm   |   (dnf) sudo dnf install npm",
        "Windows": "Se instala junto con Node.js",
    },
    "node-red": {
        "Darwin":  "npm install -g --unsafe-perm node-red",
        "Linux":   "sudo npm install -g --unsafe-perm node-red",
        "Windows": "npm install -g --unsafe-perm node-red",
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
        "Windows": "https://aquasecurity.github.io/trivy/latest/getting-started/installation",
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

# Estado de herramientas opcionales (rellenado en step2, usado en resumen final)
_tool_status: dict = {}

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
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            return "instalado pero el daemon no está en ejecución — ábrelo primero"
        return None
    except Exception:
        return "no se pudo conectar con el daemon de Docker"


def get_auto_install_cmd(tool: str) -> str | None:
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
            return {
                "nmap":   "winget install -e --id Insecure.Nmap --source winget",
                "docker": "winget install -e --id Docker.DockerDesktop --source winget",
            }.get(tool)
        return None

    return None


def run_install(cmd: str, label: str, timeout: int = 300) -> bool:
    """Runs a shell install command. Returns True on success."""
    work(f"Instalando {label}...")
    tip(f"Ejecutando: {cmd}")
    blank()
    try:
        result = subprocess.run(cmd, shell=True, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        err(f"La instalación de {label} superó el tiempo límite ({timeout}s)")
        tip(f"Intenta manualmente: {MANUAL_INSTALL.get(label.lower(), {}).get(OS, '?')}")
        return False
    except Exception as exc:
        err(f"Error inesperado instalando {label}: {exc}")
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
def _print_summary():
    if OUTPUT_QUEUE is not None:
        active   = [(label, TOOL_DESC.get(cmd, "")) for cmd, label in OPTIONAL_TOOLS if _tool_status.get(cmd)]
        inactive = [(label, TOOL_DESC.get(cmd, "")) for cmd, label in OPTIONAL_TOOLS if not _tool_status.get(cmd)]
        if active:
            ok("Módulos activos: " + ", ".join(label for label, _ in active))
        if inactive:
            warn("Fallback (no instalados): " + ", ".join(label for label, _ in inactive))
        return

    if not RICH:
        return

    active   = [(label, TOOL_DESC.get(cmd, "")) for cmd, label in OPTIONAL_TOOLS if _tool_status.get(cmd)]
    inactive = [(label, TOOL_DESC.get(cmd, "")) for cmd, label in OPTIONAL_TOOLS if not _tool_status.get(cmd)]

    t = Table(box=rbox.SIMPLE, show_header=False, pad_edge=False, expand=True)
    t.add_column("icon", width=5,  no_wrap=True)
    t.add_column("name", width=18, no_wrap=True, style="bold")
    t.add_column("desc", style="dim")

    if active:
        t.add_row("", "[bold green]Módulos activos[/bold green]", "")
        for label, desc in active:
            t.add_row("  [green]✅[/green]", f"[green]{label}[/green]", desc)
        if inactive:
            t.add_row("", "", "")

    if inactive:
        t.add_row("", "[bold yellow]Fallback[/bold yellow]", "")
        for label, desc in inactive:
            t.add_row("  [yellow]⚠️ [/yellow]", f"[yellow]{label}[/yellow]", desc)

    if not active and not inactive:
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
    step_header(1, "Dependencias requeridas")
    missing = []

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
        else:
            ok("Node-RED instalado")

    return missing


# ─────────────────────────────────────────────
#  Paso 2 — Herramientas opcionales
# ─────────────────────────────────────────────
def step2_optional_tools():
    step_header(2, "Herramientas opcionales")

    is_tty     = sys.stdin.isatty()
    all_present = True

    for cmd, label in OPTIONAL_TOOLS:
        # Lynis is not available natively on Windows
        if cmd == "lynis" and OS == "Windows":
            _tool_status[cmd] = False
            warn(f"{label} — no disponible en Windows sin WSL")
            tip("Instala WSL: https://learn.microsoft.com/es-es/windows/wsl/install")
            blank()
            continue

        if command_exists(cmd):
            if cmd == "docker":
                daemon_warn = check_docker_daemon()
                if daemon_warn:
                    _tool_status[cmd] = False
                    warn(f"Docker {daemon_warn}")
                else:
                    _tool_status[cmd] = True
                    ok("Docker instalado y daemon activo")
            else:
                _tool_status[cmd] = True
                ok(f"{label} instalado — {TOOL_DESC.get(cmd, '')}")
            continue

        # ── Tool missing ──
        _tool_status[cmd] = False
        all_present = False
        warn(f"{label} no encontrado — {TOOL_DESC.get(cmd, '')}")

        auto_cmd = get_auto_install_cmd(cmd)

        if auto_cmd and OUTPUT_QUEUE is not None:
            # GUI mode: ask via queue, block until user responds
            evt    = threading.Event()
            result = []
            OUTPUT_QUEUE.put({
                "type":   "ask",
                "tool":   label,
                "desc":   auto_cmd,
                "event":  evt,
                "result": result,
            })
            evt.wait()
            # result queda vacía si la ventana se cierra sin responder;
            # ["No, omitir"] mete False, así que hay que mirar el contenido
            if result and result[0]:
                blank()
                success = run_install(auto_cmd, label)
                if success and command_exists(cmd):
                    _tool_status[cmd] = True
                    ok(f"{label} instalado correctamente")
                    if cmd == "docker":
                        daemon_warn = check_docker_daemon()
                        if daemon_warn:
                            _tool_status[cmd] = False
                            warn(f"Docker {daemon_warn}")
                elif success:
                    warn(f"Instalación completada pero {label} no se encontró en PATH")
                    tip("Puede ser necesario reabrir la terminal o actualizar el PATH")
                else:
                    err(f"La instalación de {label} falló")
                    tip(f"Intenta manualmente: {MANUAL_INSTALL.get(cmd, {}).get(OS, 'Consulta la documentación oficial')}")
            else:
                warn(f"Omitiendo {label} — el nodo correspondiente usará el modo de fallback")

        elif auto_cmd and is_tty:
            if RICH:
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
                if success and command_exists(cmd):
                    _tool_status[cmd] = True
                    ok(f"{label} instalado correctamente")
                    if cmd == "docker":
                        daemon_warn = check_docker_daemon()
                        if daemon_warn:
                            _tool_status[cmd] = False
                            warn(f"Docker {daemon_warn}")
                elif success:
                    warn(f"Instalación completada pero {label} no se encontró en PATH")
                    tip("Puede ser necesario reabrir la terminal o actualizar el PATH")
                else:
                    err(f"La instalación de {label} falló")
                    tip(f"Intenta manualmente: {MANUAL_INSTALL.get(cmd, {}).get(OS, 'Consulta la documentación oficial')}")
            else:
                warn(f"Omitiendo {label} — el nodo correspondiente usará el modo de fallback")
        else:
            # No auto-install available or non-interactive shell
            tip(f"Para instalarlo: {MANUAL_INSTALL.get(cmd, {}).get(OS, 'Consulta la documentación oficial')}")

        blank()

    if all_present:
        ok("Todas las herramientas opcionales están disponibles")


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
    global NODE_RED_PROC
    step_header(6, "Iniciando Node-RED")
    _print_summary()
    ok("Todo listo. Arrancando Node-RED...")

    if OUTPUT_QUEUE is not None:
        # GUI mode: launch without blocking the background thread
        try:
            NODE_RED_PROC = subprocess.Popen(
                [NODE_RED_CMD], **_detached_popen_kwargs()
            )
            blank()
            ok("Node-RED iniciado — abre http://localhost:1880 en tu navegador")
        except FileNotFoundError:
            err(f"No se pudo lanzar '{NODE_RED_CMD}' — comprueba que está en el PATH")
            tip(f"Instálalo: {MANUAL_INSTALL['node-red'].get(OS)}")
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
        subprocess.run([NODE_RED_CMD])
    except KeyboardInterrupt:
        blank()
        warn("Node-RED detenido por el usuario")
        blank()
    except FileNotFoundError:
        err(f"No se pudo lanzar '{NODE_RED_CMD}' — comprueba que está en el PATH")
        tip(f"Instálalo: {MANUAL_INSTALL['node-red'].get(OS)}")
        sys.exit(1)


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
    step2_optional_tools()
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
                           on_stop=stop_node_red)
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

        step2_optional_tools()
        step3_register_package()
        step4_install_dashboard()
        step5_copy_flows()
        step6_launch()
