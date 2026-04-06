#!/usr/bin/env python3
"""
LCAudit Launcher — Menú interactivo para el framework de auditoría LCAudit.

Verifica dependencias, lanza Node-RED y abre dashboards.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import shutil
import webbrowser
import platform
import socket
import os
import threading
import signal
import sys

# ── Configuración ──────────────────────────────────────────────────────────

NODE_RED_URL = "http://localhost:1880"
AUDIT_REPORTS_DIR = os.path.expanduser("~/audit-reports")

TOOLS = [
    {
        "name": "Node.js",
        "cmd": "node",
        "check_args": ["--version"],
        "install_hint": "https://nodejs.org/",
        "required": True,
    },
    {
        "name": "Node-RED",
        "cmd": "node-red",
        "check_args": ["--help"],
        "install_hint": "npm install -g node-red",
        "required": True,
    },
    {
        "name": "Nmap",
        "cmd": "nmap",
        "check_args": ["--version"],
        "install_hint": "brew install nmap / apt install nmap",
        "required": False,
    },
    {
        "name": "Trivy",
        "cmd": "trivy",
        "check_args": ["--version"],
        "install_hint": "brew install trivy / https://trivy.dev",
        "required": False,
    },
    {
        "name": "Nuclei",
        "cmd": "nuclei",
        "check_args": ["-version"],
        "install_hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "required": False,
    },
]

# ── Colores ────────────────────────────────────────────────────────────────

COLORS = {
    "bg": "#0f0f1a",
    "bg_card": "#1a1a2e",
    "bg_card_hover": "#24243e",
    "accent": "#6c5ce7",
    "accent_hover": "#7d6ff0",
    "success": "#2ecc71",
    "warning": "#f1c40f",
    "danger": "#e74c3c",
    "text": "#cdd6f4",
    "text_dim": "#888",
    "text_muted": "#555",
    "border": "#2d2d44",
}


class LCAuditLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("LCAudit — Framework de Auditoría")
        self.root.geometry("700x620")
        self.root.configure(bg=COLORS["bg"])
        self.root.resizable(False, False)

        self.node_red_process = None
        self.tool_status = {}

        self._build_ui()
        self._check_dependencies()

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=COLORS["accent"], height=70)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡️  LCAudit Framework",
            font=("Helvetica", 18, "bold"),
            fg="#fff",
            bg=COLORS["accent"],
        ).pack(side="left", padx=20, pady=15)

        tk.Label(
            header,
            text="v2.0",
            font=("Helvetica", 10),
            fg="#ddd",
            bg=COLORS["accent"],
        ).pack(side="right", padx=20)

        # ── Info del sistema ──
        sys_frame = tk.Frame(self.root, bg=COLORS["bg_card"], highlightbackground=COLORS["border"], highlightthickness=1)
        sys_frame.pack(fill="x", padx=16, pady=(12, 6))

        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()}"
        arch = platform.machine()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "No disponible"

        info_text = f"💻 {hostname}  ·  📡 {ip}  ·  🖥️ {os_info}  ·  ⚙️ {arch}"
        tk.Label(
            sys_frame,
            text=info_text,
            font=("Helvetica", 11),
            fg=COLORS["text"],
            bg=COLORS["bg_card"],
            pady=10,
            padx=14,
        ).pack(anchor="w")

        # ── Dependencias ──
        dep_label = tk.Label(
            self.root,
            text="DEPENDENCIAS",
            font=("Helvetica", 10, "bold"),
            fg=COLORS["text_dim"],
            bg=COLORS["bg"],
        )
        dep_label.pack(anchor="w", padx=18, pady=(10, 4))

        self.deps_frame = tk.Frame(self.root, bg=COLORS["bg"])
        self.deps_frame.pack(fill="x", padx=16)

        # ── Botones principales ──
        btn_frame = tk.Frame(self.root, bg=COLORS["bg"])
        btn_frame.pack(fill="x", padx=16, pady=(16, 8))

        self._make_button(
            btn_frame,
            "🚀  Iniciar Node-RED",
            self._start_node_red,
            COLORS["accent"],
            COLORS["accent_hover"],
        ).pack(side="left", padx=(0, 8), expand=True, fill="x")

        self._make_button(
            btn_frame,
            "🌐  Abrir Node-RED",
            self._open_node_red,
            "#2d6a4f",
            "#369670",
        ).pack(side="left", padx=(0, 8), expand=True, fill="x")

        self._make_button(
            btn_frame,
            "🛑  Detener Node-RED",
            self._stop_node_red,
            COLORS["danger"],
            "#c0392b",
        ).pack(side="left", expand=True, fill="x")

        # Fila 2
        btn_frame2 = tk.Frame(self.root, bg=COLORS["bg"])
        btn_frame2.pack(fill="x", padx=16, pady=(0, 8))

        self._make_button(
            btn_frame2,
            "📊  Abrir Dashboard",
            self._open_dashboard,
            "#2d3436",
            "#444",
        ).pack(side="left", padx=(0, 8), expand=True, fill="x")

        self._make_button(
            btn_frame2,
            "📂  Abrir Reportes",
            self._open_reports_dir,
            "#2d3436",
            "#444",
        ).pack(side="left", padx=(0, 8), expand=True, fill="x")

        self._make_button(
            btn_frame2,
            "🔄  Verificar",
            self._check_dependencies,
            "#2d3436",
            "#444",
        ).pack(side="left", expand=True, fill="x")

        # ── Log area ──
        log_label = tk.Label(
            self.root,
            text="LOG",
            font=("Helvetica", 10, "bold"),
            fg=COLORS["text_dim"],
            bg=COLORS["bg"],
        )
        log_label.pack(anchor="w", padx=18, pady=(10, 4))

        log_frame = tk.Frame(
            self.root,
            bg=COLORS["bg_card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        log_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.log_text = tk.Text(
            log_frame,
            bg=COLORS["bg_card"],
            fg=COLORS["text"],
            font=("Menlo", 10),
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
            height=6,
            state="disabled",
        )
        self.log_text.pack(fill="both", expand=True)

        self._log("LCAudit Launcher iniciado")

    def _make_button(self, parent, text, command, bg, hover_bg):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=("Helvetica", 11, "bold"),
            fg="#fff",
            bg=bg,
            activebackground=hover_bg,
            activeforeground="#fff",
            relief="flat",
            bd=0,
            padx=12,
            pady=10,
            cursor="hand2",
        )
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover_bg))
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
        return btn

    def _log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"  {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _check_dependencies(self):
        # Limpiar frame
        for w in self.deps_frame.winfo_children():
            w.destroy()

        self._log("Verificando dependencias...")

        for tool in TOOLS:
            frame = tk.Frame(
                self.deps_frame,
                bg=COLORS["bg_card"],
                highlightbackground=COLORS["border"],
                highlightthickness=1,
            )
            frame.pack(fill="x", pady=2)

            found = shutil.which(tool["cmd"]) is not None
            version = ""

            if found:
                try:
                    result = subprocess.run(
                        [tool["cmd"]] + tool["check_args"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    output = (result.stdout + result.stderr).strip()
                    # Extraer primera línea con versión
                    for line in output.split("\n"):
                        line = line.strip()
                        if line and ("version" in line.lower() or line.startswith("v") or any(c.isdigit() for c in line[:5])):
                            version = line[:60]
                            break
                except Exception:
                    version = "versión desconocida"

            status_icon = "✅" if found else ("❌" if tool["required"] else "⚠️")
            status_color = COLORS["success"] if found else (COLORS["danger"] if tool["required"] else COLORS["warning"])

            tk.Label(
                frame,
                text=f"  {status_icon}  {tool['name']}",
                font=("Helvetica", 11, "bold"),
                fg=status_color,
                bg=COLORS["bg_card"],
                anchor="w",
                padx=8,
                pady=6,
            ).pack(side="left")

            if version:
                tk.Label(
                    frame,
                    text=version,
                    font=("Menlo", 9),
                    fg=COLORS["text_dim"],
                    bg=COLORS["bg_card"],
                    padx=8,
                ).pack(side="left")
            elif not found:
                tk.Label(
                    frame,
                    text=tool["install_hint"],
                    font=("Menlo", 9),
                    fg=COLORS["text_muted"],
                    bg=COLORS["bg_card"],
                    padx=8,
                ).pack(side="left")

            self.tool_status[tool["cmd"]] = found

        self._log("Verificación completada")

    def _start_node_red(self):
        if self.node_red_process and self.node_red_process.poll() is None:
            self._log("⚠️  Node-RED ya está ejecutándose")
            return

        if not self.tool_status.get("node-red", False):
            messagebox.showerror(
                "Error",
                "Node-RED no está instalado.\nInstalar con: npm install -g node-red",
            )
            return

        self._log("🚀 Iniciando Node-RED...")

        def run():
            try:
                self.node_red_process = subprocess.Popen(
                    ["node-red"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.root.after(100, lambda: self._log("✅ Node-RED iniciado en http://localhost:1880"))

                for line in self.node_red_process.stdout:
                    line = line.strip()
                    if line:
                        self.root.after(0, lambda l=line: self._log(f"  NR: {l[:80]}"))
            except Exception as e:
                self.root.after(0, lambda: self._log(f"❌ Error al iniciar Node-RED: {e}"))

        threading.Thread(target=run, daemon=True).start()

    def _stop_node_red(self):
        if self.node_red_process and self.node_red_process.poll() is None:
            self.node_red_process.terminate()
            self.node_red_process = None
            self._log("🛑 Node-RED detenido")
        else:
            self._log("⚠️  Node-RED no está ejecutándose")

    def _open_node_red(self):
        self._log(f"🌐 Abriendo {NODE_RED_URL}")
        webbrowser.open(NODE_RED_URL)

    def _open_dashboard(self):
        dashboard_path = os.path.join(AUDIT_REPORTS_DIR, "dashboard.html")
        if os.path.exists(dashboard_path):
            self._log(f"📊 Abriendo dashboard: {dashboard_path}")
            webbrowser.open(f"file://{dashboard_path}")
        else:
            self._log("⚠️  No se encontró dashboard.html. Ejecuta una auditoría primero.")
            messagebox.showinfo(
                "Dashboard no encontrado",
                f"No se encontró dashboard en:\n{dashboard_path}\n\nEjecuta una auditoría desde Node-RED primero.",
            )

    def _open_reports_dir(self):
        if os.path.exists(AUDIT_REPORTS_DIR):
            self._log(f"📂 Abriendo {AUDIT_REPORTS_DIR}")
            if platform.system() == "Darwin":
                subprocess.Popen(["open", AUDIT_REPORTS_DIR])
            elif platform.system() == "Linux":
                subprocess.Popen(["xdg-open", AUDIT_REPORTS_DIR])
            else:
                subprocess.Popen(["explorer", AUDIT_REPORTS_DIR])
        else:
            self._log("⚠️  Directorio de reportes no existe todavía")
            messagebox.showinfo(
                "Directorio no encontrado",
                f"El directorio {AUDIT_REPORTS_DIR} se creará automáticamente al ejecutar una auditoría.",
            )


def main():
    root = tk.Tk()

    # Centrar ventana
    root.update_idletasks()
    w = 700
    h = 620
    x = (root.winfo_screenwidth() // 2) - (w // 2)
    y = (root.winfo_screenheight() // 2) - (h // 2)
    root.geometry(f"{w}x{h}+{x}+{y}")

    app = LCAuditLauncher(root)

    def on_close():
        if app.node_red_process and app.node_red_process.poll() is None:
            app.node_red_process.terminate()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
