import platform as _platform
import tkinter as tk
from tkinter import ttk
import threading
import queue
import webbrowser


class LoCoAuditGUI:
    def __init__(self, version, os_name, py_version, on_stop=None,
                 on_start=None, is_running=None):
        self.q = queue.Queue()
        self.on_stop = on_stop
        self.on_start = on_start
        # Fuente única del estado de Node-RED para todos los botones.
        self.is_running = is_running or (lambda: False)
        self._busy = False    # transición en curso: bloquea dobles pulsaciones
        self._last_state = None   # último estado pintado, para no repintar en balde
        self.root = tk.Tk()
        self.root.title("LoCoAudit")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, True)
        self.root.minsize(900, 600)
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"1000x660+{(sw-1000)//2}+{(sh-660)//2}")
        if _platform.system() == "Linux":
            self.root.attributes("-zoomed", True)
        else:
            self.root.state("zoomed")
        self._construir(version, os_name, py_version)
        self.root.protocol("WM_DELETE_WINDOW", self._al_cerrar)
        self.root.after(100, self._sondear)

    def _construir(self, version, os_name, py_version):
        # CABECERA
        header = tk.Frame(self.root, bg="#181825", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        left = tk.Frame(header, bg="#181825")
        left.pack(side="left", padx=20, pady=10)
        tk.Label(left, text="◈ LoCoAudit", font=("Courier", 20, "bold"),
                 fg="#89dceb", bg="#181825").pack(anchor="w")
        tk.Label(left, text="Node-RED Security Audit Suite",
                 font=("Courier", 9), fg="#6c7086", bg="#181825").pack(anchor="w")
        tk.Label(header, text=f"v{version}  |  {os_name}  |  Python {py_version}",
                 font=("Courier", 9), fg="#6c7086", bg="#181825").pack(
                 side="right", padx=20, anchor="e")

        # CONTENIDO: panel izquierdo + derecho
        content = tk.Frame(self.root, bg="#1e1e2e")
        content.pack(fill="both", expand=True)

        # Panel izquierdo
        left_panel = tk.Frame(content, bg="#181825", width=220)
        left_panel.pack(side="left", fill="y")
        left_panel.pack_propagate(False)
        tk.Label(left_panel, text="PASOS", font=("Courier", 8),
                 fg="#6c7086", bg="#181825").pack(anchor="w", padx=16, pady=(14, 6))

        self.step_frames = []
        self.step_icons = []
        self.step_subs = []
        steps = [
            "Dependencias",
            "Herramientas",
            "Registrar",
            "Dashboard",
            "Flujos demo",
            "Node-RED",
        ]
        for i, name in enumerate(steps):
            f = tk.Frame(left_panel, bg="#181825", cursor="arrow")
            f.pack(fill="x", padx=8, pady=2)
            icon_lbl = tk.Label(f, text="○", font=("Courier", 14),
                                fg="#6c7086", bg="#181825", width=2)
            icon_lbl.pack(side="left", padx=(8, 4), pady=6)
            text_frame = tk.Frame(f, bg="#181825")
            text_frame.pack(side="left", fill="x", expand=True)
            tk.Label(text_frame, text=name, font=("Courier", 10),
                     fg="#cdd6f4", bg="#181825",
                     wraplength=180, justify="left").pack(anchor="w")
            sub = tk.Label(text_frame, text="", font=("Courier", 8),
                           fg="#6c7086", bg="#181825")
            sub.pack(anchor="w")
            self.step_frames.append(f)
            self.step_icons.append(icon_lbl)
            self.step_subs.append(sub)

        # Panel derecho con scroll
        right_panel = tk.Frame(content, bg="#1e1e2e")
        right_panel.pack(side="left", fill="both", expand=True)
        canvas = tk.Canvas(right_panel, bg="#1e1e2e", highlightthickness=0)
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical",
                                  command=canvas.yview)
        self.cards_frame = tk.Frame(canvas, bg="#1e1e2e")
        self.cards_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Frame de pregunta (oculto por defecto)
        self.ask_frame = tk.Frame(self.root, bg="#45475a", pady=12)
        self.ask_label = tk.Label(self.ask_frame, text="", font=("Courier", 11),
                                  fg="#cdd6f4", bg="#45475a")
        self.ask_label.pack(pady=(0, 4))
        self.ask_desc = tk.Label(self.ask_frame, text="", font=("Courier", 9),
                                 fg="#6c7086", bg="#45475a")
        self.ask_desc.pack(pady=(0, 8))
        # Aviso opcional (descarga, reinicio...); solo se muestra si el mensaje trae "note".
        self.ask_note = tk.Label(self.ask_frame, text="", font=("Courier", 9),
                                 fg="#f9e2af", bg="#45475a",
                                 wraplength=760, justify="center")
        btn_row = tk.Frame(self.ask_frame, bg="#45475a")
        btn_row.pack()
        self.yes_btn = tk.Button(btn_row, text="Sí, instalar",
                                 bg="#a6e3a1", fg="#1e1e2e", font=("Courier", 10, "bold"),
                                 relief="flat", padx=16, pady=6)
        self.yes_btn.pack(side="left", padx=8)
        self.no_btn = tk.Button(btn_row, text="No, omitir",
                                bg="#585b70", fg="#cdd6f4", font=("Courier", 10),
                                relief="flat", padx=16, pady=6)
        self.no_btn.pack(side="left", padx=8)

        # FOOTER
        footer = tk.Frame(self.root, bg="#181825", height=80)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Loco.Horizontal.TProgressbar",
                        background="#89dceb", troughcolor="#313244",
                        bordercolor="#313244", lightcolor="#89dceb",
                        darkcolor="#89dceb")
        self.progress = ttk.Progressbar(footer, style="Loco.Horizontal.TProgressbar",
                                        maximum=6, length=820, value=0)
        self.progress.pack(pady=(10, 2))
        self.footer_label = tk.Label(footer, text="Iniciando...",
                                     font=("Courier", 9), fg="#6c7086", bg="#181825")
        self.footer_label.pack()
        self.btn_row = tk.Frame(footer, bg="#181825")
        self.open_btn = tk.Button(self.btn_row, text="🚀  Abrir Node-RED en el navegador",
                                  bg="#89dceb", fg="#1e1e2e",
                                  font=("Courier", 11, "bold"), relief="flat",
                                  padx=20, pady=8,
                                  command=lambda: webbrowser.open("http://localhost:1880"))
        # Un único botón para arrancar y parar; su aspecto lo fija _pintar_botones().
        self.toggle_btn = tk.Button(self.btn_row, text="■  Detener Node-RED",
                                    bg="#f38ba8", fg="#1e1e2e",
                                    font=("Courier", 11, "bold"), relief="flat",
                                    padx=20, pady=8,
                                    command=self._pulsar_alternar)
        # btn_row se muestra solo al terminar

    def agregar_tarjeta(self, title, items):
        """items = lista de (icono, texto, color)"""
        card = tk.Frame(self.cards_frame, bg="#313244", pady=10, padx=12)
        card.pack(fill="x", padx=12, pady=6)
        tk.Label(card, text=title, font=("Courier", 10, "bold"),
                 fg="#cdd6f4", bg="#313244").pack(anchor="w", pady=(0, 6))
        for icon, text, color in items:
            row = tk.Frame(card, bg="#313244")
            row.pack(fill="x", pady=1)
            tk.Label(row, text=icon, font=("Courier", 11),
                     fg=color, bg="#313244", width=2).pack(side="left")
            tk.Label(row, text=text, font=("Courier", 10),
                     fg=color, bg="#313244",
                     wraplength=680, justify="left").pack(side="left", padx=6)

    def mostrar_pregunta(self, tool, desc, event, result, note="",
                         yes_text="Sí, instalar", no_text="No, omitir",
                         title=None):
        self.ask_label.config(text=title or f"⚠  ¿Instalar {tool}?")
        self.ask_desc.config(text=desc)
        if note:
            self.ask_note.config(text=note)
            self.ask_note.pack(pady=(0, 8))
        else:
            self.ask_note.pack_forget()
        self.yes_btn.config(text=yes_text,
                            command=lambda: self._responder(True, event, result))
        self.no_btn.config(text=no_text,
                           command=lambda: self._responder(False, event, result))
        self.ask_frame.pack(fill="x", before=self.root.winfo_children()[-1])

    def _responder(self, yes, event, result):
        result.append(yes)
        event.set()
        self.ask_frame.pack_forget()

    def _pintar_botones(self, transicion=""):
        """Pinta los botones según is_running(); `transicion` fuerza el estado intermedio."""
        APAGADO = {"state": "disabled", "bg": "#45475a", "fg": "#6c7086"}
        if transicion:
            self.toggle_btn.config(text=transicion, **APAGADO)
            self.open_btn.config(**APAGADO)
            return
        self._last_state = self.is_running()
        if self._last_state:
            self.toggle_btn.config(text="■  Detener Node-RED", state="normal",
                                   bg="#f38ba8", fg="#1e1e2e")
            self.open_btn.config(state="normal", bg="#89dceb", fg="#1e1e2e")
        else:
            self.toggle_btn.config(text="▶  Iniciar Node-RED", state="normal",
                                   bg="#a6e3a1", fg="#1e1e2e")
            self.open_btn.config(**APAGADO)

    def _pulsar_alternar(self):
        # Arrancar o parar puede tardar: se hace en otro hilo para no congelar la ventana.
        if self._busy:
            return
        self._busy = True
        arrancar = not self.is_running()
        if arrancar:
            rotulo = "Arrancando..."
        else:
            rotulo = "Deteniendo..."
        self._pintar_botones(rotulo)
        threading.Thread(target=self._alternar_en_hilo, args=(arrancar,),
                         daemon=True).start()

    def _alternar_en_hilo(self, arrancar):
        try:
            if arrancar:
                accion = self.on_start
            else:
                accion = self.on_stop
            if accion is not None:
                accion()
        except Exception:
            pass
        finally:
            self._busy = False
            self.q.put({"type": "node_red_state"})

    def _al_cerrar(self):
        if self.on_stop is not None:
            try:
                self.on_stop()
            except Exception:
                pass
        self.root.destroy()

    def actualizar_paso(self, idx, icon, color, sub=""):
        icons = {"ok": ("✓", "#a6e3a1"), "err": ("✗", "#f38ba8"),
                 "active": ("⟳", "#89b4fa"), "pending": ("○", "#6c7086")}
        ic, col = icons.get(icon, (icon, color))
        self.step_icons[idx].config(text=ic, fg=col)
        self.step_subs[idx].config(text=sub)
        if icon == "active":
            bg = "#313244"
        else:
            bg = "#181825"
        self.step_frames[idx].config(bg=bg)
        for w in self.step_frames[idx].winfo_children():
            w.config(bg=bg)
            for ww in w.winfo_children():
                try:
                    ww.config(bg=bg)
                except Exception:
                    pass

    def _sondear(self):
        try:
            while True:
                msg = self.q.get_nowait()
                t = msg.get("type")
                if t == "progress":
                    n = msg["step"]
                    self.progress["value"] = n
                    self.footer_label.config(text=msg.get("label", ""))
                    if n > 0:
                        self.actualizar_paso(n - 1, "active", "")
                    if n > 1:
                        self.actualizar_paso(n - 2, "ok", "", msg.get("prev_sub", ""))
                elif t == "card":
                    self.agregar_tarjeta(msg["title"], msg["items"])
                elif t == "ask":
                    self.mostrar_pregunta(msg["tool"], msg["desc"],
                                          msg["event"], msg["result"],
                                          note=msg.get("note", ""),
                                          yes_text=msg.get("yes_text", "Sí, instalar"),
                                          no_text=msg.get("no_text", "No, omitir"),
                                          title=msg.get("title"))
                elif t == "status":
                    # Instalaciones largas: sin esto la ventana parece colgada.
                    self.footer_label.config(text=msg.get("text", ""))
                elif t == "step_status":
                    self.actualizar_paso(msg["step"], msg["icon"],
                                         msg.get("color", ""), msg.get("sub", ""))
                elif t == "node_red_state":
                    self._pintar_botones()
                elif t == "done":
                    self.progress["value"] = 6
                    self.actualizar_paso(5, "ok", "")
                    self.footer_label.pack_forget()
                    self.progress.pack_forget()
                    self.open_btn.pack(side="left", padx=8)
                    # Siempre visible, para reintentar si el primer arranque falló.
                    self.toggle_btn.pack(side="left", padx=8)
                    self.btn_row.pack(pady=14, anchor="center")
                    self._pintar_botones()
        except Exception:
            pass
        # Node-RED puede caerse solo: se reconsulta su estado para no dejar el botón desfasado.
        if not self._busy and self.btn_row.winfo_ismapped():
            estado = self.is_running()
            if estado != self._last_state:
                self._pintar_botones()
        self.root.after(100, self._sondear)

    def ejecutar(self):
        self.root.mainloop()
