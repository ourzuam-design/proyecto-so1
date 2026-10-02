import os
import re
import socket
import ssl
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog


IP_SERVIDOR = "192.168.1.197"
PUERTO = 5000

CERT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "servidor.crt"
)


# ============================================================
# CONEXIÓN CON EL SERVIDOR
# ============================================================

class Conexion:

    def __init__(self):
        self.sock = None
        self.f = None
        self.rol = None

    def conectar(self, usuario, clave):

        ctx = ssl.create_default_context(
            cafile=CERT
        )

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(10)

        self.sock = ctx.wrap_socket(
            s,
            server_hostname=IP_SERVIDOR
        )

        self.sock.connect(
            (IP_SERVIDOR, PUERTO)
        )

        self.f = self.sock.makefile(
            "rw",
            encoding="utf-8",
            newline="\n"
        )

        self.f.write(
            f"LOGIN {usuario} {clave}\n"
        )

        self.f.flush()

        resp = self.f.readline().strip()

        if not resp.startswith("OK"):
            self.cerrar()
            return False, resp

        m = re.search(
            r"rol: (\w+)",
            resp
        )

        self.rol = m.group(1) if m else "usuario"

        return True, resp

    def enviar(self, comando):

        self.f.write(
            comando + "\n"
        )

        self.f.flush()

        lineas = []

        while True:

            linea = self.f.readline()

            if linea == "":
                raise ConnectionError(
                    "El servidor cerró la conexión"
                )

            linea = linea.rstrip("\n")

            if linea == "<<FIN>>":
                break

            lineas.append(linea)

        return lineas

    def salir(self):

        try:

            if self.f:
                self.f.write("SALIR\n")
                self.f.flush()

        except (OSError, ssl.SSLError):
            pass

        self.cerrar()

    def cerrar(self):

        for x in (self.f, self.sock):

            try:

                if x:
                    x.close()

            except (OSError, ssl.SSLError):
                pass

        self.f = None
        self.sock = None


# ============================================================
# PARTE GRÁFICA
# ============================================================

class App(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            "Sistema de Administración Remota"
        )

        self.geometry("900x620")

        self.minsize(
            820,
            560
        )

        self.configure(
            bg="#101827"
        )

        self.con = Conexion()

        self.job = None

        self.usuario = ""

        self.configurar_estilos()

        self.protocol(
            "WM_DELETE_WINDOW",
            self.cerrar_app
        )

        self.pantalla_login()


    # ========================================================
    # ESTILOS
    # ========================================================

    def configurar_estilos(self):

        estilo = ttk.Style()

        estilo.theme_use("clam")

        # Fondo general
        estilo.configure(
            "TFrame",
            background="#101827"
        )

        # Tarjetas
        estilo.configure(
            "Card.TFrame",
            background="#182235"
        )

        # Texto general
        estilo.configure(
            "TLabel",
            background="#101827",
            foreground="#E5E7EB",
            font=("Segoe UI", 10)
        )

        # Título
        estilo.configure(
            "Title.TLabel",
            background="#101827",
            foreground="#FFFFFF",
            font=("Segoe UI", 22, "bold")
        )

        # Subtítulo
        estilo.configure(
            "Subtitle.TLabel",
            background="#101827",
            foreground="#94A3B8",
            font=("Segoe UI", 10)
        )

        # Título de tarjeta
        estilo.configure(
            "CardTitle.TLabel",
            background="#182235",
            foreground="#94A3B8",
            font=("Segoe UI", 10, "bold")
        )

        # Valor de tarjeta
        estilo.configure(
            "CardValue.TLabel",
            background="#182235",
            foreground="#FFFFFF",
            font=("Segoe UI", 18, "bold")
        )

        # Encabezado
        estilo.configure(
            "Header.TFrame",
            background="#111C2F"
        )

        estilo.configure(
            "Header.TLabel",
            background="#111C2F",
            foreground="#FFFFFF",
            font=("Segoe UI", 11, "bold")
        )

        # Estado conectado
        estilo.configure(
            "Status.TLabel",
            background="#111C2F",
            foreground="#22C55E",
            font=("Segoe UI", 9, "bold")
        )

        # Botón principal
        estilo.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(15, 9),
            background="#2563EB",
            foreground="#FFFFFF",
            borderwidth=0
        )

        estilo.map(
            "Accent.TButton",
            background=[
                ("active", "#1D4ED8"),
                ("pressed", "#1E40AF")
            ]
        )

        # Botón eliminar
        estilo.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(15, 9),
            background="#DC2626",
            foreground="#FFFFFF",
            borderwidth=0
        )

        estilo.map(
            "Danger.TButton",
            background=[
                ("active", "#B91C1C")
            ]
        )

        # Botón secundario
        estilo.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 8),
            background="#334155",
            foreground="#FFFFFF",
            borderwidth=0
        )

        estilo.map(
            "Secondary.TButton",
            background=[
                ("active", "#475569")
            ]
        )

        # Pestañas
        estilo.configure(
            "TNotebook",
            background="#101827",
            borderwidth=0
        )

        estilo.configure(
            "TNotebook.Tab",
            background="#1E293B",
            foreground="#CBD5E1",
            padding=(20, 10),
            font=("Segoe UI", 10, "bold")
        )

        estilo.map(
            "TNotebook.Tab",
            background=[
                ("selected", "#2563EB")
            ],
            foreground=[
                ("selected", "#FFFFFF")
            ]
        )

        # Tabla
        estilo.configure(
            "Treeview",
            background="#182235",
            foreground="#E5E7EB",
            fieldbackground="#182235",
            rowheight=30,
            font=("Segoe UI", 9)
        )

        estilo.configure(
            "Treeview.Heading",
            background="#263449",
            foreground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            padding=8
        )

        estilo.map(
            "Treeview",
            background=[
                ("selected", "#2563EB")
            ],
            foreground=[
                ("selected", "#FFFFFF")
            ]
        )

        # Checkbutton
        estilo.configure(
            "TCheckbutton",
            background="#101827",
            foreground="#CBD5E1",
            font=("Segoe UI", 9)
        )

        # ====================================================
        # COLORES DE LAS BARRAS
        # ====================================================

        # CPU = azul
        estilo.configure(
            "CPU.Horizontal.TProgressbar",
            troughcolor="#0F172A",
            background="#3B82F6"
        )

        # RAM = verde
        estilo.configure(
            "RAM.Horizontal.TProgressbar",
            troughcolor="#0F172A",
            background="#22C55E"
        )

        # Disco = naranja
        estilo.configure(
            "Disco.Horizontal.TProgressbar",
            troughcolor="#0F172A",
            background="#F59E0B"
        )


    # ========================================================
    # LIMPIAR PANTALLA
    # ========================================================

    def limpiar(self):

        if self.job:

            self.after_cancel(
                self.job
            )

            self.job = None

        for w in self.winfo_children():

            w.destroy()


    # ========================================================
    # COMUNICACIÓN
    # ========================================================

    def pedir(self, comando):

        try:

            return self.con.enviar(
                comando
            )

        except (
            OSError,
            ssl.SSLError,
            ConnectionError
        ) as e:

            messagebox.showerror(
                "Conexión perdida",
                str(e)
            )

            self.con.cerrar()

            self.pantalla_login()

            return None


    # ========================================================
    # CERRAR
    # ========================================================

    def cerrar_app(self):

        self.con.salir()

        self.destroy()


    def cerrar_sesion(self):

        self.con.salir()

        self.pantalla_login()


    # ========================================================
    # LOGIN
    # ========================================================

    def pantalla_login(self):

        self.limpiar()

        contenedor = tk.Frame(
            self,
            bg="#101827"
        )

        contenedor.pack(
            fill="both",
            expand=True
        )

        tarjeta = tk.Frame(
            contenedor,
            bg="#182235",
            padx=45,
            pady=40
        )

        tarjeta.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            tarjeta,
            text="ADMINISTRACIÓN REMOTA",
            bg="#182235",
            fg="#60A5FA",
            font=("Segoe UI", 11, "bold")
        ).pack(
            pady=(0, 8)
        )

        tk.Label(
            tarjeta,
            text="Panel de control",
            bg="#182235",
            fg="#FFFFFF",
            font=("Segoe UI", 24, "bold")
        ).pack()

        tk.Label(
            tarjeta,
            text="Conexión segura mediante TCP + TLS",
            bg="#182235",
            fg="#94A3B8",
            font=("Segoe UI", 10)
        ).pack(
            pady=(5, 28)
        )

        tk.Label(
            tarjeta,
            text="Usuario",
            bg="#182235",
            fg="#CBD5E1",
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w"
        )

        self.e_usuario = tk.Entry(
            tarjeta,
            width=34,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 11)
        )

        self.e_usuario.pack(
            pady=(6, 15),
            ipady=9
        )

        tk.Label(
            tarjeta,
            text="Contraseña",
            bg="#182235",
            fg="#CBD5E1",
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w"
        )

        self.e_clave = tk.Entry(
            tarjeta,
            width=34,
            show="*",
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 11)
        )

        self.e_clave.pack(
            pady=(6, 20),
            ipady=9
        )

        ttk.Button(
            tarjeta,
            text="INICIAR SESIÓN",
            style="Accent.TButton",
            command=self.entrar
        ).pack(
            fill="x"
        )

        self.lbl_error = tk.Label(
            tarjeta,
            text="",
            bg="#182235",
            fg="#F87171",
            font=("Segoe UI", 9)
        )

        self.lbl_error.pack(
            pady=(15, 0)
        )

        tk.Label(
            tarjeta,
            text=f"Servidor: {IP_SERVIDOR}:{PUERTO}",
            bg="#182235",
            fg="#64748B",
            font=("Segoe UI", 8)
        ).pack(
            pady=(15, 0)
        )

        self.e_usuario.focus()

        self.bind(
            "<Return>",
            lambda e: self.entrar()
        )


    def entrar(self):

        usuario = self.e_usuario.get().strip()

        clave = self.e_clave.get()

        if not usuario or not clave:

            self.lbl_error.config(
                text="Escribe usuario y contraseña"
            )

            return

        if " " in usuario or " " in clave:

            self.lbl_error.config(
                text="No se permiten espacios"
            )

            return

        try:

            ok, resp = self.con.conectar(
                usuario,
                clave
            )

        except (
            OSError,
            ssl.SSLError
        ) as e:

            self.lbl_error.config(
                text=f"No se pudo conectar: {e}"
            )

            return

        if not ok:

            self.lbl_error.config(
                text=resp.replace(
                    "ERROR ",
                    ""
                )
            )

            return

        self.unbind(
            "<Return>"
        )

        self.usuario = usuario

        self.pantalla_principal()


    # ========================================================
    # PANTALLA PRINCIPAL
    # ========================================================

    def pantalla_principal(self):

        self.limpiar()

        encabezado = tk.Frame(
            self,
            bg="#111C2F",
            height=70
        )

        encabezado.pack(
            fill="x"
        )

        encabezado.pack_propagate(False)

        izquierda = tk.Frame(
            encabezado,
            bg="#111C2F"
        )

        izquierda.pack(
            side="left",
            padx=20
        )

        tk.Label(
            izquierda,
            text="●",
            bg="#111C2F",
            fg="#22C55E",
            font=("Segoe UI", 15)
        ).pack(
            side="left",
            padx=(0, 8)
        )

        tk.Label(
            izquierda,
            text="Servidor conectado",
            bg="#111C2F",
            fg="#FFFFFF",
            font=("Segoe UI", 11, "bold")
        ).pack(
            side="left"
        )

        usuario_frame = tk.Frame(
            encabezado,
            bg="#111C2F"
        )

        usuario_frame.pack(
            side="right",
            padx=20
        )

        tk.Label(
            usuario_frame,
            text=f"{self.usuario}",
            bg="#111C2F",
            fg="#FFFFFF",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left",
            padx=10
        )

        tk.Label(
            usuario_frame,
            text=f"({self.con.rol})",
            bg="#111C2F",
            fg="#60A5FA",
            font=("Segoe UI", 9)
        ).pack(
            side="left"
        )

        ttk.Button(
            usuario_frame,
            text="Cerrar sesión",
            style="Secondary.TButton",
            command=self.cerrar_sesion
        ).pack(
            side="left",
            padx=(15, 0)
        )

        self.tabs = ttk.Notebook(
            self
        )

        self.tabs.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        self.construir_sistema()

        self.construir_procesos()

        if self.con.rol == "admin":

            self.construir_usuarios()

        self.actualizar_sistema()


    # ========================================================
    # SISTEMA
    # ========================================================

    def construir_sistema(self):

        tab = ttk.Frame(
            self.tabs
        )

        self.tabs.add(
            tab,
            text="  Sistema  "
        )

        titulo = ttk.Label(
            tab,
            text="Estado del servidor",
            style="Title.TLabel"
        )

        titulo.pack(
            anchor="w",
            padx=20,
            pady=(20, 3)
        )

        ttk.Label(
            tab,
            text="Monitoreo de recursos del sistema remoto",
            style="Subtitle.TLabel"
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 20)
        )

        tarjetas = tk.Frame(
            tab,
            bg="#101827"
        )

        tarjetas.pack(
            fill="x",
            padx=20
        )

        self.barras = {}

        for nombre in (
            "CPU",
            "RAM",
            "Disco"
        ):

            tarjeta = tk.Frame(
                tarjetas,
                bg="#182235",
                padx=18,
                pady=15
            )

            tarjeta.pack(
                side="left",
                fill="both",
                expand=True,
                padx=6
            )

            tk.Label(
                tarjeta,
                text=nombre,
                bg="#182235",
                fg="#94A3B8",
                font=("Segoe UI", 10, "bold")
            ).pack(
                anchor="w"
            )

            lbl = tk.Label(
                tarjeta,
                text="-",
                bg="#182235",
                fg="#FFFFFF",
                font=("Segoe UI", 15, "bold")
            )

            lbl.pack(
                anchor="w",
                pady=(5, 10)
            )

            # Selecciona automáticamente el color
            # dependiendo de si es CPU, RAM o Disco
            barra = ttk.Progressbar(
                tarjeta,
                length=180,
                maximum=100,
                style=f"{nombre}.Horizontal.TProgressbar"
            )

            barra.pack(
                fill="x"
            )

            self.barras[nombre] = (
                lbl,
                barra
            )

        red_card = tk.Frame(
            tab,
            bg="#182235",
            padx=20,
            pady=18
        )

        red_card.pack(
            fill="x",
            padx=26,
            pady=20
        )

        tk.Label(
            red_card,
            text="TRÁFICO DE RED",
            bg="#182235",
            fg="#94A3B8",
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w"
        )

        self.lbl_red = tk.Label(
            red_card,
            text="Red: -",
            bg="#182235",
            fg="#FFFFFF",
            font=("Segoe UI", 11)
        )

        self.lbl_red.pack(
            anchor="w",
            pady=(5, 0)
        )

        botones = tk.Frame(
            tab,
            bg="#101827"
        )

        botones.pack(
            anchor="w",
            padx=26
        )

        ttk.Button(
            botones,
            text="Actualizar ahora",
            style="Accent.TButton",
            command=self.actualizar_sistema
        ).pack(
            side="left"
        )

        self.auto = tk.BooleanVar(
            value=False
        )

        ttk.Checkbutton(
            botones,
            text="Actualización automática cada 3 segundos",
            variable=self.auto,
            command=self.alternar_auto
        ).pack(
            side="left",
            padx=15
        )


    def actualizar_sistema(self):

        lineas = self.pedir(
            "INFO"
        )

        if lineas is None:
            return

        for linea in lineas:

            if linea.startswith("Red"):

                self.lbl_red.config(
                    text=" ".join(
                        linea.split()
                    )
                )

                continue

            for nombre, (
                lbl,
                barra
            ) in self.barras.items():

                if linea.startswith(nombre):

                    lbl.config(
                        text=" ".join(
                            linea.split()
                        )
                    )

                    porcentajes = re.findall(
                        r"([\d.]+)%",
                        linea
                    )

                    if porcentajes:

                        barra["value"] = float(
                            porcentajes[-1]
                        )


    def alternar_auto(self):

        if self.auto.get():

            self.tick()

        elif self.job:

            self.after_cancel(
                self.job
            )

            self.job = None


    def tick(self):

        self.actualizar_sistema()

        if self.auto.get():

            self.job = self.after(
                3000,
                self.tick
            )


    # ========================================================
    # PROCESOS
    # ========================================================

    def construir_procesos(self):

        tab = ttk.Frame(
            self.tabs
        )

        self.tabs.add(
            tab,
            text="  Procesos  "
        )

        ttk.Label(
            tab,
            text="Procesos del servidor",
            style="Title.TLabel"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 3)
        )

        ttk.Label(
            tab,
            text="Procesos que actualmente utilizan recursos del sistema",
            style="Subtitle.TLabel"
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15)
        )

        contenedor = tk.Frame(
            tab,
            bg="#182235"
        )

        contenedor.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 12)
        )

        cols = (
            "PID",
            "Usuario",
            "Mem %",
            "Nombre"
        )

        self.tabla_proc = ttk.Treeview(
            contenedor,
            columns=cols,
            show="headings"
        )

        for c, ancho in zip(
            cols,
            (90, 180, 100, 400)
        ):

            self.tabla_proc.heading(
                c,
                text=c
            )

            self.tabla_proc.column(
                c,
                width=ancho,
                anchor="w"
            )

        scroll = ttk.Scrollbar(
            contenedor,
            orient="vertical",
            command=self.tabla_proc.yview
        )

        self.tabla_proc.configure(
            yscrollcommand=scroll.set
        )

        self.tabla_proc.pack(
            side="left",
            fill="both",
            expand=True
        )

        scroll.pack(
            side="right",
            fill="y"
        )

        ttk.Button(
            tab,
            text="Actualizar procesos",
            style="Accent.TButton",
            command=self.actualizar_procesos
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15)
        )

        self.actualizar_procesos()


    def actualizar_procesos(self):

        lineas = self.pedir(
            "PROCESOS"
        )

        if lineas is None:
            return

        self.tabla_proc.delete(
            *self.tabla_proc.get_children()
        )

        for linea in lineas[1:]:

            partes = linea.split(
                None,
                3
            )

            if len(partes) == 4:

                self.tabla_proc.insert(
                    "",
                    "end",
                    values=partes
                )


    # ========================================================
    # USUARIOS
    # ========================================================

    def construir_usuarios(self):

        tab = ttk.Frame(
            self.tabs
        )

        self.tabs.add(
            tab,
            text="  Usuarios  "
        )

        ttk.Label(
            tab,
            text="Administración de usuarios",
            style="Title.TLabel"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 3)
        )

        ttk.Label(
            tab,
            text="Crear, consultar y eliminar cuentas del servidor",
            style="Subtitle.TLabel"
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15)
        )

        contenedor = tk.Frame(
            tab,
            bg="#182235"
        )

        contenedor.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 12)
        )

        cols = (
            "ID",
            "Usuario",
            "Rol"
        )

        self.tabla_usr = ttk.Treeview(
            contenedor,
            columns=cols,
            show="headings"
        )

        for c, ancho in zip(
            cols,
            (80, 350, 150)
        ):

            self.tabla_usr.heading(
                c,
                text=c
            )

            self.tabla_usr.column(
                c,
                width=ancho,
                anchor="w"
            )

        self.tabla_usr.pack(
            fill="both",
            expand=True
        )

        botones = tk.Frame(
            tab,
            bg="#101827"
        )

        botones.pack(
            anchor="w",
            padx=20,
            pady=(0, 15)
        )

        ttk.Button(
            botones,
            text="Actualizar",
            style="Secondary.TButton",
            command=self.actualizar_usuarios
        ).pack(
            side="left",
            padx=(0, 8)
        )

        ttk.Button(
            botones,
            text="+ Crear usuario",
            style="Accent.TButton",
            command=self.crear_usuario
        ).pack(
            side="left",
            padx=8
        )

        ttk.Button(
            botones,
            text="Eliminar",
            style="Danger.TButton",
            command=self.eliminar_usuario
        ).pack(
            side="left",
            padx=8
        )

        self.actualizar_usuarios()


    def actualizar_usuarios(self):

        lineas = self.pedir(
            "LISTARUSUARIOS"
        )

        if lineas is None:
            return

        self.tabla_usr.delete(
            *self.tabla_usr.get_children()
        )

        for linea in lineas[1:]:

            partes = linea.split()

            if len(partes) == 3:

                self.tabla_usr.insert(
                    "",
                    "end",
                    values=partes
                )


    # ========================================================
    # CREAR USUARIO
    # ========================================================

    def crear_usuario(self):

        nombre = simpledialog.askstring(
            "Crear usuario",
            "Nombre (3-20 letras o números):",
            parent=self
        )

        if not nombre:
            return

        clave = simpledialog.askstring(
            "Crear usuario",
            "Contraseña (mínimo 6 caracteres):",
            parent=self,
            show="*"
        )

        if not clave:
            return

        rol = simpledialog.askstring(
            "Crear usuario",
            "Rol (admin / usuario):",
            parent=self,
            initialvalue="usuario"
        )

        if not rol:
            return

        if (
            " " in nombre
            or " " in clave
            or " " in rol
        ):

            messagebox.showerror(
                "Error",
                "No se permiten espacios"
            )

            return

        resp = self.pedir(
            f"CREARUSUARIO {nombre} {clave} {rol}"
        )

        if resp is not None:

            messagebox.showinfo(
                "Resultado",
                "\n".join(resp)
            )

            self.actualizar_usuarios()


    # ========================================================
    # ELIMINAR USUARIO
    # ========================================================

    def eliminar_usuario(self):

        sel = self.tabla_usr.selection()

        if not sel:

            messagebox.showwarning(
                "Eliminar usuario",
                "Selecciona un usuario de la tabla"
            )

            return

        nombre = str(
            self.tabla_usr.item(
                sel[0]
            )["values"][1]
        )

        confirmar = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Deseas eliminar al usuario '{nombre}'?"
        )

        if not confirmar:
            return

        resp = self.pedir(
            f"ELIMINARUSUARIO {nombre}"
        )

        if resp is not None:

            messagebox.showinfo(
                "Resultado",
                "\n".join(resp)
            )

            self.actualizar_usuarios()


# ============================================================
# INICIO DEL PROGRAMA
# ============================================================

if __name__ == "__main__":

    App().mainloop()