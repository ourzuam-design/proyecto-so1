import base64
import csv
import json
import os
import re
import socket
import ssl
import urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import cifrado


IP_SERVIDOR_DEFECTO = "192.168.1.197"
PUERTO_DEFECTO = 5000

RUTA_CERTIFICADO = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "servidor.crt"
)


class Conexion:

    def __init__(self):
        self.socket_tls = None
        self.flujo = None
        self.rol = None
        self.ip_servidor = None
        self.puerto_servidor = None
        self.usuario = None
        self.clave = None

    def conectar(self, ip_servidor, puerto_servidor, usuario, clave):
        self.ip_servidor = ip_servidor
        self.puerto_servidor = puerto_servidor
        self.usuario = usuario
        self.clave = clave

        contexto_ssl = ssl.create_default_context()
        contexto_ssl.check_hostname = False
        contexto_ssl.verify_mode = ssl.CERT_NONE

        socket_crudo = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        socket_crudo.settimeout(10)

        self.socket_tls = contexto_ssl.wrap_socket(
            socket_crudo,
            server_hostname=ip_servidor
        )

        self.socket_tls.connect(
            (ip_servidor, puerto_servidor)
        )

        self.flujo = self.socket_tls.makefile(
            "rw",
            encoding="utf-8",
            newline="\n"
        )

        self.flujo.write(
            f"LOGIN {usuario} {clave}\n"
        )
        self.flujo.flush()

        respuesta = self.flujo.readline().strip()

        if not respuesta.startswith("OK"):
            self.cerrar()
            return False, respuesta

        coincidencia_rol = re.search(
            r"rol: (\w+)",
            respuesta
        )
        self.rol = coincidencia_rol.group(1) if coincidencia_rol else "usuario"

        return True, respuesta

    def enviar(self, comando):
        self.flujo.write(
            comando + "\n"
        )
        self.flujo.flush()

        lineas = []
        while True:
            linea = self.flujo.readline()
            if linea == "":
                raise ConnectionError(
                    "El servidor cerró la conexión inesperadamente"
                )
            linea = linea.rstrip("\n")
            if linea == "<<FIN>>":
                break
            lineas.append(linea)

        return lineas

    def subir_archivo(self, ruta_local, clave_cifrado):
        if not os.path.isfile(ruta_local):
            return False, "El archivo local seleccionado no existe"

        nombre_archivo = os.path.basename(ruta_local)
        with open(ruta_local, "rb") as archivo_disco:
            datos_claros = archivo_disco.read()

        tamano_original = len(datos_claros)
        datos_cifrados = cifrado.cifrar_datos(datos_claros, clave_cifrado)
        tamano_cifrado = len(datos_cifrados)

        nombre_codificado = urllib.parse.quote(nombre_archivo)
        self.flujo.write(f"SUBIRARCHIVO {nombre_codificado} {tamano_original} {tamano_cifrado}\n")
        self.flujo.flush()

        respuesta = self.flujo.readline().strip()
        if respuesta != "OK_ENVIAR":
            while True:
                fin = self.flujo.readline().strip()
                if fin == "<<FIN>>" or fin == "":
                    break
            return False, respuesta

        tamano_bloque = 32768
        for indice in range(0, tamano_cifrado, tamano_bloque):
            bloque = datos_cifrados[indice:indice + tamano_bloque]
            linea_b64 = base64.b64encode(bloque).decode("ascii")
            self.flujo.write(linea_b64 + "\n")
        self.flujo.write("<<FIN_ARCHIVO>>\n")
        self.flujo.flush()

        lineas_respuesta = []
        while True:
            linea = self.flujo.readline()
            if linea == "":
                raise ConnectionError("El servidor cerró la conexión durante la subida")
            linea = linea.rstrip("\n")
            if linea == "<<FIN>>":
                break
            lineas_respuesta.append(linea)

        return True, "\n".join(lineas_respuesta)

    def descargar_archivo(self, identificador, clave_descifrado, ruta_guardado):
        identificador_codificado = urllib.parse.quote(str(identificador))
        self.flujo.write(f"DESCARGARARCHIVO {identificador_codificado}\n")
        self.flujo.flush()

        cabecera = self.flujo.readline().strip()
        if not cabecera.startswith("OK_DESCARGAR"):
            while True:
                fin = self.flujo.readline().strip()
                if fin == "<<FIN>>" or fin == "":
                    break
            return False, cabecera

        partes_cab = cabecera.split(" ")
        hash_servidor = partes_cab[3] if len(partes_cab) >= 4 else None

        bloques_recibidos = []
        while True:
            linea = self.flujo.readline()
            if not linea:
                break
            linea = linea.rstrip("\r\n")
            if linea == "<<FIN_ARCHIVO>>":
                break
            bloques_recibidos.append(base64.b64decode(linea))

        paquete_cifrado = b"".join(bloques_recibidos)

        hash_verificado = False
        if hash_servidor:
            hash_local = cifrado.calcular_hash_sha256(paquete_cifrado)
            if hash_local == hash_servidor:
                hash_verificado = True

        try:
            datos_descifrados = cifrado.descifrar_datos(paquete_cifrado, clave_descifrado)
        except ValueError as error_descifrado:
            return False, f"Fallo de descifrado: {error_descifrado}"

        with open(ruta_guardado, "wb") as archivo_salida:
            archivo_salida.write(datos_descifrados)

        mensaje_exito = f"Archivo guardado y descifrado correctamente ({len(datos_descifrados)} bytes)"
        if hash_verificado:
            mensaje_exito += "\n✓ Integridad SHA-256 verificada con el servidor"

        return True, mensaje_exito

    def compartir_archivo(self, identificador, usuario_destino):
        lineas = self.enviar(f"COMPARTIRARCHIVO {urllib.parse.quote(str(identificador))} {usuario_destino}")
        return "\n".join(lineas)

    def revocar_archivo(self, identificador, usuario_destino):
        lineas = self.enviar(f"REVOCARARCHIVO {urllib.parse.quote(str(identificador))} {usuario_destino}")
        return "\n".join(lineas)

    def consultar_cuota(self):
        try:
            lineas = self.enviar("CUOTA")
            if not lineas:
                return 0, -1
            resp = lineas[0]
            if resp.startswith("USADO:"):
                partes = resp.split()
                usado = int(partes[0].split(":")[1])
                limite = int(partes[1].split(":")[1])
                return usado, limite
        except Exception:
            pass
        return 0, -1

    def cambiar_clave(self, actual, nueva):
        lineas = self.enviar(f"CAMBIARCLAVE {actual} {nueva}")
        return "\n".join(lineas)

    def kill_proceso(self, pid):
        lineas = self.enviar(f"KILLPROCESO {pid}")
        return "\n".join(lineas)

    def usuarios_conectados(self):
        return self.enviar("USUARIOSCONECTADOS")

    def ejecutar_shell(self, comando):
        return self.enviar(f"EJECUTAR {comando}")

    def eliminar_archivo(self, identificador):
        identificador_codificado = urllib.parse.quote(str(identificador))
        lineas = self.enviar(f"ELIMINARARCHIVO {identificador_codificado}")
        return True, "\n".join(lineas)

    def salir(self):
        try:
            if self.flujo:
                self.flujo.write("SALIR\n")
                self.flujo.flush()
        except (OSError, ssl.SSLError):
            pass
        self.cerrar()

    def cerrar(self):
        for elemento in (self.flujo, self.socket_tls):
            try:
                if elemento:
                    elemento.close()
            except (OSError, ssl.SSLError):
                pass
        self.flujo = None
        self.socket_tls = None


class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Sistema de Administración Remota - Ubuntu")
        self.geometry("1020x720")
        self.minsize(940, 640)
        self.configure(bg="#101827")

        self.con = Conexion()
        self.tarea_auto = None
        self.usuario = ""

        self.configurar_estilos()
        self.protocol("WM_DELETE_WINDOW", self.cerrar_app)
        self.pantalla_login()

    def configurar_estilos(self):
        estilo = ttk.Style()
        estilo.theme_use("clam")

        estilo.configure("TFrame", background="#101827")
        estilo.configure("Card.TFrame", background="#182235")
        estilo.configure("TLabel", background="#101827", foreground="#E5E7EB", font=("Segoe UI", 10))
        estilo.configure("Title.TLabel", background="#101827", foreground="#FFFFFF", font=("Segoe UI", 20, "bold"))
        estilo.configure("Subtitle.TLabel", background="#101827", foreground="#94A3B8", font=("Segoe UI", 10))
        estilo.configure("CardTitle.TLabel", background="#182235", foreground="#94A3B8", font=("Segoe UI", 10, "bold"))
        estilo.configure("CardValue.TLabel", background="#182235", foreground="#FFFFFF", font=("Segoe UI", 18, "bold"))
        estilo.configure("Header.TFrame", background="#111C2F")
        estilo.configure("Header.TLabel", background="#111C2F", foreground="#FFFFFF", font=("Segoe UI", 11, "bold"))
        estilo.configure("Status.TLabel", background="#111C2F", foreground="#22C55E", font=("Segoe UI", 9, "bold"))

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
            background=[("active", "#1D4ED8"), ("pressed", "#1E40AF")]
        )

        estilo.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(15, 9),
            background="#DC2626",
            foreground="#FFFFFF",
            borderwidth=0
        )
        estilo.map("Danger.TButton", background=[("active", "#B91C1C")])

        estilo.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 8),
            background="#334155",
            foreground="#FFFFFF",
            borderwidth=0
        )
        estilo.map("Secondary.TButton", background=[("active", "#475569")])

        estilo.configure("TNotebook", background="#101827", borderwidth=0)
        estilo.configure(
            "TNotebook.Tab",
            background="#1E293B",
            foreground="#CBD5E1",
            padding=(18, 9),
            font=("Segoe UI", 10, "bold")
        )
        estilo.map(
            "TNotebook.Tab",
            background=[("selected", "#2563EB")],
            foreground=[("selected", "#FFFFFF")]
        )

        estilo.configure(
            "Treeview",
            background="#182235",
            foreground="#E5E7EB",
            fieldbackground="#182235",
            rowheight=28,
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
            background=[("selected", "#2563EB")],
            foreground=[("selected", "#FFFFFF")]
        )

        estilo.configure("TCheckbutton", background="#101827", foreground="#CBD5E1", font=("Segoe UI", 9))
        estilo.configure("CPU.Horizontal.TProgressbar", troughcolor="#0F172A", background="#3B82F6")
        estilo.configure("RAM.Horizontal.TProgressbar", troughcolor="#0F172A", background="#22C55E")
        estilo.configure("Disco.Horizontal.TProgressbar", troughcolor="#0F172A", background="#F59E0B")

    def limpiar(self):
        if self.tarea_auto:
            self.after_cancel(self.tarea_auto)
            self.tarea_auto = None
        for elemento in self.winfo_children():
            elemento.destroy()

    def pedir(self, comando):
        try:
            return self.con.enviar(comando)
        except (OSError, ssl.SSLError, ConnectionError) as error_peticion:
            messagebox.showerror("Conexión perdida", str(error_peticion))
            self.con.cerrar()
            self.pantalla_login()
            return None

    def cerrar_app(self):
        self.con.salir()
        self.destroy()

    def cerrar_sesion(self):
        self.con.salir()
        self.pantalla_login()

    def pantalla_login(self):
        self.limpiar()

        contenedor = tk.Frame(self, bg="#101827")
        contenedor.pack(fill="both", expand=True)

        tarjeta = tk.Frame(contenedor, bg="#182235", padx=40, pady=30)
        tarjeta.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            tarjeta,
            text="ADMINISTRACIÓN REMOTA UBUNTU",
            bg="#182235",
            fg="#60A5FA",
            font=("Segoe UI", 10, "bold")
        ).pack(pady=(0, 6))

        tk.Label(
            tarjeta,
            text="Conexión Segura TCP",
            bg="#182235",
            fg="#FFFFFF",
            font=("Segoe UI", 20, "bold")
        ).pack()

        tk.Label(
            tarjeta,
            text="Canal seguro TLS y archivos cifrados contra intrusiones",
            bg="#182235",
            fg="#94A3B8",
            font=("Segoe UI", 9)
        ).pack(pady=(4, 18))

        marco_red = tk.Frame(tarjeta, bg="#182235")
        marco_red.pack(fill="x", pady=(0, 10))

        marco_ip = tk.Frame(marco_red, bg="#182235")
        marco_ip.pack(side="left", fill="x", expand=True, padx=(0, 6))

        tk.Label(marco_ip, text="IP del Servidor", bg="#182235", fg="#CBD5E1", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.entrada_ip = tk.Entry(
            marco_ip,
            width=20,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.entrada_ip.insert(0, IP_SERVIDOR_DEFECTO)
        self.entrada_ip.pack(fill="x", pady=(4, 0), ipady=6)

        marco_puerto = tk.Frame(marco_red, bg="#182235")
        marco_puerto.pack(side="right", padx=(6, 0))

        tk.Label(marco_puerto, text="Puerto", bg="#182235", fg="#CBD5E1", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.entrada_puerto = tk.Entry(
            marco_puerto,
            width=8,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.entrada_puerto.insert(0, str(PUERTO_DEFECTO))
        self.entrada_puerto.pack(pady=(4, 0), ipady=6)

        tk.Label(tarjeta, text="Usuario", bg="#182235", fg="#CBD5E1", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.entrada_usuario = tk.Entry(
            tarjeta,
            width=32,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.entrada_usuario.pack(fill="x", pady=(4, 10), ipady=6)

        tk.Label(tarjeta, text="Contraseña", bg="#182235", fg="#CBD5E1", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.entrada_clave = tk.Entry(
            tarjeta,
            width=32,
            show="*",
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.entrada_clave.pack(fill="x", pady=(4, 18), ipady=6)

        ttk.Button(
            tarjeta,
            text="CONECTAR E INICIAR SESIÓN",
            style="Accent.TButton",
            command=self.entrar
        ).pack(fill="x")

        self.etiqueta_error = tk.Label(tarjeta, text="", bg="#182235", fg="#F87171", font=("Segoe UI", 9))
        self.etiqueta_error.pack(pady=(12, 0))

        self.entrada_usuario.focus()
        self.bind("<Return>", lambda e: self.entrar())

    def entrar(self):
        ip_servidor = self.entrada_ip.get().strip()
        puerto_texto = self.entrada_puerto.get().strip()
        usuario = self.entrada_usuario.get().strip()
        clave = self.entrada_clave.get()

        if not ip_servidor or not puerto_texto:
            self.etiqueta_error.config(text="Escribe la dirección IP y el puerto")
            return

        try:
            puerto_servidor = int(puerto_texto)
        except ValueError:
            self.etiqueta_error.config(text="El puerto debe ser un número entero")
            return

        if not usuario or not clave:
            self.etiqueta_error.config(text="Escribe usuario y contraseña")
            return

        if " " in usuario or " " in clave:
            self.etiqueta_error.config(text="No se permiten espacios en usuario o contraseña")
            return

        try:
            ok, resp = self.con.conectar(ip_servidor, puerto_servidor, usuario, clave)
        except (OSError, ssl.SSLError) as error_conexion:
            self.etiqueta_error.config(text=f"No se pudo conectar a {ip_servidor}:{puerto_servidor}: {error_conexion}")
            return

        if not ok:
            self.etiqueta_error.config(text=resp.replace("ERROR ", ""))
            return

        self.unbind("<Return>")
        self.usuario = usuario
        self.pantalla_principal()

    def pantalla_principal(self):
        self.limpiar()

        encabezado = tk.Frame(self, bg="#111C2F", height=65)
        encabezado.pack(fill="x")
        encabezado.pack_propagate(False)

        izquierda = tk.Frame(encabezado, bg="#111C2F")
        izquierda.pack(side="left", padx=20)

        tk.Label(izquierda, text="●", bg="#111C2F", fg="#22C55E", font=("Segoe UI", 14)).pack(side="left", padx=(0, 6))
        tk.Label(
            izquierda,
            text=f"Servidor Ubuntu ({self.con.ip_servidor}:{self.con.puerto_servidor})",
            bg="#111C2F",
            fg="#FFFFFF",
            font=("Segoe UI", 11, "bold")
        ).pack(side="left")

        usuario_marco = tk.Frame(encabezado, bg="#111C2F")
        usuario_marco.pack(side="right", padx=20)

        tk.Label(usuario_marco, text=f"{self.usuario}", bg="#111C2F", fg="#FFFFFF", font=("Segoe UI", 10, "bold")).pack(side="left", padx=8)
        tk.Label(usuario_marco, text=f"({self.con.rol})", bg="#111C2F", fg="#60A5FA", font=("Segoe UI", 9)).pack(side="left")

        ttk.Button(usuario_marco, text="Cambiar clave", style="Secondary.TButton", command=self.cambiar_clave_gui).pack(side="left", padx=(10, 4))
        ttk.Button(usuario_marco, text="Usuarios en línea", style="Secondary.TButton", command=self.ver_usuarios_conectados_gui).pack(side="left", padx=4)
        ttk.Button(usuario_marco, text="Cerrar sesión", style="Danger.TButton", command=self.cerrar_sesion).pack(side="left", padx=(10, 0))

        self.pestanas = ttk.Notebook(self)
        self.pestanas.pack(fill="both", expand=True, padx=15, pady=15)

        self.construir_sistema()
        self.construir_procesos()
        self.construir_archivos()

        if self.con.rol == "admin":
            self.construir_usuarios()
            self.construir_logs()
            self.construir_terminal()

        self.actualizar_sistema()

    def construir_sistema(self):
        tab = ttk.Frame(self.pestanas)
        self.pestanas.add(tab, text="  Sistema  ")

        ttk.Label(tab, text="Estado del servidor", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(tab, text="Monitoreo de recursos y detalles del sistema remoto", style="Subtitle.TLabel").pack(anchor="w", padx=20, pady=(0, 10))

        marco_detalles = tk.Frame(tab, bg="#182235", padx=16, pady=12)
        marco_detalles.pack(fill="x", padx=20, pady=(0, 12))

        marco_host = tk.Frame(marco_detalles, bg="#182235")
        marco_host.pack(side="left", fill="x", expand=True)
        tk.Label(marco_host, text="SERVIDOR", bg="#182235", fg="#94A3B8", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.lbl_host = tk.Label(marco_host, text="-", bg="#182235", fg="#FFFFFF", font=("Segoe UI", 11, "bold"))
        self.lbl_host.pack(anchor="w", pady=(2, 0))

        marco_so = tk.Frame(marco_detalles, bg="#182235")
        marco_so.pack(side="left", fill="x", expand=True)
        tk.Label(marco_so, text="SISTEMA OPERATIVO", bg="#182235", fg="#94A3B8", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.lbl_so = tk.Label(marco_so, text="-", bg="#182235", fg="#60A5FA", font=("Segoe UI", 11, "bold"))
        self.lbl_so.pack(anchor="w", pady=(2, 0))

        marco_uptime = tk.Frame(marco_detalles, bg="#182235")
        marco_uptime.pack(side="left", fill="x", expand=True)
        tk.Label(marco_uptime, text="TIEMPO ACTIVO", bg="#182235", fg="#94A3B8", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.lbl_uptime = tk.Label(marco_uptime, text="-", bg="#182235", fg="#22C55E", font=("Segoe UI", 11, "bold"))
        self.lbl_uptime.pack(anchor="w", pady=(2, 0))

        tarjetas = tk.Frame(tab, bg="#101827")
        tarjetas.pack(fill="x", padx=20)

        self.barras = {}
        for nombre in ("CPU", "RAM", "Disco"):
            tarjeta = tk.Frame(tarjetas, bg="#182235", padx=16, pady=12)
            tarjeta.pack(side="left", fill="both", expand=True, padx=6)

            tk.Label(tarjeta, text=nombre, bg="#182235", fg="#94A3B8", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            lbl = tk.Label(tarjeta, text="-", bg="#182235", fg="#FFFFFF", font=("Segoe UI", 14, "bold"))
            lbl.pack(anchor="w", pady=(4, 8))

            barra = ttk.Progressbar(tarjeta, length=180, maximum=100, style=f"{nombre}.Horizontal.TProgressbar")
            barra.pack(fill="x")
            self.barras[nombre] = (lbl, barra)

        tarjeta_red = tk.Frame(tab, bg="#182235", padx=18, pady=12)
        tarjeta_red.pack(fill="x", padx=26, pady=12)

        tk.Label(tarjeta_red, text="TRÁFICO DE RED", bg="#182235", fg="#94A3B8", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.lbl_red = tk.Label(tarjeta_red, text="Red: -", bg="#182235", fg="#FFFFFF", font=("Segoe UI", 10))
        self.lbl_red.pack(anchor="w", pady=(4, 0))

        botones = tk.Frame(tab, bg="#101827")
        botones.pack(anchor="w", padx=26)

        ttk.Button(botones, text="Actualizar ahora", style="Accent.TButton", command=self.actualizar_sistema).pack(side="left")

        self.auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(botones, text="Actualización automática cada 3 segundos", variable=self.auto, command=self.alternar_auto).pack(side="left", padx=15)

    def actualizar_sistema(self):
        lineas = self.pedir("INFO")
        if lineas is None:
            return

        for linea in lineas:
            if linea.startswith("Host:"):
                self.lbl_host.config(text=linea.split(":", 1)[1].strip())
            elif linea.startswith("SO:"):
                self.lbl_so.config(text=linea.split(":", 1)[1].strip())
            elif linea.startswith("Uptime:"):
                self.lbl_uptime.config(text=linea.split(":", 1)[1].strip())
            elif linea.startswith("Red"):
                self.lbl_red.config(text=" ".join(linea.split()))
            else:
                for nombre, (lbl, barra) in self.barras.items():
                    if linea.startswith(nombre):
                        lbl.config(text=" ".join(linea.split()))
                        porcentajes = re.findall(r"([\d.]+)%", linea)
                        if porcentajes:
                            barra["value"] = float(porcentajes[-1])

    def alternar_auto(self):
        if self.auto.get():
            self.tick()
        elif self.tarea_auto:
            self.after_cancel(self.tarea_auto)
            self.tarea_auto = None

    def tick(self):
        self.actualizar_sistema()
        if self.auto.get():
            self.tarea_auto = self.after(3000, self.tick)

    def construir_procesos(self):
        tab = ttk.Frame(self.pestanas)
        self.pestanas.add(tab, text="  Procesos  ")

        ttk.Label(tab, text="Procesos del servidor", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(tab, text="Procesos en ejecución en el servidor remoto Ubuntu", style="Subtitle.TLabel").pack(anchor="w", padx=20, pady=(0, 10))

        marco_herramientas = tk.Frame(tab, bg="#101827")
        marco_herramientas.pack(fill="x", padx=20, pady=(0, 8))

        tk.Label(
            marco_herramientas,
            text="Buscar:",
            bg="#101827",
            fg="#CBD5E1",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 6))

        self.entrada_buscar_proc = tk.Entry(
            marco_herramientas,
            width=20,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.entrada_buscar_proc.pack(side="left", ipady=4, padx=(0, 10))
        self.entrada_buscar_proc.bind("<KeyRelease>", lambda e: self.filtrar_procesos())

        ttk.Button(
            marco_herramientas,
            text="Actualizar procesos",
            style="Accent.TButton",
            command=self.actualizar_procesos
        ).pack(side="left", padx=(0, 8))

        if self.con.rol == "admin":
            ttk.Button(
                marco_herramientas,
                text="Finalizar proceso",
                style="Danger.TButton",
                command=self.kill_proceso_gui
            ).pack(side="left")

        self.etiqueta_total_proc = tk.Label(
            marco_herramientas,
            text="Cargando procesos...",
            bg="#101827",
            fg="#94A3B8",
            font=("Segoe UI", 9)
        )
        self.etiqueta_total_proc.pack(side="right", padx=10)

        contenedor = tk.Frame(tab, bg="#182235")
        contenedor.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        columnas = ("PID", "Usuario", "Mem %", "CPU %", "Nombre")
        self.tabla_proc = ttk.Treeview(contenedor, columns=columnas, show="headings")

        self.orden_inverso_proc = {c: False for c in columnas}

        for col, ancho in zip(columnas, (80, 150, 90, 90, 360)):
            self.tabla_proc.heading(
                col,
                text=col,
                command=lambda c=col: self.ordenar_procesos(c)
            )
            self.tabla_proc.column(col, width=ancho, anchor="w")

        scroll = ttk.Scrollbar(contenedor, orient="vertical", command=self.tabla_proc.yview)
        self.tabla_proc.configure(yscrollcommand=scroll.set)
        self.tabla_proc.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.datos_procesos = []
        self.actualizar_procesos()

    def actualizar_procesos(self):
        lineas = self.pedir("PROCESOS")
        if lineas is None:
            return

        self.datos_procesos = []
        for linea in lineas[1:]:
            partes = linea.split(None, 4)
            if len(partes) == 5:
                self.datos_procesos.append(partes)

        self.filtrar_procesos()

    def filtrar_procesos(self):
        termino = self.entrada_buscar_proc.get().strip().lower()
        self.tabla_proc.delete(*self.tabla_proc.get_children())

        filtrados = []
        for pid, usuario, mem, cpu, nombre in self.datos_procesos:
            if not termino or (termino in pid.lower() or termino in usuario.lower() or termino in nombre.lower()):
                filtrados.append((pid, usuario, mem, cpu, nombre))
                self.tabla_proc.insert("", "end", values=(pid, usuario, mem, cpu, nombre))

        total = len(self.datos_procesos)
        mostrados = len(filtrados)
        self.etiqueta_total_proc.config(
            text=f"Mostrando {mostrados} de {total} procesos (clic en columna para ordenar)"
        )

    def ordenar_procesos(self, columna):
        self.orden_inverso_proc[columna] = not self.orden_inverso_proc[columna]
        inverso = self.orden_inverso_proc[columna]

        indices = {"PID": 0, "Usuario": 1, "Mem %": 2, "CPU %": 3, "Nombre": 4}
        indice = indices.get(columna, 0)

        def obtener_clave(item):
            valor = item[indice]
            if columna in ("PID", "Mem %", "CPU %"):
                try:
                    return float(valor)
                except ValueError:
                    return 0.0
            return valor.lower()

        self.datos_procesos.sort(key=obtener_clave, reverse=inverso)
        self.filtrar_procesos()

    def kill_proceso_gui(self):
        seleccion = self.tabla_proc.selection()
        if not seleccion:
            messagebox.showwarning("Finalizar proceso", "Por favor selecciona un proceso de la lista", parent=self)
            return

        valores = self.tabla_proc.item(seleccion[0])["values"]
        pid = str(valores[0])
        nombre = str(valores[4])

        confirmar = messagebox.askyesno(
            "Confirmar finalización de proceso",
            f"¿Deseas terminar el proceso '{nombre}' (PID: {pid})?",
            parent=self
        )
        if not confirmar:
            return

        try:
            resp = self.con.kill_proceso(pid)
            if resp.startswith("OK"):
                messagebox.showinfo("Proceso finalizado", resp, parent=self)
            else:
                messagebox.showerror("Error", resp, parent=self)
            self.actualizar_procesos()
        except Exception as error_kill:
            messagebox.showerror("Error", f"No se pudo terminar el proceso: {error_kill}", parent=self)


    def construir_archivos(self):
        tab = ttk.Frame(self.pestanas)
        self.pestanas.add(tab, text="  Archivos Cifrados  ")

        ttk.Label(tab, text="Transferencia y Almacenamiento Seguro", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(
            tab,
            text="Los archivos se transfieren por TCP y se guardan cifrados con PBKDF2/HMAC para proteger su privacidad en el servidor.",
            style="Subtitle.TLabel"
        ).pack(anchor="w", padx=20, pady=(0, 12))

        contenedor = tk.Frame(tab, bg="#182235")
        contenedor.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        columnas = ("ID", "Archivo", "Propietario", "Tam. Orig (B)", "Tam. Cifrado (B)", "Compartido", "Fecha")
        self.tabla_archivos = ttk.Treeview(contenedor, columns=columnas, show="headings")

        for col, ancho in zip(columnas, (50, 220, 110, 100, 100, 120, 150)):
            self.tabla_archivos.heading(col, text=col)
            self.tabla_archivos.column(col, width=ancho, anchor="w")

        scroll = ttk.Scrollbar(contenedor, orient="vertical", command=self.tabla_archivos.yview)
        self.tabla_archivos.configure(yscrollcommand=scroll.set)
        self.tabla_archivos.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        botones = tk.Frame(tab, bg="#101827")
        botones.pack(anchor="w", fill="x", padx=20, pady=(0, 12))

        ttk.Button(botones, text="Actualizar", style="Secondary.TButton", command=self.actualizar_archivos).pack(side="left", padx=(0, 6))
        ttk.Button(botones, text="▲ Subir y cifrar", style="Accent.TButton", command=self.subir_archivo_gui).pack(side="left", padx=6)
        ttk.Button(botones, text="▼ Descargar y descifrar", style="Secondary.TButton", command=self.descargar_archivo_gui).pack(side="left", padx=6)
        ttk.Button(botones, text="🔗 Compartir", style="Secondary.TButton", command=self.compartir_archivo_gui).pack(side="left", padx=6)
        ttk.Button(botones, text="Descompartir", style="Secondary.TButton", command=self.revocar_archivo_gui).pack(side="left", padx=6)
        ttk.Button(botones, text="Eliminar", style="Danger.TButton", command=self.eliminar_archivo_gui).pack(side="left", padx=6)

        self.etiqueta_cuota = tk.Label(
            botones,
            text="",
            bg="#101827",
            fg="#94A3B8",
            font=("Segoe UI", 9)
        )
        self.etiqueta_cuota.pack(side="right", padx=10)

        self.actualizar_archivos()

    def actualizar_archivos(self):
        lineas = self.pedir("LISTARARCHIVOS")
        if lineas is None:
            return

        self.tabla_archivos.delete(*self.tabla_archivos.get_children())
        if len(lineas) > 1:
            for linea in lineas[1:]:
                partes = linea.split(None, 6)
                if len(partes) >= 7:
                    self.tabla_archivos.insert("", "end", values=partes)

        usado_b, limite_b = self.con.consultar_cuota()
        usado_mb = round(usado_b / (1024 * 1024), 2)
        if limite_b < 0:
            self.etiqueta_cuota.config(text=f"Almacenamiento: {usado_mb} MB (Ilimitado - Admin)")
        else:
            limite_mb = round(limite_b / (1024 * 1024), 1)
            self.etiqueta_cuota.config(text=f"Cuota: {usado_mb} MB / {limite_mb} MB usados")


    def subir_archivo_gui(self):
        ruta_local = filedialog.askopenfilename(
            title="Seleccionar archivo para cifrar y transferir",
            parent=self
        )
        if not ruta_local:
            return

        nombre_archivo = os.path.basename(ruta_local)
        clave_cifrado = simpledialog.askstring(
            "Cifrado de archivo",
            f"Contraseña para cifrar '{nombre_archivo}':\n(Dejar en blanco para usar tu contraseña de sesión)",
            show="*",
            parent=self
        )
        if clave_cifrado is None:
            return

        clave_usada = clave_cifrado if clave_cifrado else self.con.clave

        try:
            ok, mensaje = self.con.subir_archivo(ruta_local, clave_usada)
            if ok:
                messagebox.showinfo("Subida exitosa", mensaje, parent=self)
                self.actualizar_archivos()
            else:
                messagebox.showerror("Error al subir", mensaje, parent=self)
        except Exception as error_subida:
            messagebox.showerror("Error", f"Ocurrió un error al transferir: {error_subida}", parent=self)

    def descargar_archivo_gui(self):
        seleccion = self.tabla_archivos.selection()
        if not seleccion:
            messagebox.showwarning("Descargar archivo", "Por favor selecciona un archivo de la lista", parent=self)
            return

        valores = self.tabla_archivos.item(seleccion[0])["values"]
        id_archivo = str(valores[0])
        nombre_archivo = str(valores[1])

        ruta_destino = filedialog.asksaveasfilename(
            title="Guardar archivo descifrado",
            initialfile=nombre_archivo,
            parent=self
        )
        if not ruta_destino:
            return

        clave_descifrado = simpledialog.askstring(
            "Descifrado de archivo",
            f"Contraseña para descifrar '{nombre_archivo}':\n(Dejar en blanco para usar tu contraseña de sesión)",
            show="*",
            parent=self
        )
        if clave_descifrado is None:
            return

        clave_usada = clave_descifrado if clave_descifrado else self.con.clave

        try:
            ok, mensaje = self.con.descargar_archivo(id_archivo, clave_usada, ruta_destino)
            if ok:
                messagebox.showinfo("Descarga completada", mensaje, parent=self)
            else:
                messagebox.showerror("Error", mensaje, parent=self)
        except Exception as error_descarga:
            messagebox.showerror("Error", f"Ocurrió un error al descargar: {error_descarga}", parent=self)

    def eliminar_archivo_gui(self):
        seleccion = self.tabla_archivos.selection()
        if not seleccion:
            messagebox.showwarning("Eliminar archivo", "Por favor selecciona un archivo de la lista", parent=self)
            return

        valores = self.tabla_archivos.item(seleccion[0])["values"]
        id_archivo = str(valores[0])
        nombre_archivo = str(valores[1])

        confirmar = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Deseas eliminar el archivo '{nombre_archivo}' del servidor?",
            parent=self
        )
        if not confirmar:
            return

        try:
            ok, mensaje = self.con.eliminar_archivo(id_archivo)
            if ok:
                messagebox.showinfo("Eliminado", mensaje, parent=self)
                self.actualizar_archivos()
            else:
                messagebox.showerror("Error", mensaje, parent=self)
        except Exception as error_eliminar:
            messagebox.showerror("Error", f"Ocurrió un error al eliminar: {error_eliminar}", parent=self)

    def compartir_archivo_gui(self):
        seleccion = self.tabla_archivos.selection()
        if not seleccion:
            messagebox.showwarning("Compartir archivo", "Por favor selecciona un archivo de la lista", parent=self)
            return

        valores = self.tabla_archivos.item(seleccion[0])["values"]
        id_archivo = str(valores[0])
        nombre_archivo = str(valores[1])

        destino = simpledialog.askstring(
            "Compartir archivo",
            f"Introduce el nombre de usuario con quien deseas compartir '{nombre_archivo}':",
            parent=self
        )
        if not destino:
            return

        try:
            resp = self.con.compartir_archivo(id_archivo, destino)
            if resp.startswith("OK"):
                messagebox.showinfo("Archivo compartido", resp, parent=self)
            else:
                messagebox.showerror("Error", resp, parent=self)
            self.actualizar_archivos()
        except Exception as err:
            messagebox.showerror("Error", f"No se pudo compartir el archivo: {err}", parent=self)

    def revocar_archivo_gui(self):
        seleccion = self.tabla_archivos.selection()
        if not seleccion:
            messagebox.showwarning("Revocar acceso", "Por favor selecciona un archivo de la lista", parent=self)
            return

        valores = self.tabla_archivos.item(seleccion[0])["values"]
        id_archivo = str(valores[0])
        nombre_archivo = str(valores[1])

        destino = simpledialog.askstring(
            "Revocar acceso",
            f"Usuario al que deseas revocar acceso para '{nombre_archivo}':",
            parent=self
        )
        if not destino:
            return

        try:
            resp = self.con.revocar_archivo(id_archivo, destino)
            if resp.startswith("OK"):
                messagebox.showinfo("Acceso revocado", resp, parent=self)
            else:
                messagebox.showerror("Error", resp, parent=self)
            self.actualizar_archivos()
        except Exception as err:
            messagebox.showerror("Error", f"No se pudo revocar el acceso: {err}", parent=self)

    def construir_usuarios(self):
        tab = ttk.Frame(self.pestanas)

        self.pestanas.add(tab, text="  Usuarios  ")

        ttk.Label(tab, text="Administración de usuarios", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(tab, text="Crear, consultar y eliminar cuentas del servidor", style="Subtitle.TLabel").pack(anchor="w", padx=20, pady=(0, 12))

        contenedor = tk.Frame(tab, bg="#182235")
        contenedor.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        columnas = ("ID", "Usuario", "Rol")
        self.tabla_usr = ttk.Treeview(contenedor, columns=columnas, show="headings")

        for col, ancho in zip(columnas, (80, 350, 150)):
            self.tabla_usr.heading(col, text=col)
            self.tabla_usr.column(col, width=ancho, anchor="w")

        self.tabla_usr.pack(fill="both", expand=True)

        botones = tk.Frame(tab, bg="#101827")
        botones.pack(anchor="w", padx=20, pady=(0, 12))

        ttk.Button(botones, text="Actualizar", style="Secondary.TButton", command=self.actualizar_usuarios).pack(side="left", padx=(0, 8))
        ttk.Button(botones, text="+ Crear usuario", style="Accent.TButton", command=self.crear_usuario).pack(side="left", padx=8)
        ttk.Button(botones, text="Eliminar", style="Danger.TButton", command=self.eliminar_usuario).pack(side="left", padx=8)

        self.actualizar_usuarios()

    def actualizar_usuarios(self):
        lineas = self.pedir("LISTARUSUARIOS")
        if lineas is None:
            return

        self.tabla_usr.delete(*self.tabla_usr.get_children())
        for linea in lineas[1:]:
            partes = linea.split()
            if len(partes) == 3:
                self.tabla_usr.insert("", "end", values=partes)

    def crear_usuario(self):
        nombre = simpledialog.askstring("Crear usuario", "Nombre (3-20 letras o números):", parent=self)
        if not nombre:
            return

        clave = simpledialog.askstring("Crear usuario", "Contraseña (mínimo 6 caracteres):", parent=self, show="*")
        if not clave:
            return

        rol = simpledialog.askstring("Crear usuario", "Rol (admin / usuario):", parent=self, initialvalue="usuario")
        if not rol:
            return

        if " " in nombre or " " in clave or " " in rol:
            messagebox.showerror("Error", "No se permiten espacios", parent=self)
            return

        resp = self.pedir(f"CREARUSUARIO {nombre} {clave} {rol}")
        if resp is not None:
            messagebox.showinfo("Resultado", "\n".join(resp), parent=self)
            self.actualizar_usuarios()

    def eliminar_usuario(self):
        sel = self.tabla_usr.selection()
        if not sel:
            messagebox.showwarning("Eliminar usuario", "Selecciona un usuario de la tabla", parent=self)
            return

        nombre = str(self.tabla_usr.item(sel[0])["values"][1])
        confirmar = messagebox.askyesno("Confirmar eliminación", f"¿Deseas eliminar al usuario '{nombre}'?", parent=self)
        if not confirmar:
            return

        resp = self.pedir(f"ELIMINARUSUARIO {nombre}")
        if resp is not None:
            messagebox.showinfo("Resultado", "\n".join(resp), parent=self)
            self.actualizar_usuarios()

    def construir_logs(self):
        tab = ttk.Frame(self.pestanas)
        self.pestanas.add(tab, text="  Auditoría  ")

        ttk.Label(tab, text="Registro de Auditoría y Eventos", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(tab, text="Historial de inicios de sesión, transferencias y operaciones del sistema", style="Subtitle.TLabel").pack(anchor="w", padx=20, pady=(0, 10))

        marco_herramientas = tk.Frame(tab, bg="#101827")
        marco_herramientas.pack(fill="x", padx=20, pady=(0, 8))

        ttk.Button(
            marco_herramientas,
            text="Actualizar registros",
            style="Accent.TButton",
            command=self.actualizar_logs
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            marco_herramientas,
            text="Exportar CSV",
            style="Secondary.TButton",
            command=self.exportar_logs_csv
        ).pack(side="left", padx=6)

        ttk.Button(
            marco_herramientas,
            text="Exportar JSON",
            style="Secondary.TButton",
            command=self.exportar_logs_json
        ).pack(side="left", padx=6)

        self.etiqueta_total_logs = tk.Label(
            marco_herramientas,
            text="Cargando registros...",
            bg="#101827",
            fg="#94A3B8",
            font=("Segoe UI", 9)
        )
        self.etiqueta_total_logs.pack(side="right", padx=10)

        contenedor = tk.Frame(tab, bg="#182235")
        contenedor.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        columnas = ("ID", "Fecha", "Usuario", "Acción", "Detalle")
        self.tabla_logs = ttk.Treeview(contenedor, columns=columnas, show="headings")

        for col, ancho in zip(columnas, (60, 170, 130, 160, 360)):
            self.tabla_logs.heading(col, text=col)
            self.tabla_logs.column(col, width=ancho, anchor="w")

        scroll = ttk.Scrollbar(contenedor, orient="vertical", command=self.tabla_logs.yview)
        self.tabla_logs.configure(yscrollcommand=scroll.set)
        self.tabla_logs.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.actualizar_logs()

    def actualizar_logs(self):
        lineas = self.pedir("LISTARLOGS")
        if lineas is None:
            return

        self.tabla_logs.delete(*self.tabla_logs.get_children())
        if len(lineas) <= 1:
            self.etiqueta_total_logs.config(text="No hay registros disponibles")
            return

        total = 0
        for linea in lineas[1:]:
            partes = linea.split(None, 4)
            if len(partes) >= 5:
                self.tabla_logs.insert("", "end", values=partes)
                total += 1

        self.etiqueta_total_logs.config(text=f"Total de eventos registrados: {total}")

    def exportar_logs_csv(self):
        items = self.tabla_logs.get_children()
        if not items:
            messagebox.showinfo("Exportar", "No hay registros para exportar", parent=self)
            return

        ruta = filedialog.asksaveasfilename(
            title="Guardar auditoría como CSV",
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            initialfile="reporte_auditoria.csv",
            parent=self
        )
        if not ruta:
            return

        try:
            with open(ruta, "w", newline="", encoding="utf-8") as archivo_csv:
                escritor = csv.writer(archivo_csv)
                escritor.writerow(["ID", "Fecha", "Usuario", "Acción", "Detalle"])
                for item in items:
                    escritor.writerow(self.tabla_logs.item(item)["values"])
            messagebox.showinfo("Exportación exitosa", f"Registros guardados en:\n{ruta}", parent=self)
        except Exception as error_csv:
            messagebox.showerror("Error al exportar", f"No se pudo guardar el archivo: {error_csv}", parent=self)

    def exportar_logs_json(self):
        items = self.tabla_logs.get_children()
        if not items:
            messagebox.showinfo("Exportar", "No hay registros para exportar", parent=self)
            return

        ruta = filedialog.asksaveasfilename(
            title="Guardar auditoría como JSON",
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")],
            initialfile="reporte_auditoria.json",
            parent=self
        )
        if not ruta:
            return

        try:
            lista_registros = []
            for item in items:
                vals = self.tabla_logs.item(item)["values"]
                lista_registros.append({
                    "id": vals[0],
                    "fecha": vals[1],
                    "usuario": vals[2],
                    "accion": vals[3],
                    "detalle": vals[4]
                })
            with open(ruta, "w", encoding="utf-8") as archivo_json:
                json.dump(lista_registros, archivo_json, indent=4, ensure_ascii=False)
            messagebox.showinfo("Exportación exitosa", f"Registros guardados en:\n{ruta}", parent=self)
        except Exception as error_json:
            messagebox.showerror("Error al exportar", f"No se pudo guardar el archivo: {error_json}", parent=self)

    def construir_terminal(self):
        tab = ttk.Frame(self.pestanas)
        self.pestanas.add(tab, text="  Terminal Remota  ")

        ttk.Label(tab, text="Consola Remota del Servidor (Admin)", style="Title.TLabel").pack(anchor="w", padx=20, pady=(15, 2))
        ttk.Label(tab, text="Ejecuta comandos del sistema operativo de manera remota y segura en el servidor", style="Subtitle.TLabel").pack(anchor="w", padx=20, pady=(0, 10))

        marco_botones_rapidos = tk.Frame(tab, bg="#101827")
        marco_botones_rapidos.pack(fill="x", padx=20, pady=(0, 6))

        tk.Label(marco_botones_rapidos, text="Comandos rápidos:", bg="#101827", fg="#94A3B8", font=("Segoe UI", 9)).pack(side="left", padx=(0, 8))

        comandos_rapidos = [
            ("whoami", "whoami"),
            ("Red", "ip a" if os.name != "nt" else "ipconfig"),
            ("Puertos", "netstat -tuln" if os.name != "nt" else "netstat -an"),
            ("Disco", "df -h" if os.name != "nt" else "wmic logicaldisk get caption,size,freespace"),
            ("Uptime", "uptime"),
        ]

        for etiqueta, cmd in comandos_rapidos:
            ttk.Button(
                marco_botones_rapidos,
                text=etiqueta,
                style="Secondary.TButton",
                command=lambda c=cmd: self.ejecutar_comando_rapido(c)
            ).pack(side="left", padx=4)

        ttk.Button(
            marco_botones_rapidos,
            text="Limpiar pantalla",
            style="Secondary.TButton",
            command=self.limpiar_terminal
        ).pack(side="right")

        marco_salida = tk.Frame(tab, bg="#0B0F17")
        marco_salida.pack(fill="both", expand=True, padx=20, pady=(0, 8))

        self.texto_terminal = tk.Text(
            marco_salida,
            bg="#0B0F17",
            fg="#10B981",
            insertbackground="#10B981",
            font=("Consolas", 10),
            relief="flat",
            wrap="word"
        )
        scroll_term = ttk.Scrollbar(marco_salida, orient="vertical", command=self.texto_terminal.yview)
        self.texto_terminal.configure(yscrollcommand=scroll_term.set)
        self.texto_terminal.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        scroll_term.pack(side="right", fill="y")

        marco_entrada = tk.Frame(tab, bg="#101827")
        marco_entrada.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(marco_entrada, text="$", bg="#101827", fg="#10B981", font=("Consolas", 12, "bold")).pack(side="left", padx=(0, 8))

        self.entrada_terminal = tk.Entry(
            marco_entrada,
            bg="#0F172A",
            fg="#FFFFFF",
            insertbackground="#FFFFFF",
            font=("Consolas", 10),
            relief="flat"
        )
        self.entrada_terminal.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.entrada_terminal.bind("<Return>", lambda e: self.enviar_comando_terminal())

        ttk.Button(marco_entrada, text="Ejecutar", style="Accent.TButton", command=self.enviar_comando_terminal).pack(side="right")

        self.texto_terminal.insert("end", "=== CONSOLA REMOTA DEL SERVIDOR TLS ===\nEscribe un comando abajo y presiona Enter o el botón Ejecutar.\n\n")
        self.texto_terminal.config(state="disabled")

    def limpiar_terminal(self):
        self.texto_terminal.config(state="normal")
        self.texto_terminal.delete("1.0", "end")
        self.texto_terminal.insert("end", "=== CONSOLA LIMPIA ===\n\n")
        self.texto_terminal.config(state="disabled")

    def ejecutar_comando_rapido(self, cmd):
        self.entrada_terminal.delete(0, "end")
        self.entrada_terminal.insert(0, cmd)
        self.enviar_comando_terminal()

    def enviar_comando_terminal(self):
        cmd = self.entrada_terminal.get().strip()
        if not cmd:
            return

        self.entrada_terminal.delete(0, "end")
        self.texto_terminal.config(state="normal")
        self.texto_terminal.insert("end", f"> {cmd}\n")
        self.texto_terminal.see("end")

        try:
            lineas = self.con.ejecutar_shell(cmd)
            for linea in lineas:
                self.texto_terminal.insert("end", f"{linea}\n")
            self.texto_terminal.insert("end", "\n")
        except Exception as error_term:
            self.texto_terminal.insert("end", f"Error al ejecutar: {error_term}\n\n")

        self.texto_terminal.see("end")
        self.texto_terminal.config(state="disabled")

    def cambiar_clave_gui(self):
        actual = simpledialog.askstring("Cambiar contraseña", "Introduce tu contraseña actual:", parent=self, show="*")
        if not actual:
            return
        nueva = simpledialog.askstring("Cambiar contraseña", "Introduce tu nueva contraseña (mínimo 6 caracteres):", parent=self, show="*")
        if not nueva:
            return
        if len(nueva) < 6:
            messagebox.showerror("Error", "La nueva contraseña debe tener al menos 6 caracteres", parent=self)
            return
        confirmar = simpledialog.askstring("Cambiar contraseña", "Confirma tu nueva contraseña:", parent=self, show="*")
        if nueva != confirmar:
            messagebox.showerror("Error", "Las contraseñas no coinciden", parent=self)
            return

        try:
            resp = self.con.cambiar_clave(actual, nueva)
            if resp.startswith("OK"):
                self.con.clave = nueva
                messagebox.showinfo("Éxito", resp, parent=self)
            else:
                messagebox.showerror("Error", resp, parent=self)
        except Exception as err:
            messagebox.showerror("Error", f"Ocurrió un error al cambiar la contraseña: {err}", parent=self)

    def ver_usuarios_conectados_gui(self):
        try:
            lineas = self.con.usuarios_conectados()
            if not lineas:
                messagebox.showinfo("Usuarios en línea", "No hay usuarios conectados", parent=self)
                return

            ventana_usr = tk.Toplevel(self)
            ventana_usr.title("Usuarios Conectados en Tiempo Real")
            ventana_usr.geometry("540x330")
            ventana_usr.configure(bg="#101827")
            ventana_usr.transient(self)

            tk.Label(
                ventana_usr,
                text="Sesiones Activas en el Servidor",
                bg="#101827",
                fg="#FFFFFF",
                font=("Segoe UI", 12, "bold")
            ).pack(anchor="w", padx=16, pady=(12, 4))

            contenedor = tk.Frame(ventana_usr, bg="#182235")
            contenedor.pack(fill="both", expand=True, padx=16, pady=8)

            columnas = ("Usuario", "IP", "Puerto", "Tiempo Activo")
            tabla = ttk.Treeview(contenedor, columns=columnas, show="headings")
            for c, w in zip(columnas, (130, 140, 80, 130)):
                tabla.heading(c, text=c)
                tabla.column(c, width=w, anchor="w")

            scroll = ttk.Scrollbar(contenedor, orient="vertical", command=tabla.yview)
            tabla.configure(yscrollcommand=scroll.set)
            tabla.pack(side="left", fill="both", expand=True)
            scroll.pack(side="right", fill="y")

            for linea in lineas[1:]:
                partes = linea.split()
                if len(partes) >= 4:
                    tabla.insert("", "end", values=partes)

            ttk.Button(
                ventana_usr,
                text="Cerrar",
                style="Secondary.TButton",
                command=ventana_usr.destroy
            ).pack(anchor="e", padx=16, pady=(0, 12))

        except Exception as err:
            messagebox.showerror("Error", f"No se pudo consultar usuarios en línea: {err}", parent=self)



if __name__ == "__main__":
    App().mainloop()