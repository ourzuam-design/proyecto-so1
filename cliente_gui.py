import os
import re
import socket
import ssl
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

IP_SERVIDOR = "192.168.1.64"
PUERTO = 5000
CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "servidor.crt")


class Conexion:
    def __init__(self):
        self.sock = None
        self.f = None
        self.rol = None

    def conectar(self, usuario, clave):
        ctx = ssl.create_default_context(cafile=CERT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        self.sock = ctx.wrap_socket(s, server_hostname=IP_SERVIDOR)
        self.sock.connect((IP_SERVIDOR, PUERTO))
        self.f = self.sock.makefile("rw", encoding="utf-8", newline="\n")
        self.f.write(f"LOGIN {usuario} {clave}\n")
        self.f.flush()
        resp = self.f.readline().strip()
        if not resp.startswith("OK"):
            self.cerrar()
            return False, resp
        m = re.search(r"rol: (\w+)", resp)
        self.rol = m.group(1) if m else "usuario"
        return True, resp

    def enviar(self, comando):
        self.f.write(comando + "\n")
        self.f.flush()
        lineas = []
        while True:
            linea = self.f.readline()
            if linea == "":
                raise ConnectionError("El servidor cerró la conexión")
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
        self.f = self.sock = None


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Administración remota de servidor")
        self.geometry("680x460")
        self.con = Conexion()
        self.job = None
        self.protocol("WM_DELETE_WINDOW", self.cerrar_app)
        self.pantalla_login()

    
    def limpiar(self):
        if self.job:
            self.after_cancel(self.job)
            self.job = None
        for w in self.winfo_children():
            w.destroy()

    def pedir(self, comando):
        try:
            return self.con.enviar(comando)
        except (OSError, ssl.SSLError, ConnectionError) as e:
            messagebox.showerror("Conexión perdida", str(e))
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
        marco = ttk.Frame(self, padding=30)
        marco.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(marco, text="Acceso al servidor", font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 15))
        ttk.Label(marco, text="Usuario:").grid(row=1, column=0, sticky="e", pady=4)
        ttk.Label(marco, text="Contraseña:").grid(row=2, column=0, sticky="e", pady=4)
        self.e_usuario = ttk.Entry(marco, width=25)
        self.e_clave = ttk.Entry(marco, width=25, show="*")
        self.e_usuario.grid(row=1, column=1, padx=6)
        self.e_clave.grid(row=2, column=1, padx=6)
        ttk.Button(marco, text="Entrar", command=self.entrar).grid(
            row=3, column=0, columnspan=2, pady=12)
        self.lbl_error = ttk.Label(marco, text="", foreground="red")
        self.lbl_error.grid(row=4, column=0, columnspan=2)
        self.e_usuario.focus()
        self.bind("<Return>", lambda e: self.entrar())

    def entrar(self):
        usuario = self.e_usuario.get().strip()
        clave = self.e_clave.get()
        if not usuario or not clave:
            self.lbl_error.config(text="Escribe usuario y contraseña")
            return
        if " " in usuario or " " in clave:
            self.lbl_error.config(text="No se permiten espacios")
            return
        try:
            ok, resp = self.con.conectar(usuario, clave)
        except (OSError, ssl.SSLError) as e:
            self.lbl_error.config(text=f"No se pudo conectar: {e}")
            return
        if not ok:
            self.lbl_error.config(text=resp.replace("ERROR ", ""))
            return
        self.unbind("<Return>")
        self.usuario = usuario
        self.pantalla_principal()

   
    def pantalla_principal(self):
        self.limpiar()
        barra = ttk.Frame(self, padding=(10, 8))
        barra.pack(fill="x")
        ttk.Label(barra, text=f"Usuario: {self.usuario}  (rol: {self.con.rol})").pack(side="left")
        ttk.Button(barra, text="Cerrar sesión", command=self.cerrar_sesion).pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.construir_sistema()
        self.construir_procesos()
        if self.con.rol == "admin":
            self.construir_usuarios()
        self.actualizar_sistema()

    
    def construir_sistema(self):
        tab = ttk.Frame(self.tabs, padding=15)
        self.tabs.add(tab, text="Sistema")
        self.barras = {}
        for i, nombre in enumerate(("CPU", "RAM", "Disco")):
            lbl = ttk.Label(tab, text=f"{nombre}: -")
            lbl.grid(row=i * 2, column=0, sticky="w", pady=(8, 0))
            barra = ttk.Progressbar(tab, length=520, maximum=100)
            barra.grid(row=i * 2 + 1, column=0, sticky="w")
            self.barras[nombre] = (lbl, barra)
        self.lbl_red = ttk.Label(tab, text="Red: -")
        self.lbl_red.grid(row=6, column=0, sticky="w", pady=(14, 0))
        botones = ttk.Frame(tab)
        botones.grid(row=7, column=0, sticky="w", pady=15)
        ttk.Button(botones, text="Actualizar", command=self.actualizar_sistema).pack(side="left")
        self.auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(botones, text="Automático (cada 3 s)", variable=self.auto,
                        command=self.alternar_auto).pack(side="left", padx=12)

    def actualizar_sistema(self):
        lineas = self.pedir("INFO")
        if lineas is None:
            return
        for linea in lineas:
            if linea.startswith("Red"):
                self.lbl_red.config(text=" ".join(linea.split()))
                continue
            for nombre, (lbl, barra) in self.barras.items():
                if linea.startswith(nombre):
                    lbl.config(text=" ".join(linea.split()))
                    porcentajes = re.findall(r"([\d.]+)%", linea)
                    if porcentajes:
                        barra["value"] = float(porcentajes[-1])

    def alternar_auto(self):
        if self.auto.get():
            self.tick()
        elif self.job:
            self.after_cancel(self.job)
            self.job = None

    def tick(self):
        self.actualizar_sistema()
        if self.auto.get():
            self.job = self.after(3000, self.tick)

    
    def construir_procesos(self):
        tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab, text="Procesos")
        cols = ("PID", "Usuario", "Mem %", "Nombre")
        self.tabla_proc = ttk.Treeview(tab, columns=cols, show="headings", height=14)
        for c, ancho in zip(cols, (70, 130, 70, 300)):
            self.tabla_proc.heading(c, text=c)
            self.tabla_proc.column(c, width=ancho)
        self.tabla_proc.pack(fill="both", expand=True)
        ttk.Button(tab, text="Actualizar", command=self.actualizar_procesos).pack(pady=8)
        self.actualizar_procesos()

    def actualizar_procesos(self):
        lineas = self.pedir("PROCESOS")
        if lineas is None:
            return
        self.tabla_proc.delete(*self.tabla_proc.get_children())
        for linea in lineas[1:]:
            partes = linea.split(None, 3)
            if len(partes) == 4:
                self.tabla_proc.insert("", "end", values=partes)

    
    def construir_usuarios(self):
        tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab, text="Usuarios")
        cols = ("ID", "Usuario", "Rol")
        self.tabla_usr = ttk.Treeview(tab, columns=cols, show="headings", height=12)
        for c, ancho in zip(cols, (60, 250, 120)):
            self.tabla_usr.heading(c, text=c)
            self.tabla_usr.column(c, width=ancho)
        self.tabla_usr.pack(fill="both", expand=True)
        botones = ttk.Frame(tab)
        botones.pack(pady=8)
        ttk.Button(botones, text="Actualizar", command=self.actualizar_usuarios).pack(side="left", padx=4)
        ttk.Button(botones, text="Crear usuario", command=self.crear_usuario).pack(side="left", padx=4)
        ttk.Button(botones, text="Eliminar usuario", command=self.eliminar_usuario).pack(side="left", padx=4)
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
        clave = simpledialog.askstring("Crear usuario", "Contraseña (mínimo 6):", parent=self, show="*")
        if not clave:
            return
        rol = simpledialog.askstring("Crear usuario", "Rol (admin / usuario):",
                                     parent=self, initialvalue="usuario")
        if not rol:
            return
        if " " in nombre or " " in clave or " " in rol:
            messagebox.showerror("Error", "No se permiten espacios")
            return
        resp = self.pedir(f"CREARUSUARIO {nombre} {clave} {rol}")
        if resp is not None:
            messagebox.showinfo("Resultado", "\n".join(resp))
            self.actualizar_usuarios()

    def eliminar_usuario(self):
        sel = self.tabla_usr.selection()
        if not sel:
            messagebox.showwarning("Eliminar", "Selecciona un usuario de la tabla")
            return
        nombre = str(self.tabla_usr.item(sel[0])["values"][1])
        if not messagebox.askyesno("Confirmar", f"¿Eliminar al usuario '{nombre}'?"):
            return
        resp = self.pedir(f"ELIMINARUSUARIO {nombre}")
        if resp is not None:
            messagebox.showinfo("Resultado", "\n".join(resp))
            self.actualizar_usuarios()


if __name__ == "__main__":
    App().mainloop()