import socket
import ssl
import sqlite3
import hashlib
import hmac
import os
import psutil

HOST = "0.0.0.0"
PUERTO = 5000
SOLO_ADMIN = {"CREARUSUARIO", "LISTARUSUARIOS", "ELIMINARUSUARIO"}

def hash_clave(clave, sal):
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, 100000).hex()

def registrar(usuario, accion, detalle=""):
    con = sqlite3.connect("sistema.db")
    con.execute("INSERT INTO logs (usuario, accion, detalle) VALUES (?, ?, ?)",
                (usuario, accion, detalle))
    con.commit()
    con.close()

def verificar(usuario, clave):
    con = sqlite3.connect("sistema.db")
    fila = con.execute("SELECT sal, clave_hash, rol FROM usuarios WHERE nombre = ?",
                       (usuario,)).fetchone()
    con.close()
    if fila is None:
        return None
    sal, hash_guardado, rol = fila
    if hmac.compare_digest(hash_clave(clave, sal), hash_guardado):
        return rol
    return None

def cmd_info():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disco = psutil.disk_usage("/")
    red = psutil.net_io_counters()
    return [
        f"CPU:   {cpu}% de uso ({psutil.cpu_count()} núcleos)",
        f"RAM:   {ram.used // 1024**2} MB usados de {ram.total // 1024**2} MB ({ram.percent}%)",
        f"Disco: {round(disco.used / 1024**3, 1)} GB usados de {round(disco.total / 1024**3, 1)} GB ({disco.percent}%)",
        f"Red:   {red.bytes_sent // 1024} KB enviados, {red.bytes_recv // 1024} KB recibidos",
    ]

def cmd_procesos():
    lista = []
    for p in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        lista.append(p.info)
    lista.sort(key=lambda x: x["memory_percent"] or 0, reverse=True)
    lineas = [f"{'PID':<8}{'USUARIO':<14}{'MEM%':<8}NOMBRE"]
    for p in lista[:15]:
        lineas.append(f"{p['pid']:<8}{(p['username'] or '?'):<14}"
                      f"{(p['memory_percent'] or 0):<8.1f}{p['name']}")
    return lineas

def cmd_crear(args, actual):
    if len(args) != 3:
        return ["Uso: CREARUSUARIO nombre clave rol"]
    nombre, clave, rol = args
    if not (nombre.isalnum() and 3 <= len(nombre) <= 20):
        return ["Nombre inválido: solo letras y números, de 3 a 20 caracteres"]
    if len(clave) < 6:
        return ["Contraseña inválida: mínimo 6 caracteres"]
    if rol not in ("admin", "usuario"):
        return ["Rol inválido: use 'admin' o 'usuario'"]
    sal = os.urandom(16)
    con = sqlite3.connect("sistema.db")
    try:
        con.execute(
            "INSERT INTO usuarios (nombre, sal, clave_hash, rol) VALUES (?, ?, ?, ?)",
            (nombre, sal, hash_clave(clave, sal), rol))
        con.commit()
    except sqlite3.IntegrityError:
        return [f"El usuario '{nombre}' ya existe"]
    finally:
        con.close()
    registrar(actual, "CREARUSUARIO", f"creó a {nombre} ({rol})")
    return [f"Usuario '{nombre}' creado con rol {rol}"]

def cmd_listar():
    con = sqlite3.connect("sistema.db")
    filas = con.execute("SELECT id, nombre, rol FROM usuarios ORDER BY id").fetchall()
    con.close()
    lineas = [f"{'ID':<6}{'USUARIO':<22}ROL"]
    for i, n, r in filas:
        lineas.append(f"{i:<6}{n:<22}{r}")
    return lineas

def cmd_eliminar(args, actual):
    if len(args) != 1:
        return ["Uso: ELIMINARUSUARIO nombre"]
    nombre = args[0]
    if nombre == actual:
        return ["No puedes eliminar tu propio usuario"]
    con = sqlite3.connect("sistema.db")
    cur = con.execute("DELETE FROM usuarios WHERE nombre = ?", (nombre,))
    con.commit()
    borrados = cur.rowcount
    con.close()
    if borrados == 0:
        return [f"El usuario '{nombre}' no existe"]
    registrar(actual, "ELIMINARUSUARIO", f"eliminó a {nombre}")
    return [f"Usuario '{nombre}' eliminado"]

def atender(conn_tls, addr):
    f = conn_tls.makefile("rw", encoding="utf-8", newline="\n")
    linea = f.readline().strip()
    partes = linea.split(" ", 2)
    if not (len(partes) == 3 and partes[0] == "LOGIN"):
        f.write("ERROR Comando no válido\n")
        f.flush()
        return
    _, usuario, clave = partes
    rol = verificar(usuario, clave)
    if not rol:
        registrar(usuario, "LOGIN_FALLIDO", addr[0])
        f.write("ERROR Usuario o contraseña incorrectos\n")
        f.flush()
        return

    registrar(usuario, "LOGIN_OK", addr[0])
    f.write(f"OK Bienvenido {usuario} (rol: {rol})\n")
    f.flush()

    while True:
        linea = f.readline()
        if linea == "":          # el cliente se desconectó
            break
        partes = linea.strip().split(" ")
        cmd = partes[0].upper()
        args = partes[1:]

        if cmd == "SALIR":
            registrar(usuario, "SALIR", addr[0])
            break

        if cmd in SOLO_ADMIN and rol != "admin":
            registrar(usuario, "DENEGADO", cmd)
            lineas = ["Permiso denegado: solo el administrador puede hacer esto"]
        elif cmd == "INFO":
            registrar(usuario, "INFO", addr[0])
            lineas = cmd_info()
        elif cmd == "PROCESOS":
            registrar(usuario, "PROCESOS", addr[0])
            lineas = cmd_procesos()
        elif cmd == "CREARUSUARIO":
            lineas = cmd_crear(args, usuario)
        elif cmd == "LISTARUSUARIOS":
            registrar(usuario, "LISTARUSUARIOS", addr[0])
            lineas = cmd_listar()
        elif cmd == "ELIMINARUSUARIO":
            lineas = cmd_eliminar(args, usuario)
        else:
            lineas = ["Comando desconocido"]

        f.write("\n".join(lineas) + "\n<<FIN>>\n")
        f.flush()

contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
contexto.load_cert_chain(certfile="servidor.crt", keyfile="servidor.key")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PUERTO))
srv.listen(5)
print(f"Servidor TLS escuchando en el puerto {PUERTO}...")

while True:
    conn, addr = srv.accept()
    try:
        conn_tls = contexto.wrap_socket(conn, server_side=True)
        print(f"Conexión segura desde {addr}")
        atender(conn_tls, addr)
        conn_tls.close()
        print(f"Sesión terminada con {addr}")
    except (ssl.SSLError, OSError) as e:
        print(f"Error con {addr}: {e}")
        conn.close()