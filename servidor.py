import base64
import hashlib
import hmac
import os
import platform
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.parse

try:
    import psutil
except ImportError:
    psutil = None

ANFITRION = "0.0.0.0"
PUERTO = 5000
CARPETA_ARCHIVOS = "archivos_servidor"
COMANDOS_SOLO_ADMIN = {"CREARUSUARIO", "LISTARUSUARIOS", "ELIMINARUSUARIO", "LISTARLOGS", "KILLPROCESO", "EJECUTAR"}
CUOTA_USUARIO_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_INTENTOS_FALLIDOS = 5
BLOQUEO_SEGUNDOS = 60

sesiones_lock = threading.Lock()
sesiones_activas = {}  # {clave_sesion: {"usuario": str, "ip": str, "puerto": int, "inicio": float}}

intentos_lock = threading.Lock()
intentos_fallidos = {}  # {ip: [float]}


def obtener_conexion_bd():
    return sqlite3.connect("sistema.db", timeout=15.0)


def inicializar_base_datos():
    conexion = obtener_conexion_bd()
    conexion.execute("PRAGMA journal_mode=WAL;")
    cursor = conexion.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT UNIQUE NOT NULL,
        sal BLOB NOT NULL,
        clave_hash TEXT NOT NULL,
        rol TEXT NOT NULL DEFAULT 'usuario')""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT DEFAULT CURRENT_TIMESTAMP,
        usuario TEXT,
        accion TEXT,
        detalle TEXT)""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS archivos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre_archivo TEXT NOT NULL,
        nombre_guardado TEXT NOT NULL,
        propietario TEXT NOT NULL,
        tamano_original INTEGER NOT NULL,
        tamano_cifrado INTEGER NOT NULL,
        fecha TEXT DEFAULT CURRENT_TIMESTAMP,
        hash_sha256 TEXT NOT NULL)""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS archivos_compartidos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_archivo INTEGER NOT NULL,
        usuario_destino TEXT NOT NULL,
        fecha TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(id_archivo, usuario_destino))""")

    conexion.commit()
    conexion.close()

    os.makedirs(CARPETA_ARCHIVOS, exist_ok=True)



def hash_clave(clave_texto, sal):
    return hashlib.pbkdf2_hmac("sha256", clave_texto.encode(), sal, 100000).hex()


def registrar(usuario, accion, detalle=""):
    conexion = obtener_conexion_bd()
    conexion.execute(
        "INSERT INTO logs (usuario, accion, detalle) VALUES (?, ?, ?)",
        (usuario, accion, detalle)
    )
    conexion.commit()
    conexion.close()


def verificar(usuario, clave_texto):
    conexion = obtener_conexion_bd()
    fila = conexion.execute(
        "SELECT sal, clave_hash, rol FROM usuarios WHERE nombre = ?",
        (usuario,)
    ).fetchone()
    conexion.close()
    if fila is None:
        return None
    sal, hash_guardado, rol = fila
    if hmac.compare_digest(hash_clave(clave_texto, sal), hash_guardado):
        return rol
    return None


def ip_esta_bloqueada(ip):
    ahora = time.time()
    with intentos_lock:
        tiempos = [t for t in intentos_fallidos.get(ip, []) if ahora - t < BLOQUEO_SEGUNDOS]
        intentos_fallidos[ip] = tiempos
        return len(tiempos) >= MAX_INTENTOS_FALLIDOS


def registrar_intento_fallido(ip):
    ahora = time.time()
    with intentos_lock:
        if ip not in intentos_fallidos:
            intentos_fallidos[ip] = []
        intentos_fallidos[ip].append(ahora)


def limpiar_intentos_fallidos(ip):
    with intentos_lock:
        intentos_fallidos.pop(ip, None)


def obtener_espacio_usado(usuario):
    conexion = obtener_conexion_bd()
    fila = conexion.execute(
        "SELECT COALESCE(SUM(tamano_cifrado), 0) FROM archivos WHERE propietario = ?",
        (usuario,)
    ).fetchone()
    conexion.close()
    return int(fila[0]) if fila else 0


def obtener_nombre_sistema():
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", encoding="utf-8") as archivo_so:
                for linea in archivo_so:
                    if linea.startswith("PRETTY_NAME="):
                        return linea.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
    return f"{platform.system()} {platform.release()}"


def cmd_info():
    if psutil is None:
        return ["psutil no está disponible en este servidor"]

    nombre_host = socket.gethostname()
    nombre_so = obtener_nombre_sistema()

    tiempo_arranque = psutil.boot_time()
    segundos_activo = int(time.time() - tiempo_arranque)
    dias = segundos_activo // 86400
    horas = (segundos_activo % 86400) // 3600
    minutos = (segundos_activo % 3600) // 60
    uptime_texto = f"{dias}d {horas}h {minutos}m"

    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    ruta_disco = "/" if os.name != "nt" else "C:\\"
    disco = psutil.disk_usage(ruta_disco)
    red = psutil.net_io_counters()

    return [
        f"Host:    {nombre_host}",
        f"SO:      {nombre_so}",
        f"Uptime:  {uptime_texto}",
        f"CPU:     {cpu}% de uso ({psutil.cpu_count()} núcleos)",
        f"RAM:     {ram.used // 1024**2} MB usados de {ram.total // 1024**2} MB ({ram.percent}%)",
        f"Disco:   {round(disco.used / 1024**3, 1)} GB usados de {round(disco.total / 1024**3, 1)} GB ({disco.percent}%)",
        f"Red:     {red.bytes_sent // 1024} KB enviados, {red.bytes_recv // 1024} KB recibidos",
    ]


def cmd_procesos(argumentos=None):
    if psutil is None:
        return ["psutil no está disponible en este servidor"]

    lista_procesos = []
    for proceso in psutil.process_iter(["pid", "name", "username", "memory_percent", "cpu_percent"]):
        try:
            info = proceso.info
            lista_procesos.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    lista_procesos.sort(key=lambda item: item.get("memory_percent") or 0.0, reverse=True)

    limite = None
    if argumentos and len(argumentos) > 0 and argumentos[0].isdigit():
        limite = int(argumentos[0])

    procesos_filtrados = lista_procesos[:limite] if limite else lista_procesos

    lineas = [f"{'PID':<8}{'USUARIO':<16}{'MEM%':<8}{'CPU%':<8}NOMBRE"]
    for proceso in procesos_filtrados:
        usuario_proc = proceso.get("username") or "?"
        if len(usuario_proc) > 15:
            usuario_proc = usuario_proc[:14] + "…"
        nombre_proc = proceso.get("name") or "?"
        memoria = proceso.get("memory_percent") or 0.0
        cpu = proceso.get("cpu_percent") or 0.0
        lineas.append(
            f"{proceso['pid']:<8}{usuario_proc:<16}"
            f"{memoria:<8.1f}{cpu:<8.1f}{nombre_proc}"
        )
    return lineas


def cmd_kill_proceso(argumentos, usuario_actual):
    if len(argumentos) != 1 or not argumentos[0].isdigit():
        return ["ERROR Uso: KILLPROCESO <pid>"]
    pid = int(argumentos[0])
    if psutil is None:
        return ["ERROR psutil no está disponible en este servidor"]
    try:
        proc = psutil.Process(pid)
        nombre = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        registrar(usuario_actual, "KILL_PROCESO", f"Terminó PID {pid} ({nombre})")
        return [f"OK Proceso {pid} ({nombre}) terminado exitosamente"]
    except psutil.NoSuchProcess:
        return [f"ERROR No existe ningún proceso con PID {pid}"]
    except psutil.AccessDenied:
        return [f"ERROR Permiso denegado por el SO para terminar el proceso {pid}"]
    except Exception as error_kill:
        return [f"ERROR al terminar proceso: {error_kill}"]


def cmd_crear_usuario(argumentos, usuario_actual):
    if len(argumentos) != 3:
        return ["Uso: CREARUSUARIO nombre clave rol"]
    nombre, clave_nueva, rol = argumentos
    if not (nombre.isalnum() and 3 <= len(nombre) <= 20):
        return ["Nombre inválido: solo letras y números, de 3 a 20 caracteres"]
    if len(clave_nueva) < 6:
        return ["Contraseña inválida: mínimo 6 caracteres"]
    if rol not in ("admin", "usuario"):
        return ["Rol inválido: use 'admin' o 'usuario'"]
    sal = os.urandom(16)
    conexion = obtener_conexion_bd()
    try:
        conexion.execute(
            "INSERT INTO usuarios (nombre, sal, clave_hash, rol) VALUES (?, ?, ?, ?)",
            (nombre, sal, hash_clave(clave_nueva, sal), rol)
        )
        conexion.commit()
    except sqlite3.IntegrityError:
        return [f"El usuario '{nombre}' ya existe"]
    finally:
        conexion.close()
    registrar(usuario_actual, "CREARUSUARIO", f"creó a {nombre} ({rol})")
    return [f"Usuario '{nombre}' creado con rol {rol}"]


def cmd_listar_usuarios():
    conexion = obtener_conexion_bd()
    filas = conexion.execute("SELECT id, nombre, rol FROM usuarios ORDER BY id").fetchall()
    conexion.close()
    lineas = [f"{'ID':<6}{'USUARIO':<22}ROL"]
    for id_u, nombre_u, rol_u in filas:
        lineas.append(f"{id_u:<6}{nombre_u:<22}{rol_u}")
    return lineas


def cmd_eliminar_usuario(argumentos, usuario_actual):
    if len(argumentos) != 1:
        return ["Uso: ELIMINARUSUARIO nombre"]
    nombre = argumentos[0]
    if nombre == usuario_actual:
        return ["No puedes eliminar tu propio usuario"]
    conexion = obtener_conexion_bd()
    cursor = conexion.execute("DELETE FROM usuarios WHERE nombre = ?", (nombre,))
    conexion.commit()
    borrados = cursor.rowcount
    conexion.close()
    if borrados == 0:
        return [f"El usuario '{nombre}' no existe"]
    registrar(usuario_actual, "ELIMINARUSUARIO", f"eliminó a {nombre}")
    return [f"Usuario '{nombre}' eliminado"]


def cmd_cambiar_clave(argumentos, usuario_actual):
    if len(argumentos) != 2:
        return ["ERROR Uso: CAMBIARCLAVE clave_actual nueva_clave"]
    clave_actual, clave_nueva = argumentos
    if len(clave_nueva) < 6:
        return ["ERROR La nueva contraseña debe tener al menos 6 caracteres"]
    if not verificar(usuario_actual, clave_actual):
        return ["ERROR La contraseña actual es incorrecta"]
    sal = os.urandom(16)
    conexion = obtener_conexion_bd()
    conexion.execute(
        "UPDATE usuarios SET sal = ?, clave_hash = ? WHERE nombre = ?",
        (sal, hash_clave(clave_nueva, sal), usuario_actual)
    )
    conexion.commit()
    conexion.close()
    registrar(usuario_actual, "CAMBIAR_CLAVE", "Cambio de contraseña exitoso")
    return ["OK Contraseña actualizada correctamente"]


def cmd_usuarios_conectados():
    ahora = time.time()
    with sesiones_lock:
        if not sesiones_activas:
            return ["No hay usuarios conectados"]
        lineas = [f"{'USUARIO':<18}{'IP':<18}{'PUERTO':<10}TIEMPO_ACTIVO"]
        for sesion in sesiones_activas.values():
            segundos = int(ahora - sesion["inicio"])
            minutos = segundos // 60
            segs = segundos % 60
            tiempo = f"{minutos}m {segs}s"
            lineas.append(f"{sesion['usuario']:<18}{sesion['ip']:<18}{sesion['puerto']:<10}{tiempo}")
    return lineas


def cmd_ejecutar(argumentos, usuario_actual):
    if not argumentos:
        return ["ERROR Uso: EJECUTAR <comando>"]
    comando_str = " ".join(argumentos)
    registrar(usuario_actual, "EJECUTAR_SHELL", comando_str[:60])
    try:
        resultado = subprocess.run(
            comando_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=8
        )
        salida = resultado.stdout
        if resultado.stderr:
            salida += ("\n" if salida else "") + resultado.stderr
        if not salida.strip():
            salida = "(Comando ejecutado sin salida en consola)"
        return salida.splitlines()
    except subprocess.TimeoutExpired:
        return ["ERROR Tiempo límite excedido (8 segundos)"]
    except Exception as error_cmd:
        return [f"ERROR al ejecutar comando: {error_cmd}"]


def cmd_listar_archivos(usuario_actual, rol_usuario):
    conexion = obtener_conexion_bd()
    if rol_usuario == "admin":
        filas = conexion.execute(
            """SELECT a.id, a.nombre_archivo, a.propietario, a.tamano_original, a.tamano_cifrado,
                      COALESCE(GROUP_CONCAT(ac.usuario_destino, ','), '-') as compartidos, a.fecha
               FROM archivos a
               LEFT JOIN archivos_compartidos ac ON a.id = ac.id_archivo
               GROUP BY a.id
               ORDER BY a.id DESC"""
        ).fetchall()
    else:
        filas = conexion.execute(
            """SELECT a.id, a.nombre_archivo, a.propietario, a.tamano_original, a.tamano_cifrado,
                      COALESCE(GROUP_CONCAT(ac.usuario_destino, ','), '-') as compartidos, a.fecha
               FROM archivos a
               LEFT JOIN archivos_compartidos ac ON a.id = ac.id_archivo
               WHERE a.propietario = ? 
                  OR a.id IN (SELECT id_archivo FROM archivos_compartidos WHERE usuario_destino = ?)
               GROUP BY a.id
               ORDER BY a.id DESC""",
            (usuario_actual, usuario_actual)
        ).fetchall()
    conexion.close()

    if not filas:
        return ["No hay archivos almacenados en el servidor"]

    lineas = [f"{'ID':<6}{'ARCHIVO':<26}{'PROPIETARIO':<14}{'ORIGINAL':<12}{'CIFRADO':<12}{'COMPARTIDO':<20}FECHA"]
    for id_arch, nombre, prop, t_orig, t_cif, comp, fecha in filas:
        comp_str = comp.replace(" ", "") if comp else "-"
        if len(comp_str) > 18:
            comp_str = comp_str[:17] + "…"
        lineas.append(f"{id_arch:<6}{nombre:<26}{prop:<14}{t_orig:<12}{t_cif:<12}{comp_str:<20}{fecha}")
    return lineas


def cmd_compartir_archivo(argumentos, usuario_actual, rol_usuario):
    if len(argumentos) != 2:
        return ["ERROR Uso: COMPARTIRARCHIVO <id_o_nombre> <usuario_destino>"]
    parametro, usuario_destino = urllib.parse.unquote(argumentos[0]), argumentos[1]

    if usuario_destino == usuario_actual:
        return ["ERROR No puedes compartir un archivo contigo mismo"]

    conexion = obtener_conexion_bd()
    usr_dest = conexion.execute("SELECT id FROM usuarios WHERE nombre = ?", (usuario_destino,)).fetchone()
    if not usr_dest:
        conexion.close()
        return [f"ERROR El usuario destinatario '{usuario_destino}' no existe"]

    if rol_usuario == "admin":
        fila = conexion.execute(
            "SELECT id, nombre_archivo, propietario FROM archivos WHERE id = ? OR nombre_archivo = ? ORDER BY id DESC LIMIT 1",
            (parametro, parametro)
        ).fetchone()
    else:
        fila = conexion.execute(
            "SELECT id, nombre_archivo, propietario FROM archivos WHERE (id = ? OR nombre_archivo = ?) AND propietario = ? ORDER BY id DESC LIMIT 1",
            (parametro, parametro, usuario_actual)
        ).fetchone()

    if not fila:
        conexion.close()
        return ["ERROR Archivo no encontrado o no eres su propietario"]

    id_arch, nom_arch, prop = fila
    try:
        conexion.execute(
            "INSERT INTO archivos_compartidos (id_archivo, usuario_destino) VALUES (?, ?)",
            (id_arch, usuario_destino)
        )
        conexion.commit()
    except sqlite3.IntegrityError:
        conexion.close()
        return [f"El archivo '{nom_arch}' ya estaba compartido con {usuario_destino}"]
    conexion.close()

    registrar(usuario_actual, "COMPARTIR_ARCHIVO", f"Compartió '{nom_arch}' con {usuario_destino}")
    return [f"OK Archivo '{nom_arch}' compartido exitosamente con {usuario_destino}"]


def cmd_revocar_archivo(argumentos, usuario_actual, rol_usuario):
    if len(argumentos) != 2:
        return ["ERROR Uso: REVOCARARCHIVO <id_o_nombre> <usuario_destino>"]
    parametro, usuario_destino = urllib.parse.unquote(argumentos[0]), argumentos[1]

    conexion = obtener_conexion_bd()
    if rol_usuario == "admin":
        fila = conexion.execute(
            "SELECT id, nombre_archivo FROM archivos WHERE id = ? OR nombre_archivo = ? ORDER BY id DESC LIMIT 1",
            (parametro, parametro)
        ).fetchone()
    else:
        fila = conexion.execute(
            "SELECT id, nombre_archivo FROM archivos WHERE (id = ? OR nombre_archivo = ?) AND propietario = ? ORDER BY id DESC LIMIT 1",
            (parametro, parametro, usuario_actual)
        ).fetchone()

    if not fila:
        conexion.close()
        return ["ERROR Archivo no encontrado o no eres su propietario"]

    id_arch, nom_arch = fila
    cursor = conexion.execute(
        "DELETE FROM archivos_compartidos WHERE id_archivo = ? AND usuario_destino = ?",
        (id_arch, usuario_destino)
    )
    conexion.commit()
    borrados = cursor.rowcount
    conexion.close()

    if borrados == 0:
        return [f"El archivo '{nom_arch}' no estaba compartido con {usuario_destino}"]

    registrar(usuario_actual, "REVOCAR_ARCHIVO", f"Revocó acceso a '{nom_arch}' para {usuario_destino}")
    return [f"OK Acceso a '{nom_arch}' revocado para {usuario_destino}"]


def cmd_cuota(usuario_actual, rol_usuario):
    usado = obtener_espacio_usado(usuario_actual)
    limite = -1 if rol_usuario == "admin" else CUOTA_USUARIO_BYTES
    return [f"USADO:{usado} LIMITE:{limite}"]


def cmd_listar_logs():
    conexion = obtener_conexion_bd()
    filas = conexion.execute(
        "SELECT id, fecha, usuario, accion, detalle FROM logs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conexion.close()

    if not filas:
        return ["No hay registros de auditoría en la base de datos"]

    lineas = [f"{'ID':<6}{'FECHA':<22}{'USUARIO':<16}{'ACCIÓN':<18}DETALLE"]
    for id_l, fecha_l, usr_l, act_l, det_l in filas:
        lineas.append(f"{id_l:<6}{fecha_l:<22}{usr_l:<16}{act_l:<18}{det_l}")
    return lineas


def atender(conexion_tls, direccion_cliente):
    flujo = conexion_tls.makefile("rw", encoding="utf-8", newline="\n")

    if ip_esta_bloqueada(direccion_cliente[0]):
        registrar("DESCONOCIDO", "BLOQUEO_IP", f"IP {direccion_cliente[0]} bloqueada temporalmente")
        flujo.write("ERROR Demasiados intentos fallidos. Tu IP está bloqueada temporalmente (espera 60s)\n")
        flujo.flush()
        return

    linea_login = flujo.readline().strip()
    partes_login = linea_login.split(" ", 2)

    if not (len(partes_login) == 3 and partes_login[0] == "LOGIN"):
        flujo.write("ERROR Comando no válido\n")
        flujo.flush()
        return

    _, usuario, clave_recibida = partes_login
    rol = verificar(usuario, clave_recibida)

    if not rol:
        registrar_intento_fallido(direccion_cliente[0])
        registrar(usuario, "LOGIN_FALLIDO", direccion_cliente[0])
        flujo.write("ERROR Usuario o contraseña incorrectos\n")
        flujo.flush()
        return

    limpiar_intentos_fallidos(direccion_cliente[0])
    clave_sesion = f"{direccion_cliente[0]}:{direccion_cliente[1]}"
    with sesiones_lock:
        sesiones_activas[clave_sesion] = {
            "usuario": usuario,
            "ip": direccion_cliente[0],
            "puerto": direccion_cliente[1],
            "inicio": time.time()
        }

    registrar(usuario, "LOGIN_OK", direccion_cliente[0])
    flujo.write(f"OK Bienvenido {usuario} (rol: {rol})\n")
    flujo.flush()

    try:
        while True:
            linea_comando = flujo.readline()
            if linea_comando == "":
                break

            partes = linea_comando.strip().split(" ")
            comando = partes[0].upper()
            argumentos = partes[1:]

            if comando == "SALIR":
                registrar(usuario, "SALIR", direccion_cliente[0])
                break

            if comando in COMANDOS_SOLO_ADMIN and rol != "admin":
                registrar(usuario, "DENEGADO", comando)
                lineas_respuesta = ["Permiso denegado: solo el administrador puede hacer esto"]
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()
                continue

            if comando == "INFO":
                registrar(usuario, "INFO", direccion_cliente[0])
                lineas_respuesta = cmd_info()
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "PROCESOS":
                registrar(usuario, "PROCESOS", direccion_cliente[0])
                lineas_respuesta = cmd_procesos(argumentos)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "KILLPROCESO":
                lineas_respuesta = cmd_kill_proceso(argumentos, usuario)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "CREARUSUARIO":
                lineas_respuesta = cmd_crear_usuario(argumentos, usuario)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "LISTARUSUARIOS":
                registrar(usuario, "LISTARUSUARIOS", direccion_cliente[0])
                lineas_respuesta = cmd_listar_usuarios()
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "ELIMINARUSUARIO":
                lineas_respuesta = cmd_eliminar_usuario(argumentos, usuario)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "CAMBIARCLAVE":
                lineas_respuesta = cmd_cambiar_clave(argumentos, usuario)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "USUARIOSCONECTADOS":
                lineas_respuesta = cmd_usuarios_conectados()
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "EJECUTAR":
                lineas_respuesta = cmd_ejecutar(argumentos, usuario)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "LISTARLOGS":
                lineas_respuesta = cmd_listar_logs()
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "LISTARARCHIVOS":
                registrar(usuario, "LISTARARCHIVOS", direccion_cliente[0])
                lineas_respuesta = cmd_listar_archivos(usuario, rol)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "COMPARTIRARCHIVO":
                lineas_respuesta = cmd_compartir_archivo(argumentos, usuario, rol)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "REVOCARARCHIVO":
                lineas_respuesta = cmd_revocar_archivo(argumentos, usuario, rol)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "CUOTA":
                lineas_respuesta = cmd_cuota(usuario, rol)
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()

            elif comando == "SUBIRARCHIVO":
                if len(argumentos) != 3:
                    flujo.write("ERROR Uso: SUBIRARCHIVO <nombre> <tam_orig> <tam_cifrado>\n<<FIN>>\n")
                    flujo.flush()
                    continue

                nombre_archivo_crudo = urllib.parse.unquote(argumentos[0])
                nombre_archivo_seguro = os.path.basename(nombre_archivo_crudo)

                if not nombre_archivo_seguro:
                    flujo.write("ERROR Nombre de archivo no válido\n<<FIN>>\n")
                    flujo.flush()
                    continue

                try:
                    tamano_original = int(argumentos[1])
                    tamano_cifrado = int(argumentos[2])
                except ValueError:
                    flujo.write("ERROR Tamaños numéricos inválidos\n<<FIN>>\n")
                    flujo.flush()
                    continue

                if rol != "admin":
                    usado_actual = obtener_espacio_usado(usuario)
                    if usado_actual + tamano_cifrado > CUOTA_USUARIO_BYTES:
                        flujo.write(f"ERROR Cuota de almacenamiento excedida (Límite: 50MB, Usado actual: {usado_actual // (1024*1024)}MB)\n<<FIN>>\n")
                        flujo.flush()
                        continue

                flujo.write("OK_ENVIAR\n")
                flujo.flush()

                nombre_guardado = f"{usuario}_{int(time.time())}_{nombre_archivo_seguro}.enc"
                ruta_guardado = os.path.join(CARPETA_ARCHIVOS, nombre_guardado)

                hasher_sha = hashlib.sha256()
                bytes_recibidos = 0

                with open(ruta_guardado, "wb") as archivo_disco:
                    while True:
                        linea_bloque = flujo.readline()
                        if not linea_bloque:
                            break
                        linea_bloque = linea_bloque.rstrip("\r\n")
                        if linea_bloque == "<<FIN_ARCHIVO>>":
                            break
                        bloque_bytes = base64.b64decode(linea_bloque)
                        hasher_sha.update(bloque_bytes)
                        bytes_recibidos += len(bloque_bytes)
                        archivo_disco.write(bloque_bytes)

                conexion = obtener_conexion_bd()
                conexion.execute(
                    "INSERT INTO archivos (nombre_archivo, nombre_guardado, propietario, tamano_original, tamano_cifrado, hash_sha256) VALUES (?, ?, ?, ?, ?, ?)",
                    (nombre_archivo_seguro, nombre_guardado, usuario, tamano_original, bytes_recibidos, hasher_sha.hexdigest())
                )
                conexion.commit()
                conexion.close()

                registrar(usuario, "SUBIR_ARCHIVO", f"{nombre_archivo_seguro} ({bytes_recibidos} bytes cifrados)")
                flujo.write(f"OK Archivo '{nombre_archivo_seguro}' almacenado cifrado correctamente en el servidor\n<<FIN>>\n")
                flujo.flush()

            elif comando == "DESCARGARARCHIVO":
                if len(argumentos) != 1:
                    flujo.write("ERROR Uso: DESCARGARARCHIVO <nombre_o_id>\n<<FIN>>\n")
                    flujo.flush()
                    continue

                parametro = urllib.parse.unquote(argumentos[0])
                conexion = obtener_conexion_bd()

                if rol == "admin":
                    fila = conexion.execute(
                        "SELECT id, nombre_archivo, nombre_guardado, propietario, tamano_cifrado, hash_sha256 FROM archivos WHERE nombre_archivo = ? OR id = ? ORDER BY id DESC LIMIT 1",
                        (parametro, parametro)
                    ).fetchone()
                else:
                    fila = conexion.execute(
                        """SELECT a.id, a.nombre_archivo, a.nombre_guardado, a.propietario, a.tamano_cifrado, a.hash_sha256 
                           FROM archivos a 
                           LEFT JOIN archivos_compartidos ac ON a.id = ac.id_archivo 
                           WHERE (a.nombre_archivo = ? OR a.id = ?) 
                             AND (a.propietario = ? OR ac.usuario_destino = ?) 
                           ORDER BY a.id DESC LIMIT 1""",
                        (parametro, parametro, usuario, usuario)
                    ).fetchone()
                conexion.close()

                if not fila:
                    flujo.write("ERROR Archivo no encontrado o no tienes permiso para acceder a él\n<<FIN>>\n")
                    flujo.flush()
                    continue

                id_arch, nombre_arch, nombre_guardado, prop, tam_cif, hash_sha = fila
                ruta_guardado = os.path.join(CARPETA_ARCHIVOS, nombre_guardado)

                if not os.path.isfile(ruta_guardado):
                    flujo.write("ERROR El archivo cifrado en disco no se encuentra\n<<FIN>>\n")
                    flujo.flush()
                    continue

                nombre_codificado = urllib.parse.quote(nombre_arch)
                flujo.write(f"OK_DESCARGAR {tam_cif} {nombre_codificado} {hash_sha}\n")
                flujo.flush()

                with open(ruta_guardado, "rb") as archivo_disco:
                    while True:
                        pedazo = archivo_disco.read(32768)
                        if not pedazo:
                            break
                        linea_b64 = base64.b64encode(pedazo).decode("ascii")
                        flujo.write(linea_b64 + "\n")
                flujo.write("<<FIN_ARCHIVO>>\n")
                flujo.flush()

                registrar(usuario, "DESCARGAR_ARCHIVO", nombre_arch)

            elif comando == "ELIMINARARCHIVO":
                if len(argumentos) != 1:
                    flujo.write("ERROR Uso: ELIMINARARCHIVO <nombre_o_id>\n<<FIN>>\n")
                    flujo.flush()
                    continue

                parametro = urllib.parse.unquote(argumentos[0])
                conexion = obtener_conexion_bd()

                if rol == "admin":
                    fila = conexion.execute(
                        "SELECT id, nombre_archivo, nombre_guardado, propietario FROM archivos WHERE nombre_archivo = ? OR id = ? ORDER BY id DESC LIMIT 1",
                        (parametro, parametro)
                    ).fetchone()
                else:
                    fila = conexion.execute(
                        "SELECT id, nombre_archivo, nombre_guardado, propietario FROM archivos WHERE (nombre_archivo = ? OR id = ?) AND propietario = ? ORDER BY id DESC LIMIT 1",
                        (parametro, parametro, usuario)
                    ).fetchone()

                if not fila:
                    conexion.close()
                    flujo.write("ERROR Archivo no encontrado o no tienes permiso para eliminarlo\n<<FIN>>\n")
                    flujo.flush()
                    continue

                id_arch, nombre_arch, nombre_guardado, prop = fila
                conexion.execute("DELETE FROM archivos_compartidos WHERE id_archivo = ?", (id_arch,))
                conexion.execute("DELETE FROM archivos WHERE id = ?", (id_arch,))
                conexion.commit()
                conexion.close()

                ruta_guardado = os.path.join(CARPETA_ARCHIVOS, nombre_guardado)
                if os.path.isfile(ruta_guardado):
                    try:
                        os.remove(ruta_guardado)
                    except OSError:
                        pass

                registrar(usuario, "ELIMINAR_ARCHIVO", nombre_arch)
                flujo.write(f"OK Archivo '{nombre_arch}' eliminado exitosamente del servidor\n<<FIN>>\n")
                flujo.flush()

            else:
                lineas_respuesta = ["Comando desconocido"]
                flujo.write("\n".join(lineas_respuesta) + "\n<<FIN>>\n")
                flujo.flush()
    finally:
        with sesiones_lock:
            sesiones_activas.pop(clave_sesion, None)


def gestionar_cliente(conexion_cruda, direccion_cliente, contexto_ssl):
    try:
        conexion_tls = contexto_ssl.wrap_socket(conexion_cruda, server_side=True)
        print(f"[+] Conexión segura establecida desde {direccion_cliente} (Hilo activo: {threading.current_thread().name})")
        atender(conexion_tls, direccion_cliente)
        conexion_tls.close()
        print(f"[-] Sesión terminada con {direccion_cliente}")
    except (ssl.SSLError, OSError) as error_conexion:
        print(f"[!] Conexión cerrada o error con {direccion_cliente}: {error_conexion}")
        try:
            conexion_cruda.close()
        except OSError:
            pass


def iniciar_servidor():
    inicializar_base_datos()

    contexto_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto_ssl.load_cert_chain(certfile="servidor.crt", keyfile="servidor.key")

    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_servidor.bind((ANFITRION, PUERTO))
    socket_servidor.listen(15)
    print(f"Servidor TLS multihilo escuchando en el puerto {PUERTO} (soporte para múltiples clientes simultáneos)...")

    while True:
        try:
            conexion_cruda, direccion_cliente = socket_servidor.accept()
            hilo_cliente = threading.Thread(
                target=gestionar_cliente,
                args=(conexion_cruda, direccion_cliente, contexto_ssl),
                daemon=True
            )
            hilo_cliente.start()
        except KeyboardInterrupt:
            print("\nDeteniendo servidor...")
            break
        except Exception as error_bucle:
            print(f"Error al aceptar conexión de cliente: {error_bucle}")


if __name__ == "__main__":
    iniciar_servidor()