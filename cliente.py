import base64
import getpass
import os
import socket
import ssl
import sys
import urllib.parse
import cifrado

IP_SERVIDOR_POR_DEFECTO = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.197"
PUERTO_POR_DEFECTO = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 5000

print("=== CONEXIÓN AL SERVIDOR UBUNTU ===")
ip_entrada = input(f"Dirección IP del servidor [{IP_SERVIDOR_POR_DEFECTO}]: ").strip()
ip_servidor = ip_entrada if ip_entrada else IP_SERVIDOR_POR_DEFECTO

puerto_entrada = input(f"Puerto [{PUERTO_POR_DEFECTO}]: ").strip()
puerto_servidor = int(puerto_entrada) if puerto_entrada.isdigit() else PUERTO_POR_DEFECTO

usuario = input("Usuario: ").strip()
clave_sesion = getpass.getpass("Contraseña: ")

contexto_ssl = ssl.create_default_context()
contexto_ssl.check_hostname = False
contexto_ssl.verify_mode = ssl.CERT_NONE

socket_crudo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_tls = contexto_ssl.wrap_socket(socket_crudo, server_hostname=ip_servidor)

try:
    socket_tls.connect((ip_servidor, puerto_servidor))
except Exception as error_conexion:
    print(f"Error al conectar con {ip_servidor}:{puerto_servidor} -> {error_conexion}")
    raise SystemExit

flujo = socket_tls.makefile("rw", encoding="utf-8", newline="\n")
flujo.write(f"LOGIN {usuario} {clave_sesion}\n")
flujo.flush()

respuesta_login = flujo.readline().strip()
print(respuesta_login)

if not respuesta_login.startswith("OK"):
    socket_tls.close()
    raise SystemExit


def enviar_comando_simple(comando_texto):
    flujo.write(comando_texto + "\n")
    flujo.flush()
    while True:
        linea_recibida = flujo.readline().rstrip("\n")
        if linea_recibida == "<<FIN>>" or linea_recibida == "":
            break
        print(linea_recibida)


def subir_archivo():
    ruta_local = input("Ruta del archivo local a transferir: ").strip()
    if not os.path.isfile(ruta_local):
        print("El archivo local especificado no existe.")
        return

    nombre_archivo = os.path.basename(ruta_local)
    clave_cifrado = getpass.getpass("Contraseña para cifrar el archivo [Enter = usar contraseña de sesión]: ")
    clave_final = clave_cifrado if clave_cifrado else clave_sesion

    try:
        with open(ruta_local, "rb") as archivo_local:
            contenido_claro = archivo_local.read()
    except Exception as error_lectura:
        print(f"Error al leer el archivo local: {error_lectura}")
        return

    tamano_original = len(contenido_claro)
    print("Cifrando archivo para proteger su privacidad en el servidor...")
    contenido_cifrado = cifrado.cifrar_datos(contenido_claro, clave_final)
    tamano_cifrado = len(contenido_cifrado)

    nombre_codificado = urllib.parse.quote(nombre_archivo)
    flujo.write(f"SUBIRARCHIVO {nombre_codificado} {tamano_original} {tamano_cifrado}\n")
    flujo.flush()

    respuesta_servidor = flujo.readline().strip()
    if respuesta_servidor != "OK_ENVIAR":
        print(f"Error del servidor: {respuesta_servidor}")
        while True:
            fin = flujo.readline().strip()
            if fin == "<<FIN>>" or fin == "":
                break
        return

    print("Transfiriendo archivo cifrado por el canal seguro TCP...")
    tamano_bloque = 32768
    for indice in range(0, tamano_cifrado, tamano_bloque):
        bloque = contenido_cifrado[indice:indice + tamano_bloque]
        linea_b64 = base64.b64encode(bloque).decode("ascii")
        flujo.write(linea_b64 + "\n")
    flujo.write("<<FIN_ARCHIVO>>\n")
    flujo.flush()

    while True:
        linea_recibida = flujo.readline().rstrip("\n")
        if linea_recibida == "<<FIN>>" or linea_recibida == "":
            break
        print(linea_recibida)


def descargar_archivo():
    identificador = input("Nombre o ID del archivo a descargar: ").strip()
    if not identificador:
        return

    clave_descifrado = getpass.getpass("Contraseña para descifrar el archivo [Enter = usar contraseña de sesión]: ")
    clave_final = clave_descifrado if clave_descifrado else clave_sesion

    identificador_codificado = urllib.parse.quote(identificador)
    flujo.write(f"DESCARGARARCHIVO {identificador_codificado}\n")
    flujo.flush()

    cabecera_descarga = flujo.readline().strip()
    if not cabecera_descarga.startswith("OK_DESCARGAR"):
        print(cabecera_descarga)
        while True:
            fin = flujo.readline().strip()
            if fin == "<<FIN>>" or fin == "":
                break
        return

    partes_cabecera = cabecera_descarga.split(" ")
    nombre_archivo_servidor = urllib.parse.unquote(partes_cabecera[2]) if len(partes_cabecera) >= 3 else identificador

    ruta_destino = input(f"Ruta o nombre para guardar [{nombre_archivo_servidor}]: ").strip()
    if not ruta_destino:
        ruta_destino = nombre_archivo_servidor

    print("Descargando archivo cifrado desde el servidor...")
    bloques_recibidos = []
    while True:
        linea_bloque = flujo.readline()
        if not linea_bloque:
            break
        linea_bloque = linea_bloque.rstrip("\r\n")
        if linea_bloque == "<<FIN_ARCHIVO>>":
            break
        bloques_recibidos.append(base64.b64decode(linea_bloque))

    paquete_cifrado = b"".join(bloques_recibidos)
    print("Descifrando archivo descargado y verificando autenticidad...")

    try:
        contenido_descifrado = cifrado.descifrar_datos(paquete_cifrado, clave_final)
    except ValueError as error_cifrado:
        print(f"Error al descifrar: {error_cifrado}")
        return

    try:
        with open(ruta_destino, "wb") as archivo_salida:
            archivo_salida.write(contenido_descifrado)
        print(f"¡Éxito! Archivo guardado correctamente en: {ruta_destino} ({len(contenido_descifrado)} bytes)")
    except Exception as error_escritura:
        print(f"Error al escribir en disco local: {error_escritura}")


while True:
    print("\n--- MENÚ PRINCIPAL ---")
    print("1) Info del sistema")
    print("2) Procesos en ejecución")
    print("3) Subir archivo cifrado")
    print("4) Listar archivos en servidor")
    print("5) Descargar y descifrar archivo")
    print("6) Eliminar archivo en servidor")
    print("7) Crear usuario      (solo admin)")
    print("8) Listar usuarios    (solo admin)")
    print("9) Eliminar usuario   (solo admin)")
    print("10) Listar logs        (solo admin)")
    print("11) Salir")
    opcion_elegida = input("Opción: ").strip()

    if opcion_elegida == "1":
        enviar_comando_simple("INFO")
    elif opcion_elegida == "2":
        limite_proc = input("Cantidad máxima de procesos a mostrar [Enter para ver TODOS]: ").strip()
        if limite_proc.isdigit():
            enviar_comando_simple(f"PROCESOS {limite_proc}")
        else:
            enviar_comando_simple("PROCESOS")
    elif opcion_elegida == "3":
        subir_archivo()
    elif opcion_elegida == "4":
        enviar_comando_simple("LISTARARCHIVOS")
    elif opcion_elegida == "5":
        descargar_archivo()
    elif opcion_elegida == "6":
        archivo_a_borrar = input("Nombre o ID del archivo a eliminar en servidor: ").strip()
        if archivo_a_borrar:
            enviar_comando_simple(f"ELIMINARARCHIVO {urllib.parse.quote(archivo_a_borrar)}")
    elif opcion_elegida == "7":
        nombre_nuevo = input("Nombre del nuevo usuario: ").strip()
        clave_nueva = getpass.getpass("Contraseña del nuevo usuario: ")
        rol_nuevo = input("Rol (admin/usuario) [usuario]: ").strip() or "usuario"
        if " " in nombre_nuevo or " " in clave_nueva:
            print("El nombre y la contraseña no pueden tener espacios")
        else:
            enviar_comando_simple(f"CREARUSUARIO {nombre_nuevo} {clave_nueva} {rol_nuevo}")
    elif opcion_elegida == "8":
        enviar_comando_simple("LISTARUSUARIOS")
    elif opcion_elegida == "9":
        usuario_a_eliminar = input("Usuario a eliminar: ").strip()
        if usuario_a_eliminar:
            enviar_comando_simple(f"ELIMINARUSUARIO {usuario_a_eliminar}")
    elif opcion_elegida == "10":
        enviar_comando_simple("LISTARLOGS")
    elif opcion_elegida == "11":
        flujo.write("SALIR\n")
        flujo.flush()
        break
    else:
        print("Opción no válida")

socket_tls.close()
print("Sesión cerrada")