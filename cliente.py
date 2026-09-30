import socket
import ssl
import getpass

IP_SERVIDOR = "192.168.1.64"
PUERTO = 5000

usuario = input("Usuario: ")
clave = getpass.getpass("Contraseña: ")

contexto = ssl.create_default_context(cafile="servidor.crt")
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c_tls = contexto.wrap_socket(c, server_hostname=IP_SERVIDOR)
c_tls.connect((IP_SERVIDOR, PUERTO))

f = c_tls.makefile("rw", encoding="utf-8", newline="\n")
f.write(f"LOGIN {usuario} {clave}\n")
f.flush()

respuesta = f.readline().strip()
print(respuesta)
if not respuesta.startswith("OK"):
    c_tls.close()
    raise SystemExit

def enviar(comando):
    f.write(comando + "\n")
    f.flush()
    while True:
        linea = f.readline().rstrip("\n")
        if linea == "<<FIN>>" or linea == "":
            break
        print(linea)

while True:
    print("\n1) Info del sistema")
    print("2) Procesos")
    print("3) Crear usuario      (solo admin)")
    print("4) Listar usuarios    (solo admin)")
    print("5) Eliminar usuario   (solo admin)")
    print("6) Salir")
    opcion = input("Opción: ").strip()

    if opcion == "1":
        enviar("INFO")
    elif opcion == "2":
        enviar("PROCESOS")
    elif opcion == "3":
        nombre = input("Nombre del nuevo usuario: ").strip()
        clave_nueva = getpass.getpass("Contraseña del nuevo usuario: ")
        rol = input("Rol (admin/usuario) [usuario]: ").strip() or "usuario"
        if " " in nombre or " " in clave_nueva:
            print("El nombre y la contraseña no pueden tener espacios")
        else:
            enviar(f"CREARUSUARIO {nombre} {clave_nueva} {rol}")
    elif opcion == "4":
        enviar("LISTARUSUARIOS")
    elif opcion == "5":
        nombre = input("Usuario a eliminar: ").strip()
        enviar(f"ELIMINARUSUARIO {nombre}")
    elif opcion == "6":
        f.write("SALIR\n")
        f.flush()
        break
    else:
        print("Opción no válida")

c_tls.close()
print("Sesión cerrada")