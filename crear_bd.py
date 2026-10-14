import sqlite3
import hashlib
import os

def hash_clave(clave, sal):
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, 100000).hex()

conexion = sqlite3.connect("sistema.db")
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

sal_aleatoria = os.urandom(16)
try:
    cursor.execute(
        "INSERT INTO usuarios (nombre, sal, clave_hash, rol) VALUES (?, ?, ?, ?)",
        ("admin", sal_aleatoria, hash_clave("admin123", sal_aleatoria), "admin"))
    print("Usuario admin creado (clave: admin123)")
except sqlite3.IntegrityError:
    print("El usuario admin ya existe")

conexion.commit()
conexion.close()