import sqlite3
import hashlib
import os

def hash_clave(clave, sal):
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, 100000).hex()

con = sqlite3.connect("sistema.db")
cur = con.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT UNIQUE NOT NULL,
    sal BLOB NOT NULL,
    clave_hash TEXT NOT NULL,
    rol TEXT NOT NULL DEFAULT 'usuario')""")

cur.execute("""CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT DEFAULT CURRENT_TIMESTAMP,
    usuario TEXT,
    accion TEXT,
    detalle TEXT)""")

sal = os.urandom(16)
try:
    cur.execute(
        "INSERT INTO usuarios (nombre, sal, clave_hash, rol) VALUES (?, ?, ?, ?)",
        ("admin", sal, hash_clave("admin123", sal), "admin"))
    print("Usuario admin creado (clave: admin123)")
except sqlite3.IntegrityError:
    print("El usuario admin ya existe")

con.commit()
con.close()