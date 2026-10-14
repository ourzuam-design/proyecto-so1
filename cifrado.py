import hashlib
import hmac
import os

ENCABEZADO_MAGICO = b"SO1ENC_V1"
ITERACIONES_KDF = 100000


def derivar_claves(clave_texto, sal):
    material_claves = hashlib.pbkdf2_hmac(
        "sha256",
        clave_texto.encode("utf-8"),
        sal,
        ITERACIONES_KDF,
        dklen=64
    )
    clave_cifrado = material_claves[:32]
    clave_autenticacion = material_claves[32:]
    return clave_cifrado, clave_autenticacion


def cifrar_datos(datos_claros, clave_texto):
    sal = os.urandom(16)
    vector_iv = os.urandom(16)
    clave_cifrado, clave_autenticacion = derivar_claves(clave_texto, sal)

    longitud = len(datos_claros)
    resultado = bytearray(longitud)
    numero_bloque = 0

    for indice in range(0, longitud, 32):
        contador = numero_bloque.to_bytes(8, "big")
        flujo_clave = hmac.new(
            clave_cifrado,
            vector_iv + contador,
            hashlib.sha256
        ).digest()
        limite = min(indice + 32, longitud)
        for offset in range(indice, limite):
            resultado[offset] = datos_claros[offset] ^ flujo_clave[offset - indice]
        numero_bloque += 1

    cuerpo_cifrado = bytes(resultado)
    etiqueta_hmac = hmac.new(
        clave_autenticacion,
        ENCABEZADO_MAGICO + sal + vector_iv + cuerpo_cifrado,
        hashlib.sha256
    ).digest()

    return ENCABEZADO_MAGICO + sal + vector_iv + etiqueta_hmac + cuerpo_cifrado


def descifrar_datos(paquete_cifrado, clave_texto):
    longitud_magico = len(ENCABEZADO_MAGICO)
    tamano_minimo = longitud_magico + 16 + 16 + 32

    if len(paquete_cifrado) < tamano_minimo:
        raise ValueError("El paquete cifrado está corrupto o incompleto")

    magico = paquete_cifrado[:longitud_magico]
    if magico != ENCABEZADO_MAGICO:
        raise ValueError("Formato de cifrado no reconocido")

    sal = paquete_cifrado[longitud_magico:longitud_magico + 16]
    vector_iv = paquete_cifrado[longitud_magico + 16:longitud_magico + 32]
    etiqueta_guardada = paquete_cifrado[longitud_magico + 32:longitud_magico + 64]
    cuerpo_cifrado = paquete_cifrado[longitud_magico + 64:]

    clave_cifrado, clave_autenticacion = derivar_claves(clave_texto, sal)

    etiqueta_calculada = hmac.new(
        clave_autenticacion,
        ENCABEZADO_MAGICO + sal + vector_iv + cuerpo_cifrado,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(etiqueta_calculada, etiqueta_guardada):
        raise ValueError("Contraseña incorrecta o los datos fueron alterados")

    longitud = len(cuerpo_cifrado)
    resultado = bytearray(longitud)
    numero_bloque = 0

    for indice in range(0, longitud, 32):
        contador = numero_bloque.to_bytes(8, "big")
        flujo_clave = hmac.new(
            clave_cifrado,
            vector_iv + contador,
            hashlib.sha256
        ).digest()
        limite = min(indice + 32, longitud)
        for offset in range(indice, limite):
            resultado[offset] = cuerpo_cifrado[offset] ^ flujo_clave[offset - indice]
        numero_bloque += 1

    return bytes(resultado)


def calcular_hash_sha256(datos_bytes):
    return hashlib.sha256(datos_bytes).hexdigest()
