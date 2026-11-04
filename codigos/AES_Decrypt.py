
from pathlib import Path
from contextlib import redirect_stdout
import os
import csv
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Reutilizar el detector de la actividad anterior
from AES_Capture import detectar_aes


# ==========================================
# CONFIGURACION
# ==========================================

BASE = Path(__file__).resolve().parent.parent

RUTA_AES = BASE / "capturas y llaves" / "clave_aes.bin"

RUTA_RESULTADOS = (
    BASE / "transacciones_recuperadas.csv"
)


# ==========================================
# 1. IDENTIFICAR PAQUETES AES-GCM
# ==========================================

def localizar_paquetes():

    # Ejecutar el detector sin imprimir
    # todos los hexadecimales
    with open(os.devnull, "w") as salida:
        with redirect_stdout(salida):
            paquetes = detectar_aes()

    print("\n========== RESPUESTA 1 ==========")
    print("IDENTIFICACION DE PAQUETES AES-GCM")
    print("Paquetes encontrados:", len(paquetes))

    print(
        "Numeros de paquete:",
        [p["numero"] for p in paquetes]
    )

    return paquetes


# ==========================================
# 2. EXTRAER NONCE Y DESCIFRAR AES-GCM
# ==========================================

def intentar_descifrar(paquete, aes):

    datos = paquete["datos"]
    etiqueta = paquete["etiqueta"]
    posicion = paquete["posicion"]

    inicio = posicion + len(etiqueta)
    contenido = datos[inicio:]

    # Probar la estructura directa y la que
    # contiene el separador "|" tras la etiqueta.
    candidatos = [contenido]

    if contenido.startswith(b"|"):
        candidatos.append(contenido[1:])

    for candidato in candidatos:

        # Nonce 12 + tag 16 + mensaje cifrado
        if len(candidato) < 29:
            continue

        nonce = candidato[:12]
        cifrado_con_tag = candidato[12:]

        try:
            mensaje = aes.decrypt(
                nonce,
                cifrado_con_tag,
                None
            )

            return {
                "nonce": nonce,
                "tag": cifrado_con_tag[-16:],
                "mensaje": mensaje
            }

        except InvalidTag:
            continue

    return None


# ==========================================
# 3. IDENTIFICAR CAMPOS DE TRANSACCION
# ==========================================

def extraer_campos(texto):

    campos = {}

    # Separar los campos del mensaje recuperado
    partes = re.split(r"[|\r\n;]", texto)

    for parte in partes:

        if "=" not in parte:
            continue

        clave, valor = parte.split("=", 1)
        clave = clave.strip().upper()
        valor = valor.strip()

        campos[clave] = valor

    return {
        "ID": campos.get("ID", ""),
        "Remitente": campos.get(
            "DE",
            campos.get("REMITENTE", "")
        ),
        "Destinatario": campos.get(
            "A",
            campos.get("DESTINATARIO", "")
        ),
        "Monto": campos.get("MONTO", "")
    }


# ==========================================
# 4. PROCESAR TODAS LAS TRANSACCIONES
# ==========================================

def recuperar_transacciones(paquetes):

    print("\n========== RESPUESTA 2 ==========")
    print("DESCIFRADO Y AUTENTICACION AES-GCM")

    if not RUTA_AES.is_file():
        raise FileNotFoundError(
            "No existe clave_aes.bin. "
            "Ejecute primero key_recuperate.py."
        )

    clave = RUTA_AES.read_bytes()

    if len(clave) != 32:
        raise ValueError(
            "La clave AES debe tener 32 bytes."
        )

    aes = AESGCM(clave)

    resultados = []
    errores = 0

    for paquete in paquetes:

        numero = paquete["numero"]

        resultado = intentar_descifrar(
            paquete,
            aes
        )

        if resultado is None:
            errores += 1
            print(
                f"\nPaquete {numero}: "
                "No se pudo autenticar/descifrar"
            )
            continue

        nonce = resultado["nonce"]
        tag = resultado["tag"]
        mensaje = resultado["mensaje"]

        try:
            texto = mensaje.decode("utf-8")
        except UnicodeDecodeError:
            errores += 1
            print(
                f"\nPaquete {numero}: "
                "Mensaje autenticado, pero no es UTF-8"
            )
            continue

        campos = extraer_campos(texto)

        print("\n--------------------------------")
        print("Paquete:", numero)
        print("Nonce:", nonce.hex(" "))
        print("Longitud nonce:", len(nonce), "bytes")
        print("Tag:", tag.hex(" "))
        print("Autenticacion: CORRECTA")

        print("\nMensaje original:")
        print(texto)

        print("\nCampos recuperados:")
        print("ID:", campos["ID"] or "No identificado")
        print(
            "Remitente:",
            campos["Remitente"] or "No identificado"
        )
        print(
            "Destinatario:",
            campos["Destinatario"] or "No identificado"
        )
        print("Monto:", campos["Monto"] or "No identificado")

        resultados.append({
            "Paquete": numero,
            "ID": campos["ID"],
            "Remitente": campos["Remitente"],
            "Destinatario": campos["Destinatario"],
            "Monto": campos["Monto"],
            "Mensaje original": texto,
            "Autenticacion": "Correcta"
        })

    return resultados, errores


# ==========================================
# 5. GUARDAR RESULTADOS
# ==========================================

def guardar_resultados(resultados):

    columnas = [
        "Paquete",
        "ID",
        "Remitente",
        "Destinatario",
        "Monto",
        "Mensaje original",
        "Autenticacion"
    ]

    with RUTA_RESULTADOS.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as archivo:

        escritor = csv.DictWriter(
            archivo,
            fieldnames=columnas
        )

        escritor.writeheader()
        escritor.writerows(resultados)


# ==========================================
# PROGRAMA PRINCIPAL
# ==========================================

def main():

    paquetes = localizar_paquetes()

    if not paquetes:
        print("No se encontraron paquetes AES-GCM.")
        return

    resultados, errores = recuperar_transacciones(
        paquetes
    )

    guardar_resultados(resultados)

    print("\n========== RESUMEN FINAL ==========")
    print("Paquetes detectados:", len(paquetes))
    print("Mensajes autenticados y recuperados:", len(resultados))
    print("Paquetes sin recuperar:", errores)
    print("Archivo:", RUTA_RESULTADOS.name)

    if resultados:
        print("Descifrado AES-GCM realizado.")
    else:
        print("No se recuperaron transacciones.")

    print("===================================")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, OSError) as error:
        print("ERROR:", error)
