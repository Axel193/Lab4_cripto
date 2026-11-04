
from pathlib import Path
from contextlib import redirect_stdout
from getpass import getpass
import io

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from RSA_Capture import detectar_rsa

# Rutas
BASE = Path(__file__).resolve().parent.parent

RUTA_RSA = BASE / "capturas y llaves" / "clave_privada.pem"
RUTA_AES = BASE / "capturas y llaves" / "clave_aes.bin"


def recuperar_claves():

    # 1. Localizar paquete RSA-PIN
    with redirect_stdout(io.StringIO()):
        paquetes = detectar_rsa()

    if not paquetes:
        print("ERROR: No se encontro RSA-PIN.")
        return

    primero = paquetes[0]
    datos = primero["datos"]

    inicio = primero["posicion"] + len(primero["etiqueta"])

    # Omitir el separador | (7C)
    if datos[inicio:inicio + 1] == b"|":
        inicio += 1

    # 2. Extraer salt
    salt = datos[inicio:inicio + 16]

    # 3. Cargar clave privada RSA
    contenido = RUTA_RSA.read_bytes()

    try:
        clave_privada = serialization.load_pem_private_key(
            contenido,
            password=None
        )
    except TypeError:
        password = getpass("Contrasena RSA: ")
        clave_privada = serialization.load_pem_private_key(
            contenido,
            password=password.encode()
        )

    # 4. Extraer PIN cifrado
    longitud_rsa = (clave_privada.key_size + 7) // 8

    pin_cifrado = datos[
        inicio + 16:
        inicio + 16 + longitud_rsa
    ]

    if len(salt) != 16 or len(pin_cifrado) != longitud_rsa:
        print("ERROR: Campos RSA incompletos.")
        return

    # 5. Descifrar PIN mediante RSA-OAEP
    pin = clave_privada.decrypt(
        pin_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if len(pin) != 4 or not pin.isdigit():
        print("ERROR: PIN recuperado no valido.")
        return

    # 6. Derivar clave AES-256 mediante Scrypt
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    clave_aes = kdf.derive(pin)

    # Guardar clave para el descifrado AES-GCM
    RUTA_AES.write_bytes(clave_aes)

    # 7. Mostrar solamente resultados finales
    print("\n========== RESULTADOS FINALES ==========")

    print(f"Paquete RSA-PIN: {primero['numero']}")
    print(f"Paquetes encontrados: {len(paquetes)}")
    print(f"Salt (16 bytes): {salt.hex(' ')}")

    print("\n--- DESCIFRADO RSA-OAEP ---")
    print(f"PIN recuperado: {pin.decode('ascii')}")

    print("\n--- DERIVACION AES-256 ---")
    print("Algoritmo: Scrypt")
    print("Parametros: N=16384, r=8, p=1")
    print(f"Longitud AES: {len(clave_aes) * 8} bits")
    print(f"Clave guardada: {RUTA_AES.name}")

    print("\nEstado: PROCESO COMPLETADO")
    print("========================================")


if __name__ == "__main__":
    try:
        recuperar_claves()
    except (ValueError, TypeError, OSError) as error:
        print(f"ERROR: {error}")
