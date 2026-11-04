
from pathlib import Path
from scapy.all import PcapReader, TCP, UDP, IP, IPv6

ARCHIVO = (
    Path(__file__).resolve().parent.parent
    / "capturas y llaves"
    / "transacciones_cifradas.pcap"
)

ETIQUETAS = [b"AESGCM", b"AES_GCM", b"AES-GCM"]


def mostrar_hexadecimal(datos):
    """Imprime los bytes completos en filas de 16."""

    print("\nOFFSET    HEXADECIMAL")
    print("-" * 66)

    for i in range(0, len(datos), 16):
        bloque = datos[i:i + 16]

        hexadecimal = " ".join(
            f"{byte:02X}" for byte in bloque
        )

        ascii_texto = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in bloque
        )

        print(
            f"{i:06X}    "
            f"{hexadecimal:<47}  {ascii_texto}"
        )


def detectar_aes():

    encontrados = []

    with PcapReader(str(ARCHIVO)) as captura:
        for numero, paquete in enumerate(captura, 1):

            if TCP in paquete:
                datos = bytes(paquete[TCP].payload)
                transporte = paquete[TCP]

            elif UDP in paquete:
                datos = bytes(paquete[UDP].payload)
                transporte = paquete[UDP]

            else:
                continue

            for etiqueta in ETIQUETAS:
                posicion = datos.find(etiqueta)

                if posicion != -1:
                    encontrados.append({
                        "numero": numero,
                        "paquete": paquete,
                        "datos": datos,
                        "etiqueta": etiqueta,
                        "posicion": posicion,
                        "transporte": transporte
                    })
                    break

    print("\n========== ANALISIS AES-GCM ==========")
    print(f"Paquetes encontrados: {len(encontrados)}")

    for resultado in encontrados:

        paquete = resultado["paquete"]
        datos = resultado["datos"]
        transporte = resultado["transporte"]

        numero = resultado["numero"]
        posicion = resultado["posicion"]
        etiqueta = resultado["etiqueta"]

        print(f"\n{'=' * 66}")
        print(f"PAQUETE NUMERO: {numero}")
        print(f"{'=' * 66}")

        if IP in paquete:
            print("IP origen:", paquete[IP].src)
            print("IP destino:", paquete[IP].dst)

        elif IPv6 in paquete:
            print("IP origen:", paquete[IPv6].src)
            print("IP destino:", paquete[IPv6].dst)

        print("Puerto origen:", transporte.sport)
        print("Puerto destino:", transporte.dport)
        print("Etiqueta:", etiqueta.decode())
        print("Posicion de etiqueta:", posicion)
        print("Longitud del payload:", len(datos), "bytes")
        print("Longitud del paquete:", len(bytes(paquete)), "bytes")

        # Datos posteriores a la etiqueta
        inicio = posicion + len(etiqueta)
        contenido = datos[inicio:]

        print("\n--- CAMPOS AES-GCM ---")

        if len(contenido) >= 28:

            nonce = contenido[:12]
            cifrado = contenido[12:-16]
            tag = contenido[-16:]

            print("Nonce candidato (12 bytes):")
            print(nonce.hex(" "))

            print("\nPosible texto cifrado:")
            mostrar_hexadecimal(cifrado)

            print("\nTag candidato (16 bytes):")
            print(tag.hex(" "))

            print("\nLongitud cifrado:", len(cifrado), "bytes")

        else:
            print("Datos insuficientes para extraer nonce y tag.")

        print("\n--- HEXADECIMAL COMPLETO DEL PAQUETE ---")
        mostrar_hexadecimal(bytes(paquete))

    print("\n========== RESUMEN ==========")
    print("AES-GCM encontrados:", len(encontrados))
    print("Numeros de paquete:",
          [p["numero"] for p in encontrados])

    return encontrados


if __name__ == "__main__":
    paquetes_aes = detectar_aes()
