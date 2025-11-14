import hashlib
import random
import math
from collections import defaultdict, deque
import os

def hash_fnv1(texto: str) -> str:
    h = 2166136261
    for byte in texto.encode('utf-8'):  #hash FNV-1
        h = (h * 16777619) ^ byte
        h &= 0xFFFFFFFF  # 32 bits
    return f"{h:08x}"


class NodoHuffman:
    def __init__(self, char=None, freq=0, izq=None, der=None):
        self.char = char
        self.freq = freq   #huffman node
        self.izq = izq
        self.der = der
        
    
    def __lt__(self, otro):
        return self.freq < otro.freq

def construir_arbol_huffman(texto):
    if not texto:
        return None, {}
    
    frecuencia = defaultdict(int)
    for c in texto:
        frecuencia[c] += 1
    
    cola = [NodoHuffman(char=c, freq=f) for c, f in frecuencia.items()]
    import heapq
    heapq.heapify(cola)
    
    while len(cola) > 1:
        izq = heapq.heappop(cola)
        der = heapq.heappop(cola)
        padre = NodoHuffman(freq=izq.freq + der.freq, izq=izq, der=der)
        heapq.heappush(cola, padre)
    
    raiz = cola[0]
    
    
    codigos = {}
    def generar_codigos(nodo, codigo_actual=""):  # genraciónde codigo huffman
        if nodo is None:
            return
        if nodo.char is not None:
            codigos[nodo.char] = codigo_actual if codigo_actual else "0"
        generar_codigos(nodo.izq, codigo_actual + "0")
        generar_codigos(nodo.der, codigo_actual + "1")
    
    generar_codigos(raiz)
    return raiz, codigos

def comprimir_huffman(texto):
    if not texto:
        return "", {}
    
    _, codigos = construir_arbol_huffman(texto)
    comprimido_bin = "".join(codigos[c] for c in texto)
    
    # Convertir a bytes (agregando padding si es necesario)
    padding = 8 - len(comprimido_bin) % 8
    if padding == 8:
        padding = 0
    comprimido_bin += "0" * padding
    comprimido_bytes = bytearray()
    for i in range(0, len(comprimido_bin), 8):
        byte = comprimido_bin[i:i+8]
        comprimido_bytes.append(int(byte, 2))
    
    return comprimido_bytes.hex(), codigos, padding

def descomprimir_huffman(comprimido_hex, codigos, padding):
    if not comprimido_hex:
        return ""
    
    comprimido_bin = ""
    for h in bytes.fromhex(comprimido_hex):
        comprimido_bin += f"{h:08b}"
    
    comprimido_bin = comprimido_bin[:-padding] if padding > 0 else comprimido_bin
    
    # Invertir códigos
    char_por_codigo = {v: k for k, v in codigos.items()}
    
    texto = ""
    codigo_actual = ""
    for bit in comprimido_bin:
        codigo_actual += bit
        if codigo_actual in char_por_codigo:
            texto += char_por_codigo[codigo_actual]
            codigo_actual = ""
    
    return texto

def es_primo(n):  #cifrado y firma de Rsa
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generar_primo(tam=10):
    while True:
        p = random.randint(2**tam, 2**(tam+1))
        if es_primo(p):
            return p

def mcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generar_claves_rsa():
    print("Generando claves RSA (puede tomar unos segundos)...")
    p = generar_primo(12)
    q = generar_primo(12)
    while p == q:
        q = generar_primo(12)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    if mcd(e, phi) != 1:
        e = 3
    
    d = pow(e, -1, phi)  # Inverso modular
    
    clave_publica = (e, n)
    clave_privada = (d, n)
    
    print(f"Clave pública (e, n): ({e}, {n})")
    print(f"Clave privada (d, n): ({d}, {n})")
    return clave_publica, clave_privada

def firmar_rsa(hash_hex: str, clave_privada):
    d, n = clave_privada
    hash_int = int(hash_hex, 16)
    firma = pow(hash_int, d, n)
    return firma

def verificar_firma_rsa(hash_hex: str, firma: int, clave_publica):
    e, n = clave_publica
    hash_int = int(hash_hex, 16)
    hash_recuperado = pow(firma, e, n)
    return hash_recuperado == hash_int


def main():   # Menu principal
    os.system('cls')
    print("="*60)
    print("    SISTEMA DE MENSAJES SEGUROS - URL (Guatemala)")
    print("="*60)
    
    mensaje = ""
    hash_fnv = ""
    comprimido_hex = ""
    codigos_huffman = {}
    padding = 0
    firma = None
    clave_publica = None
    clave_privada = None
    
    while True:
        print("\n" + "-_-"*20)
        print("MENÚ PRINCIPAL")
        print("-"*50)
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (Huffman)")
        print("4. Firmar el hash con clave privada RSA")
        print("5. Simular envío (mensaje comprimido + firma + clave pública)")
        print("6. Descomprimir y verificar firma (receptor)")
        print("7. Mostrar si el mensaje es auténtico o alterado")
        print("8. Salir")
        print("-_-"*20)
        
        try:
            opc = int(input("Seleccione una opción (1-8): "))
        except:
            print("Error: Ingrese un número válido.")
            continue
        os.system('cls')
        
        if opc == 1:
            print("\n--- INGRESO DE MENSAJE ---")
            mensaje = input("Ingrese el mensaje de texto: ").strip()
            if mensaje:
                print(f"Mensaje guardado ({len(mensaje)} caracteres).")
                # Reiniciar variables dependientes
                hash_fnv = ""
                comprimido_hex = ""
                firma = None
            else:
                print("Error: El mensaje no puede estar vacío.")
        
        elif opc == 2:
            if not mensaje:
                print("Error: Primero debe ingresar un mensaje (opción 1).")
            else:
                print("\n--- CÁLCULO DE HASH FNV-1 ---")
                hash_fnv = hash_fnv1(mensaje)
                print(f"Hash FNV-1: {hash_fnv}")
                print(f"Tamaño original: {len(mensaje)} caracteres")
                print(f"Tamaño hash: 8 caracteres hexadecimales (32 bits)")
        
        elif opc == 3:
            if not mensaje:
                print("Error: Primero debe ingresar un mensaje.")
            else:
                print("\n--- COMPRESIÓN HUFFMAN ---")
                print(f"Tamaño original: {len(mensaje)} caracteres")
                comprimido_hex, codigos_huffman, padding = comprimir_huffman(mensaje)
                tam_comprimido = len(bytes.fromhex(comprimido_hex))
                print(f"Mensaje comprimido (hex): {comprimido_hex}")
                print(f"Tamaño comprimido: {tam_comprimido} bytes")
                print(f"Reducción: {100 * (1 - tam_comprimido / len(mensaje.encode('utf-8'))):.1f}% aprox.")
        
        elif opc == 4:
            if not hash_fnv:
                print("Error: Primero debe calcular el hash (opción 2).")
            elif clave_privada is None:
                print("\nGenerando par de claves RSA...")
                clave_publica, clave_privada = generar_claves_rsa()
                print("Claves generadas exitosamente.")
            
            print("\n--- FIRMA DIGITAL RSA ---")
            firma = firmar_rsa(hash_fnv, clave_privada)
            print(f"Firma digital generada: {firma}")
            print(f"Usando clave privada (d, n)")
        
        elif opc == 5:
            if not all([mensaje, hash_fnv, comprimido_hex, firma, clave_publica]):
                print("Error: Complete los pasos 1 → 2 → 3 → 4 primero.")
            else:
                print("\n" + "="*60)
                print("        SIMULACIÓN DE ENVÍO SEGURO")
                print("="*60)
                print(f"Mensaje original: {mensaje}")
                print(f"Hash FNV-1: {hash_fnv}")
                print(f"Mensaje comprimido (hex): {comprimido_hex}")
                print(f"Firma digital (RSA): {firma}")
                print(f"Clave pública (e, n): {clave_publica}")
                print("="*60)
                print("Datos listos para enviarse de forma segura.")
                print("La clave privada NUNCA se envía.")
                print("="*60)
                print ("Simulación de envío completada.")
        
        elif opc == 6:
            if not all([comprimido_hex, firma, clave_publica]):
                print("Error: No hay datos recibidos. Use la opción 5 primero.")
            else:
                print("\n--- RECEPTOR: DESCOMPRESIÓN Y VERIFICACIÓN ---")
                mensaje_recibido = descomprimir_huffman(comprimido_hex, codigos_huffman, padding)
                hash_recibido = hash_fnv1(mensaje_recibido)
                
                print(f"Mensaje descomprimido: {mensaje_recibido}")
                print(f"Hash recalculado (FNV-1): {hash_recibido}")
                
                es_valida = verificar_firma_rsa(hash_recibido, firma, clave_publica)
                if es_valida:
                    print("Firma digital válida.")
                else:
                    print("Firma digital NO válida.")
                    print()
        
        elif opc == 7:
            if not all([comprimido_hex, firma, clave_publica]):
                print("Error: No hay datos para verificar.")
            else:
                mensaje_recibido = descomprimir_huffman(comprimido_hex, codigos_huffman, padding)
                hash_recibido = hash_fnv1(mensaje_recibido)
                es_valida = verificar_firma_rsa(hash_recibido, firma, clave_publica)
                
                print("\n" + "="*50)
                if es_valida and mensaje_recibido == mensaje:
                    print("MENSAJE AUTÉNTICO Y NO MODIFICADO")
                else:
                    print("MENSAJE ALTERADO O FIRMA NO VÁLIDA")
                print("="*50)
        
        elif opc == 8:
            print("\nGracias por usar el sistema. ¡Adiós!")
            break
        
        else:
            print("Opción no válida.")
        
        input("\nPresione Enter para continuar...")
        os.system('cls')

main()

