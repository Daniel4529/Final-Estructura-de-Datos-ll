Modo de trabajo de rsa (como implemetarlo)

def es_primo(n):
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

