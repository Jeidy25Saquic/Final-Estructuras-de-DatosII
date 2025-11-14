import heapq
import struct
from collections import Counter, defaultdict



class FNV1Hash:
    def __init__(self, bits=32):
        if bits == 32:
            self.FNV_prime = 16777619
            self.FNV_offset_basis = 2166136261
            self.mask = 0xFFFFFFFF
        elif bits == 64:
            self.FNV_prime = 1099511628211
            self.FNV_offset_basis = 14695981039346656037
            self.mask = 0xFFFFFFFFFFFFFFFF
        else:
            raise ValueError("FNV-1 solo soporta 32 o 64 bits")

    def hash(self, data):
        # Calcular hash FNV-1 del mensaje
        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_value = self.FNV_offset_basis

        for byte in data:
            hash_value = (hash_value * self.FNV_prime) & self.mask
            hash_value = hash_value ^ byte

        return hash_value

    def hash_hex(self, data):
        # Retornar hash en formato hexadecimal
        return format(self.hash(data), 'x')



class HuffmanCompressor:
    class NodoHuffman:
        def __init__(self, simbolo=None, frecuencia=0):
            self.simbolo = simbolo
            self.frecuencia = frecuencia
            self.izquierda = None
            self.derecha = None

        def __lt__(self, otro):
            return self.frecuencia < otro.frecuencia

    def __init__(self):
        self.codigos = {}
        self.arbol_raiz = None

    def construir_arbol(self, texto):
        # Paso 1: Contar frecuencias de caracteres
        if not texto:
            return None

        frecuencias = Counter(texto)

        # Crear nodos iniciales
        heap = []
        for simbolo, freq in frecuencias.items():
            nodo = self.NodoHuffman(simbolo, freq)
            heapq.heappush(heap, nodo)

        # Construir arbol Huffman
        while len(heap) > 1:
            nodo1 = heapq.heappop(heap)
            nodo2 = heapq.heappop(heap)

            nodo_padre = self.NodoHuffman(None, nodo1.frecuencia + nodo2.frecuencia)
            nodo_padre.izquierda = nodo1
            nodo_padre.derecha = nodo2

            heapq.heappush(heap, nodo_padre)

        self.arbol_raiz = heap[0] if heap else None
        return self.arbol_raiz

    def generar_codigos(self, nodo=None, codigo_actual=""):
        # Generar codigos Huffman recursivamente
        if nodo is None:
            nodo = self.arbol_raiz
            self.codigos = {}

        if nodo.simbolo is not None:
            self.codigos[nodo.simbolo] = codigo_actual
        else:
            if nodo.izquierda:
                self.generar_codigos(nodo.izquierda, codigo_actual + "0")
            if nodo.derecha:
                self.generar_codigos(nodo.derecha, codigo_actual + "1")

        return self.codigos

    def comprimir(self, texto):
        # Comprimir texto usando Huffman
        if not texto:
            return b"", {}

        self.construir_arbol(texto)
        self.generar_codigos()

        # Convertir texto a bits
        bits = ""
        for caracter in texto:
            bits += self.codigos[caracter]

        # Convertir bits a bytes
        padding = 8 - (len(bits) % 8)
        if padding == 8:
            padding = 0
        bits += "0" * padding

        bytes_comprimidos = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            bytes_comprimidos.append(int(byte, 2))


        bytes_finales = bytearray([padding]) + bytes_comprimidos

        return bytes(bytes_finales), self.codigos.copy()

    def descomprimir(self, datos_comprimidos, codigos_huffman):
        # Descomprimir datos usando codigos Huffman
        if not datos_comprimidos or not codigos_huffman:
            return ""

        # Extraer padding del primer byte
        padding = datos_comprimidos[0]
        datos_bits = datos_comprimidos[1:]

        # Convertir bytes a bits
        bits = ""
        for byte in datos_bits:
            bits += format(byte, '08b')

        # Remover padding
        if padding > 0:
            bits = bits[:-padding]

        # Reconstruir diccionario inverso
        codigos_inversos = {v: k for k, v in codigos_huffman.items()}

        # Decodificar bits
        texto_reconstruido = ""
        codigo_actual = ""

        for bit in bits:
            codigo_actual += bit
            if codigo_actual in codigos_inversos:
                texto_reconstruido += codigos_inversos[codigo_actual]
                codigo_actual = ""

        return texto_reconstruido



class RSA:
    def __init__(self):
        self.clave_publica = None
        self.clave_privada = None
        self.n = None

    def calcular_mcd(self, a, b):
        # Calcular maximo comun divisor
        while b != 0:
            a, b = b, a % b
        return a

    def son_coprimos(self, a, b):
        # Verificar si dos numeros son coprimos
        return self.calcular_mcd(a, b) == 1

    def funcion_totiente_euler(self, p, q):
        # Calcular funcion totiente de Euler
        return (p - 1) * (q - 1)

    def generar_claves(self, p=61, q=53):
        # Generar par de claves RSA
        self.n = p * q
        phi_n = self.funcion_totiente_euler(p, q)

        # Encontrar e (clave publica)
        e = 17  # Valor comun para e
        while not self.son_coprimos(e, phi_n):
            e += 2

        # Encontrar d (clave privada)
        d = self.modular_inverse(e, phi_n)

        self.clave_publica = (e, self.n)
        self.clave_privada = (d, self.n)

        return self.clave_publica, self.clave_privada

    def modular_inverse(self, e, phi):
        # Calcular inverso modular usando algoritmo extendido de Euclides
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, x, _ = extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("No existe inverso modular")
        return x % phi

    def firmar_hash(self, hash_value):
        # Firmar hash con clave privada
        if not self.clave_privada:
            raise ValueError("Clave privada no generada")

        d, n = self.clave_privada
        # Convertir hash a numero para firmar
        if isinstance(hash_value, str):
            hash_num = int(hash_value, 16)
        else:
            hash_num = hash_value

        firma = pow(hash_num, d, n)
        return firma

    def verificar_firma(self, hash_value, firma):
        # Verificar firma con clave publica
        if not self.clave_publica:
            raise ValueError("Clave publica no disponible")

        e, n = self.clave_publica
        # Convertir hash a numero para verificar
        if isinstance(hash_value, str):
            hash_num = int(hash_value, 16)
        else:
            hash_num = hash_value

        hash_verificado = pow(firma, e, n)
        return hash_num == hash_verificado


# Clase principal del sistema
class SistemaMensajesSeguros:
    def __init__(self):
        self.fnv = FNV1Hash()
        self.huffman = HuffmanCompressor()
        self.rsa = RSA()

        self.mensaje_original = ""
        self.hash_mensaje = None
        self.mensaje_comprimido = None
        self.codigos_huffman = None
        self.firma_digital = None
        self.clave_publica = None

        self.mensaje_recibido = None
        self.firma_recibida = None
        self.clave_publica_recibida = None

    def mostrar_menu(self):
        # Mostrar menu principal
        print("\n" + "=" * 50)
        print("      SISTEMA DE MENSAJES SEGUROS")
        print("=" * 50)
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (Huffman)")
        print("4. Firmar el hash con la clave privada RSA")
        print("5. Simular envio (mensaje comprimido + firma + clave publica)")
        print("6. Descomprimir y verificar firma (clave publica)")
        print("7. Mostrar si el mensaje es autentico o alterado")
        print("8. Salir")
        print("=" * 50)

    def ingresar_mensaje(self):
        # Paso 1: Ingresar mensaje
        self.mensaje_original = input("Ingrese el mensaje: ")
        print(f"Mensaje ingresado: {self.mensaje_original}")
        print(f"Tamaño original: {len(self.mensaje_original)} caracteres")

    def calcular_hash(self):
        # Paso 2: Calcular hash FNV-1
        if not self.mensaje_original:
            print("Error: Primero ingrese un mensaje")
            return

        self.hash_mensaje = self.fnv.hash_hex(self.mensaje_original)
        print(f"Hash FNV-1 calculado: {self.hash_mensaje}")

    def comprimir_mensaje(self):
        # Paso 3: Comprimir mensaje con Huffman
        if not self.mensaje_original:
            print("Error: Primero ingrese un mensaje")
            return

        self.mensaje_comprimido, self.codigos_huffman = self.huffman.comprimir(self.mensaje_original)

        tamaño_original = len(self.mensaje_original)
        tamaño_comprimido = len(self.mensaje_comprimido)
        tasa_compresion = (1 - tamaño_comprimido / tamaño_original) * 100 if tamaño_original > 0 else 0

        print(f"Tamaño antes de compresión: {tamaño_original} caracteres")
        print(f"Tamaño después de compresión: {tamaño_comprimido} bytes")
        print(f"Tasa de compresión: {tasa_compresion:.2f}%")
        print(f"Códigos Huffman generados: {self.codigos_huffman}")

    def firmar_hash(self):
        # Paso 4: Firmar hash con RSA
        if not self.hash_mensaje:
            print("Error: Primero calcule el hash del mensaje")
            return

        # Generar claves RSA
        self.clave_publica, clave_privada = self.rsa.generar_claves()
        self.firma_digital = self.rsa.firmar_hash(self.hash_mensaje)

        print("Claves RSA generadas:")
        print(f"  Clave pública (e, n): {self.clave_publica}")
        print(f"  Clave privada (d, n): ({clave_privada[0]}, {clave_privada[1]})")
        print(f"Firma digital generada: {self.firma_digital}")

    def simular_envio(self):
        # Paso 5: Simular envio de datos
        if not self.mensaje_comprimido or not self.firma_digital or not self.clave_publica:
            print("Error: Faltan datos para simular el envio")
            return

        # Simular envio almacenando en variables
        self.mensaje_recibido = self.mensaje_comprimido
        self.firma_recibida = self.firma_digital
        self.clave_publica_recibida = self.clave_publica
        self.codigos_huffman_recibidos = self.codigos_huffman

        print("Envio simulado exitosamente:")
        print(f"  - Mensaje comprimido: {len(self.mensaje_recibido)} bytes")
        print(f"  - Firma digital: {self.firma_recibida}")
        print(f"  - Clave pública: {self.clave_publica_recibida}")
        print("  - Clave privada: NO TRANSMITIDA")

    def descomprimir_verificar(self):
        #  Descomprimir y verificar firma
        if not self.mensaje_recibido or not self.firma_recibida or not self.clave_publica_recibida:
            print("Error: No hay datos recibidos para verificar")
            return

        # Descomprimir mensaje
        mensaje_descomprimido = self.huffman.descomprimir(
            self.mensaje_recibido,
            self.codigos_huffman_recibidos
        )

        # Calcular hash del mensaje descomprimido
        hash_recibido = self.fnv.hash_hex(mensaje_descomprimido)

        # Verificar firma usando clave publica
        self.rsa.clave_publica = self.clave_publica_recibida
        firma_valida = self.rsa.verificar_firma(hash_recibido, self.firma_recibida)

        print(f"Mensaje descomprimido: {mensaje_descomprimido}")
        print(f"Hash calculado del mensaje recibido: {hash_recibido}")
        print(f"Firma verificada: {'VALIDA' if firma_valida else 'INVÁLIDA'}")

        self.verificacion_final = firma_valida
        self.mensaje_verificado = mensaje_descomprimido

    def mostrar_autenticidad(self):
        #  Mostrar resultado de autenticacion
        if not hasattr(self, 'verificacion_final'):
            print("Error: Primero realice la verificacion de firma")
            return

        if self.verificacion_final:
            print("=" * 50)
            print("✓ MENSAJE AUTÉNTICO Y NO MODIFICADO")
            print("=" * 50)
            print(f"Mensaje original: {self.mensaje_verificado}")
        else:
            print("=" * 50)
            print("✗ MENSAJE ALTERADO O FIRMA NO VALIDA")
            print("=" * 50)

    def ejecutar(self):

        while True:
            self.mostrar_menu()
            opcion = input("Seleccione una opcion: ")

            try:
                if opcion == "1":
                    self.ingresar_mensaje()
                elif opcion == "2":
                    self.calcular_hash()
                elif opcion == "3":
                    self.comprimir_mensaje()
                elif opcion == "4":
                    self.firmar_hash()
                elif opcion == "5":
                    self.simular_envio()
                elif opcion == "6":
                    self.descomprimir_verificar()
                elif opcion == "7":
                    self.mostrar_autenticidad()
                elif opcion == "8":
                    print("Saliendo del sistema...")
                    break
                else:
                    print("Opción no válida. Por favor seleccione 1-8.")
            except Exception as e:
                print(f"Error: {str(e)}")



if __name__ == "__main__":
    sistema = SistemaMensajesSeguros()
    sistema.ejecutar()