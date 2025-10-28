import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class User:
    def __init__(self, username, password_hash, salt, public_key, private_key_encrypted):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.public_key = public_key
        self.private_key_encrypted = private_key_encrypted
        self.vehicles = []

class Vehicle:
    def __init__(self, encrypted_license_plate, vehicle_data, symmetric_key):
        self.encrypted_license_plate = encrypted_license_plate
        self.encrypted_vehicle_data = vehicle_data
        self.encrypted_symmetric_key = symmetric_key



class VehicleManager:
    def __init__(self):
        self.users = []
        self.current_user = None
        self.current_private_key = None

    def hash_password(self, password, salt=None):
        """Genera hash de contraseña usando PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        password_hash = kdf.derive(password.encode())
        return salt, password_hash

    def verify_password(self, password, salt, stored_hash):
        """Verifica si una contraseña al convertirla al hash es igual al almacenaddo"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        try:
            kdf.verify(password.encode(), stored_hash)
            return True
        except Exception:
            return False

    def register_user(self, username, password):
        """Registra un nuevo usuario"""
        # Verificar si el usuario ya existe
        for user in self.users:
            if user.username == username:
                return False,  #El usuario ya existe


        # Generar hash apartir de la  contraseña
        salt, password_hash = self.hash_password(password)

        # Generar las claves privadas y publicas del usuario
        private_key, public_key = self.generate_key_pair()

        # Cifrar clave privada con la contraseña

        encrypted_private_key = self.encrypt_private_key(private_key, password) #falta por hacr

        # Serializar clave pública
        public_key_str = self.serialize_public_key(public_key)

        # crear y almacenar usuario
        new_user = User(username, password_hash, salt,
                        public_key_str, encrypted_private_key)
        self.users.append(new_user)

        # tod o correcto
        return True

    def authenticate_user(self, username, password):
        # Buscar usuario
        user = None
        for u in self.users:
            if u.username == username:
                user = u
                break

        if not user:
            print("Usuario no encontrado")
            return False

        salt = user.salt

        #verificamos si el usuario es el correcto a partir de la contraseña
        if self.verify_password(password, salt, user.password_hash):

            # Desifrar clave privada
            private_key = self.decrypt_private_key(user.private_key_encrypted, password)
            if private_key:
                #guardamos TEMPORALMENTE la clave privada para ser usada ahora
                self.current_user = user
                self.current_private_key = private_key
                return True
            else:
                print("No se ha pudo ddescifrar la clave privada")
        else:
            print("Contraseña incorrecta")

        return False


    def generate_key_pair(self):
        """Genera par de claves RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key):
        """Convierte a bytes la clave publica para poder ser usado en archivos json"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def deserialize_public_key(self, public_key_str):
        """Deserializa clave pública para poder ser usada en funciones del cryptohraphy()"""
        return serialization.load_pem_public_key(public_key_str.encode())

    def encrypt_private_key(self, private_key, password):
        """Cifra clave la clave privada a partir de la contraseña, se serializa automaticamente"""
        encrypted_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return encrypted_private

    def decrypt_private_key(self, encrypted_private_key, password):
        """Descifra la calve privada a partir de la contraseña """
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_private_key,
                password=password.encode()
            )
            return private_key
        except Exception as e:
            print("Error al descifrar clave privada")
            return None

    def add_vehicle(self, license_plate, vehicle_data):
        """Añade un vehículo para el usuario actual"""
        if not self.current_user or not self.current_private_key:
            return False # no hay usuario autenticado

        # Generar clave simétrica aleatoria para este vehículo
        symmetric_key = self.generate_symmetric_key()

        # Cifrar matrícula con clave simétrica, los primeros 16 bytes son el texto generado para el CBC
        encrypted_license = self.encrypt_symmetric(license_plate, symmetric_key)
        encrypted_vehicle_data = self.encrypt_symmetric(vehicle_data, symmetric_key)

        # Obtener clave pública del usuario
        public_key = self.deserialize_public_key(self.current_user.public_key)

        # Cifrar la clave simétrica con la clave publica de nuestro usuario
        encrypted_symmetric_key = self.encrypt_asymmetric(symmetric_key, public_key)

        # Crear y almacenar vehículo
        vehicle = Vehicle(encrypted_license, encrypted_vehicle_data, encrypted_symmetric_key)
        self.current_user.vehicles.append(vehicle)

        return True

    def get_user_vehicles(self):
        """Obtiene los vehículos del usuario actual"""
        if not self.current_user or not self.current_private_key:
            return []

        vehicles_license_plates = []
        vehicles_data = []

        for vehicle in self.current_user.vehicles:
            try:
                # Extraer claves cifradas
                encrypted_symmetric_key = vehicle.encrypted_symmetric_key

                # Descifrar claves simétrica con clave privada del usuario
                symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key, self.current_private_key)

                # Descifrar matrícula y datos con la clave simetrica ya descifrada
                license_plate = self.decrypt_symmetric(vehicle.encrypted_license_plate, symmetric_key)
                vehicle_data = self.decrypt_symmetric(vehicle.encrypted_vehicle_data, symmetric_key)
                vehicles_license_plates.append(license_plate)
                vehicles_data.append(vehicle_data)


            except Exception as e:
                print("Error procesando vehículos")
                continue

        return vehicles_license_plates, vehicles_data

    def encrypt_symmetric(self, data, key):
        """Cifrado simétrico con AES-256-CBC """

        iv = os.urandom(16) # vector de inicializacion para el CBC

        # Usamos el padder PKCS7 que añade bytes para llegar al tamalo de bloque requerido
        padder = padding.PKCS7(128).padder()

        #convertimos la string a bytes y la dividimos en bloques para cumplir con el tamaño del AES 256 -> 32 B
        padded_data = padder.update(data.encode()) + padder.finalize()

        #Hacemos el cifrado con la clave creada con AES y modo CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Devuelve IV y texto cifrado en bytes puros
        return iv + ciphertext

    def encrypt_asymmetric(self, data, public_key):
        """Cifrado asimétrico con RSA"""

        ciphertext = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    def generate_symmetric_key(self):
        """Genera clave simétrica AES (256 bits)"""
        key = os.urandom(32)
        return key

    def decrypt_asymmetric(self, encrypted_data, private_key):
        """Descifrado asimétrico con RSA"""

        ciphertext = encrypted_data
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def decrypt_symmetric(self, encrypted_data, key):
        """Descifrado simétrico con AES"""

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        #descifra el texto usando AES con CBC usando el mismo texto inicial usado para cifrarlo
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        #Quitamos el padding que se habia puesto a algunos bloques y vovlemos a juntar los bloques
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

