import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class User:
    def __init__(self, username, password_hash, salt, public_key, private_key_encrypted):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.public_key = public_key
        self.private_key_encrypted = private_key_encrypted
        self.vehicles = []


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
        print("Generando par de claves RSA-2048...")
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
