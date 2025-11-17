from JsonStore import JsonStore
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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
        self.user_storer = JsonStore("users.json")
        self.vehicle_storer = JsonStore("vehicles.json")
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
        self.users = self.user_storer.elementos
        for user in self.users:
            if user["username"] == username:
                print("username already exists")
                return False  #El usuario ya existe


        # Generar hash apartir de la  contraseña
        salt, password_hash = self.hash_password(password)

        # Generar las claves privadas y publicas del usuario
        private_key, public_key = self.generate_key_pair()

        # Cifrar clave privada con la contraseña

        encrypted_private_key = self.encrypt_private_key(private_key, password) #falta por hacr

        # Serializar clave pública
        public_key_str = self.serialize_public_key(public_key)

        # crear y almacenar usuario

        json_user = {"username": username,
                     "password_hash": base64.b64encode(password_hash).decode("utf-8"),
                     "salt": base64.b64encode(salt).decode("utf-8"),
                     "public_key_str": public_key_str,
                     "private_key_encrypted": base64.b64encode(encrypted_private_key).decode("utf-8"),
                     "vehicles":[],
                     "symmetric_key":[]}

        self.user_storer.sumar_elemento(json_user)
        self.users = self.user_storer.elementos

        # tod o correcto
        return True

    def authenticate_user(self, username, password):
        # Buscar usuario
        user = None
        self.users = self.user_storer.elementos
        for u in self.users:
            if u["username"] == username:
                user = u
                break

        if not user:
            print("User not found")
            return False

        salt = base64.b64decode(user["salt"])
        stored_hash = base64.b64decode(user["password_hash"])
        encrypted_private_key = base64.b64decode(user["private_key_encrypted"])

        #verificamos si el usuario es el correcto a partir de la contraseña
        if self.verify_password(password, salt, stored_hash):

            # Desifrar clave privada
            private_key = self.decrypt_private_key(encrypted_private_key, password)
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
        for vehicle in self.vehicle_storer.elementos:
            if vehicle["license"] == license_plate:
                print("El vehiculo ya ha sido registrado por otra persona")
                return False
        # Generar clave simétrica aleatoria para este vehículo
        symmetric_key = self.generate_symmetric_key()

        # Cifrar datos de coche con clave simétrica, los primeros 16 bytes son el texto generado para el nonce
        encrypted_vehicle_data = self.encrypt_symmetric(vehicle_data, symmetric_key)

        # Obtener clave pública del usuario
        public_key = self.deserialize_public_key(self.current_user[
                                                     "public_key_str"])

        # Cifrar la clave simétrica con la clave publica de nuestro usuario
        encrypted_symmetric_key = self.encrypt_asymmetric(symmetric_key, public_key)

        json_vehicle = {"license": license_plate,
                     "data": base64.b64encode(encrypted_vehicle_data).decode("utf-8")}

        self.vehicle_storer.sumar_elemento(json_vehicle)

        for n in self.user_storer.elementos:
            if n["username"] == self.current_user["username"]:
                n["vehicles"].append(license_plate)
                n["symmetric_key"].append(base64.b64encode(encrypted_symmetric_key).decode("utf-8"))

        self.user_storer.guardar_datos()

        return True

    def get_user_vehicles(self):
        """Obtiene los vehículos del usuario actual"""
        if not self.current_user or not self.current_private_key:
            return []

        vehicles = self.vehicle_storer.elementos
        vehicles_license_plates = []
        vehicles_data = []
        i = 0

        for vehicle in vehicles:
                # Miramos que vehiculos tiene cada usuario
                matricula = vehicle["license"]
                if matricula in self.current_user["vehicles"]:
                    encrypted_symmetric_key = base64.b64decode(self.current_user["symmetric_key"][i])
                    encrypted_vehicle_data = base64.b64decode(vehicle["data"])

                    # Descifrar claves simétrica con clave privada del usuario
                    symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key, self.current_private_key)

                    # Descifrar los datos con la clave simetrica ya descifrada
                    vehicle_data = self.decrypt_symmetric(encrypted_vehicle_data, symmetric_key)

                    vehicles_license_plates.append(matricula)
                    vehicles_data.append(vehicle_data)
                    i += 1

        return vehicles_license_plates, vehicles_data


    def generate_symmetric_key(self):
        """Genera clave simétrica para el ChaCha20 de 256 bits/ 32 Bytes"""
        key = os.urandom(32)
        return key

    def encrypt_symmetric(self, data, key):
        """Cifrado simétrico con ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # 96 bits
        ciphertext = chacha.encrypt(nonce, data.encode(), None)
        print("\nCifrado el dato con ChaCha-Poly1305: " + str(data) + " \nLongitud de clave " + str(len(key)) +"\nResultando en el texto cifrado: " + str(nonce)+str(ciphertext))
        # Guardamos nonce primeros 12 bytes + ciphertext el resto
        return nonce + ciphertext

    def decrypt_symmetric(self, encrypted_data, key):
        """Descifrado simétrico con ChaCha20-Poly1305"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

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
        print("\nCifrado el dato usando RSA: " + str(data) + "\nLongitud de clave: 2048" + "\nResultando en el texto cifrado: " + str(ciphertext))

        return ciphertext


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

    def access_vehicle_symmetric(self, matricula):
        """Funcion para acceder a la clave simetrica de un vehiculo exacto del usuario actual"""

        vehicles = self.vehicle_storer.elementos
        if matricula not in self.current_user["vehicles"]:
            print("Este vehiculo no esta registrado a su nombre")
            return False # No existe la matricula en este usuario

        for vehicle in vehicles:
            if vehicle["license"] == matricula:
                i = self.current_user["vehicles"].index(matricula)
                encrypted_symmetric_key = base64.b64decode(self.current_user["symmetric_key"][i])

                # Descifrar claves simétrica con clave privada del usuario
                symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key, self.current_private_key)

                return symmetric_key


        return True

    def add_vehicle_to_user(self, license_plate, symmetric_key, user):
        """Funcion para añadir la clave simetrica de un vehiculo a un usuario"""
        if license_plate in user["vehicles"]:
            print("User already haves this vehicle")
            return False
        # Obtener clave pública del usuario a compartir
        public_key = self.deserialize_public_key(user["public_key_str"])

        # Cifrar la clave simétrica con la clave publica de usuario a compartir
        encrypted_symmetric_key = self.encrypt_asymmetric(symmetric_key, public_key)

        for n in self.user_storer.elementos:
            if n["username"] == user["username"]:
                n["vehicles"].append(license_plate)
                n["symmetric_key"].append(base64.b64encode(encrypted_symmetric_key).decode("utf-8"))

        self.user_storer.guardar_datos()

        return True

    def share_vehicle(self,name ,matricula):
        """Funcion para compartir un vehiculo a otro usuario"""
        if not self.current_user or not self.current_private_key:
            print("Este usuario no esta registrado en la base de datos")
            return False

        users = self.user_storer.elementos
        found = False
        for user in users:
            if user["username"] == name:
                found = True
                symmetric_key = self.access_vehicle_symmetric(matricula)
                if symmetric_key != False:
                    self.add_vehicle_to_user(matricula, symmetric_key, user)
        if not found:
            print("No existe usuario para compartir los datos")
            return False

        return True


