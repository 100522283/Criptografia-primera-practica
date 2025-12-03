import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from JsonStore import JsonStore
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def encrypt_private_key(private_key, password):
    """Cifra clave la clave privada a partir de la contraseña, se serializa automaticamente"""
    encrypted_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    return encrypted_private


def decrypt_private_key(encrypted_private_key, password):
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

def hash_password(password, salt = None):
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
def verify_password(password, salt, stored_hash):
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

class AutoridadCertificados:
    def __init__(self):
        self.autoridad_storer = JsonStore("autoridad.json")
        self.salt = None
        self.hash = None
        self.private_key_encrypted = None
        self.certificado = None

        self.cargar_autoridad_existente()

    def create_authority(self):
        if self.certificado is not None:
            return False

        #contraseña de autoridad para encriptar clave
        contraseña_autoridad = str(1234)
        print("Usando contraseña de autoridad super secreta: 1234")
        salt, password_hash = hash_password(contraseña_autoridad)

        root_key =  rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        #Clave privada de Autoridad encriptada
        encrypted_private_key = encrypt_private_key(root_key, contraseña_autoridad)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coches.net"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Coches Root CA"),
        ])
        root_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            root_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        ).sign(root_key, hashes.SHA256()) #La autoridad autofirma su certificado


        pem = root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

        autoridad_user = {
                     "password_hash": base64.b64encode(password_hash).decode("utf-8"),
                     "salt": base64.b64encode(salt).decode("utf-8"),
                     "private_key_encrypted": base64.b64encode(encrypted_private_key).decode("utf-8"),
                     "certificado": pem,

        }
        self.autoridad_storer.sumar_elemento(autoridad_user)
        self.cargar_autoridad_existente()

        return True

    def cargar_autoridad_existente(self):
        """Revisa si el JsonStore tiene datos y carga la CA en memoria"""

        if len(self.autoridad_storer.elementos) > 0: # Miramos si ya existe una autoridad
            try:
                user = self.autoridad_storer.elementos[0]

                self.salt = base64.b64decode(user["salt"])
                self.password_hash = base64.b64decode(user["password_hash"])
                self.private_key_encrypted = base64.b64decode(user["private_key_encrypted"])

                # Cargar certificado desde PEM
                self.certificado = x509.load_pem_x509_certificate(
                    user["certificado"].encode('utf-8'),
                    default_backend()
                )
                print("Autoridad CA cargada correctamente.")
                return True
            except Exception as e:
                print("Error al procesar los datos del JSON ")
                return False
        else:
            print("No se encontró ninguna Autoridad guardada.")
            self.create_authority()
            return False

    def guardar_autoridad(self):
        """Serializa los datos actuales y los guarda en el JsonStore."""
        if not self.certificado:
            return False

        # Convertir certificado a PEM string
        pem_cert = self.certificado.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

        # Convertir bytes a base64 string para JSON
        autoridad_data = {
            "password_hash": base64.b64encode(self.password_hash).decode("utf-8"),
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "private_key_encrypted": base64.b64encode(self.private_key_encrypted).decode("utf-8"),
            "certificado": pem_cert,
        }

        self.autoridad_storer.elementos = []
        self.autoridad_storer.sumar_elemento(autoridad_data)
        self.autoridad_storer.guardar_datos()
        return True

    def firmar_certificado(self,csr):

        password = input("Contraseña de autoridad para firmar: ")
        salt = self.salt
        stored_hash = self.password_hash
        encrypted_private_key = self.private_key_encrypted
        certificado_autoridad = self.certificado

        if verify_password(password, salt, stored_hash):
            llave_privada = decrypt_private_key(encrypted_private_key, password)
            one_day = datetime.timedelta(1, 0, 0)
            certificado_firmado = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                certificado_autoridad.subject  # El Emisor es la CA
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.today() - one_day
            ).not_valid_after(
                # un mes de validez
                datetime.datetime.today() + (one_day * 30)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            ).sign(
                private_key=llave_privada,  #firmamos con la clave privada de la Autoridad
                algorithm=hashes.SHA256(),
            )
            print("Certificado firmado por autoridad")
            return certificado_firmado

        else:
            print("Contraseña incorrecta")
            return False

    def verificar_firma_certificado(self, crt):
        try:
            crt.verify_directly_issued_by(self.certificado)
            return True
        except ValueError as e:
            print("Fallo al verificar la firma")
            return False
        except Exception as e :
            print("La firma no es correcta")
            return False

    def salir(self):
        self.salt = None
        self.certificado = None
        self.private_key_encrypted = None
        self.certificado = None
        return True


