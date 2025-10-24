class Usuario:
    def __init__(self, nombre, contraseña):
        self.nombre = nombre
        self.contraseña = contraseña
        self.salt = ?
    def generar_clave_privada(self):

        return str

class BaseDeDatos:
    """ Aqui guardamos todos los mesajes cifrados """
    def __init__(self):
        self.datos_cifrados: Json
        self.claves_privadas_cifradas:


    def obtener_clave_privada(self, contraseña):
        """Usamos la contraseña para obtener la clave privada del
        usuario para descifrar sus mensajes """


class Autentificacion_usuario:


class Cifrador_Bloques:
    """ AES usando una clave del admin?"""
    def __init__(self):

    def cifrar_bloque(self, mensaje, clave_secreta):
        """ se cifrara con una clave secreta"""

    def descifrar_bloque(self, mensaje, clave_secreta):

