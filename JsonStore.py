import json
import os

class JsonStore():

    def __init__(self, archivo):
        self.elementos = []
        self.archivo = os.path.join(os.path.dirname(__file__), "") + archivo
        self.cargar_datos()

    def guardar_datos(self):
        try:
            with open(self.archivo, "w", encoding="utf-8", newline="") as file:
                json.dump(self.elementos, file, indent=2)
        except:
            print("Error al guardar los datos")


    def cargar_datos(self):
        try:
            with open(self.archivo, "r", encoding="utf-8",
                      newline="") as file_opened:
                self.elementos = json.load(file_opened)
        except FileNotFoundError:
            self.elementos = []
        except:
            print("Error al cargar los datos")

    def sumar_elemento(self, item):
        self.cargar_datos()
        self.elementos.append(item)
        self.guardar_datos()
