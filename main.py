from VehicleManager import VehicleManager


vehicle_manager = VehicleManager()
while 0 != 1:
    start = input("¿Qué desea hacer?: Registro = 0|Inicio de sesión = 1: "      )
    if int(start) == 0:
        usuario = input("Nombre usuario: ")
        contraseña = input("Contraseña: ")
        vehicle_manager.register_user(usuario, contraseña)
    elif int(start) == 1:
        usuario = input("Nombre usuario: ")
        contraseña = input("Contraseña: ")
        sesion_iniciada = vehicle_manager.authenticate_user(usuario, contraseña)
        while sesion_iniciada:
            acción = input("¿Qué desea hacer?: Añadir vahículo = 0|Ver "
                           "vehículos = 1|Compartir Coche = 2|Ver mensajes = "
                           "3|Cierre "
                           "de "
                          "sesión = 4: " )
            if int(acción) == 0:
                matricula = input("Mátricula: ")
                informacion = input("Información del coche: ")
                vehicle_manager.add_vehicle(matricula, informacion)
            elif int(acción) == 1:
                matriculas_vehiculos, datos_vehiculos = vehicle_manager.get_user_vehicles()
                if matriculas_vehiculos == []:
                    print("No tiene vehiculos registrados")
                else:
                    for i in range(len(matriculas_vehiculos)):
                        print("Matriculas: " + matriculas_vehiculos[i])
                        print("Datos: " + datos_vehiculos[i])
            elif int(acción) == 2:
                nombre = input("Nombre Persona a compartir vehiculo: ")
                matricula = input("Matricula del vehiculo a compartir: ")
                vehicle_manager.enviar_mensaje(nombre, matricula)
            elif int(acción) == 3:
                vehicle_manager.ver_mensajes()
            elif int(acción) == 4:
                vehicle_manager.current_user = None
                vehicle_manager.current_private_key = None
                sesion_iniciada = False


