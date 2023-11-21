import socket
import sys
import aux_functions

# HASTA "nos" funciona, después falla

# el mensaje a enviar
mssg = "na ne ni el coco no el coco nu ns te me subas al hola agrego vainas pero a "

for i in range(0,1):
    new_mssg = mssg+" "+str(i+1)
    # estructura
    struct = ["127.0.0.1", 8885, 10, i+1, 0, len(new_mssg.encode()), 0, new_mssg]
    # se pasa a mensaje
    full_mssg = aux_functions.create_packet(struct)
    # se pasa a bytes
    full_mssg = full_mssg.encode()

    print("TAMAÑO TOTAL EN BYTES DEL MENSAJE", len(full_mssg))

    # se crea el socket
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # se envía el mensaje al socket en el puerto 8001
    test_socket.sendto(full_mssg, ("127.0.0.1", 8881))
