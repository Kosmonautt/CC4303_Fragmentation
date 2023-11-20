# función que transforma un número en a su versión en string, con una cantidad a elegir de largo máximo
def to_set_size(num, size):
    # se transforma el número a string
    num_str = str(num)

    # si el largo del número en forma de string es mayor al de el size, entonces se lanza un error
    if(len(num_str)>size):
        raise Exception("Number does not fit in given size")
    
    # mientras el tamaño sea menor al size, se le agregan 0's al comienzo para rellenar
    while(len(num_str) < size):
        num_str = "0"+num_str

    # se retorna el número transformado
    return num_str

# función que un número en forma de string con número de dígitos fijo y lo tranforma a un int
def from_set_size(num):
    # solo se pasa a int
    return int(num)


# función que recibe un paquete y lo parsea, retornando cada componente en una estrucutra
def parse_packet(IP_packet):
    # el separador a usar
    separator = ","

    # se le hace decode
    IP_packet = IP_packet.decode()
    # se divide por comas
    IP_packet = IP_packet.split(separator)
    
    # se guarda la dirección IP (siempre es localhost, 127.0.0.1)
    ip = IP_packet[0]
    # se guarda el puerto 
    port = from_set_size(IP_packet[1])
    # se guarda el TTL 
    ttl = from_set_size(IP_packet[2])
    # se guarda el ID del mensaje
    id = from_set_size(IP_packet[3])
    # se guarda el offset
    offset = from_set_size(IP_packet[4])
    # se guarda el tamaño
    size = from_set_size(IP_packet[5])
    # se guarda la flag
    flag = from_set_size(IP_packet[6])
    # el mensaje (quizá en forma de lista, osea con más de un elemento)
    mssg_list = IP_packet[7:len(IP_packet)]

    # el mensaje en forma de string
    mssg = ""

    # se recontruye el mensaje (si es necesario)
    for slice in mssg_list:
        # se agrega al mensaje final
        mssg += slice
        # si es que es el útlimo, no se agrega una coma, si no es el último, entonces se agrega
        if(slice == mssg_list[len(mssg_list)-1]):
            pass
        else:
            mssg += ","

    # se retorna la estrcutura
    return [ip, port, ttl, id, offset, size, flag, mssg]

# función que recibe una estrcutra y la transforma en un mensaje
def create_packet(parsed_IP_packet):
    # el separador a usar
    separator = ","

    # se consigue la estrcutura para modificarla
    list_param = parsed_IP_packet

    # se actualizan las partes del mensaje para que sigan el formato correcto
    # puerto (4 dígitos)
    list_param[1] = to_set_size(list_param[1], 4)
    # ttl (3 dígitos)
    list_param[2] = to_set_size(list_param[2], 3)
    # ID (8 dígitos)
    list_param[3] = to_set_size(list_param[3], 8)
    # offset (8 dígitos)
    list_param[4] = to_set_size(list_param[4], 8)
    # tamaño (8 dígitos)
    list_param[5] = to_set_size(list_param[5], 8)
    # flag (1 dígito)
    list_param[6] = to_set_size(list_param[6], 1)

    # donde se guarda el mensaje final
    final_mssg = ""
    
    # se crea el mensaje final en el formato correcto
    for param in list_param:
        # se agrega al mensaje final
        final_mssg += param
        # si es que es el útlimo, no se agrega una coma, si no es el último, entonces se agrega
        if(param == list_param[len(list_param)-1]):
            pass
        else:
            final_mssg += ","    

    # se retorna el mensaje final
    return final_mssg

# # test de funcionalidad
# IP_packet_v1 = "127.0.0.1,8881,010,00223344,00345678,00000300,1,hola, cómo estás?".encode()
# parsed_IP_packet = parse_packet(IP_packet_v1)
# IP_packet_v2_str = create_packet(parsed_IP_packet)
# IP_packet_v2 = IP_packet_v2_str.encode()
# print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# función que recibe el nombre del archivo con la rutas, la dirección de destino y el objeto ForwardList,
# retorna el par con la dirección de hacia donde debe "saltar", si no encuntrea ninguno retorna none
def check_routes(r_lines, destination_address, forwardList):
    
    # se debe recivsar si la dirección de destino no está en la lista de Forward
    if(not (forwardList.in_forward_list(destination_address))):
        # si no está, se debe agregar a la lista un objeto

        # se crea el nuevo objeto
        new_forward = Forward(destination_address)
        # se le incializa su lista
        new_forward.innit_jump_list(r_lines)
        # se agrega a forward list
        forwardList.add_forward(new_forward)
        
    # se retorna la dirección de salto y el MTU
    return forwardList.get_nxt_jump(destination_address)

# función que recibe un paquete (en bytes) y un MTU y retorna una lista con 1 o más fragmentos de tamaño a lo más MTU
def fragment_IP_packet(IP_packet, MTU):
    # el paquete se pasa a estructura
    IP_packet_struct = parse_packet(IP_packet)

    # se consiguen los campos que siempre se mantienen constantes
    ip = IP_packet_struct[0]
    port = IP_packet_struct[1]
    ttl = IP_packet_struct[2]
    id = IP_packet_struct[3]

    # offset actual
    current_offset = IP_packet_struct[4]
    # flag del mensaje original
    flag = IP_packet_struct[6]
    # lista que guardará los fragmentos
    fragments = []

    # si es que el tamaño del packet es menor o igual a TTL, se retorna una lista de inmediato, si no, se debe dividir en trozos
    if(len(IP_packet)<=MTU):
        return [IP_packet]
    
    # tamaño de los headers
    headers_size = 48

    # se consigue el mensaje y se pasa a bytes
    mssg_section = (IP_packet_struct[7]).encode()
    # se consigue el largo del mensaje (en bytes)
    len_mssg_section = len(mssg_section)
    # cantidad de bytes del mensaje que han sido encapsuladas
    bytes_encapsuled = 0

    # se consigue el largo máximo en bytes que tendra cada sección de mensaje (en bytes)
    new_len_mssg_section = MTU-headers_size

    # ciclo while en el que se van creando los fragmentos
    while bytes_encapsuled < len_mssg_section:
        # nuevo mensaje parcial (en bytes)
        new_mssg = mssg_section[current_offset:new_len_mssg_section+bytes_encapsuled]
        # se calcula su tamaño
        new_mssg_size = len(new_mssg)
        # se pasa a string
        new_mssg = new_mssg.decode()
        # se aumenta el número de bytes que se han encapsulado
        bytes_encapsuled += new_mssg_size
        # se guarda el offset nuevo
        new_offset = current_offset
        # se aumenta el offset en la cantidad de bytes encapsulados
        current_offset += new_mssg_size

        # almacena la nueva flag
        new_flag = 1

        # se elige la flag, si es que se llegó al byte final del mensaje y la flag original era 0,
        #  entonces la nueva flag es 0, si no es 1
        if((flag == 0) and (bytes_encapsuled >= len_mssg_section)):
            new_flag = 0

        # se crea un nuevo fragmento
        fragment = create_packet([ip, port, ttl, id, new_offset, new_mssg_size, new_flag, new_mssg])

        # se añade a la lista
        fragments.append(fragment)

    # se retorna la lista con los fragmentos
    return fragments

packet_IP_test = "127.0.0.1,8885,010,00000347,00000000,00000005,0,hola!, soy yo el chupa".encode()

print(fragment_IP_packet(packet_IP_test, 50))


# clase que representa todas las posibles salidas del router para una dirección de destino específica, en el router actual
class Forward:
    def __init__(self, destination_address):
        self.destination_address = destination_address
        self.jumps = None
        self.i = None
        self.len = None

    # función que inicializa la lista con todas las posibles salidas
    def innit_jump_list(self, route_table):
        # la lista de saltos se inicializa como una lista vacía
        self.jumps = []

        # se obtienen la dirección IP y puerto de destino
        ip_destination = self.destination_address[0]
        port_destination = self.destination_address[1]

        # se lee cada linea de la tabla
        for line in route_table:
            # se divide la línea por componente
            line = line.split()
            
            # IP que reprsenta la red
            cidr = line[0]
            # rangos de los puertos
            inf_r = int(line[1])
            sup_r = int(line[2])

            # si se encuentra una línea que corresponde
            if((ip_destination == cidr) and ((inf_r <= port_destination) and (port_destination <= sup_r))):
                # se actualiza la lista con el par ip lista y el MTU
                self.jumps.append(((line[3], int(line[4])), int(line[5])))
        
        # se inicializa el índice
        self.i = 0
        # se guarda el largo de la lista
        self.len = len(self.jumps)

    # función que retorna el siguiente valor de la lista cíclica y actualiza el índice
    def get_nxt_jump(self):
        # si es que la lista es de tamaño 0 (vacía, osea no hay saltos) se retorna none
        if (self.len == 0):
            return None
        
        # se consigue el elemento de la lista
        nxt_jump = self.jumps[self.i]
        # se actualiza el índice
        self.i = (self.i+1)%self.len
        # se retorna el siguiente salto
        return nxt_jump

# clase que representa todas las listas de salidas de el router para cada dirección de destino
class ForwardList:
    def __init__(self, current_address):
        self.current_address = current_address
        self.forward_list = []

    # función que agrega un objeto Forward a la lista
    def add_forward(self, new_forward):
        self.forward_list.append(new_forward)

    # función que dice si es que se encuentra el objeto 
    # asociado a la dirección de destino dada
    def in_forward_list(self, destination_address):
        # dice si está o no en la lista
        in_list = False

        # para cada obejto en la lista
        for forward in self.forward_list:
            # si la dirección de destino es correcta
            if(forward.destination_address == destination_address):
                # está en la lista
                in_list = True
        
        return in_list

    # función que recibe una dirección de destino (ip y puerto)
    # y retorna el par (ip, puerto) que le corresponde del round 
    # robin (puede ser None)
    def get_nxt_jump(self, destination_address):
        # para cada obejto en la lista
        for forward in self.forward_list:
            # si la dirección de destino es correcta
            if(forward.destination_address == destination_address):
                # se consigue el siguiente salto (y actualiza su indice)
                nxt_jump = forward.get_nxt_jump()
                # se retorna el valor
                return nxt_jump