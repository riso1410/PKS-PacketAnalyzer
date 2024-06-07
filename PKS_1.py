from scapy.all import *
import ruamel.yaml
from os.path import exists
from binascii import hexlify

# Dictionaries for protocols read from protocols.txt
LLC = {}
ETHERTYPE = {}
IPPROTOCOL = {}
ICMP = {}
TCP = {}
UDP = {}
PID = {}

# Classes for communication
class comm_TCP:
    def __init__(self, src_ip, dst_ip,src_port = None, dst_port = None):
        self.source = src_ip
        self.dest = dst_ip
        self.tcp_s_port = src_port
        self.tcp_d_port = dst_port
        self.packets = [] 
        self.start = None
        self.end = None
        self.order = []

class comm_UDP:
    def __init__(self, src_port, dst_port):
        self.order = []
        self.packets = []
        self.udp_s_port = src_port
        self.udp_d_port = dst_port
        self.done = None
        self.size = None

class comm_ICMP:
    def __init__(self, src_ip, dst_ip,icmp_id, icmp_seq,id):
        self.icmp_s_address = src_ip
        self.icmp_d_address = dst_ip
        self.order = []
        self.packets = []  
        self.type = []     
        self.icmp_id = icmp_id
        self.icmp_seq = icmp_seq
        self.done = None
        self.id = id
    
class comm_ARP:
    def __init__(self, src_ip, dst_ip):
        self.source_hw = None
        self.target_hw = None
        self.source_ip = src_ip
        self.dest_ip = dst_ip
        self.done = False
        self.order = []
        self.packets = []

# Arrays for packets with the protocols
class Arrays:
    def __init__(self):
        self.http_array = []
        self.https_array = []
        self.telnet_array = []
        self.ssh_array = []
        self.ftpc_array = []
        self.ftpd_array = []
        self.tftp_array = []
        self.icmp_array = []
        self.arp_array = []

# Text file load
def database_load():
    with open('protocols.txt', 'r') as file:
        content = file.read()

    lines = content.split('\n')

    current = None 

    for line in lines: # Reading protocols.txt and separating them into globals dictionaries
        if line == 'LLC:':
            current = LLC
        elif line == 'ETHERTYPE:':
            current = ETHERTYPE
        elif line == 'IPPROTOCOL:':
            current = IPPROTOCOL
        elif line == 'ICMP:':
            current = ICMP
        elif line == 'TCP:':
            current = TCP
        elif line == 'UDP:':
            current = UDP
        elif line == 'PID:':
            current = PID
        elif current is not None and ':' in line:
            parts = line.split(':')
            key = int(parts[0])
            value = parts[1]
            current[key] = value                

# MAC address
def MACaddress(packet):
    sourceMAC = ''
    destMAC = ''

    mac_array = [] # Array for source and destination MAC address 

    for x in range(6):
        destMAC += hexlify(packet[x:x + 1]).decode('utf-8') + ':'

    for x in range(6, 12):
        sourceMAC += hexlify(packet[x:x + 1]).decode('utf-8') + ':'
    
    sourceMAC = sourceMAC[:-1] 
    destMAC = destMAC[:-1] 
    mac_array.append(sourceMAC.upper())
    mac_array.append(destMAC.upper())

    return mac_array # Return array of 2 MAC addresses first source, second destination

# get IP address
def single_IPaddress(packet):
    IP_address = ""

    for i in range(0, 4): # IP address is 4 bytes long 
        IP_address = IP_address + str(int((hexlify(packet[i:i + 1]).decode('utf-8')), 16))
        if i != 3:
            IP_address = IP_address + '.'

    return IP_address # Return IP address converted from raw data to decimal

# Task 1-2 analyze frame
def frame_analyze(packet, number_of_packet, comm = None, counter = None ):
    
    packet_len = len(packet) # Length of packet
    new_packet = {'frame_number': number_of_packet,
                'len_frame_pcap': packet_len,
                'len_frame_medium': 64 if packet_len < 60 else packet_len + 4,
                }       

    # Ethernet II
    if 1500 <= int(hexlify(packet[12:14]).decode('utf-8'), 16):
        new_packet['frame_type'] = "ETHERNET II"

    # IEEE 802.3
    # RAW
    elif str(hexlify(packet[14:16]))[2: -1] == 'ffff':
        new_packet['frame_type'] = "IEEE 802.3 RAW"

    # LLC + SNAP
    elif str(hexlify(packet[14:16]))[2: -1] == 'aaaa':
        new_packet['frame_type'] = "IEEE 802.3 LLC & SNAP"  

        # PID
        if int(hexlify(packet[20:22]).decode('utf-8'), 16) in PID:
            new_packet['pid'] = PID[int(hexlify(packet[20:22]).decode("utf-8"), 16)]

    # LLC
    else:
        new_packet['frame_type'] = "IEEE 802.3 LLC"

        # SAP
        if int(hexlify(packet[14:15]).decode('utf-8'), 16) in LLC:
            new_packet['sap'] = LLC[int(hexlify(packet[14:15]).decode("utf-8"), 16)]

    # MAC address
    mac_array = MACaddress(packet)
    new_packet['src_mac'] = mac_array[0]
    new_packet['dst_mac'] = mac_array[1]

    # Header protocol
    if int(hexlify(packet[12:14]).decode('utf-8'), 16) in ETHERTYPE:
        new_packet['ether_type'] = ETHERTYPE[int(hexlify(packet[12:14]).decode("utf-8"), 16)]

        # IPv4
        if int(hexlify(packet[12:14]).decode('utf-8'), 16) == 2048:
            
            # Protocol 
            protocol = IPPROTOCOL[int(hexlify(packet[23:24]).decode('utf-8'), 16)]
            new_packet['protocol'] = protocol

            # IP address
            new_packet['src_ip'] = single_IPaddress(packet[26:30])
            new_packet['dst_ip'] = single_IPaddress(packet[30:34])

            # Application layer protocols
            if protocol in ['TCP','UDP']:

                # Ports
                s_port = int(hexlify(packet[34:36]).decode('utf-8'), 16)
                d_port = int(hexlify(packet[36:38]).decode('utf-8'), 16)
                new_packet['src_port'] = s_port
                new_packet['dst_port'] = d_port

                # Well known protocols on higher layers
                if new_packet['src_port'] in TCP:
                    new_packet['app_protocol'] = TCP[new_packet['src_port']]
                elif new_packet['dst_port'] in TCP:
                    new_packet['app_protocol'] = TCP[new_packet['dst_port']]

                elif new_packet['src_port'] in UDP:
                    new_packet['app_protocol'] = UDP[new_packet['src_port']]
                elif new_packet['dst_port'] in UDP:
                    new_packet['app_protocol'] = UDP[new_packet['dst_port']]


            # ICMP
            elif new_packet['protocol'] == 'ICMP':
                
                # ICMP output for fragments and regular ICMP comm
                if comm != None:
                    offset = int(str(hexlify(packet[14:15]))[3:-1], 16) * 4 + 14
                    flag_mf = hexlify(packet[20:21]).decode('utf-8')
                    flag_mf = bin(int(flag_mf, 16))[2:]
                    flag_mf = flag_mf[0]
                    f_offset = hexlify(packet[21:22]).decode('utf-8')
                    f_offset = bin(int(f_offset, 16))[2:]
                    f_offset = f_offset[0:]
                    
                    # Fragments 
                    if flag_mf == '1':
                        new_packet['id'] = int(hexlify(packet[18:20]).decode('utf-8'), 16)
                        new_packet['flags_mf'] = True if flag_mf == '1' else False
                        new_packet['frag_offset'] = int(f_offset, 2) * 8

                    # Non-fragmented packet
                    elif flag_mf == '0' and f_offset == '0':
                        new_packet['icmp_type'] = ICMP[int(hexlify(packet[offset:offset+1]).decode('utf-8'), 16)]
                        new_packet['icmp_id'] = comm.icmp_id
                        new_packet['icmp_seq'] = comm.icmp_seq
                    
                    # Last fragment
                    elif flag_mf == '0' and f_offset != '0':
                        new_packet['id'] = int(hexlify(packet[18:20]).decode('utf-8'), 16)
                        new_packet['flags_mf'] = True if flag_mf == '1' else False
                        new_packet['frag_offset'] = int(f_offset,2) * 8
                        new_packet['icmp_type'] = comm.type[counter]
                        new_packet['icmp_id'] = comm.icmp_id
                        new_packet['icmp_seq'] = comm.icmp_seq
                         
        # ARP
        elif int(hexlify(packet[12:14]).decode('utf-8'), 16) == 2054:
            if int(hexlify(packet[21:22]).decode('utf-8'), 16) == 1:
                opcode = 'REQUEST'
            elif int(hexlify(packet[21:22]).decode('utf-8'), 16) == 2:
                opcode = 'REPLY'

            new_packet['arp_opcode'] = opcode
            new_packet['src_ip'] = single_IPaddress(packet[28:32])
            new_packet['dst_ip'] = single_IPaddress(packet[38:42])

    # Unknown protocol -> skip the code above
    else:
        pass

    # Raw Packet 
    str_packet = ''
    length = 0
    for x in range(len(packet)):
        if length != 0 and length % 16 == 0:
            str_packet = str_packet[:-1]
            str_packet += '\n'
        length += 1
        str_packet += hexlify(packet[x:x + 1]).decode("utf-8") + ' ' # Raw data to hexa adding space

    str_packet = str_packet[:-1]
    str_packet += '\n'

    new_packet['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(str_packet) # Packet in hexa

    return new_packet
                 
#Filling arrays with packets 
def well_known_ports(packet,number_of_packet,arrays):

    port = int(hexlify(packet[12:14]).decode('utf-8'), 16) # Port number
    protocol = ''
    well_known = ''

    # IPv4
    if port == 2048:
        try:
            protocol = IPPROTOCOL[int(hexlify(packet[23:24]).decode('utf-8'), 16)] # Check if protocol is known
        except:
            pass

        offset = int(str(hexlify(packet[14:15]))[3: -1], 16) * 4 + 14 

        if protocol == 'TCP':
            source_port = int(hexlify(packet[offset:offset + 2]).decode('utf-8'), 16)
            destination_port = int(hexlify(packet[offset + 2:offset + 4]).decode('utf-8'), 16)
            well_known = TCP.get(source_port, TCP.get(destination_port, "")) # Check if port is well known in both ports

            try:
                if well_known in ["HTTP", "HTTPS", "TELNET", "SSH", "FTP-CONTROL", "FTP-DATA"]:
                    getattr(arrays, well_known.lower() + "_array").append([number_of_packet, packet]) # Add packet to array with same protocol
            except:
                pass

        elif protocol == 'UDP':
            arrays.tftp_array.append([number_of_packet, packet])
        elif protocol == 'ICMP':
            arrays.icmp_array.append([number_of_packet, packet])

    # ARP
    elif port == 2054:
        arrays.arp_array.append([number_of_packet, packet])

# TCP communication
def uloha_tcp(array,output):

    del output['complete_comms'] # For output reason

    comm_array = []

    for packet in array: # For each packet with TCP protocol

        offset = int(str(hexlify(packet[1][14:15]))[3:-1], 16) * 4 + 14
        src_ip = single_IPaddress(packet[1][26:30])
        dst_ip = single_IPaddress(packet[1][30:34])
        src_port = int(hexlify(packet[1][offset:offset + 2]).decode('utf-8'), 16)
        dst_port = int(hexlify(packet[1][offset + 2:offset + 4]).decode('utf-8'), 16)

        new_comm = comm_TCP(src_ip, dst_ip, src_port, dst_port) # Create new comm

        if len(comm_array) == 0: # If comm_array is empty add packet to new comm and add comm to comm_array
            new_comm.order.append(packet[0])
            new_comm.packets.append(packet[1])
            comm_array.append(new_comm)

        else:
            flag = False # Flag for checking if we need new comm
            for single_comm_tcp in comm_array:            
                 # Sort packets into existing communication based on IP, PORT
                if (single_comm_tcp.source == src_ip and single_comm_tcp.dest == dst_ip 
                    and single_comm_tcp.tcp_s_port == src_port and single_comm_tcp.tcp_d_port == dst_port or 
                    single_comm_tcp.source == dst_ip and single_comm_tcp.dest == src_ip and
                    single_comm_tcp.tcp_s_port == dst_port and single_comm_tcp.tcp_d_port == src_port):

                    flag = True # Flag we dont need new comm
                    single_comm_tcp.order.append(packet[0])
                    single_comm_tcp.packets.append(packet[1])

            if flag == False:
                new_comm.order.append(packet[0])
                new_comm.packets.append(packet[1])
                comm_array.append(new_comm)

    # Check if communication is estabilished
    for comm in comm_array: # For each comm in comm_array
        
        # Flags for estabilishing communication 2 possible ways
        order_packet = {}
        flag_syn = False
        flag_syn1 = False
        flag_syn2 = False
        flag_ack = False
        flag_ack1 = False
        flag_ack2 = False
        flag_syn_ack = False
        order_packet_data = zip(comm.order, comm.packets) # Creating pairs of order and packets
        for order,packet in order_packet_data: # For each packet in comm
            packet_src_ip = single_IPaddress(packet[26:30])
            packet_dst_ip = single_IPaddress(packet[30:34])
            offset = int(str(hexlify(packet[14:15]))[3:-1], 16) * 4 + 14
            flag = hexlify(packet[offset+13:offset+14]).decode('utf-8')
            flag = bin(int(flag, 16))
            flag = flag[2:] # Ignore 0b (first 2 characters of binary value)

            add_count = 5 - len(flag)
            # Checking binary value of flag 
            flag = '0' * add_count + flag

            if comm.start != True:
                # Checking 3-way handshake and 4-way handshake
                # 0 - ack | 1 -psh | 2 - rst | 3 - syn | 4 - fin
                if flag[3] == '1' and flag_syn != True and (comm.source == packet_src_ip and comm.dest == packet_dst_ip):
                    order_packet[order] = packet
                    flag_syn = True
                    flag_syn1 = True
                
                elif flag[0] == '1' and flag[3] == '1' and flag_syn == True and flag_syn_ack != True and (comm.source == packet_dst_ip and comm.dest == packet_src_ip):
                    order_packet[order] = packet
                    flag_syn_ack = True
                    
                elif flag[0] == '1' and flag[3] != '1' and (comm.source == packet_src_ip and comm.dest == packet_dst_ip):
                    order_packet[order] = packet
                    flag_ack = True
                
                elif flag[3] == '1'and flag_syn1 == True and flag_syn2 != True and (comm.source == packet_dst_ip and comm.dest == packet_src_ip):
                    order_packet[order] = packet
                    flag_syn2 = True

                elif flag[0] == '1' and flag_ack1 != True and flag_syn2 == True and flag_syn1 == True and (comm.source == packet_src_ip and comm.dest == packet_dst_ip):
                    order_packet[order] = packet
                    flag_ack1 = True

                elif flag[0] == '1' and flag_ack2 != True and flag_ack1 == True and flag_syn1 == True and flag_syn2 == True and (comm.source == packet_dst_ip and comm.dest == packet_src_ip):
                    order_packet[order] = packet
                    flag_ack2 = True

                if ((flag_syn == True and flag_ack == True and flag_syn_ack == True) or
                    (flag_syn == True and flag_ack == True and flag_syn2 == True and flag_ack2 == True)):
                    comm.start = True # Communication is estabilished if all flags are True for 3-way handshake or 4-way handshake

                    # Remove from comm.order and comm.packets all packets before the final which ended communication estabilishment
                    for comm_order in comm.order[:]:
                        comm.order.remove(comm_order)
                        comm.packets.remove(comm.packets[0])
                        if comm_order == order:
                            order_packet = dict(reversed(list(order_packet.items()))) # Reverse order of packets, we need to add higher packets first to maintain order
                            for order_dict, packet_dict in order_packet.items():
                                comm.order.insert(0,order_dict)
                                comm.packets.insert(0,packet_dict)
                            break
                    break

    # Check if communication is terminated
    for comm in comm_array: # For each comm in comm_array
        
        # Flags for terminating communication 2 possible ways + RST
        fin = False
        fin_ack = False
        ack_last = False
        rst = False
        ack1 = False
        fin_ack1 = False
        ack2 = False
        fin_ack2 = False
        fin_ack3 = False
        fin_ack4 = False
        ack3 = False
        ack4 = False

        order_packet_data = list(zip(comm.order, comm.packets))
        for order,packet in reversed(order_packet_data): # For each packet in comm, checking from last, termination expected at the end
            packet_src_ip = single_IPaddress(packet[26:30])
            packet_dst_ip = single_IPaddress(packet[30:34])
            offset = int(str(hexlify(packet[14:15]))[3:-1], 16) * 4 + 14
            flag = hexlify(packet[offset+13:offset+14]).decode('utf-8')
            flag = bin(int(flag, 16))
            flag = flag[2:]

            add_count = 5 - len(flag)
            # Checking binary value of flag 
            flag = '0' * add_count + flag

            # 0 - ack | 1 -psh | 2 - rst | 3 - syn | 4 - fin
            if comm.end != True:
                #RST
                if flag[2] == '1' and (comm.source == packet_src_ip and comm.dest == packet_dst_ip):
                    rst = True

                # Three-way termination FIN, FIN ACK, ACK and FIN ACK, FIN ACK, ACK, ACK 
                elif flag[0] == '1' and ack_last != True:
                    ack_last = True # Three-way ACK (last)
                    ack2 = True # Four-way ACK (last)
                    ack4 = True # Four-way ACK (last)
                
                elif flag[0] == '1' and flag[4] == '0' and ack4 == True and ack3 != True:
                    ack3 = True # Four-way ACK (middle)
                
                elif flag[0] == '1' and flag[4] == '1' and fin_ack != True and ack_last == True:
                    fin_ack = True # Three-way FIN ACK (midde)
                    fin_ack2 = True # Four-way FIN ACK (last)
                    fin_ack4 = True # Four-way FIN ACK (last)

                elif flag[0] == '1' and flag[4] == '1' and fin_ack3 != True and ack3 == True and ack4 == True:
                    fin_ack3 = True

                # Four-way termination FIN ACK, ACK, FIN ACK, ACK
                elif flag[0] == '1' and flag[4] == '0' and ack1 != True and fin_ack2 == True and ack2 == True:
                    ack1 = True # Four-way ACK (first)
                
                elif flag[4] == '1' and fin != True and fin_ack == True and ack_last == True:
                    fin = True # Three-way FIN (first)
                    
                elif flag[0] == '1' and flag[4] == '1' and fin_ack1 != True and fin_ack4 and (ack1 == True or ack3 == True and ack4 == True and fin_ack3 == True):
                    fin_ack1 = True # Four-way FIN ACK (first)
                
                if fin_ack == False and fin == False and ack_last == False and rst == False and ack1 == False and fin_ack1 == False and ack2 == False and fin_ack2 == False:
                    comm.order.remove(order)
                    comm.packets.remove(packet)          
                
                if ((rst == True) or (fin_ack1 == True and ack1 == True and fin_ack2 == True and ack2 == True) or 
                (fin == True and fin_ack == True and ack_last == True) or (fin_ack3 == True and ack3 == True and fin_ack4 == True and ack4 == True)):
                    comm.end = True
                    break

    # Communication output 
    comm_num = 0
    flag = False
    c_flag = False
    
    #Print all complete comms and first incomplete comm
    for single_comm_tcp in comm_array:
        
        # For each complete comm
        if single_comm_tcp.start == True and single_comm_tcp.end == True:
            
            if c_flag == False:
                output['complete_comms'] = []
                c_flag = True

            comm_num += 1
            commun = {'number_comm': comm_num,
                    'src_comm': single_comm_tcp.source,
                    'dst_comm': single_comm_tcp.dest,
                    'packets': []}
            output['complete_comms'].append(commun)
            packet_num = 0

            for packet in single_comm_tcp.packets:

                number_of_packet = single_comm_tcp.order[packet_num]
                commun['packets'].append(frame_analyze(packet,number_of_packet))
                packet_num += 1
        
        # First incomplete comm and then set flag
        elif (single_comm_tcp.start == True and single_comm_tcp.end == None or single_comm_tcp.start == None and single_comm_tcp.end == True) and flag == False: 

            flag = True
            partial_comms = []
            packet_num = 0
            partial_comms = {'number_comm': 1,
                            'packets':[]}
            
            for packet in single_comm_tcp.packets:
                
                number_of_packet = single_comm_tcp.order[packet_num]
                partial_comms['packets'].append(frame_analyze(packet,number_of_packet))
                packet_num += 1

    if flag == True:
        output['partial_comms'] = []
        output['partial_comms'].append(partial_comms)

# UDP communication 
def uloha_udp(array,output):
    
    del output['complete_comms'] # For output reason
    comm_array = []

    for packet in array: # For each packet with UDP protocol
        offset = int(str(hexlify(packet[1][14:15]))[3:-1], 16) * 4 + 14
        source_port = int(hexlify(packet[1][offset:offset + 2]).decode('utf-8'), 16)
        dest_port = int(hexlify(packet[1][offset + 2:offset + 4]).decode('utf-8'), 16)
        op_code_tftp = int(hexlify(packet[1][offset+8:offset+10]).decode('utf-8'), 16)    

        single_comm_udp = comm_UDP(source_port, dest_port)
        
        # Create first comm, 69 -> beginning of TFTP communication, opcode 1,2 -> RRQ,WRQ
        if dest_port == 69 and op_code_tftp in [1,2]:
            single_comm_udp.order.append(packet[0])
            single_comm_udp.packets.append(packet[1])
            comm_array.append(single_comm_udp)
        
        else:
            # op_code_tftp 3,4,5 -> DATA,ACK,ERROR
            if op_code_tftp in [3,4,5]:
                # Check if comm exists and add packet to comm or create new comm
                for single_comm_udp in comm_array:
                    if ((single_comm_udp.udp_s_port == dest_port and single_comm_udp.udp_d_port == source_port) or
                    (single_comm_udp.udp_d_port == 69 and single_comm_udp.udp_s_port == dest_port) or
                    (single_comm_udp.udp_d_port == dest_port and single_comm_udp.udp_s_port == source_port)):
                        
                        if single_comm_udp.udp_d_port == 69:
                            single_comm_udp.udp_d_port = source_port # Work with new port to maintain comm

                        if op_code_tftp == 3 and single_comm_udp.size == None: 
                            single_comm_udp.size = int(str(hexlify(packet[1][offset+4:offset+6]))[2:-1], 16)
                        
                        single_comm_udp.order.append(packet[0])
                        single_comm_udp.packets.append(packet[1])
                        break
                
                if op_code_tftp == 5: # ERROR flag
                    single_comm_udp.done = False
                
                # ACK and DATA are smaller than agreed size of packet
                elif op_code_tftp == 4 and single_comm_udp.size != None:
                    if int(str(hexlify(single_comm_udp.packets[-2][offset+4:offset+6]))[2:-1], 16) < single_comm_udp.size or \
                    int(str(hexlify(single_comm_udp.packets[-2][offset+4:offset+6]))[2:-1], 16) == single_comm_udp.size and len(single_comm_udp.packets) == 4:
                        single_comm_udp.done = True
                
                else:
                    single_comm_udp.done = False
                    
    # Communication output 
    comm_num = 0
    comm_num_part = 0
    flag_c = False
    flag_p = False

    # Output purpose
    for comm in comm_array:
        if comm.done == True:
            flag_c = True
        else:
            flag_p = True

    if flag_c == True:
        output['complete_comms'] = []
    if flag_p == True:
        output['partial_comms'] = []

    #Print all complete comms and first incomplete comm
    for comm in comm_array:
        
        # For each complete comm
        if comm.done == True:
            comm_num += 1
            commun = {'number_comm': comm_num,
                    'packets': []}
            output['complete_comms'].append(commun)
            packet_num = 0

            for packet in comm.packets:

                number_of_packet = comm.order[packet_num]
                commun['packets'].append(frame_analyze(packet,number_of_packet))
                packet_num += 1
        
        # For each incomplete comm
        else: 
            partial_comms = []
            packet_num = 0
            comm_num_part += 1
            partial_comms = {'number_comm': comm_num_part,
                                'packets':[]
                                }
            
            for packet in comm.packets:
                
                number_of_packet = comm.order[packet_num]
                partial_comms['packets'].append(frame_analyze(packet,number_of_packet))
                packet_num += 1

            output['partial_comms'].append(partial_comms)

# ICMP communication   
def uloha_icmp(array,output):

    comm_array = []

    for packet in array:
        
        offset = int(str(hexlify(packet[1][14:15]))[3:-1], 16) * 4 + 14
        flag_mf = hexlify(packet[1][20:21]).decode('utf-8')
        f_offset = hexlify(packet[1][21:22]).decode('utf-8')
        flag_mf = bin(int(flag_mf, 16))[2:]
        f_offset = bin(int(f_offset, 16))[2:]
        flag_mf = flag_mf[0]
        f_offset = f_offset[0:]
        src_ip = single_IPaddress(packet[1][26:30])
        dst_ip = single_IPaddress(packet[1][30:34])
        id = int(hexlify(packet[1][18:20]).decode('utf-8'), 16)            
        
        # Different ways of getting ICMP ID and SEQ (different positions in packet) TIME EXCEED, FRAGMENTED, NON-FRAGMENTED
        if (int(hexlify(packet[1][offset:offset+1]).decode('utf-8'), 16)) == 11:
            icmp_id = int(hexlify(packet[1][offset+32:offset+34]).decode('utf-8'), 16)
            icmp_seq = int(hexlify(packet[1][offset+34:offset+36]).decode('utf-8'), 16)

        elif flag_mf == '1':
            icmp_id = int(hexlify(packet[1][offset+4:offset+6]).decode('utf-8'), 16)
            icmp_seq = int(hexlify(packet[1][offset+6:offset+8]).decode('utf-8'), 16)
        
        elif flag_mf == '0' and f_offset == '0':
            icmp_id = int(hexlify(packet[1][offset+4:offset+6]).decode('utf-8'), 16)
            icmp_seq = int(hexlify(packet[1][offset+6:offset+8]).decode('utf-8'), 16)

        new_comm = comm_ICMP(src_ip, dst_ip, icmp_id, icmp_seq, id)

        if len(comm_array) == 0:
            new_comm.order.append(packet[0])
            new_comm.packets.append(packet[1])
            comm_array.append(new_comm)

        else:
            flag = False
            for single_icmp_comm in comm_array:
                # Sort packets into existing communication based on IP, ID, SEQ
                if (single_icmp_comm.icmp_s_address == src_ip and single_icmp_comm.icmp_d_address == dst_ip and
                    single_icmp_comm.icmp_id == icmp_id and single_icmp_comm.icmp_seq == icmp_seq or
                    single_icmp_comm.icmp_s_address == dst_ip and single_icmp_comm.icmp_d_address == src_ip and
                    single_icmp_comm.icmp_id == icmp_id and single_icmp_comm.icmp_seq == icmp_seq or
                     single_icmp_comm.icmp_s_address == dst_ip and single_icmp_comm.icmp_id == icmp_id and 
                     single_icmp_comm.icmp_seq == icmp_seq):
                    
                    flag = True
                    single_icmp_comm.order.append(packet[0])
                    single_icmp_comm.packets.append(packet[1])
                    break
                
            if flag == False:
                new_comm.order.append(packet[0])
                new_comm.packets.append(packet[1])
                comm_array.append(new_comm)

    # Communication check if done and set ICMP type
    for single_icmp_comm in comm_array:
        for packets in single_icmp_comm.packets:

            offset = int(str(hexlify(packets[14:15]))[3:-1], 16) * 4 + 14
            flag_mf = hexlify(packets[20:21]).decode('utf-8')
            f_offset = hexlify(packets[21:22]).decode('utf-8')
            flag_mf = bin(int(flag_mf, 16))[2:]
            flag_mf = flag_mf[0]
            
            if flag_mf == '1':
                single_icmp_comm.done = False
            
            elif flag_mf == '0':
                # Adding ICMP type based on values and setting done 
                if int(hexlify(packets[offset:offset+1]).decode('utf-8'), 16) in [8,11]:
                    single_icmp_comm.type.append("Echo request") if int(hexlify(packets[offset:offset+1]).decode('utf-8'), 16) == 8 else single_icmp_comm.type.append("Time Exceeded")
                else:
                    single_icmp_comm.type.append("Echo reply")
                    single_icmp_comm.done = True

            if single_icmp_comm.done == False and int(hexlify(packets[0:1]).decode('utf-8'), 16) in [8,11]:
                single_icmp_comm.type.append("Echo request") if int(hexlify(packets[offset:offset+1]).decode('utf-8'), 16) == 8 else single_icmp_comm.type.append("Time Exceeded")
            else:
                single_icmp_comm.type.append("Echo reply")
                single_icmp_comm.done = True

    # Merge comms with same IP and ICMP ID
    merged_comm_array = []

    for single_icmp_comm in comm_array: # For each comm in comm_array
        merged = False
        for merged_comm in merged_comm_array: # For each comm in merged_comm_array
            if (single_icmp_comm.icmp_s_address == merged_comm.icmp_s_address and
                single_icmp_comm.icmp_d_address == merged_comm.icmp_d_address and
                single_icmp_comm.icmp_id == merged_comm.icmp_id and single_icmp_comm.done == merged_comm.done):
                merged_comm.order += single_icmp_comm.order
                merged_comm.packets += single_icmp_comm.packets
                merged_comm.type += single_icmp_comm.type
                merged = True
                break
        if not merged:
            merged_comm_array.append(single_icmp_comm)

    comm_array = merged_comm_array

    # Communication output 
    comm_num = 0
    comm_num_part = 0

    # Output purpose
    if comm_array:
        for comms in comm_array:
            if comms.done == True:
                output['complete_comms'] = []
            else:
                output['partial_comms'] = []

    #Print all complete comms and incomplete comm
    for comm in comm_array:
        
        if comm.done == True:
            comm_num += 1
            commun = {'number_comm': comm_num,
                    'src_comm': comm.icmp_s_address,
                    'dst_comm': comm.icmp_d_address,
                    'packets': []}
            output['complete_comms'].append(commun)
            packet_num = 0

            for packet in comm.packets:

                number_of_packet = comm.order[packet_num]
                commun['packets'].append(frame_analyze(packet,number_of_packet,comm, packet_num))
                packet_num += 1
              
        else: 
            partial_comms = []
            packet_num = 0
            comm_num_part += 1
            partial_comms = {'number_comm': comm_num_part,
                            'packets':[]
                            }
            
            for packet in comm.packets:
                
                number_of_packet = comm.order[packet_num]
                partial_comms['packets'].append(frame_analyze(packet,number_of_packet,comm, packet_num))
                packet_num += 1

            output['partial_comms'].append(partial_comms)

# ARP communication
def uloha_arp(array,output):
    
    del output['complete_comms'] # For output purpose

    comm_array = []
    for packet in array: # For each packet with ARP protocol
        source_ip = single_IPaddress(packet[1][28:32])
        target_ip = single_IPaddress(packet[1][38:42])
        opcode = int(hexlify(packet[1][21:22]).decode('utf-8'), 16)

        if opcode in [1,2]: # Working only with ARP request and reply
            new_comm = comm_ARP(source_ip, target_ip)

            if len(comm_array) == 0:
                new_comm.order.append(packet[0])
                new_comm.packets.append(packet[1])
                comm_array.append(new_comm)

            else:
                flag = False
                for single_comm_arp in comm_array:
                    # Sort packets into existing communication based on IP, flag done if comm is finished (pairs only)
                    if ((single_comm_arp.source_ip == source_ip and single_comm_arp.dest_ip == target_ip and len(single_comm_arp.packets) == 1 and single_comm_arp.done != True) or
                        (single_comm_arp.source_ip == target_ip and single_comm_arp.dest_ip == source_ip and len(single_comm_arp.packets) == 1 and single_comm_arp.done != True)):
                        
                        single_comm_arp.order.append(packet[0])
                        single_comm_arp.packets.append(packet[1])

                        if int(hexlify(single_comm_arp.packets[0][21:22]).decode('utf-8'), 16) == 1 and opcode == 2:
                            single_comm_arp.done = True

                        flag = True
                        break  

                if not flag:
                    new_comm.order.append(packet[0])
                    new_comm.packets.append(packet[1])
                    comm_array.append(new_comm)

    # Communication output
    complete_counter = 1
    partial_counter = 1
    partial1 = False # Flag for partial ARP request
    partial2 = False # Flag for partial ARP reply
    complete = False # Flag for complete ARP

    # Merger comms with same dest_ip 
    for comm in comm_array:
        dest_ip = comm.dest_ip
        for single_comm in comm_array:
            if comm == single_comm:
                continue
            if single_comm.dest_ip == dest_ip and comm.done == single_comm.done and comm.packets[0][21:22] == single_comm.packets[0][21:22]:
                comm.packets += single_comm.packets
                comm.order += single_comm.order
                comm_array.remove(single_comm)

    # ARP sorting based on opcode and pairs
    for single_comm_arp in comm_array:

        # Check if communication is complete or partial
        if single_comm_arp.done == True:    
            
            # Create complete comms output
            if complete == False:
                output['complete_comms'] = []
                complete = True

            # For each complete comm
            complete_comm = {'number_comm': complete_counter,
            'packets': []}
            complete_counter += 1
            counter = 0

            for packet in single_comm_arp.packets:
                complete_comm['packets'].append(frame_analyze(packet, single_comm_arp.order[counter]))
                counter += 1

            output['complete_comms'].append(complete_comm)

        else:
            packet = single_comm_arp.packets[0]
            counter2 = 0                
            if int(hexlify(packet[21:22]).decode('utf-8'), 16) == 1:
                if partial1 == False:
                    output['partial_comms'] = []
                    partial1 = True

                partial_comm_request = {'number_comm': partial_counter,
                'packets': []}
                partial_counter += 1

                for packet in single_comm_arp.packets:
                    partial_comm_request['packets'].append(frame_analyze(packet, single_comm_arp.order[counter2]))
                    counter2 += 1
                
                output['partial_comms'].append(partial_comm_request)

            elif int(hexlify(packet[21:22]).decode('utf-8'), 16) == 2:
                if partial2 == False:
                    output['partial_comms'] = []
                    partial2 = True

                partial_comm_reply = {'number_comm': partial_counter,
                'packets': []}
                partial_counter += 1

                for packet in single_comm_arp.packets:
                    partial_comm_reply['packets'].append(frame_analyze(packet, single_comm_arp.order[counter2]))
                    counter2 += 1

                output['partial_comms'].append(partial_comm_reply)
    
def doimplemenation(packet):

    try:
        if packet['app_protocol'] == "FTP-DATA" and packet['len_frame_pcap'] > 78:
            return True 
    except:
        return False
# MENU     
def main():

    yaml = ruamel.yaml.YAML()

    file = open('results.yaml', 'w')
    
    pcap_file = input("Enter the path to the pcap file: ")
    pcap_file = pcap_file.replace('"', '')

    if exists(pcap_file) is False:
        print("File does not exist")
        sys.exit()

    print("Choose task:")
    print('Task 1-2 enter "1"\nTask 4:\nFor HTTP -> "HTTP"\nFor HTTPS -> "HTTPS"\nFor TELNET -> "TELNET" \
          \nFor SSH -> "SSH"\nFor FTP-CONTROL -> "FTPC"\nFor FTP-DATA -> "FTPD"\nFor TFTP -> "TFTP" \
          \nFor ICMP -> "ICMP"\nFor ARP -> "ARP"\nFor FTP-DATA doimp -> "FTPDD"')

    task = input("Enter the task: ")
    task = task.upper()

    # Load protocols, etc.
    database_load()

    packets = rdpcap(pcap_file) # Getting array of raw packets
    number_of_packet = 1 # Number of packet in pcap file

    # Task 1-2 - frame info 
    if task == "1":

        output = {'name':'PKS2023/24',
                'pcap_name':os.path.basename(pcap_file),
                'packets': []
                }

        # Task 3 - IPv4 senders 
        answer = input("Show ipv4 senders? (Y/N)\n")
        answer = answer.upper()

        for packet in packets:
            
            new_packet = frame_analyze(raw(packet),number_of_packet) # Analyze packet (basic info L2,L3,app protocol)
            number_of_packet += 1
            output['packets'].append(new_packet)

        if answer == "Y":
            ip_dict = {}
            
            # Count number of packets sent by each IPv4 address
            for ip in output['packets']:
                if ip['frame_type'] == 'ETHERNET II' and ip['ether_type'] == 'IPv4':
                    if ip['src_ip'] in ip_dict:
                        ip_dict[ip['src_ip']] += 1
                    else:
                        ip_dict[ip['src_ip']] = 1
                else:
                    continue
    
            # Sort dictionary by value
            ip_dict = dict(sorted(ip_dict.items(), key=lambda item: item[1], reverse=True)) 
            output['ipv4_senders'] = []
            for key, value in ip_dict.items():
                output['ipv4_senders'].append({'node': key, 'number_of_sent_packets': value})
            
            output['max_send_packets_by'] = []
            max_value = max(ip_dict.values()) # Get max value from dictionary
            for key, value in ip_dict.items():
                if value == max_value:
                    output['max_send_packets_by'].append(key) 
                         
    # MENU for task 4
    else:
        # Header for each task 
        output = {'name':'PKS2023/24',
            'pcap_name':os.path.basename(pcap_file),
            'filter_name': task,
            'complete_comms':[]}
        
        arrays = Arrays() # Create arrays for each protocol

        for packet in packets:
                well_known_ports(raw(packet),number_of_packet,arrays) # Fill arrays with packets
                number_of_packet += 1

        # Task 4 - HTTP
        if task == "HTTP":    
            uloha_tcp(arrays.http_array,output)

        # Task 4 - HTTPS
        elif task == "HTTPS":
            uloha_tcp(arrays.https_array,output)

        # Task 4 - TELNET
        elif task == "TELNET":
            uloha_tcp(arrays.telnet_array,output)

        # Task 4 - SSH
        elif task == "SSH":
            uloha_tcp(arrays.ssh_array,output)

        # Task 4 - FTPC
        elif task == "FTPC":
            uloha_tcp(arrays.ftpc_array,output)

        # Task 4 - FTPD
        elif task == "FTPD":
            uloha_tcp(arrays.ftpd_array,output)

        # Task 4 - TFTP
        elif task == "TFTP":
            uloha_udp(arrays.tftp_array,output)

        # Task 4 - ICMP
        elif task == "ICMP":
            uloha_icmp(arrays.icmp_array,output)

        # Task 4 - ARP
        elif task == "ARP":
            uloha_arp(arrays.arp_array,output)
        
        elif task == "FTPDD":
            number_of_packet = 1
            output = {'name':'PKS2023/24',
                    'pcap_name':os.path.basename(pcap_file),
                    'packets': []
                    }

            counter = 0
            for packet in packets:
                new_packet = frame_analyze(raw(packet),number_of_packet) # Analyze packet (basic info L2,L3,app protocol)
                number_of_packet += 1
                if doimplemenation(new_packet):
                    counter += 1
                    output['packets'].append(new_packet)

            output['number_of_packets'] = counter        
# Write to file
    yaml.dump(output, file)
    file.close()

if __name__ == '__main__':
    main()