import sys
import os
import time
import pathlib
import logging

EXT_MODULES = ["libs/scapy-2.3.1/python3"]

for i in EXT_MODULES:
    sys.path.insert(1, i)

import scapy.all as scapy

def get_session_list(filename, parent_thread = None):
    log = logging.getLogger("splitter.analyze")
    log.info(f"Trying to analyze {filename} file")
    sessions = {}
    size_counter = 24 # PCAP file header
    pcap_size = os.stat(filename).st_size
    log.info(f"{pcap_size} bytes received")
    analyzed_percent = 0
    with scapy.PcapReader(filename) as packets:
        for packet in packets:
            size_counter += 16 # PCAP packet header
            size_counter += len(packet)
            if parent_thread:
                current_percent = int(size_counter * 100 // pcap_size)
                if current_percent > analyzed_percent:
                    analyzed_percent = current_percent
                    parent_thread.update_progress(analyzed_percent)
            if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
                payload_size = len(packet[scapy.TCP].payload)
                packet_size = len(packet.payload)
                ip1 = ipv4_to_hex(packet[scapy.IP].src)
                ip2 = ipv4_to_hex(packet[scapy.IP].dst)
                p1 = port_to_hex(packet[scapy.TCP].sport)
                p2 = port_to_hex(packet[scapy.TCP].dport)
                proto = "00000006" # TCP
                flags = "{0:012b}".format(packet[scapy.TCP].flags)

                if int(flags[10]) and not int(flags[7]): # SYN with no ACK
                    session = (ip1, p1, ip2, p2, proto)
                    if session in sessions.keys():
                        if sessions[session][2:4] == [True, True]:
                            sessions[session][5] = True
                        elif sessions[session][4]:
                            sessions[session][5] = True
                    else:
                        sessions[session] = [True, False, False, False, False, False, packet_size, 1, payload_size]

                elif int(flags[10]) and int(flags[7]): # SYN-ACK
                    session = (ip2, p2, ip1, p1, proto)
                    if session in sessions.keys():
                        if sessions[session][1] or sessions[session][2] or sessions[session][3]:
                            if sessions[session][1:5] == [True, False, False, False]:
                                pass
                            else:
                                print(f"SYN-ACK {sessions[session]}")
                        else:
                            sessions[session][1] = True
                            sessions[session][6] += packet_size
                            sessions[session][7] += 1
                            sessions[session][8] += payload_size

                elif int(flags[11]): # FIN
                    session1 = (ip1, p1, ip2, p2, proto)
                    session2 = (ip2, p2, ip1, p1, proto)
                    if session1 in sessions.keys():
                        sessions[session1][6] += packet_size
                        sessions[session1][7] += 1
                        sessions[session1][8] += payload_size
                        if not sessions[session1][2]:
                            sessions[session1][2] = True
                    elif session2 in sessions.keys():
                        sessions[session2][6] += packet_size
                        sessions[session2][7] += 1
                        sessions[session2][8] += payload_size
                        if not sessions[session2][3]:
                            sessions[session2][3] = True

                elif int(flags[9]): # RST
                    session1 = (ip1, p1, ip2, p2, proto)
                    session2 = (ip2, p2, ip1, p1, proto)
                    if session1 in sessions.keys():
                        sessions[session1][6] += packet_size
                        sessions[session1][7] += 1
                        sessions[session1][8] += payload_size
                        sessions[session1][4] = True
                    elif session2 in sessions.keys():
                        sessions[session2][6] += packet_size
                        sessions[session2][7] += 1
                        sessions[session2][8] += payload_size
                        sessions[session2][4] = True
                
                else:
                    session1 = (ip1, p1, ip2, p2, proto)
                    session2 = (ip2, p2, ip1, p1, proto)
                    if session1 in sessions.keys():
                        sessions[session1][6] += packet_size
                        sessions[session1][7] += 1
                        sessions[session1][8] += payload_size
                    elif session2 in sessions.keys():
                        sessions[session2][6] += packet_size
                        sessions[session2][7] += 1
                        sessions[session2][8] += payload_size

            if packet.haslayer(scapy.UDP) and packet.haslayer(scapy.IP):
                payload_size = len(packet[scapy.UDP].payload)
                packet_size = len(packet.payload)
                ip1 = ipv4_to_hex(packet[scapy.IP].src)
                ip2 = ipv4_to_hex(packet[scapy.IP].dst)
                p1 = port_to_hex(packet[scapy.UDP].sport)
                p2 = port_to_hex(packet[scapy.UDP].dport)
                proto = "00000011" # UDP
                session1 = (ip1, p1, ip2, p2, proto)
                session2 = (ip2, p2, ip1, p1, proto)
                if session1 in sessions.keys():
                    sessions[session1][6] += packet_size
                    sessions[session1][7] += 1
                    sessions[session1][8] += payload_size
                elif session2 in sessions.keys():
                    sessions[session2][6] += packet_size
                    sessions[session2][7] += 1
                    sessions[session2][8] += payload_size
                else:
                    sessions[session1] = [False, False, False, False, False, False, packet_size, 1, payload_size]
            else:
                pass

    valid_sessions = {}
    for session, details in sessions.items():
        if session[4] == "00000006": # TCP
            if details[0:4] == [True, True, True, True]:
                valid_sessions[session] = details
            elif details[4] and details[0] and details[1]:
                valid_sessions[session] = details
        elif session[4] == "00000011": #UDP
            valid_sessions[session] = details
    return valid_sessions

def split_pcap(filename, session_list, parent_thread = None):
    protocol_map = {"00000006" : "tcp", "00000011" : "udp"}
    files = {}
    cap_dir = "captures"
    if not os.path.exists(cap_dir):
        os.makedirs(cap_dir)
    for session_tuple in session_list:
        sip = hex_to_ipv4(session_tuple[0])
        sp = hex_to_port(session_tuple[1])
        dip = hex_to_ipv4(session_tuple[2])
        dp = hex_to_port(session_tuple[3])
        prot = protocol_map[session_tuple[4]]
        files[session_tuple] = [cap_dir, f"{prot}_{sip}.{sp}-{dip}.{dp}.pcap"]

    size_counter = 24 # PCAP file header
    pcap_size = os.stat(filename).st_size
    analyzed_percent = 0
    with scapy.PcapReader(filename) as packets:
        for packet in packets:
            size_counter += 16 # PCAP packet header
            size_counter += len(packet)
            if parent_thread:
                current_percent = int(size_counter * 100 // pcap_size)
                if current_percent > analyzed_percent:
                    analyzed_percent = current_percent
                    parent_thread.update_progress(analyzed_percent)
            if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
                ip1 = ipv4_to_hex(packet[scapy.IP].src)
                ip2 = ipv4_to_hex(packet[scapy.IP].dst)
                p1 = port_to_hex(packet[scapy.TCP].sport)
                p2 = port_to_hex(packet[scapy.TCP].dport)
                proto = "00000006"
                session1 = (ip1, p1, ip2, p2, proto)
                session2 = (ip2, p2, ip1, p1, proto)
                if session1 in files.keys():
                    filename = pathlib.PurePath(files[session1][0], files[session1][1])
                    scapy.wrpcap(filename, packet, append=True)
                elif session2 in files.keys():
                    filename = pathlib.PurePath(files[session2][0], files[session2][1])
                    scapy.wrpcap(filename, packet, append=True)
            elif packet.haslayer(scapy.UDP) and packet.haslayer(scapy.IP):
                ip1 = ipv4_to_hex(packet[scapy.IP].src)
                ip2 = ipv4_to_hex(packet[scapy.IP].dst)
                p1 = port_to_hex(packet[scapy.UDP].sport)
                p2 = port_to_hex(packet[scapy.UDP].dport)
                proto = "00000011"
                session1 = (ip1, p1, ip2, p2, proto)
                session2 = (ip2, p2, ip1, p1, proto)
                if session1 in files.keys():
                    filename = pathlib.PurePath(files[session1][0], files[session1][1])
                    scapy.wrpcap(filename, packet, append=True)
                elif session2 in files.keys():
                    filename = pathlib.PurePath(files[session2][0], files[session2][1])
                    scapy.wrpcap(filename, packet, append=True)
    return files

def ipv4_to_hex(addr):
    octets = addr.split(".")
    hex_value = ""
    for octet in octets:
        hex_value += "{:02x}".format(int(octet))
    return hex_value

def hex_to_ipv4(addr):
    octets = []
    octets.append(str(int(addr[0:2], 16)))
    octets.append(str(int(addr[2:4], 16)))
    octets.append(str(int(addr[4:6], 16)))
    octets.append(str(int(addr[6:8], 16)))
    return ".".join(octets)

def hex_to_port(port):
    return str(int(port, 16))

def port_to_hex(port):
    return "{:08x}".format(int(port))