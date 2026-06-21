import time
import socket
import json
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
# from brain import analyze

brain_ip = "127.0.0.1"

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ## Creates the UDP socket

def send_packet(packet):
    packet_info = {
        # "protocol_type" : "",
        # "flags" : "",
        # "dport" : "",
        # "source_ip" : "",
    }

    if packet.haslayer(IP):
        packet_info["source_ip"] = packet[IP].src
    
    if packet.haslayer(TCP):
        packet_info["protocol_type"] = "TCP"
    elif packet.haslayer(UDP):
        packet_info["protocol_type"] = "UDP"
        packet_info["dport"] = None
        packet_info["flags"] = None
    else:
        packet_info["protocol_type"] = None
    
    if packet_info["protocol_type"]:
        if packet_info["protocol_type"] == "TCP":
            packet_info["dport"] = packet[TCP].dport
            packet_info["flags"] =str(packet[TCP].flags)
    else:
        packet_info["dport"] = None
        packet_info["flags"] = None
    

    print(packet_info)
    if packet_info["dport"] is not None and packet_info["dport"] != 5005:


        packet_info = json.dumps(packet_info).encode("utf-8")

        udp_socket.sendto(packet_info, ("127.0.0.1", 5005))


if __name__ == "__main__":
    try:
        sniffer = AsyncSniffer(prn=send_packet, iface="lo0")
        sniffer.start()
        print("\n[*] Guardian Angel Active.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping Guardian Angel...")

    finally:
        sniffer.stop()