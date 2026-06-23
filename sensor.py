import time
import socket
import json
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP

with open("config.json", "r") as file:
    data = json.load(file)
    sensor_ip = data["sensor_ip"]
    analyzer_ip = data["analyzer_ip"]
    enforcer_ip = data["enforcer_ip"]

    analyzer_port = data["analyzer_port"]

    network_interface = data["network_interface"]


udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ## Creates the UDP socket (sensor -> analyzer)

def send_packet(packet):
    packet_info = {
        # "protocol_type" : "",
        # "flags" : "",
        # "dport" : "",
        # "source_ip" : "",
        # "time" : ""
    }

    packet_info["time"] = packet.time

    if packet.haslayer(IP):
        packet_info["source_ip"] = packet[IP].src
    
    if packet.haslayer(TCP):
        packet_info["protocol_type"] = "TCP"
        packet_info["dport"] = packet[TCP].dport
        packet_info["flags"] =str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        packet_info["protocol_type"] = "UDP"
        packet_info["dport"] = None
        packet_info["flags"] = None

    else:
        packet_info["protocol_type"] = None
    
    if not packet_info["protocol_type"]:
        packet_info["dport"] = None
        packet_info["flags"] = None
    
    if packet_info["dport"] is not None:      

        packet_info = json.dumps(packet_info).encode("utf-8")

        udp_socket.sendto(packet_info, (analyzer_ip, analyzer_port))


if __name__ == "__main__":
    try:
        sniffer = AsyncSniffer(prn=send_packet, iface=network_interface)
        sniffer.start()
        print("\n[*] The Guardian Sensor is Active.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping the Guardian Sensor...")

    finally:
        sniffer.stop()