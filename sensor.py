import time
import socket
import json
import hmac
from hashlib import sha256
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP

with open("config.json", "r") as file:
    data = json.load(file)
    sensor_ip = data["sensor_ip"]
    analyzer_ip = data["analyzer_ip"]
    enforcer_ip = data["enforcer_ip"]
    analyzer_port = data["analyzer_port"]
    network_interface = data["network_interface"]
    hmac_key = data["hmac_key"].encode("utf-8") ## Needs to be encoded to be used for HMAC key

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ## Creates the UDP socket (sensor -> analyzer)

def calculate_hmac(packet_info):
    message = json.dumps(packet_info)
    checksum = hmac.new(hmac_key, message.encode("utf-8"), sha256)
    return checksum.hexdigest()

def send_packet(packet):
    packet_info = {
        "payload" : {
            # "protocol_type" : "",
            # "flags" : "",
            # "dport" : "",
            # "source_ip" : "",
            # "time" : ""
            # signature : ""}
        },
        "signature" : ""
    }

    packet_info["payload"]["time"] = packet.time

    if packet.haslayer(IP):
        packet_info["payload"]["source_ip"] = packet[IP].src
    
    if packet.haslayer(TCP):
        packet_info["payload"]["protocol_type"] = "TCP"
        packet_info["payload"]["dport"] = packet[TCP].dport
        packet_info["payload"]["flags"] = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        packet_info["payload"]["protocol_type"] = "UDP"
        packet_info["payload"]["dport"] = packet[UDP].dport
        packet_info["payload"]["flags"] = None

    else:
        packet_info["payload"]["protocol_type"] = None
        packet_info["payload"]["dport"] = None
        packet_info["payload"]["flags"] = None
    
    if packet_info["payload"]["dport"] is not None and packet_info["payload"]["dport"] != 5005:
        packet_info["signature"] = calculate_hmac(packet_info["payload"])
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
    
    except Exception as error:
        print(f"[?] Unknown Error: {error}")

    finally:
        sniffer.stop()
        udp_socket.close()