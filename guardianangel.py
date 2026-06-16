import time
from ssh import connect, dissconnect, execute
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP
import json

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]

block_ip = "sudo iptables -I INPUT 1 -s 1.1.1.1 -j DROP"
one_liner = "sudo iptables -I INPUT 1 -s 1.1.1.1 -j DROP && sudo iptables -L INPUT -n"

ip_tracker = {
    # "1.1.1.1" : [time, flags, status]
}

def analyze(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    
    if packet[TCP].flags == "S": ## SYN spam detectio
        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip][2] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = [timestamp, {dport}, "OPEN"]
        
        time_passed = timestamp - ip_tracker[source_ip][0]

        if time_passed > 1:
            ip_tracker[source_ip][0] = timestamp
            ip_tracker[source_ip][1] = {dport}
        else:
            ip_tracker[source_ip][1].add(dport)
        
        if len(ip_tracker[source_ip][1]) > syn_threshold and ip_tracker[source_ip][2] == "OPEN":
            print("[!] SYN port scan from", source_ip)
            ip_tracker[source_ip][2] = "BLOCKED"
            execute(f"sudo iptables -I INPUT 1 -s {source_ip} -j DROP && sudo iptables -L INPUT -n")
            print("[*] Guardian Angel has BLOCKED", source_ip)

    if packet[TCP].flags == 0:

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip][2] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = [timestamp, {dport}, "BLOCKED"]
        
        print("[!] Null port scan from", source_ip)
        execute(f"sudo iptables -I INPUT 1 -s {source_ip} -j DROP && sudo iptables -L INPUT -n")
        print("[*] Guardian Angel has BLOCKED", source_ip)

    if packet[TCP].flags == "FPU":

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip][2] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = [timestamp, {dport}, "BLOCKED"]
        
        print("[!] Xmas port scan from", source_ip)
        print(f"[*] Configuring firewall to BLOCK {source_ip}...")
        execute(f"sudo iptables -I INPUT 1 -s {source_ip} -j DROP && sudo iptables -L INPUT -n")
        print(f"[*] Guardian Angel has BLOCKED {source_ip}") 
        



if __name__ == "__main__":
    try:
        # connect()
        sniffer = AsyncSniffer(prn=analyze)
        sniffer.start()
        print("\n[*] Guardian Angel Active.")
        time.sleep(10)

    except:
        print("\n[*] Stopping Guardian Angel...")

    finally:
        sniffer.stop()
        # dissconnect()