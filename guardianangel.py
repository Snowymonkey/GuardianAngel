import time
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP
import subprocess
import json

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]
    ssh_threshold = data["ssh_threshold"]

block_ip = "sudo iptables -I INPUT 1 -s 1.1.1.1 -j DROP"
one_liner = "sudo iptables -I INPUT 1 -s 1.1.1.1 -j DROP && sudo iptables -L INPUT -n"

ip_tracker = {
    # "1.1.1.1" : {
    #     "syn" : {"time" : 10, "ports" : {23, 20}},
    #     "ssh" : {"time" : 10, "attempts" : 10},
    #     "status" : "OPEN"
    # }
}

def create_ip_tracker():
    return {
        "syn" : {"time" : None, "ports" : set()},
        "ssh" : {"time" : None, "attempts" : 0},
        "status" : "OPEN"
    }

def block(ip):
    print(f"[*] Configuring firewall to BLOCK {ip}...")
    ip_tracker[ip]["status"] = "BLOCKED"
    # subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has BLOCKED", ip)

def analyze(packet):
    
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    
    if packet[TCP].flags == "S": ## SYN spam detection
        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
            ip_tracker[source_ip]["syn"]["time"] = timestamp
            
        if ip_tracker[source_ip]["syn"]["time"] is None:
            ip_tracker[source_ip]["syn"]["time"] = timestamp
            
        time_passed = timestamp - ip_tracker[source_ip]["syn"]["time"]

        if time_passed > 1:
            ip_tracker[source_ip]["syn"]["time"] = timestamp
            ip_tracker[source_ip]["syn"]["ports"] = {dport}
        else:
            ip_tracker[source_ip]["syn"]["ports"].add(dport)
        
        if len(ip_tracker[source_ip]["syn"]["ports"]) > syn_threshold:
            print("[!] SYN port scan from", source_ip)
            block(source_ip)


    elif packet[TCP].flags == 0: ## Null Scan Detection
        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Null port scan from", source_ip)
        block(source_ip)

    elif packet[TCP].flags == "FPU": ## Xmas Scan Detection

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Xmas port scan from", source_ip)
        block(source_ip)
    
    elif packet[TCP] and packet.dport == 22: ## SSH Scan detection

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
            ip_tracker[source_ip]["ssh"]["time"] = timestamp
        
        if ip_tracker[source_ip]["ssh"]["time"] is None:
            ip_tracker[source_ip]["ssh"]["time"] = timestamp
        
        time_passed = timestamp - ip_tracker[source_ip]["ssh"]["time"]

        if time_passed > 1:
            ip_tracker[source_ip]["ssh"]["time"] = timestamp
            ip_tracker[source_ip]["ssh"]["attempts"] = 0
        else:
            ip_tracker[source_ip]["ssh"]["attempts"] += 1
        
        if ip_tracker[source_ip]["ssh"]["attempts"] > ssh_threshold:
            print("[!] SSH brute force from", source_ip)
            block(source_ip)


if __name__ == "__main__":
    try:
        sniffer = AsyncSniffer(prn=analyze)
        sniffer.start()
        print("\n[*] Guardian Angel Active.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping Guardian Angel...")

    finally:
        sniffer.stop()