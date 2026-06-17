import time
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP
import subprocess
import json

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]

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
        "syn" : {"time" : None, "ports" : {}},
        "ssh" : {"time" : None, "attempts" : None},
        "status" : "OPEN"
    }

# def check_blocked_and_new_ips(ip):

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
            tracked_ip = ip_tracker[source_ip]["syn"]
            tracked_ip["time"] = timestamp
        
        time_passed = timestamp - ip_tracker[source_ip]["syn"]["time"]

        if time_passed > 1:
            tracked_ip["time"] = timestamp
            tracked_ip["ports"] = {dport}
        else:
            tracked_ip["ports"].add(dport)
        
        if len(tracked_ip["ports"]) > syn_threshold:
            print("[!] SYN port scan from", source_ip)
            tracked_ip["status"] = "BLOCKED"
            print(f"[*] Configuring firewall to BLOCK {source_ip}...")
            subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", source_ip, "-j", "DROP"])
            print("[*] Guardian Angel has BLOCKED", source_ip)


    elif packet[TCP].flags == 0: ## Null Scan Detection

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        else:
            ip_tracker[source_ip]["status"] = "BLOCKED"
        
        print("[!] Null port scan from", source_ip)
        print(f"[*] Configuring firewall to BLOCK {source_ip}...")
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", source_ip, "-j", "DROP"])
        print("[*] Guardian Angel has BLOCKED", source_ip)

    elif packet[TCP].flags == "FPU": ## Xmas Scan Detection

        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        else:
            ip_tracker[source_ip]["status"] = "BLOCKED"
        
        print("[!] Xmas port scan from", source_ip)
        print(f"[*] Configuring firewall to BLOCK {source_ip}...")
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", source_ip, "-j", "DROP"])
        print(f"[*] Guardian Angel has BLOCKED {source_ip}") 
    
    elif packet[TCP] and packet.dport == 22: ## SSH Scan detection
        print("SSH Packet")



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