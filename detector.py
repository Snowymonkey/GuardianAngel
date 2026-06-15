import time
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP

block_ip = "sudo iptables -I INPUT 1 -s 1.1.1.1 -j DROP"
one_liner = "sudo iptables -I INPUT 1` -s 1.1.1.1 -j DROP && sudo iptables -L INPUT -n"

ip_tracker = {
}

def analyze(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    
    if packet[TCP].flags == "S":
        source_ip = packet[IP].src
        timestamp = packet.time
        dport = packet[TCP].dport

        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = [timestamp, {dport}]
        
        time_passed = timestamp - ip_tracker[source_ip][0]

        if time_passed > 1:
            ip_tracker[source_ip][0] = timestamp
            ip_tracker[source_ip][1] = {dport}
        else:
            ip_tracker[source_ip][1].add(dport)
        
        if len(ip_tracker[source_ip][1]) > 10:
            print("ALERT - PORT SCAN FROM", source_ip)


if __name__ == "__main__":
    sniffer = AsyncSniffer(prn=analyze)
    sniffer.start()
    time.sleep(10)
    sniffer.stop()