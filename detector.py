import time
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP

last_syn = {
    "1.1.1.1" : [1781481912.974055, 0]
    ## IP, Last SYN, Flag (# of SYNs that happened with a difference of 1 sec <)
}

def print_live(packet):
    if packet[TCP].flags == "S":
        print(f"{packet.summary()}, Port: {packet[TCP].dport}, Time: {packet.time}")


sniffer = AsyncSniffer(prn=print_live, filter="tcp")
sniffer.start()
time.sleep(30)
sniffer.stop()
