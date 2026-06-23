import json
import datetime
import threading
import socket
from scapy.layers.inet import IP, TCP
# from enforcer import block, unblock

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]
    ssh_threshold = data["ssh_threshold"]
    block_time = data["block_time"]

listening_port = 5005

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ## Creates the UDP socket
udp_socket.bind(("127.0.0.1", listening_port)) ## Listening Port

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
    
def schedule_unblock(ip):
    ip_tracker[ip]["status"] = "OPEN"
    # unblock(ip)
    write_log(ip, "UNBLOCKED", "Blocked Timer Complete")

def write_log(ip, action, reason):
    log = {"time" : str(datetime.datetime.now()),
        "ip" : ip,
        "action" : action,
        "reason" : reason
        }
    
    with open("guardian_angel.log", "a") as file:
        file.write(json.dumps(log) + "\n")

# {"source_ip" : source_ip, "action" : "BLOCKED", "reason" : "SYN Port Scan"}
def send_to_enforcer(ip, action, reason):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to IP")
    tcp_socket.connect(("127.0.0.1", 5006))
    block_info = json.dumps({"source_ip" : ip, "action" : action, "reason" : reason})
    block_info = block_info.encode("utf-8")
    print("Sending info")
    try:
        tcp_socket.sendall(block_info)
    except:
        print("Error sending packet")
    
    tcp_socket.close()



def analyze(packet):
    #print(packet)

    if not (packet["source_ip"]):
        return
    
    if packet["protocol_type"] == "TCP" and packet["dport"] == 22: ## SSH Scan detection

        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

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
            block_timer = threading.Timer(block_time, schedule_unblock, args=[source_ip])
            block_timer.start()
            ip_tracker[source_ip]["status"] = "BLOCKED"
            # block(source_ip)
            write_log(source_ip, "BLOCKED", "SSH Brute Force")

    elif packet["flags"] == "S": ## SYN spam detection
        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

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
            block_timer = threading.Timer(block_time, schedule_unblock, args=[source_ip])
            block_timer.start()
            ip_tracker[source_ip]["status"] = "BLOCKED"
            send_to_enforcer(source_ip, "BLOCK", "SYN Port Scan")
            # block(source_ip)
            write_log(source_ip, "BLOCKED", "SYN Port Scan")


    elif packet["flags"] == 0: ## Null Scan Detection
        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Null port scan from", source_ip)
        block_timer = threading.Timer(block_time, schedule_unblock, args=[source_ip])
        block_timer.start()
        ip_tracker[source_ip]["status"] = "BLOCKED"
        # block(source_ip)
        write_log(source_ip, "BLOCKED", "Null Port Scan")

    elif packet["flags"] == "FPU": ## Xmas Scan Detection

        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Xmas port scan from", source_ip)
        block_timer = threading.Timer(block_time, schedule_unblock, args=[source_ip])
        block_timer.start()
        ip_tracker[source_ip]["status"] = "BLOCKED"
        # block(source_ip)
        write_log(source_ip, "BLOCKED", "Xmas Port Scan")


if __name__ == "__main__":
    print("\n[*] The Guardian Heart is Active.")
    while True:
        try:
            data, address = udp_socket.recvfrom(1024)

            json_string = data.decode("utf-8")
            packet_info = json.loads(json_string)
            
            analyze(packet_info)
        except KeyboardInterrupt:
            print("\n[*] Stopping The Guardian Heart...")
            udp_socket.close()
            break
        
