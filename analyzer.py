import json
import threading
import hmac
from hashlib import sha256
import socket
from scapy.layers.inet import IP, TCP
# from enforcer import block, unblock

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]
    ssh_threshold = data["ssh_threshold"]
    block_time = data["block_time"]

    sensor_ip = data["sensor_ip"]
    analyzer_ip = data["analyzer_ip"]
    enforcer_ip = data["enforcer_ip"]

    analyzer_port = data["analyzer_port"]
    enforcer_port = data["enforcer_port"]

    hmac_key = data["hmac_key"].encode("utf-8") ## Needs to be encoded to be used for HMAC key

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((analyzer_ip, analyzer_port)) ## Listening Port (sensor -> analyzer)

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
    send_to_enforcer(ip, "UNBLOCK", "Blocked Timer Complete")
    # write_log(ip, "UNBLOCKED", "Blocked Timer Complete")

# def write_log(ip, action, reason):
#     log = {"time" : str(datetime.datetime.now()),
#         "ip" : ip,
#         "action" : action,
#         "reason" : reason
#         }
    
#     with open("guardian_angel.log", "a") as file:
#         file.write(json.dumps(log) + "\n")

def check_signature(payload, signature):
    message = json.dumps(payload)
    checksum = hmac.new(hmac_key, message.encode("utf-8"), sha256)
    return hmac.compare_digest(checksum.hexdigest(), signature)



def send_to_enforcer(ip, action, reason):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        tcp_socket.connect((enforcer_ip, enforcer_port))

        block_info = json.dumps({"source_ip" : ip, "action" : action, "reason" : reason})
        block_info = block_info.encode("utf-8")

        try:
            tcp_socket.sendall(block_info)
        except:
            print("[?] Error sending packet")

    except:
        print("[?] Enforcer Connection Not Made")
    
    tcp_socket.close()


def analyze(packet):
    #print(packet)

    if not (packet["source_ip"] or packet["protocol_type"]):
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
            send_to_enforcer(source_ip, "BLOCK", "SSH Brute Force")
            # write_log(source_ip, "BLOCKED", "SSH Brute Force")

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
            # write_log(source_ip, "BLOCKED", "SYN Port Scan")


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
        send_to_enforcer(source_ip, "BLOCK", "Null Port Scan")
        # write_log(source_ip, "BLOCKED", "Null Port Scan")

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
        send_to_enforcer(source_ip, "BLOCK", "Xmas Port Scan")
        # write_log(source_ip, "BLOCKED", "Xmas Port Scan")


if __name__ == "__main__":
    print("\n[*] The Guardian Analyzer is Active.")
    while True:
        try:
            data, ip_address = udp_socket.recvfrom(1024)

            if ip_address[0] != sensor_ip:
                print(f"[?] Recieved Packets from unrecognized IP: {ip_address[0]}")
                continue

            try:
                json_string = data.decode("utf-8")
                packet_info = json.loads(json_string)
                try:
                    payload = packet_info["payload"]
                    signature = packet_info["signature"]
                except:
                    print("[?] Malformed Packet")
                    continue
            except:
                print("[?] Error Decoding Bytes or JSON")
                continue

            if check_signature(packet_info["payload"], packet_info["signature"]):
                analyze(packet_info["payload"])
            else:
                print("[?] Invalid Checksum")

        except KeyboardInterrupt:
            print("\n[*] Stopping The Guardian Analyzer...")
            udp_socket.close()
            break
        
