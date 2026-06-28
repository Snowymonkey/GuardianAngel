import datetime
import json
import threading
import sqlite3
import hmac
from hashlib import sha256
import socket
from scapy.layers.inet import IP, TCP

with open("config.json", "r") as json_file:
    data = json.load(json_file)
    syn_threshold = data["syn_threshold"]
    ssh_threshold = data["ssh_threshold"]
    block_time = data["block_time"]
    dynamic_block_time = data["dynamic_block_time"]
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
    #     "total_blocks" : 0
    # }
}

block_times = {
    # "1.1.1.1" : {"start_time" : 0, "block_time" : 300},
    # "1.1.1.2" : {"start_time" : 0, "block_time" : 300},
    # "1.1.1.3" : {"start_time" : 0, "block_time" : 300},
    # "1.1.1.4" : {"start_time" : 0, "block_time" : 300}
}

timers = {
    # "1.1.1.1" : "thread object"
}

def serialize_and_store():
    con = sqlite3.connect("test.db") ## ip_tracker serialization
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS ip_tracker(ip, tracks)""")
    cur.execute("""DELETE FROM ip_tracker;""")
    for ip in ip_tracker:
        ip_tracker[ip]["syn"]["ports"] = list(ip_tracker[ip]["syn"]["ports"])
        serialized_text = json.dumps(ip_tracker[ip])
        cur.execute("INSERT INTO ip_tracker VALUES (?, ?)", (ip, serialized_text))
    con.commit()
    res = cur.execute("SELECT * FROM ip_tracker")
    print(res.fetchall())

    cur.execute("""CREATE TABLE IF NOT EXISTS blocks(ip, blocks)""") ## block_times serialization
    cur.execute("""DELETE FROM blocks;""")
    for ip in block_times:
        serialized_text = json.dumps(block_times[ip])
        cur.execute("INSERT INTO blocks VALUES (?, ?)", (ip, serialized_text))
    con.commit()
    res = cur.execute("SELECT * FROM blocks")
    print(res.fetchall())
    con.close()

def load_sql_database():
    con = sqlite3.connect("test.db")
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS ip_tracker(ip, tracks)""")
    res = cur.execute("SELECT * FROM ip_tracker")
    res = res.fetchall()
    for ip, data in res:
        ip_tracker[ip] = json.loads(data)
        ip_tracker[ip]["syn"]["ports"] = set(ip_tracker[ip]["syn"]["ports"])
    print(ip_tracker)

    cur.execute("""CREATE TABLE IF NOT EXISTS blocks(ip, blocks)""")
    res = cur.execute("SELECT * FROM blocks")
    res = res.fetchall()
    for ip, data in res:
        block_times[ip] = json.loads(data)
    print(block_times)
    con.close()

def create_ip_tracker():
    return {
        "syn" : {"time" : None, "ports" : set()},
        "ssh" : {"time" : None, "attempts" : 0},
        "status" : "OPEN",
        "total_blocks" : 0
    }

def load_sql_blocks():
    for ip in block_times:
        curr_time = datetime.datetime.now().timestamp()
        time_passed = curr_time - block_times[ip]["start_time"]
        if time_passed > block_times[ip]["block_time"]:
            block_times.pop(ip)
        else:
            remaining_time = block_times[ip]["block_time"] - time_passed
            block_timer = threading.Timer(remaining_time, schedule_unblock, args=[ip])
            block_timer.start()
            timers[ip] = block_timer

    print("SCHEDULED BLOCKS")

def execute_block(ip, reason):
    ip_tracker[ip]["total_blocks"] += 1
    if dynamic_block_time:
        calculated_time = calculate_block_time(ip_tracker[ip]["total_blocks"])
    else:
        calculated_time = block_time
    block_timer = threading.Timer(calculated_time, schedule_unblock, args=[ip])
    block_timer.start()
    timers[ip] = block_timer
    block_times[ip] = {"start_time" : datetime.datetime.now().timestamp(), "block_time" : calculated_time}
    ip_tracker[ip]["status"] = "BLOCKED"
    send_to_enforcer(ip, "BLOCK", reason)
    print(block_times)
    
def schedule_unblock(ip):
    ip_tracker[ip]["status"] = "OPEN"
    block_times.pop(ip)
    timers.pop(ip)
    send_to_enforcer(ip, "UNBLOCK", "Blocked Timer Complete")

def check_signature(payload, signature):
    message = json.dumps(payload)
    checksum = hmac.new(hmac_key, message.encode("utf-8"), sha256)
    return hmac.compare_digest(checksum.hexdigest(), signature)

def calculate_hmac(packet_info):
    message = json.dumps(packet_info)
    checksum = hmac.new(hmac_key, message.encode("utf-8"), sha256)
    return checksum.hexdigest()

def calculate_block_time(total_blocks):
    return max(block_time * (2 ** (total_blocks-3)), block_time)

def send_to_enforcer(ip, action, reason):

    payload = {"source_ip" : ip, "action" : action, "reason" : reason}
    signature = calculate_hmac(payload)

    packet_info = {
        "payload" : payload,
        "signature" : signature
    }

    packet_bytes = json.dumps(packet_info).encode("utf-8")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.connect((enforcer_ip, enforcer_port))
            tcp_socket.sendall(packet_bytes)

    except ConnectionRefusedError:
        print("[?] Enforcer Offline or Refused Connection")
    except Exception as error:
        print(f"[?] Unexpected Error: {error}")
    
    tcp_socket.close()


def analyze(packet):

    if not (packet["source_ip"] or packet["protocol_type"] or packet["time"]):
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
            execute_block(source_ip, "SSH Brute Force")

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
            execute_block(source_ip, "SYN Port Scan")

    elif packet["flags"] == 0: ## Null Scan Detection
        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Null port scan from", source_ip)
        execute_block(source_ip, "Null Port Scan")

    elif packet["flags"] == "FPU": ## Xmas Scan Detection

        source_ip = packet["source_ip"]
        timestamp = packet["time"]
        dport = packet["dport"]

        if source_ip in ip_tracker and ip_tracker[source_ip]["status"] == "BLOCKED":
            return
        
        if source_ip not in ip_tracker:
            ip_tracker[source_ip] = create_ip_tracker()
        
        print("[!] Xmas port scan from", source_ip)
        execute_block(source_ip, "Xmas Port Scan")

if __name__ == "__main__":
    load_sql_database()
    load_sql_blocks()
    print(block_times)
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
                except Exception as error:
                    print("[?] Malformed Packet")
                    print(error)
                    continue
            except Exception as error:
                print("[?] Error Decoding Bytes or Decoding JSON")
                print(error)
                continue

            if check_signature(payload, signature):
                try:
                    payload["source_ip"]
                    payload["protocol_type"]
                    analyze(payload)
                except:
                    continue
            else:
                print("[?] Invalid Checksum")

        except KeyboardInterrupt:
            print("\n[*] Stopping The Guardian Analyzer...")

            udp_socket.close()
            serialize_and_store()

            for ip in timers:
                timers[ip].cancel()
            break