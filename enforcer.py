import subprocess
import json
import hmac
from hashlib import sha256
import socket
import datetime

with open("config.json", "r") as file:
    data = json.load(file)
    sensor_ip = data["sensor_ip"]
    analyzer_ip = data["analyzer_ip"]
    enforcer_ip = data["enforcer_ip"]
    enforcer_port = data["enforcer_port"]
    hmac_key = data["hmac_key"].encode("utf-8") ## Needs to be encoded to be used for HMAC key

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## TCP Socket (analyzer -> enforcer)
tcp_socket.bind((enforcer_ip, enforcer_port))

def write_log(ip, action, reason):
    log = {"time" : str(datetime.datetime.now()),
        "ip" : ip,
        "action" : action,
        "reason" : reason
        }
    
    with open("guardian_angel.log", "a") as file:
        file.write(json.dumps(log) + "\n")

def check_signature(payload, signature):
    message = json.dumps(payload)
    checksum = hmac.new(hmac_key, message.encode("utf-8"), sha256)
    return hmac.compare_digest(checksum.hexdigest(), signature)

def block(ip):
    print(f"[*] Configuring firewall to BLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has BLOCKED", ip)

def unblock(ip):
    print(f"[*] Configuring firewall to UNBLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has UNBLOCKED", ip)

def execute(payload): 
    if payload["action"] == "BLOCK":
        block(payload["source_ip"])

    elif payload["action"] == "UNBLOCK":
        unblock(payload["source_ip"])
    
    write_log(payload["source_ip"], payload["action"], payload["reason"])

if __name__ == "__main__":
    tcp_socket.listen(5)
    print("\n[*] The Guardian Enforcer is Active.")
    while True:
        try:
            client_socket, source_ip = tcp_socket.accept()

            if source_ip[0] != analyzer_ip:
                print(f"[?] Recieved Packets from unrecognized IP: {source_ip[0]}")
                continue

            data = client_socket.recv(1024)

            if data:
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
                    print("[?] Error Decoding Bytes or JSON")
                    print(error)
                    continue

                if check_signature(payload, signature):
                    execute(payload)
                else:
                    print("[?] Invalid Checksum")
        except KeyboardInterrupt:
            print("]\n[*] Stopping the Guardian Enforcer...")
            tcp_socket.close()
            break
        except Exception as error:
            print(f"\n[?] Unexpected error {error}")