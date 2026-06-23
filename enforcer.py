import subprocess
import json
import socket
import datetime

with open("config.json", "r") as file:
    data = json.load(file)
    sensor_ip = data["sensor_ip"]
    analyzer_ip = data["analyzer_ip"]
    enforcer_ip = data["enforcer_ip"]

    enforcer_port = data["enforcer_port"]

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

def block(ip):
    print(f"[*] Configuring firewall to BLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has BLOCKED", ip)

def unblock(ip):
    print(f"[*] Configuring firewall to UNBLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has UNBLOCKED", ip)

if __name__ == "__main__":
    tcp_socket.listen(5)
    print("\n[*] The Guardian Enforcer is Active.")
    while True:
        try:
            client_socket, source_ip = tcp_socket.accept()

            data = client_socket.recv(1024)

            if data:
                data = data.decode('utf-8')
                data = json.loads(data)
                print(data)
        except KeyboardInterrupt:
            print("]\n[*] Stopping the Guardian Enforcer...")
            break
    