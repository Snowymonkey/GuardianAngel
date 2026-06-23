import subprocess
import json
import socket

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind(("127.0.0.1", 5006))

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
    print("\n[*] Guardian Enforcer Started.")
    while True:
        try:
            client_socket, source_ip = tcp_socket.accept()

            data = client_socket.recv(1024)

            if data:
                data = data.decode('utf-8')
                data = json.loads(data)
                print(data)
        except KeyboardInterrupt:
            print("]\n[*] Stopping Guardian Enforcer...")
    