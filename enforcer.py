import subprocess
import socket

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def block(ip):
    print(f"[*] Configuring firewall to BLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has BLOCKED", ip)

def unblock(ip):
    print(f"[*] Configuring firewall to UNBLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has UNBLOCKED", ip)

if __name__ == "__main__":
    while True:
        try:
            tcp_socket.listen(5)
            client_socket, source_ip = tcp_socket.accept()

            print(source_ip)

            data = client_socket.recv(1024)
        except:
            print("[?] Error Listening for Packets")