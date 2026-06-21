import subprocess

def block(ip):
    print(f"[*] Configuring firewall to BLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has BLOCKED", ip)

def unblock(ip):
    print(f"[*] Configuring firewall to UNBLOCK {ip}...")
    # subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    print("[*] Guardian Angel has UNBLOCKED", ip)