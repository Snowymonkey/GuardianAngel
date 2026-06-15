import paramiko

ssh = paramiko.SSHClient()

def connect():
    metasploitable_ip = "192.168.128.5" 
    username = "msfadmin"
    password = "msfadmin"

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Policy to automatically add unknown SSH host keys

    print(f"[*] Attempting connection to Metasploitable at {metasploitable_ip}...")

    try:
        ssh.connect(
            hostname=metasploitable_ip,
            username=username,
            password=password,
            timeout=10,
            disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']} # Connect while explicitly allowing legacy algorithms
        )

    except Exception as e:
        print(f"[-] Connection failed or timed out.")
        print(f"[-] Error details: {e}")

def dissconnect():
    ssh.close()

def execute(command):
    stdin, stdout, stderr = ssh.exec_command(command)
    print(stdout.read().decode("utf-8"))