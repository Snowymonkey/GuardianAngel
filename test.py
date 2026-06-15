import paramiko

def test_remote_connection():
    metasploitable_ip = "192.168.128.5" 
    username = "msfadmin"
    password = "msfadmin"

    # 2. Initialize the SSH client
    ssh = paramiko.SSHClient()

    # 3. Policy to automatically add unknown SSH host keys
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[*] Attempting connection to Metasploitable at {metasploitable_ip}...")

    try:
        # 4. Connect while explicitly allowing legacy algorithms
        ssh.connect(
            hostname=metasploitable_ip,
            username=username,
            password=password,
            timeout=10,
            disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']}
        )
        print("[+] Connection successful!")

        # 5. Define a safe test command to see who we are logging in as
        test_command = "whoami && uname -a"
        print(f"[*] Executing command: '{test_command}'")

        # 6. Run the command
        # stdin = input stream, stdout = standard output, stderr = error output
        stdin, stdout, stderr = ssh.exec_command(test_command)

        # 7. Read and decode the results
        output = stdout.read().decode('utf-8').strip()
        errors = stderr.read().decode('utf-8').strip()

        if output:
            print(f"[─] Command Output:\n{output}")
        if errors:
            print(f"[!] Command Errors:\n{errors}")

    except Exception as e:
        print(f"[-] Connection failed or timed out.")
        print(f"[-] Error details: {e}")
        
    finally:
        # 8. Always close the connection cleanly
        ssh.close()
        print("[*] SSH Session closed.")

if __name__ == "__main__":
    test_remote_connection()