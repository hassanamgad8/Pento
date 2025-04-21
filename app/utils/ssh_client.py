import paramiko
import time

def run_ssh_command(host, port, username, password, command):
    try:
        print("🔗 Connecting to SSH...")
        start_time = time.time()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=username, password=password)
        print("✅ SSH connection established.")

        output = "✅ Connected to SSH successfully.\n"
        output += f"🛠 Running command: {command}\n\n"

        stdin, stdout, stderr = ssh.exec_command(command)

        # Live-style capture for backend (optional for now)
        while True:
            line = stdout.readline()
            if not line:
                break
            print("📤", line.strip())  # Log output in terminal
            output += line

        error = stderr.read().decode()
        if error:
            print("⚠️ STDERR:", error)

        ssh.close()

        duration = round(time.time() - start_time, 2)
        output += f"\n⏱ Scan completed in {duration} seconds."

        return output + (f"\n⚠️ Errors:\n{error}" if error else "")

    except Exception as e:
        print(f"❌ SSH FAILED: {e}")
        return f"❌ SSH connection failed: {str(e)}"
