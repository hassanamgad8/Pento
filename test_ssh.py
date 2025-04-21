from app.utils.ssh_client import run_ssh_command
import os
from dotenv import load_dotenv

# Load environment variables from .env if available
load_dotenv()

# 🔐 Kali VM SSH credentials (replace or use .env)
host = os.getenv("KALI_HOST")
port = int(os.getenv("KALI_PORT"))
username = os.getenv("KALI_USER")
password = os.getenv("KALI_PASS")

# 🌐 Target IP for nmap scan
target_ip = "192.168.1.1"  # ← change this to any IP you want to scan

# 🧪 Nmap command
nmap_command = f"nmap -A {target_ip}"

print(f"🔧 Running Nmap on {target_ip} via SSH to {host}...")
output = run_ssh_command(host, port, username, password, nmap_command)
print("\n📄 Nmap Output:\n")
print(output)
