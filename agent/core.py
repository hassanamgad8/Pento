from agent.ssh import ssh_run_command
from utils.nmap_parser import parse_nmap_xml

def run_agent(target: str) -> str:
    ssh_config = {
        "hostname": "192.168.80.133",
        "port": 22,
        "username": "kali",
        "password": "kali"
    }

    command = f"nmap -sV -oX - {target}"
    raw_output = ssh_run_command(**ssh_config, command=command)
    parsed = parse_nmap_xml(raw_output)

    if "error" in parsed:
        return parsed["error"]

    # Create readable string
    display = f"Scan results for {parsed['host']}:\n"
    for port in parsed["ports"]:
        display += f"- Port {port['port']}/{port['protocol']}: {port['service']} {port['version']} [{port['state']}]\n"

    return display
