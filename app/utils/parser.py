import re

def parse_user_input(message):
    message = message.lower()
    if "nmap" in message:
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", message)
        return {"action": "nmap", "target": ip.group() if ip else None}
    elif "whois" in message or "info about" in message:
        domain = re.search(r"[\w\.-]+\.\w+", message)
        return {"action": "whois", "target": domain.group() if domain else None}
    elif "domain enumeration" in message:
        domain = re.search(r"[\w\.-]+\.\w+", message)
        return {"action": "domain_enum", "target": domain.group() if domain else None}
    elif "subdomain" in message:
        domain = re.search(r"[\w\.-]+\.\w+", message)
        return {"action": "subdomain_enum", "target": domain.group() if domain else None}
    elif "wordpress" in message:
        domain = re.search(r"[\w\.-]+\.\w+", message)
        return {"action": "wordpress_scan", "target": domain.group() if domain else None}
    elif "xss" in message or "sql" in message:
        url = re.search(r"http[s]?://[^\s]+", message)
        return {"action": "ai_scan", "target": url.group() if url else None}
    elif "active directory" in message:
        return {"action": "active_directory", "target": None}
    else:
        return {"action": "unknown"}
