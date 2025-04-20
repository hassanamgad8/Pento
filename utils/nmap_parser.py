import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_output: str):
    """
    Parses XML Nmap output and returns structured scan data.
    """
    result = {
        "host": None,
        "hostname": None,
        "status": None,
        "os": [],
        "ports": []
    }

    try:
        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            address_elem = host.find("address")
            if address_elem is not None:
                result["host"] = address_elem.get("addr")

            status_elem = host.find("status")
            if status_elem is not None:
                result["status"] = status_elem.get("state")

            hostname_elem = host.find(".//hostnames/hostname")
            if hostname_elem is not None:
                result["hostname"] = hostname_elem.get("name")

            # OS details (if -O used)
            for osmatch in host.findall(".//os/osmatch"):
                os_name = osmatch.get("name")
                accuracy = osmatch.get("accuracy")
                if os_name:
                    result["os"].append(f"{os_name} ({accuracy}%)")

            # Ports
            for port in host.findall(".//port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"

                service_elem = port.find("service")
                service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                version = service_elem.get("version", "") if service_elem is not None else ""
                product = service_elem.get("product", "") if service_elem is not None else ""

                result["ports"].append({
                    "port": portid,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version
                })

        return result

    except Exception as e:
        return {"error": f"Failed to parse Nmap output: {e}"}
