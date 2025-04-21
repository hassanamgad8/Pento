from flask import Blueprint, request, jsonify, render_template
from app.utils.ssh_client import run_ssh_command
from app.utils.parser import parse_user_input
from app.utils.ai_module import run_ai_scan

chatbot_bp = Blueprint("chatbot", __name__)

@chatbot_bp.route("/chatbot_component")
def chatbot_component():
    return render_template("components/chatbot_component.html")


@chatbot_bp.route("/api/chat", methods=["POST"])
def chat_api():
    try:
        data = request.get_json()
        message = data.get("message")
        print(f"🛠 User message: {message}")

        parsed = parse_user_input(message)
        print(f"🧠 Parsed result: {parsed}")

        target = parsed.get("target")
        action = parsed.get("action")

        # Update with your actual Kali VM SSH info
        host = "172.20.10.3"
        port = 22
        username = "kali"
        password = "kali"

        # Action routing
        if action == "nmap":
            command = f"nmap -A {target}"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        elif action == "whois":
            command = f"whois {target}"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        elif action == "domain_enum":
            command = f"amass enum -d {target}"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        elif action == "subdomain_enum":
            command = f"sublist3r -d {target}"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        elif action == "wordpress_scan":
            command = f"wpscan --url {target} --enumerate u,vp,vt"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        elif action == "ai_scan":
            result = run_ai_scan(target)
            return jsonify({"reply": result})

        elif action == "active_directory":
            command = "bloodhound-python -c All"
            result = run_ssh_command(host, port, username, password, command)
            return jsonify({"reply": result})

        else:
            return jsonify({"reply": "❌ I didn’t understand. Try: Scan 192.168.1.1 with nmap"})

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"reply": f"❌ Error occurred: {str(e)}"})
