from flask import Flask, request, render_template, redirect, url_for, session
from agent.ssh import ssh_run_command

app = Flask(__name__)
app.secret_key = "super_secret_key"

USERNAME = "admin"
PASSWORD = "pento2025"

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Dummy authentication logic
        if username != "admin" or password != "admin":
            error = "Invalid username or password."
        else:
            return redirect("/home")

    return render_template("login.html", error=error)

@app.route("/home", methods=["GET"])
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("home.html")

# 👉 New Nmap page
@app.route("/nmap", methods=["GET"])
def nmap_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("nmap.html")

# 👉 Nmap Scan Handler
@app.route("/scan-nmap", methods=["POST"])
def scan_nmap():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    target = request.form.get("target")

    ssh_config = {
        "hostname": "192.168.80.133",
        "port": 22,
        "username": "kali",
        "password": "kali"
    }

    command = f"nmap -sV {target}"
    output = ssh_run_command(**ssh_config, command=command)
    return render_template("results.html", target=target, output=output)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
