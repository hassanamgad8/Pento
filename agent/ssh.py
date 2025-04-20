import paramiko
from paramiko import SSHClient, AutoAddPolicy

def ssh_run_command(hostname: str,
                    port: int,
                    username: str,
                    password: str,
                    command: str) -> str:
    """
    Connects via SSH, runs `command`, and returns stdout.
    """
    try:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=hostname,
                       port=port,
                       username=username,
                       password=password,
                       look_for_keys=False,
                       allow_agent=False)

        stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode('utf-8').strip()
        err = stderr.read().decode('utf-8').strip()
        client.close()

        if err:
            return f"[!] SSH error:\n{err}"
        return out
    except Exception as e:
        return f"[X] SSH Exception: {e}"
