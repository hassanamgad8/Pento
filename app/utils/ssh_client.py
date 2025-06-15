import paramiko
import os
from typing import Optional

class SSHClient:
    def __init__(self, host=None, port=None, username=None, password=None):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Allow passing connection details per instance
        self.host = host or os.getenv('KALI_SSH_HOST', 'localhost')
        self.port = int(port or os.getenv('KALI_SSH_PORT', '22'))
        self.username = username or os.getenv('KALI_SSH_USER', 'kali')
        self.password = password or os.getenv('KALI_SSH_PASSWORD', 'kali')
        self._connect()
    
    def _connect(self):
        """Establish SSH connection to Kali VM"""
        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password
            )
        except Exception as e:
            raise Exception(f"Failed to connect to Kali VM: {str(e)}")
    
    def execute_command(self, command: str, timeout: Optional[int] = None) -> str:
        """Execute a command on the Kali VM and return the output
        
        Args:
            command: The command to execute
            timeout: Optional timeout in seconds for command execution
        """
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                raise Exception(f"Command execution failed: {error}")
            
            return output
        except Exception as e:
            raise Exception(f"Failed to execute command: {str(e)}")
    
    def close(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def upload_file_content(self, content: str, remote_path: str):
        import tempfile
        import os
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            tmp_path = tmp.name
        try:
            sftp = self.client.open_sftp()
            sftp.put(tmp_path, remote_path)
            sftp.close()
        finally:
            os.remove(tmp_path)
