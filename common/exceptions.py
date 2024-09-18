# Exception class for SSH connection errors.
class SSHConnectionError(Exception):
    def __init__(self, message):
        self.message = "SSHConnectionError: " + message

    def __str__(self):
        return self.message

