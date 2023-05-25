class Error(Exception):
    error_messages = []

    def __init__(self, message, ip=None):
        super().__init__(message)
        if ip is not None:
            self.store_error(ip, message)

    @classmethod
    def store_error(cls, ip, message):
        cls.error_messages.append({ip: message})

class NonCriticalError(Error):
    def __init__(self, message, ip=None, calling_function=None):
        if calling_function is not None:
            message = f"{calling_function} failed: {message}"
        super().__init__(message, ip)
