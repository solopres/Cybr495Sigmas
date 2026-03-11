from base.module import BaseModule
import ssl
import socket


class TLSCheck(BaseModule):

    name = "tls_check"
    category = "misconfig"

    description = "Check TLS configuration and supported protocol versions"

    requires = [
        "service_https"
    ]

    provides = [
        "tls_configuration"
    ]

    severity = "medium"

    def __init__(self, target, port=443):
        super().__init__(target)
        self.port = port


    def check_tls_versions(self):
        """Attempt TLS handshake with different protocol versions"""

        supported_versions = []

        versions = {
            "TLSv1": ssl.PROTOCOL_TLSv1,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2
        }

        for name, proto in versions.items():

            try:
                context = ssl.SSLContext(proto)

                with socket.create_connection((self.target, self.port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target):
                        supported_versions.append(name)

            except Exception:
                pass

        return supported_versions


    def run(self):

        tls_versions = self.check_tls_versions()

        result = {
            "module": self.name,
            "target": self.target,
            "port": self.port,
            "supported_tls_versions": tls_versions,
            "vulnerable": False
        }

        # Example misconfiguration rule
        if "TLSv1" in tls_versions or "TLSv1.1" in tls_versions:
            result["vulnerable"] = True

        return result