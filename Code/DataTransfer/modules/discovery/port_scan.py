from base.module import BaseModule
import socket

class PortScan(BaseModule):

    name = "port_scan"
    description = "Simple port check"
    category = "discovery"

    def run(self):

        ports = [22, 80, 443]
        open_ports = []

        for port in ports:
            try:
                s = socket.create_connection((self.target, port), timeout=1)
                open_ports.append(port)
                s.close()
            except:
                pass

        return {
            "module": self.name,
            "target": self.target,
            "open_ports": open_ports
        }