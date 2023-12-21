import socket
import threading
import cmdline
import requests

class ServiceScanner():
    def __init__(self, ports_to_scan: set, socket_timeout: float, target_ip) -> None:
        self.ports_to_scan = ports_to_scan
        self.socket_timeout = socket_timeout
        self.target_ip = target_ip

    def scan(self):
        port_number_service_name_dictionary = {}
        empty_space = " "
        for port in self.ports_to_scan:
            if self.port_number_matcher(port) == "http":
                server = self.scan_http()
                port_number_service_name_dictionary.update({port : f"{self.port_number_matcher(port)}{empty_space*(6-len(str(self.port_number_matcher(port))))}| {server}"})
            elif self.port_number_matcher(port) == "https":
                server = self.scan_http()
                port_number_service_name_dictionary.update({port : f"{self.port_number_matcher(port)}{empty_space*(6-len(str(self.port_number_matcher(port))))}| {server}"})
            elif self.port_number_matcher(port) == "ssh":
                service = self.scan_ssh()
                port_number_service_name_dictionary.update({port: f"{self.port_number_matcher(port)}{empty_space*(6-len(str(self.port_number_matcher(port))))}| {service}"})
            else:
                banner = self.get_banner(port)
                if banner != "":
                    port_number_service_name_dictionary.update({port : f"{self.port_number_matcher(port)} | {banner}"})
                else:
                    port_number_service_name_dictionary.update({port : f"{self.port_number_matcher(port)}{empty_space*(6-len(str(self.port_number_matcher(port))))}|"})
        
        return port_number_service_name_dictionary

    def port_number_matcher(self, port: int):
        try:
            return socket.getservbyport(port)
        except:
            return ""
        
    def scan_http(self):
        request = requests.get(f"http://{self.target_ip}")
        return request.headers["Server"]

    def scan_https(self):
        request = requests.get(f"https://{self.target_ip}")
        return request.headers["Server"]

    def scan_ssh(self):
        scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scan_socket.connect((self.target_ip, 22))
        service = scan_socket.recv(1024)
        return service.decode().strip()

    def get_banner(self, port):
        try:
            scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scan_socket.connect((self.target_ip, port))
            scan_socket.send(b"test\n")
            banner = scan_socket.recv(1024)
            return banner.decode()
        except ConnectionResetError:
            return ""
        except UnicodeDecodeError:
            return ""