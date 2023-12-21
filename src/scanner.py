import socket
import multiprocessing.pool 
import cmdline
import threading
import sys

class Scanner():
    def __init__(self, target_ip, ports_to_scan, socket_timeout: float, use_threading: bool) -> None:
        self.open_ports = set()
        self.closed_ports = set()
        self.socket_timeout = socket_timeout
        self.target_ip = target_ip
        self.ports_to_scan = ports_to_scan
        self.use_threading = use_threading

    def scan(self):
        try:
            if self.use_threading:
                
                threads = set()

                cmdline.print_status("Spawning threads")

                for port in self.ports_to_scan:
                    thread = threading.Thread(target=self.scan_port_tcp, args=(port,))
                    thread.start()
                    threads.add(thread)

                cmdline.print_status("waiting for all threads to fininsh")

                for thread in threads:
                    thread.join()
            else:
                cmdline.print_status("Running without threads")
                for port in self.ports_to_scan:
                    self.scan_port_tcp(port)
                    
            return (self.open_ports, self.closed_ports)
        except KeyboardInterrupt:
            cmdline.print_quit()
            exit()

    def scan_port_tcp(self, port: int):
        scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scan_socket.settimeout(self.socket_timeout)
        try:
            scan_socket.connect((self.target_ip, port))
            self.open_ports.add(port)
        except KeyboardInterrupt:
            cmdline.print_quit()
            sys.exit()
        except:
            self.closed_ports.add(port)