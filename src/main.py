import cmdline
import scanner
import service_scanner

if __name__ == "__main__":
    (scan_version, ports, socket_timeout, target_ip, threading) = cmdline.get_arguments()
    cmdline.print_logo()
    try:
        cmdline.print_status("Starting to scan...")
        port_scanner = scanner.Scanner(target_ip, ports, socket_timeout, threading)
        (open_ports, closed_ports) = port_scanner.scan()
        cmdline.print_status("Finished scanning")
        if scan_version:
            cmdline.print_status("Fetshing port services and infos")
            port_service_scanner = service_scanner.ServiceScanner(open_ports, socket_timeout, target_ip)
            open_ports_dictionary = port_service_scanner.scan()
            cmdline.print_status("Gathering results")
            cmdline.print_results_dict(open_ports_dictionary=open_ports_dictionary, closed_ports=closed_ports)
        else:
            cmdline.print_status("Gathering results")
            cmdline.print_results(open_ports, closed_ports)
    except KeyboardInterrupt:
        cmdline.print_quit()
    except Exception as error:
        cmdline.print_error(f"An error accured: {error}")
