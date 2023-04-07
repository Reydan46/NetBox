import argparse
import os
import platform
import socket


def ping_ip(ip, retries=3, timeout=500, logfile=None):
    ping_str = "-n 1 -w " + \
        str(timeout) if platform.system().lower(
        ) == "windows" else "-c 1 -W " + str(timeout / 1000)
    for i in range(retries):
        response = os.system("ping " + ping_str + " " + ip)
        if logfile is not None:
            with open(logfile, "a") as f:
                f.write(f"ping {ping_str} {ip} returned {response}\n")
        if response == 0:
            return True
    return False


# define the IP ranges to scan
ip_ranges = {
    '10.20.3.0/24': {'start_ip': '10.20.3.10', 'end_ip': '10.20.3.19'},
    # '192.168.2.0/24': {'start_ip': '192.168.2.1', 'end_ip': '192.168.2.10'},
    # '10.0.0.0/24': {'start_ip': '10.0.0.1', 'end_ip': '10.0.0.5'}
}

# parse the command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('scan_type', choices=['port', 'icmp'],
                    help='the type of scan to perform')
parser.add_argument('--port', type=int, default=22,
                    help='the port number to scan')
args = parser.parse_args()

# Clear log file
logfile = f"scanner.log"
with open(logfile, "w"):
    pass

# loop through the IP ranges and perform the selected scan type
for network, ip_range in ip_ranges.items():
    start_ip = ip_range['start_ip']
    end_ip = ip_range['end_ip']
    prefix = '.'.join(start_ip.split('.')[:-1]) + '.'

    # initialize a list to store IP addresses with the selected scan result
    ip_results = []

    # loop through the IP range and perform the selected scan type on each IP address
    for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        ip_address = prefix + str(i)

        if args.scan_type == 'port':
            # perform port scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, args.port))
            if result == 0:
                ip_results.append(ip_address)
            sock.close()

        elif args.scan_type == 'icmp':
            # perform ICMP ping
            try:
                if ping_ip(ip_address, logfile=logfile):
                    ip_results.append(ip_address)
            except:
                pass

        # print progress indicator
        print(f"Scanned {ip_address}")

    # save results to file
    network_prefix = '.'.join(network.split('.')[:-1])
    file_name = f"{network_prefix}_{args.scan_type}-scan-results.list"
    directory = "device_lists"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(os.path.join(directory, file_name), "w") as f:
        for ip in ip_results:
            f.write(ip + "\n")

    # print summary table
    print(f"\n{len(ip_results)} IP addresses with {args.scan_type} scan result are found in the network {network}\n")
