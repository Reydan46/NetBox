import socket
import os

# define the IP ranges to scan, along with the start and end IP addresses for each range
ip_ranges = {
    '10.10.3.': {'start': 1, 'end': 254},
    '10.10.203.': {'start': 30, 'end': 39},
}

# loop through the IP ranges and check if port 22 is open for each IP address
for ip_range, ip_range_info in ip_ranges.items():
    start_ip = ip_range_info['start']
    end_ip = ip_range_info['end']

    # initialize a list to store IP addresses with open port
    ip_with_open_port = []

    # loop through the IP range and check if port 22 is open
    for i in range(start_ip, end_ip+1):
        ip_address = ip_range + str(i)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip_address, 22))
            if result == 0:
                ip_with_open_port.append(ip_address)
            s.close()
        except:
            pass
        
        # print progress indicator
        print(f"Scanned {ip_address}")

    # save IP addresses with open port to file
    file_name = ip_range[:-1] + "-devices.list"
    directory = "device_lists"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(os.path.join(directory, file_name), "w") as f:
        for ip in ip_with_open_port:
            f.write(ip + "\n")

    # print summary table
    print("IP Address\tPort")
    print("---------\t----")
    for ip in ip_with_open_port:
        print(ip + "\t22")

    print(f"\n{len(ip_with_open_port)} IP addresses with port 22 open have been saved to {file_name}\n")
