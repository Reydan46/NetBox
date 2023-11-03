import re
import os
import sys
from prettytable import PrettyTable

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from errors import Error, NonCriticalError
from log import logger
from netbox import NetboxDevice

class IP:
    def __init__(self, ip):
        self.ip = ip
        self.netbox_prefix = NetboxDevice.get_prefix_for_ip(ip)
        self.ip_with_prefix = f'{ip}/{self.netbox_prefix.prefix.split("/")[1]}'

NetboxDevice.create_connection()

with open('dhcpd.leases', 'r') as file:
    logger.info('Reading file...')
    file_content = file.read()

ip_pattern = r'[0-9]+(?:\.[0-9]+){3}'
ip_list = re.findall(ip_pattern, file_content)
for ip in ip_list:
    try:
        logger.info(f'{ip} handling...')
        ip_obj = IP(ip)
        NetboxDevice.create_ip_address(ip_obj.ip, ip_obj.ip_with_prefix)
    except Error as e:
        continue

# ВЫВОД ОШИБОК
# ========================================================================
# Merge the error messages into a single list
all_error_messages = Error.error_messages + NonCriticalError.error_messages
# Flatten the list of dictionaries into a single dictionary
merged_error_messages = {
    k: v for d in all_error_messages for k, v in d.items()}
# Print errors in a PrettyTable
if merged_error_messages:
    table = PrettyTable(["IP", "Error"])
    table.align["IP"] = "l"
    table.align["Error"] = "l"
    table.max_width = 75
    table.valign["Error"] = "t"
    for ip, error_message in merged_error_messages.items():
        table.add_row([ip, error_message])
    logger.info(f'The work is completed.\n{table}')