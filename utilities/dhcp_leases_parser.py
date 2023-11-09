import os
import sys
import re

from dotenv import load_dotenv

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from log import logger
from netbox import NetboxDevice
from error_handling import print_errors
from errors import Error, NonCriticalError
from pfsense import download_config

class IP:
    def __init__(self, ip):
        self.ip = ip
        self.netbox_prefix = NetboxDevice.get_prefix_for_ip(ip)
        self.ip_with_prefix = f'{ip}/{self.netbox_prefix.prefix.split("/")[1]}'

def collect_ips(device):
    # with open(filepath, 'r') as file:
    #     logger.info('Reading file...')
    #     file_content = file.read()
    file_content = download_config(device)
    ip_pattern = r'[0-9]+(?:\.[0-9]+){3}'
    ip_list = re.findall(ip_pattern, file_content)
    return ip_list

def process_ips(ip_list):
    for ip in ip_list:
        try:
            logger.info(f'{ip} handling...')
            ip_obj = IP(ip)
            NetboxDevice.create_ip_address(ip_obj.ip, ip_obj.ip_with_prefix)
        except Error as e:
            continue

# Загрузка переменных окружения из .env
load_dotenv(dotenv_path='.env')
NetboxDevice.create_connection()
NetboxDevice.get_roles()
router_devices = NetboxDevice.get_vms_by_role(role=NetboxDevice.roles['Router'])
for router in router_devices:
    ip_list = collect_ips(router)
    process_ips(ip_list)
print_errors()