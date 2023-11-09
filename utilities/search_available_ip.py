import os
import sys
from dotenv import load_dotenv

import ipaddress

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

import oid.general
from log import logger
from snmp import SNMPDevice
from netbox import NetboxDevice
from error_handling import print_errors
from errors import Error, NonCriticalError


class Router:
    def __init__(self, netbox_item):
        self.netbox = netbox_item


def main():
    desired_network = ipaddress.ip_network(input('Enter network for search: '))
    logger.info(f'Searching for available IP in {desired_network} network...')

    # Получение роутеров из Netbox
    load_dotenv(dotenv_path='.env')
    NetboxDevice.create_connection()
    NetboxDevice.get_roles()
    router_vms = NetboxDevice.get_vms_by_role(role=NetboxDevice.roles['Router'])

    # Поиск подсети на роутерах
    for i in router_vms:
        router = Router(i)
        router.arp_table = SNMPDevice.get_network_table(router.netbox.primary_ip.address.split('/')[0], oid.general.arp_mac, 'IP-MAC')
        logger.debug(f'ARP-table for {router.netbox.name} was retrieved')
        ips_in_network = [ip for ip in router.arp_table if ipaddress.ip_address(ip) in desired_network]
        if ips_in_network:
            break
    if not ips_in_network:
        raise Error('The network is not found', ip=desired_network)
    else:
        for ip in ips_in_network:
            print(ip)
        return ips_in_network

def check_ip():
    desired_ip = input('Enter IP for check: ')
    ip_with_prefix = f'{desired_ip}/{NetboxDevice.get_prefix_for_ip(desired_ip).prefix.split("/")[1]}'
    ip_in_netbox = NetboxDevice.get_netbox_ip(ip_with_prefix, create=False)
    if not ip_in_netbox:
        message = 'IP is free'
        print(message)
        return message
    else:
        if ip_in_netbox[0].assigned_object:
            if hasattr(ip_in_netbox[0].assigned_object, 'device'):
                message = f'There is device {ip_in_netbox[0].assigned_object.device} with IP {ip_in_netbox[0].address}'
            elif hasattr(ip_in_netbox[0].assigned_object, 'virtual_machine'):
                message = f'There is VM {ip_in_netbox[0].assigned_object.virtual_machine} with IP {ip_in_netbox[0].address}'
            else:
                message = 'IP is occupied by an unknown object'
            print(message)
            return message
        else:
            message = 'IP in Netbox, but has no assigned object'
            print(message)
            return message

main()
check_ip()