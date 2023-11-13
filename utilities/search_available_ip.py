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
    def get_subnet():
        while True:
            subnet = input('Enter subnet number: ')
            desired_network = calculate_subnet_mask(subnet)
            if desired_network:
                return desired_network
    
    def calculate_subnet_mask(ip_address):
        # Iterate through possible prefix lengths from 1 to 32
        # First valid prefix length is returned
        for prefix_length in range(1, 33):
            try:
                return (ipaddress.ip_network((f"{ip_address}/{prefix_length}")))
            except ValueError:
                continue
        print("No valid subnet mask found.")
        return None
    
    def find_free_ip(network):
        prefixes = NetboxDevice.netbox_connection.ipam.prefixes.filter(contains=str(network.network_address))
        available_ip = None
        for prefix in prefixes:
            try:
                available_ip = prefix.available_ips.list()[0]['address']
                print(f'\nFirst available IP:\n{available_ip}\n')
                break
            except IndexError:
                pass
        if available_ip is None:
            logger.info(f'No available IP was found')
        return available_ip

    load_dotenv(dotenv_path='.env')
    NetboxDevice.create_connection()
    
    desired_network = get_subnet()  # Вычисление желаемой подсети
    logger.info(f'Searching available IP in {desired_network} network...')   
    available_ip = find_free_ip(desired_network)
    
    # Получение роутеров из Netbox
    NetboxDevice.get_roles()
    router_vms = NetboxDevice.get_vms_by_role(role=NetboxDevice.roles['Router'])
    
    # Поиск подсети на роутерах
    ips_in_network = []
    for i in router_vms:
        router = Router(i)
        router.arp_table = SNMPDevice.get_network_table(router.netbox.primary_ip.address.split('/')[0], oid.general.arp_mac, 'IP-MAC')
        logger.debug(f'ARP-table for {router.netbox.name} was retrieved')
        if not available_ip:
            ips_in_network = [ip for ip in router.arp_table if ipaddress.ip_address(ip) in desired_network]
            if ips_in_network:
                break
        else:
            for ip in router.arp_table:
                if ip == available_ip.split('/')[0]:
                    print(f'IP {available_ip} is in use')
                    break
    if not ips_in_network:
        if available_ip:
            print(f'\nIP {available_ip} is free')
            return available_ip
        else:
            raise Error("The network is not found. Try another subnet's number.")
    else:
        print(f'\nIPs that already used:')
        for ip in ips_in_network:
            print(ip)
        print()
        return None

def fetch_desired_ip():
    desired_ip = input('Enter IP for check: ')
    # Ищем префикс в Netbox для введенного IP
    try:
        prefix = NetboxDevice.get_prefix_for_ip(desired_ip).prefix.split("/")[1]
        ip_with_prefix = f'{desired_ip}/{prefix}'
    except Exception:
        print('IP out of range')
        return 'IP out of range'
    # Ищем IP в Netbox
    ip_in_netbox = NetboxDevice.get_netbox_ip(ip_with_prefix, create=False)
    if not ip_in_netbox:
        print('IP is free')
        return 'IP is free'

    # Проверяем есть ли привязанные к IP объекты
    object_assigned = ip_in_netbox[0].assigned_object
    if object_assigned:
        if hasattr(object_assigned, 'device'):
            message = f'There is device {object_assigned.device} with IP {ip_in_netbox[0].address}'
        elif hasattr(object_assigned, 'virtual_machine'):
            message = f'There is VM {object_assigned.virtual_machine} with IP {ip_in_netbox[0].address}'
        else:
            message = 'IP is occupied by an unknown object'
        print(message)
        return message
    else:
        description = ip_in_netbox[0].description
        message = f'There is no assigned object (IP {description})'
        print(message)
        return message


network_isnot_found = True
while network_isnot_found:
    try:
        free_ip = main()
        network_isnot_found = False
    except Error:
        continue
while not free_ip:
    fetch_desired_ip()