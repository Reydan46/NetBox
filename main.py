import csv
import ipaddress
import re
import argparse
import logging

import pandas as pd
from prettytable import PrettyTable

import oid.general
from errors import Error, NonCriticalError
from log import logger
from netbox import NetboxDevice
from snmp import SNMPDevice

from config import *
from custom_modules.mail_sender import send_email_with_attachment


# ========================================================================
#                                  Классы
# ========================================================================
class Site:
    @classmethod
    def get_all_ips(cls):
        cls.netbox_ips_all = list(NetboxDevice.get_netbox_objects(
            'ipam.ip_addresses',
            action='all',
        ))
        logger.info(f'{len(cls.netbox_ips_all)} IPs retrieved from NetBox')
    
    @staticmethod
    def convert_networks(subnets_list):
        return [ipaddress.ip_network(subnet) for subnet in subnets_list]
    
    def __init__(self, site_slug, prefix, gw=None):
        self.site_slug = site_slug
        self.ip_ranges = [ipaddress.ip_network(x.strip(), strict=False) for x in prefix.split(',')]
        self.gw = gw

    def check_mac_persistence(self):
        # Function to check if a MAC address is known
        def is_mac_known(mac):
            with open(known_macs_filename, 'r') as file:
                known_macs = file.read().splitlines()
            return mac in known_macs

        # Function to add a MAC address to the known list
        def add_mac_to_known(mac):
            with open(known_macs_filename, 'a') as file:
                file.write(mac + '\n')

        if hasattr(self, 'arp_table'):
            # Loop through arp_table items
            for key, value in self.arp_table.items():
                key_ip = ipaddress.ip_address(key)  # Convert the key to an IP address object for comparison
                # Check if the MAC address is already known
                if is_mac_known(value):
                    logger.debug(f'MAC: {value} is already known. Skipping...')
                    continue  # Skip further checks for this MAC address

                if any(key_ip in subnet for subnet in self.convert_networks(protected_networks)):
                    mac_found = False
                    mac_for_notification = MacNotification(key, value)
                    for netbox_ip in self.netbox_ips_all:
                        if value.lower() in netbox_ip.description:
                            mac_found = True
                            mac_for_notification.url = clean_url(netbox_ip.url)
                            logger.debug(f'{mac_for_notification.url}')
                    if not mac_found:
                        logger.debug(f'Value: {value} NOT found in Netbox IP Description.')
                        netbox_prefix = NetboxDevice.get_prefix_for_ip(key)
                        ip_with_prefix = f'{key}/{str(netbox_prefix).split("/")[-1]}'
                        NetboxDevice.create_ip_address(key, ip_with_prefix, description=value)
                    mac_for_notification_list.append(mac_for_notification)
                    add_mac_to_known(value)


class NetworkDevice:
    # Инициализация списка сайтов
    # =====================================================================
    sites = []

    @classmethod
    def initialize_sites(cls):
        with open(switches_file) as f:
            reader = csv.DictReader(f, delimiter=';')
            Site.get_all_ips()
            for row in reader:
                site = Site(row['site'], row['prefix'], row.get('gw', None))
                # Заполнение экземпляра сайта данными
                cls.__populate_site_data(site)
                site.check_mac_persistence()
                cls.sites.append(site)
            logger.info('-' * 40)

    @classmethod
    def __populate_site_data(cls, site):
        site.netbox_vlans_objs = NetboxDevice.get_vlans(site.site_slug)
        if not site.gw:
            return
        # Получаем arp-таблицу с марша площадки
        try:
            site.arp_table = SNMPDevice.get_network_table(
                site.gw, oid.general.arp_mac, 'IP-MAC')
            site.subnets = cls.get_subnets(SNMPDevice.get_network_table(
                site.gw, oid.general.ip_mask, 'IP-MASK'))  # Получаем таблицу подсетей площадки
        except Error as e:
            site.GW = None
            return

    @staticmethod
    def get_subnets(ip_table):
        return [str(subnet.network_address) + '/' + str(subnet.prefixlen)
                for ip, mask in ip_table.items()
                if (subnet := ipaddress.IPv4Network(ip + '/' + mask, strict=False)).is_private
                and str(subnet.network_address) not in ("0.0.0.0", "127.0.0.0")]
    # ====================================================================

    def __init__(self, ip_address, role, community_string, vm, snmp_version):
        self.ip_address: str = ip_address
        self.community_string: str = community_string
        self.role: str = role
        self.vm: bool = vm
        self.arp_table = None
        self.snmp_version = snmp_version
        self.physical_interfaces = []

    # Временный для дебага - потом удалить
    def print_attributes(self):
        print('NetworkDevice attributes:')
        # Печатаем аттрибуты экземпляра
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}")
        # Затем аттрибуты класса
        for attribute, value in vars(self.__class__).items():
            if not attribute.startswith('_') and not callable(value):
                print(f"{attribute}: {value}")
        print('=' * 80)

    # Find and set the site_slug attribute based on the IP address
    def find_site_slug(self):
        # Check if the NetworkDevice IP address is in one of the IP ranges
        found = False
        for site in NetworkDevice.sites:
            for ip_range in site.ip_ranges:
                if ipaddress.ip_address(self.ip_address) in ip_range:
                    self.site_slug = site.site_slug
                    found = True  # set flag to true as matching IP range is found
                    break
            if found:  # break the outer loop as well if matching IP range was found
                break
        else:
            # Raise an error if the site is not found for the given IP address
            raise Error(
                f"Site not found for IP address {self.ip_address}", self.ip_address)

    # Получение аттрибутов сайта для устройства
    # =====================================================================
    def __get_site_attribute(self, attribute):
        site = next(
            (s for s in NetworkDevice.sites if s.site_slug == self.site_slug), None)
        if not site:
            return None

        try:
            if hasattr(site, attribute):
                return getattr(site, attribute)
            else:
                raise NonCriticalError(
                    f"No {attribute} for site {site.site_slug}", self.ip_address)
        except NonCriticalError:
            pass

        return None

    def find_attribute(self, attribute):
        value = self.__get_site_attribute(attribute)
        if value is not None:
            setattr(self, attribute, value)

    # =====================================================================

    def get_role_from_hostname(self):
        role_out = re.search(role_pattern, self.hostname)
        if role_out:
            self.role = role_mapping.get(role_out.group(1))
        else:
            raise Error("Could not determine role from hostname",
                        self.ip_address)

    # Проверка наличия вланов устройства в netbox
    # =====================================================================
    @staticmethod
    def __get_all_vlans(physical_interfaces):
        untagged_vlans = {
            interface.untagged for interface in physical_interfaces if interface.untagged is not None}
        tagged_vlans = {vlan for interface in physical_interfaces if interface.tagged is not None for vlan in
                        interface.tagged}
        return untagged_vlans | tagged_vlans

    def check_vlans(self):
        all_vlans = self.__get_all_vlans(self.physical_interfaces)
        netbox_vids = [str(vlan.vid) for vlan in self.netbox_vlans_objs]
        missing_vlans = [vlan for vlan in all_vlans if vlan not in netbox_vids]

        if missing_vlans:
            NonCriticalError(
                f"Missing VLANs: {missing_vlans}", self.ip_address)
    # =====================================================================


class Interface:
    def __init__(self, kind) -> None:
        self.kind = kind


class HostInterface(Interface):
    def __init__(self, name, untagged, ip_address, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = name
        self.type = 'other'
        self.untagged = untagged
        self.tagged = []
        self.ip_address = ip_address
        self.ip_with_prefix = self.determine_ip_with_prefix()

    def determine_ip_with_prefix(self):
        for site in switch_network_device.sites:
            if switch_network_device.site_slug == site.site_slug:
                return self.get_ip_with_subnet_prefix(site.subnets)

    def get_ip_with_subnet_prefix(self, subnet_list):
        for subnet in subnet_list:
            if self.ip_in_subnet(self.ip_address, subnet):
                return f'{self.ip_address}/{subnet.split("/")[-1]}'

    @staticmethod
    def ip_in_subnet(ip, subnet):
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)


class CableConnectionError:
    body_text = """
        <html>
        <head>
        <style>
        p { font-family: Arial, sans-serif; font-size: 12pt; }
        </style>
        </head>
        <body>
        <p><h3>Зафиксированы следующие смены IP за портом без смены mac-адреса:</h3></p>
        """
    
    def __init__(self, curr_device_name, curr_device_ip, switch, switch_interface, old_device_ip, netbox_url):
        self.curr_device_name = curr_device_name
        self.curr_device_ip = curr_device_ip
        self.switch = switch
        self.switch_interface = switch_interface
        self.old_device_ip = old_device_ip
        self.netbox_url = clean_url(netbox_url)

    def __str__(self):
        return (f"<p><strong>Коммутатор:</strong> {self.switch} {self.switch_interface}<br>"
                f"<strong>Актуальное устройство:</strong> {self.curr_device_name} {self.curr_device_ip}<br>"
                f"<strong>Предыдущие данные:</strong> {self.old_device_ip}"
                f" <a href=\"{self.netbox_url}\">{self.netbox_url}</a></p>")


class MacNotification:
    body_text = """
        <html>
        <head>
        <style>
        p { font-family: Arial, sans-serif; font-size: 12pt; }
        </style>
        </head>
        <body>
        <p><h3>Зафиксированы следующие MAC-адреса:</h3></p>
        """
    
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.url = None
    
    def __str__(self) -> str:
        return f"<p><strong>MAC:</strong> {self.mac}<br><strong>IP:</strong> {self.ip}<br><a href=\"{self.url}\">{self.url}</a></p>"


# ========================================================================
#                                 Функции
# ========================================================================
def csv_reader():
    csv_devices_list = []
    with open(devices_file, newline='') as file:
        devices_reader = csv.DictReader(file, delimiter=';')
        for csv_device in devices_reader:
            csv_devices_list.append(csv_device)
    
    # Читаем столбец действия (act)
    # "+" - работать только с этим хостом
    # "-" - исключить хост из обработки
    # Note: "плюсы" имеют приоритет перед "минусами"
    act = 'all'
    for csv_device in csv_devices_list:
        if csv_device['act'] == '+':
            act = 'include'
            break
        elif csv_device['act'] == '-':
            act = 'exclude'
    
    return csv_devices_list, act

def read_host_exceptions():
    with open(host_exceptions_file, 'r') as f:
        return [line.strip() for line in f.readlines()]

def create_host(neighbor_device, neighbor_interface):
    # Чекаем свойства интерфейса и принимаем решение о создании экземпляра для хоста
    ip_address = getattr(interface, 'rem_ip', None)
    if not ip_address:
        if hasattr(neighbor_interface, 'lldp_rem'):
            if neighbor_interface.lldp_rem['name'] is not None and neighbor_interface.lldp_rem['port'] is not None:
                NetboxDevice.set_description(
                    neighbor_device.hostname,
                    neighbor_interface.name,
                    neighbor_interface.lldp_rem['name'],
                    neighbor_interface.lldp_rem['port'],
                )
                return
        return
    
    elif ip_address in host_exceptions_list:
        return

    # Не создавать хосты для ip из диапазона свичей
    is_ip_in_site_range = any(
        ipaddress.ip_address(ip_address) in ip_range 
        for site in switch_network_device.sites
        for ip_range in site.ip_ranges
    )
    if is_ip_in_site_range:
        NetboxDevice.set_description(
                neighbor_device.hostname,
                neighbor_interface.name,
                neighbor_interface.lldp_rem['name'],
                neighbor_interface.lldp_rem['port'],
            )
        return
    
    # Создаем хост в netbox
    host_netbox_device = NetboxDevice(
        hostname=ip_address,
        model='unknown',
        site_slug=switch_network_device.site_slug,
        role='Host',
        ip_address=ip_address,
        serial_number=interface.lldp_rem['name'],
        vlans=switch_network_device.netbox_vlans_objs,
    )
    # Создаем экземпляр интерфейса хоста
    host_interface = HostInterface(
        kind='interface',
        name=interface.lldp_rem['port'] or 'interface',
        untagged=interface.untagged,
        ip_address=ip_address,
    )

    host_netbox_device.add_interface(host_interface)
    host_netbox_device.connect_to_neighbor(neighbor_device, neighbor_interface)


def create_socket(interface, switch_network_device):
    socket_netbox_device = NetboxDevice(
        hostname=interface.socket,
        site_slug=switch_network_device.site_slug,
        model='1-port socket',
        role='Network socket',
    )
    rearport = Interface(kind='rearport')
    frontport = Interface(kind='frontport')
    switch_netbox_device.connect_to_neighbor(socket_netbox_device, rearport)

    return socket_netbox_device, frontport

def clean_url(netbox_url):
    parts = netbox_url.split("/")
    # Attempt to remove the 'api' part from the path
    parts = [part for part in parts if part != "api"]
    return "/".join(parts)


# ========================================================================
#                               Тело скрипта
# ========================================================================
if __name__ == '__main__':
    # Define an argument parser and an argument to control mail sending
    parser = argparse.ArgumentParser(description='Network Device Processing Script')
    parser.add_argument('--no-mail', action='store_true',
                        help='Do not send email notifications after processing')
    args = parser.parse_args()
    
    # Устанавливаем уровень логирования
    logger.setLevel(getattr(logging, log_level))
    # Читаем csv файл со списком исключений для создания хостов
    host_exceptions_list = read_host_exceptions()
    # Читаем csv файл со списком устройств
    devices_reader, act = csv_reader()
    # Формируем pandas-базу розеток
    sockets = pd.read_csv(sockets_file, sep=';', dtype=str)
    sockets = sockets.apply(lambda x: x.str.replace(' ', '') if x.dtype == 'object' else x)
    # Список MAC-ов для уведомления
    mac_for_notification_list = []

    # ГЛАВНЫЙ ЦИКЛ
    # ========================================================================
    NetboxDevice.create_connection()
    NetworkDevice.initialize_sites()  # Получаем словарь сайтов из switches.csv
    # загружаем словарь моделей по семействам
    SNMPDevice.load_models(models_list_file)

    for csv_device in devices_reader:
        switch_network_device = None
        try:
            # Условия для пропуска устройства
            if (act == 'exclude' and csv_device['act'] == '-') or \
                    (act == 'include' and csv_device['act'] != '+'):
                logger.info(f"Skipping {csv_device['ip device']}")
                continue

            logger.info(f"Processing {csv_device['ip device']}...")
            # Создаем экземпляр класса NetworkDevice, который служит "буфером" для информации между модулями
            switch_network_device = NetworkDevice(
                ip_address=csv_device['ip device'].strip(),
                role=csv_device['role'],
                community_string=csv_device['community'] if csv_device['community'] else default_snmp_community,
                vm=True if csv_device['vm'] else False,
                snmp_version=csv_device['snmp'] if csv_device['snmp'] else default_snmp_version,
            )
            # Получаем имя сайта по айпи опрашиваемого устройства
            switch_network_device.find_site_slug()
            switch_network_device.find_attribute(
                'arp_table')  # Получаем ARP-таблицу по сайту
            switch_network_device.find_attribute(
                'netbox_vlans_objs')  # Получаем список netbox-объектов вланов для устройства

            # БЛОК РАБОТЫ С МОДУЛЕМ SNMP
            # создаем экземпляр класса SNMPDevice для взаимодействия с модулем SNMP
            snmp_device = SNMPDevice(
                switch_network_device.ip_address,
                switch_network_device.community_string,
                arp_table=switch_network_device.arp_table,
                version=switch_network_device.snmp_version,
            )
            switch_network_device.hostname = snmp_device.get_hostname()  # получаем hostname
            # если device.csv не содержит значения role для устройства, то определяем role по hostname
            if not switch_network_device.role:
                switch_network_device.get_role_from_hostname()
            if switch_network_device.vm is False:
                switch_network_device.model = snmp_device.get_model()   # получаем модель
                switch_network_device.model_family = snmp_device.find_model_family()    # получаем семейство моделей
            # получаем серийный номер
            switch_network_device.serial_number = snmp_device.get_serial_number()
            # получаем список виртуальных интерфейсов
            switch_network_device.virtual_interfaces = snmp_device.get_virtual_interfaces()
            # получаем список физических интерфейсов
            switch_network_device.physical_interfaces = snmp_device.get_physical_interfaces()
            # проверяем наличие вланов устройства в netbox
            switch_network_device.check_vlans()

            # БЛОК РАБОТЫ С МОДУЛЕМ NETBOX
            # пересоздание соединения с netbox на случай, если по snmp инфа собиралась слишком долго
            NetboxDevice.create_connection()
            # создаем экземпляр класса NetBoxDevice для взаимодействия с модулем NetBox
            if switch_network_device.vm:
                switch_netbox_device = NetboxDevice(
                    ip_address=switch_network_device.ip_address,
                    site_slug=switch_network_device.site_slug,
                    hostname=switch_network_device.hostname,
                    role=switch_network_device.role,
                    vm=switch_network_device.vm,
                    vlans=switch_network_device.netbox_vlans_objs,
                )
            else:
                switch_netbox_device = NetboxDevice(
                    hostname=switch_network_device.hostname,
                    site_slug=switch_network_device.site_slug,
                    serial_number=switch_network_device.serial_number,
                    model=switch_network_device.model,
                    role=switch_network_device.role,
                    vlans=switch_network_device.netbox_vlans_objs,
                    ip_address=switch_network_device.ip_address,
                    vm=switch_network_device.vm,
                )
            
            # создаем/обновляем интерфейсы в netbox
            for interface in switch_network_device.virtual_interfaces:
                switch_netbox_device.add_interface(interface)
            
            if switch_network_device.physical_interfaces and not switch_network_device.vm:
                for interface in switch_network_device.physical_interfaces:
                    interface.kind = 'interface'
                    switch_netbox_device.add_interface(interface)

                    # БЛОК РАБОТЫ С КОНЕЧНЫМИ УСТРОЙСТВАМИ
                    # Определяем номер порта
                    match = re.search(
                        r"(?<![Po,Port\-channel])\d+$", interface.name
                    )
                    if match:
                        port_number = match.group()
                        pd_socket = sockets[(sockets["switch"] == switch_network_device.ip_address) & (
                            sockets["interface"] == port_number)]["name"]
                        # Если есть соответствующая розетка в списке sockets.csv
                        if not pd_socket.empty:
                            interface.socket = pd_socket.iloc[0]
                            socket_netbox_device, frontport = create_socket(
                                interface, switch_network_device)
                            create_host(socket_netbox_device, frontport)
                        else:
                            create_host(switch_netbox_device, interface)

        except Error as e:
            # e.store_error(csv_device['ip device'].strip(), e, True)
            # Error(e, csv_device['ip device'].strip())
            continue
        except Exception as e:
            Error.store_error(csv_device['ip device'].strip(), e, True)
            continue
        finally:
            if switch_network_device is not None:
                # switch_network_device.print_attributes()
                print('=' * 80)

    # ВЫВОД ОШИБОК
    # ========================================================================
    # Create tables for errors
    critical_error_table = PrettyTable(["IP", "Error"])
    critical_error_table.align["IP"] = "l"
    critical_error_table.align["Error"] = "l"
    critical_error_table.max_width = 75
    critical_error_table.valign["Error"] = "t"

    non_critical_error_table = PrettyTable(["IP", "Error"])
    non_critical_error_table.align["IP"] = "l"
    non_critical_error_table.align["Error"] = "l"
    non_critical_error_table.max_width = 75
    non_critical_error_table.valign["Error"] = "t"

    # Add rows to tables
    cable_connection_errors = []
    for error in Error.error_messages:
        if error['is_critical']:
            critical_error_table.add_row([error["ip"], error["message"]])
            if "Can't connect " in error['message']:
                pattern = r"Can't connect (\S+) (\S+) to (\S+) (\S+)\nSwitch interface was connected to (\S+)\n(\S+)"
                match = re.match(pattern, error['message'])
                if match:
                    cable_error_detail = CableConnectionError(
                        curr_device_name=match.group(1),
                        curr_device_ip=match.group(2),
                        switch=match.group(3),
                        switch_interface=match.group(4),
                        old_device_ip=match.group(5),
                        netbox_url=match.group(6)
                    )
                    cable_connection_errors.append(cable_error_detail)
        else:
            non_critical_error_table.add_row([error["ip"], error["message"]])

    # Log the completion of work
    logger.info('The work is completed.')
    
    # Print non-critical errors in PrettyTable if there are any
    if not non_critical_error_table.get_string().strip() == "":
        logger.info(f'Non-Critical Errors:\n{non_critical_error_table}')
    
    # Print errors in PrettyTable if there are any
    if not critical_error_table.get_string().strip() == "":
        logger.info(f'Critical Errors:\n{critical_error_table}')
    
    # Send email notifications
    if not args.no_mail:
        if cable_connection_errors:
            # Generate the body of the email
            # Starting HTML body
            for error_detail in cable_connection_errors:
                CableConnectionError.body_text += str(error_detail)
            # Close the HTML body
            CableConnectionError.body_text += """
            </body>
            </html>
            """
            # Create a list of files to attach
            files_to_attach = []

            # Send email
            send_email_with_attachment(
                host=smtp_host,
                from_addr=from_email,
                to_emails=infosec_team_mail,
                cc_emails=me_mail,
                subject='Смена IP за портом detected',
                body_text=CableConnectionError.body_text,
            )
        else:
            logger.info("No Cable Connection Errors")
        
        if mac_for_notification_list:
            for mac in mac_for_notification_list:
                MacNotification.body_text += str(mac)
            MacNotification.body_text += """
            </body>
            </html>
            """
            send_email_with_attachment(
                host=smtp_host,
                from_addr=from_email,
                to_emails=me_mail,
                subject='Новый мак в защищенной сети',
                body_text=MacNotification.body_text,
            )
        else:
            logger.info("No MAC Notification")
