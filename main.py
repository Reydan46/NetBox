import csv
import ipaddress
import re

import pandas as pd
from prettytable import PrettyTable

import oid.general
from errors import Error, NonCriticalError
from log import logger
from netbox import NetboxDevice
from snmp import SNMPDevice


# ========================================================================
#                                  Классы
# ========================================================================
class Site:
    def __init__(self, site_slug, prefix, gw=None):
        self.site_slug = site_slug
        self.ip_range = ipaddress.ip_network(prefix, strict=False)
        self.gw = gw


class NetworkDevice:
    # Инициализация списка сайтов
    # =====================================================================
    sites = []

    @classmethod
    def initialize_sites(cls):
        with open('switches.csv') as f:
            reader = csv.DictReader(f, delimiter=';')
            for row in reader:
                site = Site(row['site'], row['prefix'], row.get('gw', None))
                # Заполнение экземпляра сайта данными
                cls.__populate_site_data(site)
                cls.sites.append(site)
            logger.info('-' * 40)

    @classmethod
    def __populate_site_data(cls, site):
        site.netbox_vlans_objs = NetboxDevice.get_vlans(site.site_slug)
        if not site.gw:
            return
        # Получаем arp-таблицу с марша площадки
        site.arp_table = SNMPDevice.get_network_table(
            site.gw, oid.general.arp_mac, 'IP-MAC')
        site.subnets = cls.get_subnets(SNMPDevice.get_network_table(
            site.gw, oid.general.ip_mask, 'IP-MASK'))  # Получаем таблицу подсетей площадки

    @staticmethod
    def get_subnets(ip_table):
        return [str(subnet.network_address) + '/' + str(subnet.prefixlen)
                for ip, mask in ip_table.items()
                if (subnet := ipaddress.IPv4Network(ip + '/' + mask, strict=False)).is_private
                and str(subnet.network_address) not in ("0.0.0.0", "127.0.0.0")]
    # ====================================================================

    def __init__(self, ip_address, role, community_string):
        self.ip_address: str = ip_address
        self.community_string: str = community_string
        self.role: str = role
        self.arp_table = None
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
        for site in NetworkDevice.sites:
            if ipaddress.ip_address(self.ip_address) in site.ip_range:
                self.site_slug = site.site_slug
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
        role_out = re.search(r'-([p]?sw)\d+', self.hostname)
        role_mapping = {
            'psw': 'poe-switch',
            'sw': 'Access switch'
        }
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

# ========================================================================
#                                 Функции
# ========================================================================


def csv_reader():
    devices_file = open('devices.csv', newline='')
    devices_reader = csv.DictReader(devices_file, delimiter=';')

    # Читаем столбец действия (act)
    # "+" - работать только с этим хостом
    # "-" - исключить хост из обработки
    # Note: "плюсы" имеют приоритет перед "минусами"
    act = 'all'
    for csv_device in devices_reader:
        if csv_device['act'] == '+':
            act = 'include'
            break
        elif csv_device['act'] == '-':
            act = 'exclude'
    # Возврат в начало файла
    devices_file.seek(0)
    devices_reader.__init__(devices_file, delimiter=";")
    return devices_reader, act


def read_host_exceptions():
    with open('host_exceptions.list', 'r') as f:
        return [line.strip() for line in f.readlines()]


def create_host(neighbor_device, neighbor_interface):
    # Чекаем свойства интерфейса и принимаем решение о создании экземпляра для хоста
    ip_address = getattr(interface, 'rem_ip', None)
    if not ip_address:
        return
    # Не создавать хосты для ip из диапазона свичей
    is_ip_in_site_range = any(
        ipaddress.ip_address(ip_address) in site.ip_range
        for site in switch_network_device.sites
    )
    if is_ip_in_site_range or ip_address in host_exceptions_list:
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


# ========================================================================
#                               Тело скрипта
# ========================================================================
if __name__ == '__main__':
    # Читаем csv файл со списком исключений для создания хостов
    host_exceptions_list = read_host_exceptions()
    # Читаем csv файл со списком устройств
    devices_reader, act = csv_reader()
    # Формируем pandas-базу розеток
    sockets = pd.read_csv('sockets.csv', sep=';', dtype=str)

    # ГЛАВНЫЙ ЦИКЛ
    # ========================================================================
    NetboxDevice.create_connection()
    NetworkDevice.initialize_sites()  # Получаем словарь сайтов из switches.csv
    # загружаем словарь моделей по семействам
    SNMPDevice.load_models('models.list')

    for csv_device in devices_reader:
        switch_network_device = None
        try:
            # Условия для пропуска устройства
            if (act == 'exclude' and csv_device['act'] == '-') or \
                    (act == 'include' and csv_device['act'] != '+'):
                logger.info(f"Skipping {csv_device['ip device']}")
                continue

            logger.info(f"Processing {csv_device['ip device']}...\n")
            # Создаем экземпляр класса NetworkDevice, который служит "буфером" для информации между модулями
            switch_network_device = NetworkDevice(
                ip_address=csv_device['ip device'].strip(),
                role=csv_device['role'],
                community_string=csv_device['community'] if csv_device['community'] else 'public',
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
                switch_network_device.arp_table,
            )
            switch_network_device.hostname = snmp_device.get_hostname()  # получаем hostname
            # если device.csv не содержит значения role для устройства, то определяем role по hostname
            if not switch_network_device.role:
                switch_network_device.get_role_from_hostname()
            switch_network_device.model = snmp_device.get_model()  # получаем модель
            # получаем серийный номер
            switch_network_device.serial_number = snmp_device.get_serial_number()
            # получаем список виртуальных интерфейсов
            switch_network_device.virtual_interfaces = snmp_device.get_virtual_interfaces()
            # получаем семейство моделей
            switch_network_device.model_family = snmp_device.find_model_family()
            if switch_network_device.model_family is not None:
                #input('Нажмите любую клавишу для продолжения...')
                # получаем список физических интерфейсов
                switch_network_device.physical_interfaces = snmp_device.get_physical_interfaces()
                # проверяем наличие вланов устройства в netbox
                switch_network_device.check_vlans()

            # БЛОК РАБОТЫ С МОДУЛЕМ NETBOX
            # пересоздание соединения с netbox на случай, если по snmp инфа собиралась слишком долго
            NetboxDevice.create_connection()
            # создаем экземпляр класса NetBoxDevice для взаимодействия с модулем NetBox
            switch_netbox_device = NetboxDevice(
                hostname=switch_network_device.hostname,
                site_slug=switch_network_device.site_slug,
                serial_number=switch_network_device.serial_number,
                model=switch_network_device.model,
                role=switch_network_device.role,
                vlans=switch_network_device.netbox_vlans_objs,
                ip_address=switch_network_device.ip_address,
            )
            # создаем/обновляем интерфейсы в netbox
            for interface in switch_network_device.virtual_interfaces:
                switch_netbox_device.add_interface(interface)
            
            if switch_network_device.physical_interfaces:
                for interface in switch_network_device.physical_interfaces:
                    interface.kind = 'interface'
                    switch_netbox_device.add_interface(interface)

                    # БЛОК РАБОТЫ С КОНЕЧНЫМИ УСТРОЙСТВАМИ
                    # Определяем номер порта
                    match = re.search(
                        r"(?<!Po)\d+$", interface.name
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
            e.store_error(csv_device['ip device'].strip(), e)
            # Error(e, csv_device['ip device'].strip())
            continue
        finally:
            if switch_network_device is not None:
                # switch_network_device.print_attributes()
                print('=' * 80)

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
