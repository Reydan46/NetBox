import csv
import ipaddress

from prettytable import PrettyTable
from errors import Error

from snmp import SNMPDevice

# ========================================================================
#                                  Классы
# ========================================================================

class NetworkDevice:

    def __init__(self, ip_address, role, community_string):
        self.ip_address: str = ip_address
        self.community_string: str = community_string
        self.role: str = role

    # Временный для дебага - потом удалить
    def print_attributes(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}")
        print('-' * 40)

    # Find and set the site_slug attribute based on the IP address
    def find_site_slug(self):
        # Read the CSV file with site and IP prefix information, and store in a sites_dict variable
        sites_dict = {}
        with open('prefixes.csv') as f:
            reader = csv.DictReader(f, delimiter=';')
            for row in reader:
                site_slug = row['site']
                ip_range = row['prefix']
                sites_dict[site_slug] = ipaddress.ip_network(
                    ip_range, strict=False)

        # Check if the NetworkDevice IP address is in one of the IP ranges,
        # and store the matching site_slug in the NetworkDevice instance
        site_found = False
        for site_slug, ip_range in sites_dict.items():
            if ipaddress.ip_address(self.ip_address) in ip_range:
                self.site_slug = site_slug
                site_found = True
                break

        # Raise an error if the site is not found for the given IP address
        if not site_found:
            raise Error(f"Site not found for IP address {self.ip_address}")

# ========================================================================
#                                 Функции
# ========================================================================
def csv_reader():
    devices_with_error = []
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

# ========================================================================
#                               Тело скрипта
# ========================================================================
# Читаем csv файл со списком устройств
devices_reader, act = csv_reader()

# ГЛАВНЫЙ ЦИКЛ
# ========================================================================
error_messages = {}
for csv_device in devices_reader:
    try:
        # Условия для пропуска устройства
        if (act == 'exclude' and csv_device['act'] == '-') or \
                (act == 'include' and csv_device['act'] != '+'):
            continue

        # Создаем экземпляр класса NetworkDevice, который служит "буфером" для информации между модулями
        switch_network_device = NetworkDevice(
            ip_address=csv_device['ip device'].strip(),
            role=csv_device['role'],
            community_string=csv_device['community'] if csv_device['community'] else 'public',
        )
        # Получаем имя сайта по айпи опрашиваемого устройства
        switch_network_device.find_site_slug()

        # БЛОК РАБОТЫ С МОДУЛЕМ SNMP
        # создаем экземпляр класса SNMPDevice для взаимодействия с модулем SNMP
        snmp_device = SNMPDevice(
            switch_network_device.ip_address,
            switch_network_device.community_string
        )
        switch_network_device.hostname = snmp_device.get_hostname()  # получаем hostname
        
        switch_network_device.print_attributes()
    except Error as e:
        error_messages[csv_device['ip device'].strip()] = str(e)
        continue

# ВЫВОД ОШИБОК
# ========================================================================
if error_messages:
    table = PrettyTable(["IP", "Error"])
    table.align["Error"] = "l"
    table.max_width = 75
    table.valign["Error"] = "t"
    for i in error_messages.items():
        table.add_row([i[0], i[1]])
    print(table)
