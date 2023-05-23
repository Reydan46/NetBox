import csv
import ipaddress
import re

from prettytable import PrettyTable

from errors import Error, NonCriticalError
from snmp import SNMPDevice

# ========================================================================
#                                  Классы
# ========================================================================

class NetworkDevice:
    vlans = {}
    def __init__(self, ip_address, role, community_string):
        self.ip_address: str = ip_address
        self.community_string: str = community_string
        self.role: str = role

    # Временный для дебага - потом удалить
    def print_attributes(self):
        print('NetworkDevice attributes:')
        # Печатаем аттрибуты экземпляра
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}")
        # Затем аттрибуты класса
        for attribute, value in vars(self.__class__).items():
            if not attribute.startswith('__') and not callable(value):
                print(f"{attribute}: {value}")
        print('=' * 80)

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

    def get_role_from_hostname(self):
        role_out = re.search(r'-([p]?sw)\d+', self.hostname)
        role_mapping = {
            'psw': 'poe-switch',
            'sw': 'Access switch'
        }
        if role_out:
            self.role = role_mapping.get(role_out.group(1))
        else:
            raise Error("Could not determine role from hostname")
    
    def get_vlans(self):
        local_vlans = set()
        for interface in self.physical_interfaces:
            untagged_vid, tagged_vids = interface.untagged, interface.tagged
            if untagged_vid:
                local_vlans.add(untagged_vid)
            if tagged_vids:
                local_vlans.update(tagged_vids)

        if self.site_slug in self.__class__.vlans:
            self.__class__.vlans[self.site_slug].update(local_vlans)
        else:
            self.__class__.vlans[self.site_slug] = local_vlans

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

# ========================================================================
#                               Тело скрипта
# ========================================================================
# Читаем csv файл со списком устройств
devices_reader, act = csv_reader()

# ГЛАВНЫЙ ЦИКЛ
# ========================================================================
error_messages = {}
for csv_device in devices_reader:
    switch_network_device = None
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
        SNMPDevice.load_models('models.list') # загружаем словарь моделей по семействам
        snmp_device = SNMPDevice(
            switch_network_device.ip_address,
            switch_network_device.community_string
        )
        switch_network_device.hostname = snmp_device.get_hostname()  # получаем hostname
        # если device.csv не содержит значения role для устройства, то определяем role по hostname
        if not switch_network_device.role:
            switch_network_device.get_role_from_hostname()
        switch_network_device.model = snmp_device.get_model() # получаем модель
        switch_network_device.serial_number = snmp_device.get_serial_number() # получаем серийный номер
        switch_network_device.virtual_interfaces = snmp_device.get_virtual_interfaces() # получаем список виртуальных интерфейсов
        switch_network_device.model_family = snmp_device.find_model_family() # получаем семейство моделей
        switch_network_device.physical_interfaces = snmp_device.get_physical_interfaces() # получаем список физических интерфейсов
        switch_network_device.get_vlans() # получаем список вланов
    except Error as e:
        error_messages[csv_device['ip device'].strip()] = str(e)
        continue
    finally:
        if switch_network_device is not None:
            switch_network_device.print_attributes()
            input('Нажмите Enter для продолжения...')

# ВЫВОД ОШИБОК
# ========================================================================
# Merge the error messages into a single list
all_error_messages = Error.error_messages + NonCriticalError.error_messages

# Flatten the list of dictionaries into a single dictionary
merged_error_messages = {k: v for d in all_error_messages for k, v in d.items()}

# Print errors in a PrettyTable
if merged_error_messages:
    table = PrettyTable(["IP", "Error"])
    table.align["IP"] = "l"
    table.align["Error"] = "l"
    table.max_width = 75
    table.valign["Error"] = "t"
    for ip, error_message in merged_error_messages.items():
        table.add_row([ip, error_message])
    print(table)

