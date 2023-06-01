import inspect
import os
import traceback

import pynetbox
from colorama import init

from color_printer import print_red, print_yellow
from errors import Error, NonCriticalError

# Initialize Colorama
init()


class NetboxDevice:
    # Получение переменных окружения
    # =====================================================================
    @staticmethod
    def __get_env_variable(variable_key):
        variable_value = os.environ.get(variable_key)
        if variable_value is None:
            raise ValueError(f"Missing environment variable: {variable_key}")
        return variable_value

    __netbox_url = __get_env_variable("NETBOX_URL")
    __netbox_token = __get_env_variable("NETBOX_TOKEN")
    # ====================================================================

    # Создание netbox соединения
    @classmethod
    def create_connection(cls):
        try:
            cls.__netbox_connection = pynetbox.api(
                url=cls.__netbox_url,
                token=cls.__netbox_token
            )
            print("Connection to NetBox established...")
        except Exception as e:
            traceback.print_exc()
            raise e

    # Получение вланов сайта из netbox
    @classmethod
    def get_vlans(cls, site_slug):
        try:
            vlans = list(
                cls.__netbox_connection.ipam.vlans.filter(site=site_slug))
            # Extract VLAN IDs from the objects
            vlan_ids = [str(vlan.vid) for vlan in vlans]
            print(f"Found {len(vlan_ids)} VLANs for site {site_slug}")
            return vlans
        except pynetbox.core.query.RequestError as e:
            error_message = f"Request failed for site {site_slug}"
            print_yellow(f"NonCriticalError: {error_message}")
            calling_function = inspect.stack()[1].function
            NonCriticalError(error_message, site_slug, calling_function)
            return None

    # Создаем экземпляр устройства netbox
    def __init__(self, site_slug, model, role, hostname=None, serial_number=None, vlans=None) -> None:
        self.__hostname = hostname
        self.__site_slug = site_slug
        self.__model = model
        self.__role = role
        self.__serial_number = serial_number
        self.__vlans = vlans
        self.__netbox_device = self.__get_netbox_device() 

        # Выбор действия в зависимости от наличия или отсутствия устройства в NetBox
        if not self.__netbox_device:
            self.__create_device()
        else:
            self.__check_serial_number()

    def __get_netbox_device(self):
        device = self.__netbox_connection.dcim.devices.get(name=self.__hostname, site=self.__site_slug)
        if not device:
            device = self.__netbox_connection.dcim.virtual_chassis.get(name=self.__hostname, site=self.__site_slug)
        return device
    
    def __check_serial_number(self):
        if self.__serial_number and self.__netbox_device.serial != self.__serial_number:
            error_msg = f"Serial number of the device {self.__hostname} ({self.__serial_number}) does not match the serial number of the device in NetBox ({self.__netbox_device.serial})."
            print_red(f"CriticalError: {error_msg}")
            raise Error(error_msg)

    def __create_device(self):
        def critical_error_not_found(item_type, item_value):
            error_msg = f"{item_type} {item_value} not found in NetBox."
            print_red(f"CriticalError: {error_msg}")
            raise Error(error_msg)

        def get_netbox_object(object_type, field, value):
            netbox_object = self.__netbox_connection.dcim.__getattribute__(object_type).get(field, value)
            if not netbox_object:
                critical_error_not_found(object_type, value)
            return netbox_object

        print("Creating device...")

        # Получаем объекты netbox
        self.__netbox_device_type = get_netbox_object("device_types", "model", self.__model)
        self.__netbox_site = get_netbox_object("sites", "slug", self.__site_slug)
        self.__netbox_device_role = get_netbox_object("device_roles", "name", self.__role)

        # Создаем устройство в NetBox
        self.__netbox_device = self.__netbox_connection.dcim.devices.create(
            name=self.__hostname,
            device_type=self.__netbox_device_type.id,
            site=self.__netbox_site.id,
            device_role=self.__netbox_device_role.id,
            status="active",
        )
        # Костыль на случай отсутствия серийного номера
        if self.__serial_number:
            self.__netbox_device.serial = self.__serial_number
            self.__netbox_device.save()
        
        print("Device created...")

    def add_interface(self, interface):
        # Поиск влан-объекта netbox по vlan id
        def __find_vlan_object(vlan_id):
            for vlan in self.__vlans:
                if str(vlan.vid) == vlan_id:
                    return vlan

        # Helper function to update the fields of the Netbox interface object.
        def __update_interface_fields(netbox_interface, interface_object):
            netbox_interface.name = interface_object.name
            netbox_interface.mtu = getattr(interface_object, 'mtu', None)
            netbox_interface.mac_address = getattr(interface_object, 'mac', '')
            netbox_interface.description = getattr(
                interface_object, 'desc', '')
            netbox_interface.mode = getattr(interface_object, 'mode', '')
            if interface_object.type != "other":
                netbox_interface.type = interface_object.type
            netbox_interface.untagged_vlan = __find_vlan_object(
                interface_object.untagged)
            if interface_object.tagged:
                netbox_interface.tagged_vlans = [__find_vlan_object(
                    vlan_id) for vlan_id in interface_object.tagged]
            netbox_interface.save()

        # Проверка существует ли интерфейс в netbox
        print(f"Checking that interface {interface.name} already exists...")
        existing_interface = self.__netbox_connection.dcim.interfaces.get(
            name=interface.name, device=self.__netbox_device.name)

        # Если сущестует - обновляем
        if existing_interface:
            print(f"Interface {interface.name} already exists...")
            print("Updating interface...")
            self.__netbox_interface = existing_interface
            __update_interface_fields(self.__netbox_interface, interface)
            print("Interface updated...")
            return

        # Если не существует - создаем и обновляем
        print("Creating interface...")
        self.__netbox_interface = self.__netbox_connection.dcim.interfaces.create(
            name=interface.name,
            device=self.__netbox_device.id,
            type=getattr(interface, 'type', 'other'),
        )
        __update_interface_fields(self.__netbox_interface, interface)
