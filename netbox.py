import inspect
import os
import traceback

import pynetbox
from colorama import Fore, init

from errors import NonCriticalError

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
    
    # Пресет колорамы
    @staticmethod
    def __print_yellow(message):
        print(Fore.YELLOW + message + Fore.RESET)

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
            vlans = cls.__netbox_connection.ipam.vlans.filter(site=site_slug)
            vlan_ids = [str(vlan.vid) for vlan in vlans]    # Extract VLAN IDs from the objects
            print(f"Found {len(vlan_ids)} VLANs for site {site_slug}")
            return vlan_ids
        except pynetbox.core.query.RequestError as e:
            error_message = f"Request failed for site {site_slug}"
            cls.__print_yellow(f"NonCriticalError: {error_message}")
            calling_function = inspect.stack()[1].function
            NonCriticalError(error_message, site_slug, calling_function)
            return None
