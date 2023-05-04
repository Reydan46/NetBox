import os
import pynetbox
from pynetbox.core import api
from pynetbox.models import dcim
from snmp import SNMPDevice, Interface
import re
import logging


class NetworkDevice:
    def __init__(self, ip_address, community_string=None, site_slug=None, role=None, logger=None):
        """
        Initializes a new NetworkDevice object with provided IP address and optional parameters.
        Sets up the logger, SNMPDevice configuration, and NetBox connection.
        
        Args:
        ip_address (str): The IP address of the network device.
        community_string (str, optional): The SNMP community string for the device. Defaults to "public".
        site_slug (str, optional): The NetBox site slug for the device. Defaults to None.
        role (str, optional): The device role. Defaults to None.
        logger (logging.Logger, optional): A logger for debugging. Defaults to None, which creates a default logger.
        """
        
        # Проверяем наличие логгера
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger('NetworkDevice')

        # Initialize SNMPDevice and related attributes
        self.__snmp: SNMPDevice = None

        # Initialize NetBox connection and related attributes
        self.__netbox_connection: pynetbox.core.api.Api = None
        self.__netbox_url = None
        self.__netbox_token = None
        self.__netbox_device: pynetbox.models.dcim.Devices = None
        self.__netbox_device_sv_interfaces = []
        self.__netbox_device_sp_interfaces = []
        self.__netbox_device_ip_address = None
        self.__netbox_vlans = {}

        # Initialize password-related attributes
        self.__password_salt = None
        self.__password_decoder = None

        # Initialize dictionaries and device-related attributes
        self.models = {}
        self.hostname = ""
        self.model = ""
        self.serial_number = ""
        self.site_slug = ""
        self.role = ""
        self.interfaces = []

        # Initialize SNMP community string and error attributes
        self.community_string = "public"
        self.error = ""

        # Сохраняем не None значения атрибутов
        self.ip_address = ip_address
        if community_string:
            self.community_string = community_string
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

        # Возвращает SNMPDevice объект в атрибут __snmp
        self.__create_SNMPDevice()

    def getModel(self):
        if self.model:
            return self.model
        else:
            return "Undefined"

    def getModels(self):
        return self.__snmp.getModels()

    def setModels(self, models):
        self.__snmp.setModels(models)

    def getNetboxConnection(self):
        return self.__netbox_connection

    def setNetboxConnection(self, netbox_connection: pynetbox.core.api.Api):
        self.__netbox_connection = netbox_connection

    def getNetboxVlans(self):
        return self.__netbox_vlans

    def setNetboxVlans(self, netbox_vlans: dict):
        self.__netbox_vlans = netbox_vlans

    def __create_SNMPDevice(self):
        """
        Create an SNMPDevice if one does not already exist or if the community string has changed.

        :return: The created or existing SNMPDevice.
        """
        if not self.__snmp or self.__snmp.community_string != self.community_string:
            self.logger.debug('Create SNMP Device')
            self.__snmp = SNMPDevice(
                community_string=self.community_string,
                ip_address=self.ip_address,
                logger=self.logger
            )
        return self.__snmp

    @staticmethod
    def __indexes_to_dict(indexes):
        return {interface: value for interface, value in indexes}

    def __connect_to_netbox(self):
        self.error = ''
        try:
            if not self.__netbox_connection:
                self.__netbox_url = os.environ.get('NETBOX_URL')
                if not self.__netbox_url:
                    self.error = 'NetBox URL is empty!'
                    self.logger.error(self.error)
                    return None
                self.__netbox_token = os.environ.get('NETBOX_TOKEN')
                if not self.__netbox_token:
                    self.error = 'NetBox TOKEN is empty!'
                    self.logger.error(self.error)
                    return None
                self.logger.debug('Connect to NetBox')
                self.__netbox_connection = pynetbox.api(url=self.__netbox_url, token=self.__netbox_token)
        except:
            self.error = 'Fail connect to NetBox'
        return self.__netbox_connection

    def __get_vlans_from_netbox(self):
        self.error = ''

        # Если список Vlan уже был получен
        if self.__netbox_vlans:
            return

        self.logger.debug('Get VLANs from NetBox')
        if not self.__netbox_connection:
            self.error = 'No connecting to NetBox'
            self.logger.debug(self.error)
            return

        self.__netbox_vlans = {}
        site_out = self.__netbox_connection.dcim.sites.all()
        if not site_out:
            self.error = 'No get sites in NetBox!'
            self.logger.error(self.error)
            return

        vlans_out = self.__netbox_connection.ipam.vlans.all()
        if not vlans_out:
            self.error = 'No get vlans in NetBox!'
            self.logger.error(self.error)
            return

        for site in site_out:
            self.__netbox_vlans.update({site.slug: {}})

        # Если сайт отсуствует - ошибка
        if self.site_slug not in self.__netbox_vlans:
            self.error = f'Site Slug {self.site_slug} not found in NetBox'
            return

        for vlan in vlans_out:
            if not vlan.site:
                self.error = f'Vlan ID {vlan.vid} has no in Site ({self.site_slug})!'
                self.logger.error(self.error)
                return
            self.__netbox_vlans[vlan.site.slug].update({str(vlan.vid): vlan})

    # Проверка существования Vlan и, при его наличии, возврат его объекта
    def get_vlan_object(self, vid):
        self.__get_vlans_from_netbox()

        if self.error:
            return

        if vid not in self.__netbox_vlans[self.site_slug]:
            self.error = f'Vlan ID {vid} not found in NetBox (site {self.site_slug})'
            return

        return self.__netbox_vlans[self.site_slug][vid]

    def get_device_info(self, community_string=None):
        self.logger.info('Get Device Info')

        self.error = ''

        if community_string:
            self.community_string = community_string
            self.__create_SNMPDevice()

        self.hostname, self.error = self.__snmp.getHostname()
        if self.error:
            self.error = f'Error get hostname: {self.error}'
            self.logger.error(self.error)
            return

        self.logger.info(f'Hostname: {self.hostname}')

        self.model, self.error = self.__snmp.getModel()
        if self.error:
            self.error = f'Error get model: {self.error}'
            self.logger.error(self.error)
            return
        self.logger.info(f'Model: {self.model}')

        self.serial_number, self.error = self.__snmp.getSerialNumber()
        if self.error:
            self.error = f'Error get serial number: {self.error}'
            self.logger.error(self.error)
            return
        self.logger.info(f'Serial Number: {self.serial_number}')

    def get_role_from_hostname(self):
        if self.hostname:
            self.logger.info("Get Role from Hostname")
            role_out = re.search(r'-([p]?sw)\d+', self.hostname)
            if role_out:
                match role_out.group(1):
                    case 'psw':
                        self.role = 'poe-switch'
                    case 'sw':
                        self.role = 'Access switch'
                if self.role:
                    self.logger.info(f'Found role: {self.role}')

    def create_netbox_device(self, site_slug=None, role=None):
        self.logger.info('Create Device in NetBox')

        self.error = ''
        self.__netbox_device = None

        # Устанавливаем значения классу, если заданы
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

        if not self.role:
            self.get_role_from_hostname()

        # Если все необходимые параметры заданы
        if self.hostname and self.model and self.serial_number and self.site_slug and self.role:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Check if the device already exists in NetBox
            devices = self.__netbox_connection.dcim.devices.filter(name=self.hostname, site=self.site_slug)
            if devices:
                self.logger.info(f"Device '{self.hostname}' already exists in NetBox (skipping creation)")
                find_netbox_device = next(iter(devices))
                if find_netbox_device.serial != self.serial_number:
                    self.error = "Serial number does not match!"
                    return
                else:
                    self.__netbox_device = find_netbox_device
            else:
                netbox_device_type = self.__netbox_connection.dcim.device_types.get(model=self.model)
                if not netbox_device_type:
                    self.error = f'Device type "{self.model}" not found in NetBox!'
                    return

                netbox_site = self.__netbox_connection.dcim.sites.get(slug=self.site_slug)
                if not netbox_site:
                    self.error = f'Site slug "{self.site_slug}" not found in NetBox!'
                    return

                netbox_device_role = self.__netbox_connection.dcim.device_roles.get(name=self.role)
                if not netbox_device_role:
                    self.error = f'Device role "{self.role}" not found in NetBox!'
                    return

                self.logger.info(f"Device '{self.hostname}' creating in NetBox")
                self.__netbox_device = self.__netbox_connection.dcim.devices.create(
                    name=self.hostname,
                    device_type=netbox_device_type.id,
                    serial=self.serial_number,
                    site=netbox_site.id,
                    device_role=netbox_device_role.id,
                    status="active",
                )
        else:
            if not self.hostname:
                self.error = "Hostname is empty!"
            elif not self.model:
                self.error = "Model is empty!"
            elif not self.serial_number:
                self.error = "Serial Number is empty!"
            elif not self.site_slug:
                self.error = "Site Slug is empty!"
            elif not self.role:
                self.error = "Role is empty!"
            self.logger.error(f'Error: {self.error}')

        return self.__netbox_device

    def create_ip_interface(self, community_string=None, hostname=None):
        self.logger.info('Create IP interface and set to Device')
        self.error = ''
        self.__netbox_device_sv_interfaces = []
        self.__netbox_device_ip_address = None

        # Устанавливаем значения классу, если заданы
        if community_string:
            self.community_string = community_string
            self.__create_SNMPDevice()
        if hostname:
            self.hostname = hostname

        if self.hostname and self.site_slug:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Если объект устройства не задано, то ищем такое в NetBox
            if not self.__netbox_device:
                self.__netbox_device = self.__netbox_connection.dcim.devices.get(name=hostname)
                # Check if the device already exists in NetBox
                devices = self.__netbox_connection.dcim.devices.filter(name=self.hostname, site=self.site_slug)
                if devices:
                    self.__netbox_device = next(iter(devices))

            if not self.__netbox_device:
                self.error = 'Device not found in NetBox!'
                return

            SVIs, self.error = self.__snmp.getSVIs()
            if self.error:
                return

            # Create IP address objects and assign them to interfaces in NetBox
            for SVI in SVIs:

                # Check if the interface already exists in NetBox
                netbox_device_interface = self.__netbox_connection.dcim.interfaces.get(name=SVI.description,
                                                                                       device=self.__netbox_device.name)
                self.__netbox_device_sv_interfaces += [netbox_device_interface]
                if netbox_device_interface:
                    self.logger.info(
                        f"SVI '{SVI.description}' already exists in NetBox (skipping creation)")
                else:
                    self.logger.info(f"SVI '{SVI.description}' creating in NetBox!")
                    netbox_device_interface = self.__netbox_connection.dcim.interfaces.create(
                        name=SVI.description,
                        device=self.__netbox_device.id,
                        type="virtual",
                        mtu=SVI.MTU,
                        mac=SVI.MAC
                    )

                # TODO Заменить этот костыль на определение Vlan по IP
                # Ищем номер Vlan в названии и если он не равен 1
                vid_interface_out = re.search(r'(\d+)', netbox_device_interface.name)
                if vid_interface_out.groups() and vid_interface_out.group(1) != '1':
                    if self.error:
                        return
                    self.logger.info(f'Set Vlan {vid_interface_out.group(1)} to SVI {netbox_device_interface.name}')
                    netbox_device_interface.mode = 'access'
                    netbox_device_interface.untagged_vlan = self.get_vlan_object(vid=vid_interface_out.group(1))
                    netbox_device_interface.save()

                self.logger.info(f'IP Address: {SVI.ip_address}')
                self.logger.info(f'Subnet Mask: {SVI.mask}')
                self.logger.info(f'IP Address with Prefix: {SVI.ip_with_prefix}')

                # Check if the IP address already exists in NetBox
                self.__netbox_device_ip_address = self.__netbox_connection.ipam.ip_addresses.get(
                    address=SVI.ip_with_prefix)
                if self.__netbox_device_ip_address:
                    self.logger.info(
                        f"IP address '{SVI.ip_with_prefix}' already exists in NetBox (skipping creation)")
                else:
                    self.logger.info(f"IP address '{SVI.ip_with_prefix}' creating in NetBox!")
                    # Create the IP address object in NetBox
                    self.__netbox_device_ip_address = self.__netbox_connection.ipam.ip_addresses.create(
                        address=SVI.ip_with_prefix,
                        status='active',
                        assigned_object_type="dcim.interface",
                        assigned_object_id=netbox_device_interface.id,
                    )

                if SVI.ip_address == self.ip_address:
                    primary_ipv4 = {"address": SVI.ip_with_prefix}
                    if str(self.__netbox_device.primary_ip4) != SVI.ip_with_prefix:
                        self.logger.info(f"Set primary IPv4: '{SVI.ip_with_prefix}'")
                        self.__netbox_device.primary_ip4 = primary_ipv4
                        try:
                            self.__netbox_device.save()
                        except Exception as e:
                            self.error = str(e)
        else:
            if not self.hostname:
                self.error = "Hostname is empty!"
            elif not self.site_slug:
                self.error = "Site Slug is empty!"
            self.logger.error(f'Error: {self.error}')

    def get_interfaces(self, community_string=None):
        self.logger.info('Getting interfaces')
        self.error = ''

        # Устанавливаем значения классу, если заданы
        if community_string:
            self.community_string = community_string
            self.__create_SNMPDevice()

        self.interfaces, self.vlans = self.__snmp.find_interfaces()
        self.error = self.__snmp.error

        if self.error:
            self.logger.error(f'Error: {self.error}')
            return

        # Получаем список Vlan'ов в NetBox
        self.__get_vlans_from_netbox()
        # Проверяем все vlan id на наличие в netbox
        vlans_error = []
        for vid in self.vlans:
            vlan_obj = self.get_vlan_object(vid=vid)
            if not vlan_obj:
                vlans_error += [vid]
        if vlans_error:
            self.error = f"Vlan ID's {','.join(vlans_error)} not found in NetBox (site {self.site_slug})"
            return

        self.logger.info(f'Found {len(self.interfaces)} interfaces')

    def send_to_netbox(self, interface_object: Interface):
        self.logger.info(f"Send to NetBox: {interface_object}")
        self.error = ''

        if self.site_slug:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Получаем внутренние объекты vlan access-интерфейсов из NetBox
            netbox_untagged_id = None
            if interface_object.untagged:
                vlan_obj = self.get_vlan_object(vid=interface_object.untagged)
                if self.error:
                    return
                netbox_untagged_id = {"id": vlan_obj.id}

            # Получаем внутренние объекты vlan trunk-интерфейсов из NetBox
            netbox_tagged_vlans = []
            if interface_object.tagged:
                for vid in interface_object.tagged:
                    vlan_obj = self.get_vlan_object(vid=vid)
                    if self.error:
                        return
                    netbox_tagged_vlans += [vlan_obj]

                    # Get the existing interface object
            netbox_interface = self.__netbox_connection.dcim.interfaces.get(device=self.__netbox_device.name,
                                                                            name=interface_object.name)
            if netbox_interface:
                netbox_interface.name = interface_object.name
                netbox_interface.mtu = interface_object.mtu
                netbox_interface.mac = interface_object.mac
                netbox_interface.description = interface_object.desc
                netbox_interface.mode = interface_object.mode

                netbox_interface.untagged_vlan = netbox_untagged_id
                netbox_interface.tagged_vlans = netbox_tagged_vlans
                # Обновляем тип интерфейса, только если он не Other
                # Что бы предотвратить изменение типа из шаблона NetBox
                if interface_object.type != "other":
                    netbox_interface.type = interface_object.type
                netbox_interface.save()
                self.logger.info(f"Data in interface {interface_object.index} UPDATED in NetBox")
            else:
                netbox_interface: pynetbox.models.dcim.Interfaces = \
                    self.__netbox_connection.dcim.interfaces.create(
                        device=self.__netbox_device.id,
                        name=interface_object.name,
                        mtu=interface_object.mtu,
                        mac=interface_object.mac,
                        description=interface_object.desc,
                        mode=interface_object.mode,
                        type=interface_object.type,
                        untagged_vlan=netbox_untagged_id,
                    )
                netbox_interface.tagged_vlans = netbox_tagged_vlans
                netbox_interface.save()
                self.logger.info(f"Data in interface {interface_object.index} CREATED in NetBox")

            # Временно! Сохраняет объект interface NetBox в класс
            self.__netbox_device_sp_interfaces += [netbox_interface]
        else:
            self.error = "Site Slug is empty!"
            self.logger.error(f'Error: {self.error}')

    def ConfigureInNetBox(self, community_string=None, site_slug=None,
                          role=None):
        # Получаем Hostname, Model, Serial Number по SNMP
        self.get_device_info(community_string=community_string)
        if self.error:
            return
        # Создаём устройство в NetBox
        self.create_netbox_device(site_slug=site_slug, role=role)
        if self.error:
            return
        # Создаём IP, интерфейс у устройства, назначаем IP интерфейсу в NetBox
        self.create_ip_interface()
        if self.error:
            return
        # Получаем список интерфейсов устройства и их данных по SNMP
        self.get_interfaces()
        if self.error:
            return
        # Создаём/обновляем информацию интерфейсов устройства в NetBox
        self.__netbox_device_sp_interfaces = []
        for interface_obj in self.interfaces:
            self.send_to_netbox(interface_obj)
            if self.error:
                break
