import os
import pynetbox
from pynetbox.core import api
from pynetbox.models import dcim
from snmp import SNMPDevice, Interface
import logging


class NetworkDevice:
    def __init__(self, ip_address, community_string=None, site_slug=None, role=None, logger=None):
        # Проверяем наличие логгера
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger('NetworkDevice')

        self.__snmp: SNMPDevice = None

        self.__netbox: pynetbox.core.api.Api = None
        self.__netbox_url = None
        self.__netbox_token = None
        self.__netbox_device: pynetbox.models.dcim.Devices = None
        self.__netbox_device_interface = None
        self.__netbox_device_ip_address = None
        self.__netbox_vlans = {}

        self.__password_salt = None
        self.__password_decoder = None

        self.hostname = ""
        self.model = ""
        self.serial_number = ""
        self.site_slug = ""
        self.role = ""

        self.interfaces = []

        self.community_string = ""
        self.error = ""

        # Сохраняем не None значения атрибутов
        self.ip_address = ip_address
        if community_string:
            self.community_string = community_string
            self.__create_SNMPDevice()
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

    def getModel(self):
        if self.model:
            return self.model
        else:
            return "Undefined"

    def __create_SNMPDevice(self):
        if not self.__snmp:
            if not self.community_string:
                self.error = 'Community String is empty!'
                self.logger.error(self.error)
                return None
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
            if not self.__netbox:
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
                self.__netbox = pynetbox.api(url=self.__netbox_url, token=self.__netbox_token)
        except:
            self.error = 'Fail connect to NetBox'
        return self.__netbox

    def __get_vlans_from_netbox(self):
        self.error = ''

        # Если список Vlan уже был получен
        if self.__netbox_vlans:
            return

        self.logger.debug('Get VLANs from NetBox')
        if not self.__netbox:
            self.error = 'No connecting to NetBox'
            self.logger.debug(self.error)
            return

        self.__netbox_vlans = {}
        site_out = self.__netbox.dcim.sites.all()
        if not site_out:
            self.error = 'No get sites in NetBox!'
            self.logger.error(self.error)
            return

        vlans_out = self.__netbox.ipam.vlans.all()
        if not vlans_out:
            self.error = 'No get vlans in NetBox!'
            self.logger.error(self.error)
            return

        for site in site_out:
            self.__netbox_vlans.update({site.slug: {}})
        for vlan in vlans_out:
            if not vlan.site:
                self.error = f'Vlan ID {vlan.vid} has no Site!'
                return
            self.__netbox_vlans[vlan.site.slug].update({str(vlan.vid): vlan})

    def get_device_info(self, community_string=None):
        self.logger.info('Get Device Info')

        self.error = ''

        if community_string:
            self.community_string = community_string

        # Если все необходимые параметры заданы
        if self.community_string:
            self.__create_SNMPDevice()

            self.hostname, self.error = self.__snmp.getHostname()
            if not self.error:
                self.logger.info(f'Hostname: {self.hostname}')
            else:
                self.logger.error(f'Error get hostname: {self.error}')

            if not self.error:
                self.model, self.error = self.__snmp.getModel()
                if not self.error:
                    self.logger.info(f'Model: {self.model}')
                else:
                    self.logger.error(f'Error get model: {self.error}')

            if not self.error:
                self.serial_number, self.error = self.__snmp.getSerialNumber()
                if not self.error:
                    self.logger.info(f'Serial Number: {self.serial_number}')
                else:
                    self.logger.error(f'Error get serial number: {self.error}')
        else:
            self.error = 'Community string is Empty!'
            self.logger.error(self.error)

    def create_netbox_device(self, site_slug=None, role=None):
        self.logger.info('Create Device in NetBox')

        self.error = ''
        self.__netbox_device = None

        # Устанавливаем значения классу, если заданы
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

        # Если все необходимые параметры заданы
        if self.hostname and self.model and self.serial_number and self.site_slug and self.role:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Check if the device already exists in NetBox
            devices = self.__netbox.dcim.devices.filter(name=self.hostname, site=self.site_slug)
            if devices:
                self.logger.info(f"Device '{self.hostname}' already exists in NetBox (skipping creation)")
                find_netbox_device = next(iter(devices))
                if find_netbox_device.serial != self.serial_number:
                    self.error = "Serial number does not match!"
                    return
                else:
                    self.__netbox_device = find_netbox_device
            else:
                netbox_device_type = self.__netbox.dcim.device_types.get(model=self.model)
                if not netbox_device_type:
                    self.error = f'Device type "{self.model}" not found in NetBox!'
                    return

                netbox_site = self.__netbox.dcim.sites.get(slug=self.site_slug)
                if not netbox_site:
                    self.error = f'Site slug "{self.site_slug}" not found in NetBox!'
                    return

                netbox_device_role = self.__netbox.dcim.device_roles.get(name=self.role)
                if not netbox_device_role:
                    self.error = f'Device role "{self.role}" not found in NetBox!'
                    return

                self.logger.info(f"Device '{self.hostname}' creating in NetBox")
                self.__netbox_device = self.__netbox.dcim.devices.create(
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
        self.__netbox_device_interface = None
        self.__netbox_device_ip_address = None

        # Устанавливаем значения классу, если заданы
        if community_string:
            self.community_string = community_string
        if hostname:
            self.hostname = hostname

        if self.community_string and self.hostname and self.site_slug:
            self.__create_SNMPDevice()

            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Если объект устройства не задано, то ищем такое в NetBox
            if not self.__netbox_device:
                self.__netbox_device = self.__netbox.dcim.devices.get(name=hostname)
                # Check if the device already exists in NetBox
                devices = self.__netbox.dcim.devices.filter(name=self.hostname, site=self.site_slug)
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
                self.__netbox_device_interface = self.__netbox.dcim.interfaces.get(name=SVI.description,
                                                                                   device=self.__netbox_device.name)
                if self.__netbox_device_interface:
                    self.logger.info(
                        f"Interface '{SVI.description}' already exists in NetBox (skipping creation)")
                else:
                    self.logger.info(f"Interface '{SVI.description}' creating in NetBox!")
                    self.__netbox_device_interface = self.__netbox.dcim.interfaces.create(
                        name=SVI.description,
                        device=self.__netbox_device.id,
                        type="virtual",
                        mtu=SVI.MTU,
                        mac_address=SVI.MAC_address
                    )
                    # TODO: Добавить привязку к Vlan

                self.logger.info(f'IP Address: {SVI.ip_address}')
                self.logger.info(f'Subnet Mask: {SVI.mask}')
                self.logger.info(f'IP Address with Prefix: {SVI.ip_with_prefix}')

                # Check if the IP address already exists in NetBox
                self.__netbox_device_ip_address = self.__netbox.ipam.ip_addresses.get(
                    address=SVI.ip_with_prefix)
                if self.__netbox_device_ip_address:
                    self.logger.info(
                        f"IP address '{SVI.ip_with_prefix}' already exists in NetBox (skipping creation)")
                else:
                    self.logger.info(f"IP address '{SVI.ip_with_prefix}' creating in NetBox!")
                    # Create the IP address object in NetBox
                    self.__netbox_device_ip_address = self.__netbox.ipam.ip_addresses.create(
                        address=SVI.ip_with_prefix,
                        status='active',
                        assigned_object_type="dcim.interface",
                        assigned_object_id=self.__netbox_device_interface.id,
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
            if not self.community_string:
                self.error = "Community String is empty!"
            elif not self.hostname:
                self.error = "Hostname is empty!"
            elif not self.site_slug:
                self.error = "Site Slug is empty!"
            self.logger.error(f'Error: {self.error}')

    def get_interfaces(self, community_string=None):
        self.logger.info('Getting interfaces device')
        self.error = ''

        # Устанавливаем значения классу, если заданы
        if community_string:
            self.community_string = community_string

        if not self.community_string:
            self.error = "Community String is empty!"
            self.logger.error(f'Error: {self.error}')
            return

        self.__create_SNMPDevice()

        interfaces_out = self.__snmp.getInterfaces()
        self.error = self.__snmp.error

        if self.error:
            self.logger.error(f'Error: {self.error}')
            return

        self.interfaces = interfaces_out
        self.logger.info(f'Found {len(self.interfaces)} interfaces')

    def send_to_netbox(self, interface_object: Interface):
        self.logger.info(f"Index: {interface_object.index}, VLAN ID: {interface_object.untagged}")
        self.error = ''

        if self.site_slug:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Получаем список Vlan'ов из NetBox
            self.__get_vlans_from_netbox()
            if self.error:
                return

            if self.site_slug not in self.__netbox_vlans:
                self.error = f'Site Slug {self.site_slug} not found in NetBox'
                return

            # Получаем внутренние объекты vlan access-интерфейсов из NetBox
            netbox_untagged_id = None
            if interface_object.untagged:
                if interface_object.untagged not in self.__netbox_vlans[self.site_slug]:
                    self.error = f'Vlan ID {interface_object.untagged} not found in NetBox (Site {self.site_slug})'
                    return
                netbox_untagged_id = self.__netbox_vlans[self.site_slug][interface_object.untagged]

            # Получаем внутренние объекты vlan trunk-интерфейсов из NetBox
            netbox_tagged_vlans = []
            if interface_object.tagged:
                for vid in interface_object.tagged:
                    if vid not in self.__netbox_vlans[self.site_slug]:
                        self.error = f'Vlan ID {vid} not found in NetBox (Site {self.site_slug})'
                        return
                    netbox_tagged_vlans += [self.__netbox_vlans[self.site_slug][vid]]

            # Get the existing interface object
            netbox_interface = self.__netbox.dcim.interfaces.get(device=self.__netbox_device.name,
                                                                 name=interface_object.name)
            # Временно! Сохраняет объект interface NetBox в класс
            interface_object.object_interface_netbox = netbox_interface

            if netbox_interface:
                netbox_interface.name = interface_object.name
                netbox_interface.mtu = interface_object.mtu
                netbox_interface.mac_address = interface_object.mac_address
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
                self.__netbox_device_interface: pynetbox.models.dcim.Interfaces = \
                    self.__netbox.dcim.interfaces.create(
                        device=self.__netbox_device.id,
                        name=interface_object.name,
                        mtu=interface_object.mtu,
                        mac_address=interface_object.mac_address,
                        description=interface_object.desc,
                        mode=interface_object.mode,
                        type=interface_object.type,
                        untagged_vlan=netbox_untagged_id,
                        tagged_vlans=netbox_tagged_vlans
                    )

                self.logger.info(f"Data in interface {interface_object.index} CREATED in NetBox")
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
        for interface_obj in self.interfaces:
            self.send_to_netbox(interface_obj)
            if self.error:
                break
