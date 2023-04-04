import os
import wexpect as expect
import pynetbox
from pynetbox.core import api
from pynetbox.models import dcim
from snmp import snmpwalk, SNMPDevice
import logging
from cryptography.fernet import Fernet


class Interface:
    def __init__(self, index: str, vlan_id: int, name: str):
        self.index = index
        self.vlan_id = vlan_id
        self.mode = 'access'  # set mode to 'access' by default
        self.name = name
        self.mtu = 1500
        self.mac_address = ''
        self.desc = ''
        self.object_interface_netbox = None


class NetworkDevice:
    def __init__(self, ip_address, username=None, password=None, community_string=None, site_slug=None, role=None,
                 logger=None):
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

        self.__password_salt = None
        self.__password_decoder = None

        self.hostname = ""
        self.model = ""
        self.serial_number = ""
        self.site_slug = ""
        self.role = ""

        self.interfaces = []

        self.cred = {
            "username": "",
            "password": ""
        }
        self.community_string = ""
        self.error = ""

        # Сохраняем не None значения атрибутов
        self.ip_address = ip_address
        if username:
            self.cred.update({"username": username})
        if password:
            self.cred.update({"password": password})
        if community_string:
            self.community_string = community_string
            self.__create_SNMPDevice()
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

        # Получаем переменную окружения для расшифровки пароля
        self.__password_salt = os.environ.get('NETBOX_PASSWORD_SALT')
        if not self.__password_salt:
            self.error = 'Password SALT is empty!'
            self.logger.error(self.error)
            return
        try:
            self.__password_decoder = Fernet(self.__password_salt)
        except Exception as e:
            self.error = f'Could not initiate Password Decoder: {e}'
            self.logger.error(self.error)
            return

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
    def __iFACES2dict(iFaces):
        return {interface: value for interface, value in iFaces}

    def getPassword(self, password):
        return self.__password_decoder.decrypt(password).decode('utf-8')

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

    def configure_access_list(self, allowed_ip, username=None, password=None):
        self.logger.info('Configure access list')

        self.error = ''
        device_type = ''

        if username:
            self.cred.update({"username": username})
        if password:
            self.cred.update({"password": password})

        if not self.cred["username"] and not self.cred["password"]:
            self.cred = {"username": "network-backup",
                         "password": 'gAAAAABkJWTLKA-pCESIgNea34_AQ_OhMapaKSKp24RZSyf_ei-T5JZX0dBW_TzfueuNopnqWFmduhuLDHr-sj4mLRGq5z8J4qDyaFomECh7iS0udKIEN1w='}

        # Ели все необходимые параметры заданы
        if allowed_ip:
            ssh_options = '-oKexAlgorithms=+diffie-hellman-group-exchange-sha1 -oStrictHostKeyChecking=accept-new'

            self.logger.info(f'Connecting via ssh: {self.cred["username"]}@{self.ip_address}')
            ssh = expect.spawn(f'ssh {ssh_options} {self.cred["username"]}@{self.ip_address}', timeout=10)

            # Если процесс не завершился мгновенно (если всё хорошо)
            if ssh.isalive():
                try:
                    count = 0
                    index = -1
                    while index != 0 and count < 5:
                        count += 1
                        index = ssh.expect(['assword:', 'ame:', 'ogin:', 'ser:'])
                        if index == 0:
                            ssh.sendline(self.getPassword(self.cred["password"]))
                        else:  # elif index in [1, 2, 3]:
                            ssh.sendline(self.cred["username"])

                    # Wait for the command prompt to appear
                    ssh.expect('[>#]')

                    # Determine the device type by running the 'show inventory' command
                    ssh.sendline('show inventory')
                    ssh.expect('[>#]')

                    output_inventory = '\n'.join(['=' * 57] + [i for i in ssh.before.splitlines() if i] + ['=' * 57])
                    self.logger.debug(f'Console:\n{output_inventory}')

                    if 'WS-C2960' in output_inventory:
                        device_type = '2960'
                    elif 'SG250' in output_inventory \
                            or 'SG300' in output_inventory \
                            or 'SG350' in output_inventory:
                        device_type = 'SG'

                    # Если модель устройства определена
                    if device_type:
                        self.logger.info(f'Device type: {device_type}')
                        # Configure the access list using the appropriate commands for the device type
                        ssh.sendline('config terminal')
                        ssh.expect('[#]')

                        ssh.sendline('no logging con')
                        if device_type == '2960':
                            ssh.sendline('ip access-list standard ACL_SNMP')
                            ssh.sendline(f'permit {allowed_ip}')
                        elif device_type == 'SG':
                            ssh.sendline(f'snmp-server community public ro {allowed_ip} view Default')
                    else:
                        self.error = f'Invalid device type: {device_type}'

                    ssh.expect('[#]')
                    ssh.sendline('end')

                    # Close the SSH session
                    ssh.close()
                except Exception as e:
                    if 'Connection timed out' in ssh.before:
                        self.error = 'Connection timed out'
                    # elif 'Timeout exceeded' in str(e):
                    #     self.error = 'Timeout data wait'
                    elif 'Permission denied' in ssh.before:
                        self.error = 'Permission denied (wrong username?)'
                    elif 'User Name:' in ssh.before:
                        self.error = 'Permission denied (maybe no radius?)'
                    else:
                        # error = ssh.before
                        self.error = str(e)
            else:
                self.error = 'Unable to connect'
        else:
            if not allowed_ip:
                self.error = 'Allowed IP is Empty!'
            elif not self.cred["username"]:
                self.error = 'Username is Empty!'
            elif not self.cred["password"]:
                self.error = 'Password is Empty!'

        return device_type

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

        # Устанавливаем значения классу, если заданы
        if self.community_string:
            self.__create_SNMPDevice()

            sg = False
            vlan_output, self.error = \
                snmpwalk('1.3.6.1.4.1.9.9.68.1.2.2.1.2', self.community_string, self.ip_address, 'iFACE-INT')
            if self.error:
                self.error = ''
                sg = True
                vlan_output, self.error = \
                    snmpwalk('1.3.6.1.4.1.9.6.1.101.48.62.1.1', self.community_string, self.ip_address, 'iFACE-INT')

            if self.error:
                return
            vlan_dict = self.__iFACES2dict(vlan_output)

            mtu_output, self.error = \
                snmpwalk('1.3.6.1.2.1.2.2.1.4', self.community_string, self.ip_address, 'iFACE-INT')
            if self.error:
                return
            mtu_dict = self.__iFACES2dict(mtu_output)

            mac_output, self.error = \
                snmpwalk('1.3.6.1.2.1.2.2.1.6', self.community_string, self.ip_address, 'iFACE-MAC', hex=True)
            if self.error:
                return
            mac_dict = self.__iFACES2dict(mac_output)

            desc_output, self.error = \
                snmpwalk('1.3.6.1.2.1.31.1.1.1.18', self.community_string, self.ip_address, 'iFACE-DESC')
            if self.error:
                return
            desc_dict = self.__iFACES2dict(desc_output)

            if not sg:
                int_mode_output, self.error = \
                    snmpwalk('1.3.6.1.4.1.9.9.46.1.6.1.1.14', self.community_string, self.ip_address, 'iFACE-INT')
            else:
                int_mode_output, self.error = \
                    snmpwalk('1.3.6.1.4.1.9.6.1.101.48.65.1.1', self.community_string, self.ip_address, 'iFACE-INT')
            if self.error:
                return
            int_mode_dict = self.__iFACES2dict(int_mode_output)

            self.interfaces = []
            for int_index in int_mode_dict.keys():
                #############################################
                # Временно отбираем только порты в access
                # Для всего - 2
                # Для SG    - 4
                #############################################
                if not sg and int_mode_dict[int_index] != '2':
                    continue
                if sg and int_mode_dict[int_index] != '4':
                    continue
                #############################################

                if int_index in vlan_dict.keys():
                    if vlan_dict[int_index] in ['0', '1']:
                        continue  # skip interfaces with vlan_id of 0 or 1

                    int_name, self.error = snmpwalk(f"1.3.6.1.2.1.2.2.1.2.{int_index}", self.community_string,
                                                    self.ip_address)
                    if self.error:
                        return

                    interface_obj = Interface(int_index, vlan_dict[int_index], int_name[0])
                    interface_obj.mtu = mtu_dict[int_index]
                    interface_obj.mac_address = mac_dict[int_index]
                    interface_obj.desc = desc_dict[int_index]

                    self.interfaces.append(interface_obj)
            self.logger.info(f'Found {len(self.interfaces)} interfaces')
        else:
            self.error = "Community String is empty!"
            self.logger.error(f'Error: {self.error}')

    def send_to_netbox(self, interface_object):
        self.logger.info(f"Index: {interface_object.index}, VLAN ID: {interface_object.vlan_id}")
        self.error = ''

        if self.site_slug:
            # Создаём подключение к NetBox
            self.__connect_to_netbox()
            if self.error:
                return

            # Get the ID of the VLAN with the specified VLAN ID and associated with the specified site
            vlan = self.__netbox.ipam.vlans.get(site=self.site_slug, vid=interface_object.vlan_id)
            if not vlan:
                self.error = f'Vlan ID {interface_object.vlan_id} not found in NetBox'
                return

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
                netbox_interface.untagged_vlan = {"id": vlan.id}
                netbox_interface.save()
                self.logger.info(f"Data in interface {interface_object.index} UPDATED in NetBox")
            else:
                self.__netbox_device_interface = self.__netbox.dcim.interfaces.create(
                    device=self.__netbox_device.id,
                    name=interface_object.name,
                    mtu=interface_object.mtu,
                    mac_address=interface_object.mac_address,
                    description=interface_object.desc,
                    mode=interface_object.mode,
                    untagged_vlan={"id": vlan.id},
                    type="other",
                )
                self.logger.info(f"Data in interface {interface_object.index} CREATED in NetBox")
        else:
            self.error = "Site Slug is empty!"
            self.logger.error(f'Error: {self.error}')

    def ConfigureInNetBox(self, allowed_ip, username=None, password=None, community_string=None, site_slug=None,
                          role=None):
        # Конфигурируем Access List
        self.configure_access_list(allowed_ip=allowed_ip, username=username, password=password)
        if self.error:
            return
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
