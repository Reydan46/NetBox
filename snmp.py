# import re
# import subprocess
# import logging
# from netaddr import IPAddress
# import traceback
# from collections import defaultdict
import re
import subprocess

import oid.general
from errors import Error

# import oid.cisco_sg
# import oid.cisco_catalyst


# Класс для группировки регулярного выражения и формата его выводимого результата
class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action

class SNMPDevice:
#     # Dictionary for storing device's models
#     models = {}
#     with open('model.lists', 'r') as f:
#         for line in f:
#             model_type, models_line = line.split(':')
#             models.update({model_type: list(filter(None, models_line.split(',')))})

    def __init__(self, ip_address, community_string):
        self.community_string = community_string
        self.ip_address = ip_address

#     @staticmethod
#     def __hex_to_binary(hex_str):
#         # Преобразует шестнадцатеричное число в двоичное и удаляет префикс '0b'
#         binary_str = bin(int(hex_str, 16))[2:]
#         # Дополняем нулями слева, чтобы каждый шестнадцатеричный символ соответствовал 4 двоичным
#         binary_str = binary_str.zfill(len(hex_str) * 4)
#         return binary_str

#     @staticmethod
#     def __binary_to_list(binary_str, inc=1):
#         return [str(i + inc) for i, bit in enumerate(binary_str) if bit == '1']

#     def __hex_to_binary_list(self, hex_str, inc=1):
#         binary_str = self.__hex_to_binary(hex_str)
#         return self.__binary_to_list(binary_str, inc)

#     @staticmethod
#     def __indexes_to_dict(indexes):
#         """
#         Converts a list of tuples to a dictionary where the first item of each tuple is the key and the second item is the value.
#         """
#         return {interface: value for interface, value in indexes}

    def snmpwalk(self, oid, typeSNMP='', hex=False, custom_option=None, timeout_process=None):
        out = []  
        try:
            process = ["snmpwalk", "-Pe", "-v", "2c", "-c", self.community_string, f"-On{'x' if hex else ''}",
                       *([custom_option] if custom_option else []), self.ip_address, *([oid] if oid else [])]

            result = subprocess.run(process, capture_output=True, text=True, timeout=timeout_process, check=True)

            # Обработка ошибок
            if result.returncode != 0:
                return result.stdout, f'Fail SNMP (oid {oid})! Return code: {result.returncode}'
            elif 'No Such Object' in result.stdout:
                return [], f'No Such Object available on this agent at this OID ({oid})'
            elif 'No Such Instance currently exists' in result.stdout:
                return [], f'No Such Instance currently exists at this OID ({oid})'
    
            # Словарь паттернов парсинга
            regex_actions = {
                'Debug': RegexAction(
                    r'(.*)',
                    lambda re_out: re_out.group(1)
                ),
                'DotSplit': RegexAction(
                    r'"([A-Za-z0-9\-_]+)(\.|\")',
                    lambda re_out: re_out.group(1)
                ),
                'IP': RegexAction(
                    r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    lambda re_out: re_out.group(1)
                ),
                'INT': RegexAction(
                    r': (\d+)',
                    lambda re_out: re_out.group(1)
                ),
                'INDEX-INT': RegexAction(
                    r'.(\d+) = \w+: (\d+)',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'INDEX-MAC': RegexAction(
                    r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: [re_out.group(1), re_out.group(2).strip().replace(" ", ':').upper()]
                ),
                'PREINDEX-MAC': RegexAction(
                    r'.(\d+).\d+ = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: [re_out.group(1), re_out.group(2).strip().upper()]
                ),
                'INDEX-DESC': RegexAction(
                    r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'PREINDEX-DESC': RegexAction(
                    r'.(\d+).\d+ = [\w\-]*:? ?"([^"]*)"',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'INDEX-HEX': RegexAction(
                    r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?\n?){126,})',
                    lambda re_out: [re_out.group(1),
                                    re_out.group(2).strip().replace(" ", '').replace("\n", '').upper()]
                ),
                'INDEX-DESC-HEX': RegexAction(
                    r'.(\d+) = [\w\-]*:? ?"?(([0-9A-Fa-f]{2} ?\n?)*)"?',
                    lambda re_out: [re_out.group(1),
                                    re_out.group(2).strip().replace("\n", '').upper()]
                ),
                'MAC': RegexAction(
                    r': (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: re_out.group(1).strip().replace(" ", ':').upper()
                ),
                'DEFAULT': RegexAction(
                    r'"([^"]*)"',
                    lambda re_out: re_out.group(1)
                )
            }
            
            # Выбор паттерна по параметру typeSNMP
            regex_action = regex_actions.get(typeSNMP, regex_actions['DEFAULT'])

            # Если вывод snmpwalk не пустой (больше чем 1 символ - '.')
            if len(result.stdout) > 0:
                # Построчно обрабатываем вывод snmpwalk
                for lineSNMP in result.stdout[1:].split('\n.'):
                    # Игнорируем пустые строки
                    if not lineSNMP:
                        continue
                    
                    re_out = re.search(regex_action.pattern, lineSNMP)
                    # Игнорируем строки при НЕ нахождении паттерна
                    if re_out:
                        output = regex_action.action(re_out)
                        # Собираем результаты в список out
                        out += [output]
            return out
        
        except subprocess.CalledProcessError as e:
            if 'No Such Object' in e.stdout:
                raise Error(f'No Such Object available on this agent at this OID ({oid})')
            elif 'No Such Instance currently exists' in e.stdout:
                raise Error(f'No Such Instance currently exists at this OID ({oid})')
            else:
                raise Error(f'Fail SNMP (oid {oid})! Return code: {e.returncode}')
        
        except subprocess.TimeoutExpired as timeErr:
            if len(timeErr.stdout) > 0:
                for lineSNMP in timeErr.stdout[1:].split('\n.'):
                    if not lineSNMP:
                        continue
                    out += [lineSNMP]
            raise Error(f'Timeout Expired: {str(timeErr)}')

        except Exception as e:
            raise Error(f'Unexpected error: {str(e)}')

    def get_hostname(self):
        value = self.snmpwalk(oid.general.hostname, 'DotSplit')
        if not value:
            raise Error("Hostname is undefined")

        self.hostname = value[0]
        return self.hostname

    def get_model(self):
        # Пробуем получить модель по основному oid
        value = self.snmpwalk(oid.general.model)
        if value:
            re_out = re.search(r'(\b[A-Z][A-Z0-9]{2,}-[A-Z0-9]{2,8}\b)', value[0])
            if re_out:
                self.model = re_out.group(1)
                return self.model

        # Пробуем получить модель по альтернативному oid
        value = self.snmpwalk(oid.general.alt_model)
        if value:
            self.model = next((i for i in value if i), None)
            if self.model:
                return self.model

        # Ни по одному oid модель не получена
        raise Error("Model is undefined")

    def get_serial_number(self):
        
        value = self.snmpwalk(oid.general.serial_number)
        if value:
            self.serial_number = next((i for i in value if i), None)
            if self.serial_number:
                return self.serial_number

        raise Error("Serial number is undefined")

# # Виртуальный IP интерфейс
# class SVI:
#     def __init__(self, ip_address, mask, index, description, MTU, MAC):
#         self.index = index
#         self.ip_address = ip_address
#         self.mask = mask
#         self.ip_with_prefix = f'{self.ip_address}/{IPAddress(self.mask).netmask_bits()}'
#         self.description = description
#         self.MTU = MTU
#         self.MAC = MAC

#     def __repr__(self):
#         return f'{self.index} - {self.ip_with_prefix} ({self.MAC}) - {self.description} - {self.MTU}'


# # Физический интерфейс
# class Interface:
#     def __init__(self, index, untagged=None, tagged=None, name=None, mode=None, mtu=None, mac=None, desc=None):
#         self.index = index
#         self.untagged = None
#         if untagged:
#             self.untagged = untagged
#         self.tagged = None
#         if tagged:
#             self.tagged = tagged
#         self.name = ''
#         if name:
#             self.name = name
#         self.mode = 'access'  # set mode to 'access' by default
#         if mode:
#             self.mode = mode
#         self.mtu = 1500
#         if mtu:
#             self.mtu = mtu
#         self.mac = ''
#         if mac:
#             self.mac = mac
#         self.desc = ''
#         if desc:
#             self.desc = desc
#         self.type = "other"
#         self.object_interface_netbox = None

#     def __repr__(self):
#         tagged = f" Tagged: " + ','.join(self.tagged) if self.tagged else ""
#         return f'{self.name} {self.index} ({self.mode}){f" Untagged: {self.untagged}" if self.untagged else ""}{tagged}'

#     def getSVIs(self):
#         indexes = self.getValue(
#             snmpwalk(oid.general.svi_indexes, self.community_string, self.ip_address, 'INT', logger=self.logger))
#         if self.error:
#             return None, self.error
#         ip_addresses = self.getValue(
#             snmpwalk(oid.general.svi_ip_addresses, self.community_string, self.ip_address, 'IP'))
#         if self.error:
#             return None, self.error
#         masks = self.getValue(
#             snmpwalk(oid.general.svi_masks, self.community_string, self.ip_address, 'IP', logger=self.logger))
#         if self.error:
#             return None, self.error
#         SVIs = []
#         for i, index in enumerate(indexes):
#             if masks[i] == '0.0.0.0':
#                 continue

#             description, self.error = snmpwalk(f"{oid.general.si_int_name}.{index}", self.community_string,
#                                                self.ip_address, logger=self.logger)
#             if self.error:
#                 return
#             MTU, self.error = snmpwalk(f"{oid.general.si_mtu}.{index}", self.community_string,
#                                        self.ip_address, 'INT', logger=self.logger)
#             if self.error:
#                 return
#             MAC, self.error = snmpwalk(f"{oid.general.si_mac}.{index}", self.community_string,
#                                        self.ip_address, 'MAC', hex=True, logger=self.logger)
#             if self.error:
#                 return

#             SVIs += [SVI(
#                 ip_address=ip_addresses[i],
#                 mask=masks[i],
#                 index=index,
#                 description=description[0],
#                 MTU=MTU[0],
#                 MAC=MAC[0]
#             )]
#         return SVIs, self.error

#     def find_interfaces(self):
#         def get_lldp_data_by_index(int_name_dict, lldp_loc_port_dict, lldp_data_dict):
#             """
#             Get LLDP data by index from dictionaries of interface names and LLDP data.
#             """
#             lldp_data_by_index = {}
#             for int_index, int_name in int_name_dict.items():
#                 lldp_index = None
#                 for idx, name in lldp_loc_port_dict.items():
#                     if name.startswith(int_name):
#                         lldp_index = idx
#                         break
#                 if lldp_index:
#                     lldp_data = lldp_data_dict.get(lldp_index)
#                     if lldp_data:
#                         lldp_data_by_index[int_index] = lldp_data
#             return lldp_data_by_index

#         def get_snmp_data(oid, data_type, hex_output=False):
#             output, self.error = snmpwalk(oid, self.community_string, self.ip_address, data_type, hex=hex_output, logger=self.logger)
#             if self.error:
#                 return {}, []
#             return self.__indexes_to_dict(output)

#         self.error = ''

#         if not self.model:
#             self.error = 'Model is empty!'
#         elif not self.ip_address:
#             self.error = 'IP address is Empty!'
#         elif not self.community_string:
#             self.error = 'Community string is Empty!'

#         if self.error:
#             return [], []

#         self.logger.info(f'Find model "{self.model}" in model.lists')
#         interfaces = []
#         model_families = {
#             "cisco_catalyst": self.find_interfaces_cisco_catalyst,
#             "cisco_sg_300": self.find_interfaces_cisco_sg,
#             "cisco_sg_350": self.find_interfaces_cisco_sg,
#             "huawei": self.find_interfaces_huawei,
#             "zyxel": self.find_interfaces_zyxel,
#             "ubiquiti": self.find_interfaces_ubiquiti,
#         }

#         flag_find_family = False
#         for family, get_interfaces_func in model_families.items():
#             if self.model in self.models[family]:
#                 self.family_model = family
#                 self.logger.info(f'Run block find_interfaces for "{self.family_model}"')
#                 interfaces = get_interfaces_func()
#                 flag_find_family = True
#                 break

#         if not flag_find_family:
#             self.error = f'Model {self.model} is not found in model.lists!'

#         if self.error:
#             return [], []

#         int_name_dict = get_snmp_data(oid.general.si_int_name, 'INDEX-DESC')
#         mtu_dict = get_snmp_data(oid.general.si_mtu, 'INDEX-INT')
#         mac_dict = get_snmp_data(oid.general.si_mac, 'INDEX-MAC', hex_output=True)
#         desc_dict = get_snmp_data(oid.general.si_description, 'INDEX-DESC-HEX', hex_output=True)
        
#         lldp_loc_port_dict = get_snmp_data(oid.general.lldp_loc_port, 'INDEX-DESC')
#         lldp_rem_name_dict = get_snmp_data(oid.general.lldp_rem_name, 'PREINDEX-DESC')      
#         lldp_rem_name_by_index = get_lldp_data_by_index(int_name_dict, lldp_loc_port_dict, lldp_rem_name_dict) 
#         lldp_rem_mac_dict = get_snmp_data(oid.general.lldp_rem_mac, 'PREINDEX-MAC', hex_output=True)
#         lldp_rem_mac_by_index = get_lldp_data_by_index(int_name_dict, lldp_loc_port_dict, lldp_rem_mac_dict)
        
#         vlans = []
#         for interface in interfaces:
#             interface.name = int_name_dict[interface.index]
#             interface.mtu = mtu_dict[interface.index]
#             interface.mac = mac_dict[interface.index]
#             interface.desc = hex2string(desc_dict[interface.index])
#             # Предполагаем, что интерфейсы начинающиеся с "P" являются LAG
#             if interface.name[0].lower() == 'p':
#                 interface.type = 'lag'

#             if interface.untagged:
#                 if interface.untagged not in vlans:
#                     vlans += [interface.untagged]
#             if interface.tagged:
#                 for vid in interface.tagged:
#                     if vid not in vlans:
#                         vlans += [vid]

#             attribute_dict = {
#                 "lldp_rem_mac": lldp_rem_mac_by_index,
#                 "lldp_rem_name": lldp_rem_name_by_index
#             }
#             for attribute, data in attribute_dict.items():
#                 if interface.index in data:
#                     setattr(interface, attribute, data[interface.index])
#                     self.logger.debug(f'{interface.name}: {getattr(interface, attribute)}')

#         return interfaces, sorted(vlans, key=int)

#     def __get_snmp_dict(self, oid, snmp_type):
#         """
#         This is a helper function that uses SNMP to get a dictionary of the specified OID.
#         """
#         output, self.error = snmpwalk(oid, self.community_string, self.ip_address, snmp_type, logger=self.logger)
#         if self.error:
#             return {}
#         return self.__indexes_to_dict(output)

#     def __get_tag_dict_by_port(self, oid):
#         """
#         Метод для получения порт:влан словаря, для случаев, когда список вланов храниться в HEX
#         """
#         output, self.error = snmpwalk(oid, self.community_string, self.ip_address, 'INDEX-HEX', logger=self.logger)
#         if self.error:
#             return {}
#         tag_dict = defaultdict(list)
#         for port_index, hex_vlans in output:
#             for vid in self.__hex_to_binary_list(hex_vlans, 0):
#                 if vid == '1':
#                     continue
#                 tag_dict[port_index].append(vid)
#         return tag_dict

#     def __get_tag_dict_by_vlan(self, oid):
#         """
#         Метод для получения порт:влан словаря, для случаев, когда список портов храниться в HEX
#         """
#         output, self.error = snmpwalk(oid, self.community_string, self.ip_address, 'INDEX-HEX',
#                                       logger=self.logger)
#         if self.error:
#             return {}

#         tag_dict = defaultdict(list)
#         for vlan_id, hex_indexes in output:
#             if vlan_id == '1':
#                 continue
#             for interface_index in self.__hex_to_binary_list(hex_indexes):
#                 tag_dict[interface_index].append(vlan_id)

#         return tag_dict

#     def __create_interface_access(self, index, untag_port_dict):
#         """
#         This is a helper function that creates an access interface object.
#         """
#         return Interface(
#             index=index,
#             untagged=untag_port_dict[index] if index in untag_port_dict and untag_port_dict[index] != '1' else None,
#             mode='access',
#         )

#     def __create_interface_tagged(self, index, native_port_dict, tag_dict):
#         """
#         This is a helper function that creates a tagged interface object.
#         """
#         untagged = native_port_dict.get(index)
#         if untagged in ('1', '0'):
#             untagged = None
    
#         tagged = tag_dict.get(index, [])
#         mode = 'tagged'
#         if (len(tagged) == 1 and tagged[0] == untagged) or not tagged:
#             mode = 'tagged-all'
#         return Interface(index=index, untagged=untagged, mode=mode, tagged=tagged)

#     def find_interfaces_cisco_catalyst(self):
#         """
#         This function finds the interfaces in a Cisco Catalyst device and returns them in a list.
#         It does this by using SNMP to walk through the OID tree of the device and extract the relevant information.
#         The function returns a list of Interface objects.
#         """
#         interfaces = []

#         mode_port_dict = self.__get_snmp_dict(oid.cisco_catalyst.mode_port, 'INDEX-INT')
#         native_port_dict = self.__get_snmp_dict(oid.cisco_catalyst.native_port, 'INDEX-INT')
#         untag_port_dict = self.__get_snmp_dict(oid.cisco_catalyst.untag_port, 'INDEX-INT')
#         tag_port_dict = self.__get_tag_dict_by_port(oid.cisco_catalyst.hex_tag_port)
#         tag_noneg_port_dict = self.__get_tag_dict_by_port(oid.cisco_catalyst.hex_tag_noneg_port)

#         for index, value in mode_port_dict.items():
#             if value == oid.cisco_catalyst.mode_port_state["access"]:
#                 interfaces.append(self.__create_interface_access(index, untag_port_dict))
#             elif value == oid.cisco_catalyst.mode_port_state["tagged"]:
#                 interfaces.append(self.__create_interface_tagged(index, native_port_dict, tag_port_dict))
#             elif value == oid.cisco_catalyst.mode_port_state["tagged-noneg"]:
#                 interfaces.append(self.__create_interface_tagged(index, native_port_dict, tag_noneg_port_dict))

#         return interfaces

#     def find_interfaces_cisco_sg(self):
#         """
#         Finds and creates network interfaces for Cisco SG switches based on SNMP data.
#         Returns:
#             List of interface objects created using SNMP data.
#         """ 
#         interfaces = []
        
#         mode_port_dict = self.__get_snmp_dict(oid.cisco_sg.mode_port, 'INDEX-INT')
#         untag_port_dict = self.__get_snmp_dict(oid.cisco_sg.untag_port[self.family_model], 'INDEX-INT')
#         tag_port_dict = self.__get_tag_dict_by_vlan(oid.cisco_sg.hex_tag_port)

#         for index, value in mode_port_dict.items():
#             if value == oid.cisco_sg.mode_port_state[self.family_model]["access"]:
#                 interfaces.append(self.__create_interface_access(index, untag_port_dict))
#             elif value == oid.cisco_sg.mode_port_state[self.family_model]["tagged"]:
#                 interfaces.append(self.__create_interface_tagged(index, untag_port_dict, tag_port_dict))
#                 # Check if the last interface has both tagged and untagged VLANs,
#                 # and if the untagged VLAN is also in the tagged VLANs list
#                 if (interfaces[-1].tagged
#                     and interfaces[-1].untagged
#                     and interfaces[-1].untagged in interfaces[-1].tagged):
#                     # If yes, remove the untagged VLAN from the tagged VLANs list
#                     interfaces[-1].tagged.remove(interfaces[-1].untagged)

#         return interfaces

#     def find_interfaces_huawei(self):
#         return []

#     def find_interfaces_zyxel(self):
#         return []

#     def find_interfaces_ubiquiti(self):
#         return []


# def hex2string(hex):
#     if hex:
#         return "".join([chr(int(x, 16)) for x in hex.split()]).encode('latin1').decode('utf-8')
#     return ""


# if __name__ == "__main__":
#     print(snmpwalk('1.3.6.1.2.1.1.5.0', 'public', '10.10.3.13', 'DotSplit'))
