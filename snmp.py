import re
import subprocess
import logging
from netaddr import IPAddress
import traceback
from collections import defaultdict
import oid.general
import oid.cisco_sg
import oid.cisco_catalyst


# Виртуальный IP интерфейс
class SVI:
    def __init__(self, ip_address, mask, index, description, MTU, MAC):
        self.index = index
        self.ip_address = ip_address
        self.mask = mask
        self.ip_with_prefix = f'{self.ip_address}/{IPAddress(self.mask).netmask_bits()}'
        self.description = description
        self.MTU = MTU
        self.MAC = MAC

    def __repr__(self):
        return f'{self.index} - {self.ip_with_prefix} ({self.MAC}) - {self.description} - {self.MTU}'


# Физический интерфейс
class Interface:
    def __init__(self, index, untagged=None, tagged=None, name=None, mode=None, mtu=None, mac=None, desc=None):
        self.index = index
        self.untagged = None
        if untagged:
            self.untagged = untagged
        self.tagged = None
        if tagged:
            self.tagged = tagged
        self.name = ''
        if name:
            self.name = name
        self.mode = 'access'  # set mode to 'access' by default
        if mode:
            self.mode = mode
        self.mtu = 1500
        if mtu:
            self.mtu = mtu
        self.mac = ''
        if mac:
            self.mac = mac
        self.desc = ''
        if desc:
            self.desc = desc
        self.type = "other"
        self.object_interface_netbox = None

    def __repr__(self):
        tagged = f" Tagged: " + ','.join(self.tagged) if self.tagged else ""
        return f'{self.name} {self.index} ({self.mode}){f" Untagged: {self.untagged}" if self.untagged else ""}{tagged}'


class SNMPDevice:
    def __init__(self, community_string, ip_address, model=None, logger=None):
        if logger:
            self.logger = logger
        else:
            # Объявляем logger, если таковой не задан
            self.logger = logging.getLogger('SNMPDevice')

        self.models = {}

        self.family_model = ""

        self.error = ''
        self.model = ''
        if model:
            self.model = model
        self.community_string = community_string
        self.ip_address = ip_address

    def getModels(self):
        return self.models

    def setModels(self, models):
        self.models = models

    @staticmethod
    def __hex_to_binary(hex_str):
        # Преобразует шестнадцатеричное число в двоичное и удаляет префикс '0b'
        binary_str = bin(int(hex_str, 16))[2:]
        # Дополняем нулями слева, чтобы каждый шестнадцатеричный символ соответствовал 4 двоичным
        binary_str = binary_str.zfill(len(hex_str) * 4)
        return binary_str

    @staticmethod
    def __binary_to_list(binary_str, inc=1):
        return [str(i + inc) for i, bit in enumerate(binary_str) if bit == '1']

    def __hex_to_binary_list(self, hex_str, inc=1):
        binary_str = self.__hex_to_binary(hex_str)
        return self.__binary_to_list(binary_str, inc)

    @staticmethod
    def __indexes_to_dict(indexes):
        return {interface: value for interface, value in indexes}

    def __model_lists_reader(self):
        if not self.models:
            self.logger.info('Read models from file')

            self.family_model = ""

            with open('model.lists', 'r') as f:
                file = f.read()

            for line in file.split('\n'):
                model_type, models_line = line.split(':')
                self.models.update({model_type: list(filter(None, models_line.split(',')))})

    def getValue(self, action):
        self.error = ''
        if self.community_string and self.ip_address:
            value_out, self.error = action
            if self.error:
                return ''
            value = value_out
        else:
            if not self.community_string:
                self.error = 'Community string is Empty!'
            elif not self.community_string:
                self.error = 'IP address is Empty!'
            self.logger.error(self.error)
            return ''
        return value

    def getHostname(self):
        value = self.getValue(
            snmpwalk(oid.general.hostname, self.community_string, self.ip_address, 'DotSplit', logger=self.logger))

        if self.error:
            return None, self.error

        return value[0], self.error

    def getModel(self):
        value = self.getValue(snmpwalk(oid.general.model, self.community_string, self.ip_address, logger=self.logger))

        if self.error:
            return None, self.error

        re_out = re.search(r'(\b[A-Z][A-Z0-9]{3,}-[A-Z0-9]{2,6}\b)', value[0])
        self.model = re_out.group(1) if re_out else ''

        if not self.model:
            value = self.getValue(
                snmpwalk(oid.general.alt_model, self.community_string, self.ip_address, logger=self.logger))
            if self.error:
                return None, self.error
            self.model = next((i for i in value if i), '')

        return self.model, self.error

    def getSerialNumber(self):
        value = self.getValue(
            snmpwalk(oid.general.serial_number, self.community_string, self.ip_address, logger=self.logger))

        if self.error:
            return None, self.error
        serial_number = next((i for i in value if i), '')

        return serial_number, self.error

    def getSVIs(self):
        indexes = self.getValue(
            snmpwalk(oid.general.svi_indexes, self.community_string, self.ip_address, 'INT', logger=self.logger))
        if self.error:
            return None, self.error
        ip_addresses = self.getValue(
            snmpwalk(oid.general.svi_ip_addresses, self.community_string, self.ip_address, 'IP'))
        if self.error:
            return None, self.error
        masks = self.getValue(
            snmpwalk(oid.general.svi_masks, self.community_string, self.ip_address, 'IP', logger=self.logger))
        if self.error:
            return None, self.error
        SVIs = []
        for i, index in enumerate(indexes):
            if masks[i] == '0.0.0.0':
                continue

            description, self.error = snmpwalk(f"{oid.general.si_int_name}.{index}", self.community_string,
                                               self.ip_address, logger=self.logger)
            if self.error:
                return
            MTU, self.error = snmpwalk(f"{oid.general.si_mtu}.{index}", self.community_string,
                                       self.ip_address, 'INT', logger=self.logger)
            if self.error:
                return
            MAC, self.error = snmpwalk(f"{oid.general.si_mac}.{index}", self.community_string,
                                       self.ip_address, 'MAC', hex=True, logger=self.logger)
            if self.error:
                return

            SVIs += [SVI(
                ip_address=ip_addresses[i],
                mask=masks[i],
                index=index,
                description=description[0],
                MTU=MTU[0],
                MAC=MAC[0]
            )]
        return SVIs, self.error

    def find_interfaces(self):
        self.error = ''

        if not self.model:
            self.error = 'Model is empty!'
        elif not self.ip_address:
            self.error = 'IP address is Empty!'
        elif not self.community_string:
            self.error = 'Community string is Empty!'

        if self.error:
            return [], []

        self.__model_lists_reader()

        self.logger.info(f'Find model "{self.model}" in model.lists')
        interfaces = []
        model_families = {
            "cisco_catalyst": self.find_interfaces_cisco_catalyst,
            "cisco_sg_300": self.find_interfaces_cisco_sg,
            "cisco_sg_350": self.find_interfaces_cisco_sg,
            "huawei": self.find_interfaces_huawei,
            "zyxel": self.find_interfaces_zyxel,
            "ubiquiti": self.find_interfaces_ubiquiti,
        }

        flag_find_family = False
        for family, get_interfaces_func in model_families.items():
            if self.model in self.models[family]:
                self.family_model = family
                self.logger.info(f'Run block find_interfaces for "{self.family_model}"')
                interfaces = get_interfaces_func()
                flag_find_family = True
                break

        if not flag_find_family:
            self.error = f'Model {self.model} is not found in model.lists!'

        if self.error:
            return [], []

        int_name_output, self.error = \
            snmpwalk(oid.general.si_int_name, self.community_string, self.ip_address, 'INDEX-DESC', logger=self.logger)
        if self.error:
            return [], []
        int_name_dict = self.__indexes_to_dict(int_name_output)

        mtu_output, self.error = \
            snmpwalk(oid.general.si_mtu, self.community_string, self.ip_address, 'INDEX-INT', logger=self.logger)
        if self.error:
            return [], []
        mtu_dict = self.__indexes_to_dict(mtu_output)

        mac_output, self.error = \
            snmpwalk(oid.general.si_mac, self.community_string, self.ip_address, 'INDEX-MAC', hex=True,
                     logger=self.logger)
        if self.error:
            return [], []
        mac_dict = self.__indexes_to_dict(mac_output)

        desc_output, self.error = \
            snmpwalk(oid.general.si_description, self.community_string, self.ip_address, 'INDEX-DESC-HEX', hex=True,
                     logger=self.logger)
        if self.error:
            return [], []
        desc_dict = self.__indexes_to_dict(desc_output)

        vlans = []
        for interface in interfaces:
            interface.name = int_name_dict[interface.index]
            interface.mtu = mtu_dict[interface.index]
            interface.mac = mac_dict[interface.index]
            interface.desc = hex2string(desc_dict[interface.index])
            # Предполагаем, что интерфейсы начинающиеся с "P" являются LAG
            if interface.name[0].lower() == 'p':
                interface.type = 'lag'

            if interface.untagged:
                if interface.untagged not in vlans:
                    vlans += [interface.untagged]
            if interface.tagged:
                for vid in interface.tagged:
                    if vid not in vlans:
                        vlans += [vid]

        return interfaces, sorted(vlans, key=int)

    def find_interfaces_cisco_catalyst(self):
        interfaces = []
        mode_port_output, self.error = \
            snmpwalk(oid.cisco_catalyst.mode_port, self.community_string, self.ip_address, 'INDEX-INT',
                     logger=self.logger)

        if self.error:
            return

        mode_port_dict = self.__indexes_to_dict(mode_port_output)

        native_port_output, self.error = \
            snmpwalk(oid.cisco_catalyst.native_port, self.community_string, self.ip_address, 'INDEX-INT',
                     logger=self.logger)

        if self.error:
            return

        native_port_dict = self.__indexes_to_dict(native_port_output)

        untag_port_output, self.error = \
            snmpwalk(oid.cisco_catalyst.untag_port, self.community_string, self.ip_address, 'INDEX-INT',
                     logger=self.logger)

        if self.error:
            return

        untag_port_dict = self.__indexes_to_dict(untag_port_output)

        hex_tag_port_output, error = \
            snmpwalk(oid.cisco_catalyst.hex_tag_port, self.community_string, self.ip_address, 'INDEX-HEX',
                     logger=self.logger)

        if self.error:
            return

        hex_tag_noneg_port_output, error = \
            snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, self.community_string, self.ip_address, 'INDEX-HEX',
                     logger=self.logger)

        if self.error:
            return

        tag_port_dict = defaultdict(list)
        for port_index, hex_vlans in hex_tag_port_output:
            for vid in self.__hex_to_binary_list(hex_vlans, 0):
                if vid == '1':
                    continue
                tag_port_dict[port_index].append(vid)

        tag_noneg_port_dict = defaultdict(list)
        for port_index, hex_vlans in hex_tag_noneg_port_output:
            for vid in self.__hex_to_binary_list(hex_vlans, 0):
                if vid == '1':
                    continue
                tag_noneg_port_dict[port_index].append(vid)

        for index, value in mode_port_dict.items():
            if value == oid.cisco_catalyst.mode_port_state["access"]:
                interfaces.append(Interface(
                    index=index,
                    untagged=untag_port_dict[index] if untag_port_dict[index] != '1' else None,
                    mode='access',
                ))
            elif value == oid.cisco_catalyst.mode_port_state["tagged"]:
                interfaces.append(Interface(
                    index=index,
                    untagged=native_port_dict[index] if native_port_dict[index] != '1' else None,
                    mode='tagged',
                    tagged=tag_port_dict[index],
                ))
                if not interfaces[-1].tagged:
                    interfaces[-1].mode = 'tagged-all'
            elif value == oid.cisco_catalyst.mode_port_state["tagged-noneg"]:
                interfaces.append(Interface(
                    index=index,
                    untagged=native_port_dict[index] if native_port_dict[index] != '1' else None,
                    mode='tagged',
                    tagged=tag_noneg_port_dict[index],
                ))
                if not interfaces[-1].tagged:
                    interfaces[-1].mode = 'tagged-all'

        return interfaces

    def find_interfaces_cisco_sg(self):
        interfaces = []
        mode_port_output, self.error = \
            snmpwalk(oid.cisco_sg.mode_port, self.community_string, self.ip_address, 'INDEX-INT', logger=self.logger)

        if self.error:
            return

        mode_port_dict = self.__indexes_to_dict(mode_port_output)

        untag_port_output, self.error = \
            snmpwalk(oid.cisco_sg.untag_port[self.family_model], self.community_string, self.ip_address, 'INDEX-INT',
                     logger=self.logger)

        if self.error:
            return

        untag_port_dict = self.__indexes_to_dict(untag_port_output)

        hex_tag_port_output, error = \
            snmpwalk(oid.cisco_sg.hex_tag_port, self.community_string, self.ip_address, 'INDEX-HEX', logger=self.logger)

        if self.error:
            return

        tag_port_dict = defaultdict(list)
        for vlan_id, hex_indexes in hex_tag_port_output:
            if vlan_id == '1':
                continue
            for interface_index in self.__hex_to_binary_list(hex_indexes):
                tag_port_dict[interface_index].append(vlan_id)

        for index, value in mode_port_dict.items():

            untagged = None
            # Если Vlan Untagged 0 или 1 то пропускаем
            if index in untag_port_dict \
                    and untag_port_dict[index] not in ['0', '1']:
                untagged = untag_port_dict[index]

            interfaces.append(Interface(
                index=index,
                untagged=untagged,
            ))

            if value == oid.cisco_sg.mode_port_state[self.family_model]["access"]:
                interfaces[-1].mode = 'access'
            elif value == oid.cisco_sg.mode_port_state[self.family_model]["tagged"]:
                interfaces[-1].mode = 'tagged'
                interfaces[-1].tagged = tag_port_dict[index]

                # Если Tagged и Untagged существуют
                # и Vlan Untagged входит в список Tagged
                # Удалим Vlan Untagged из списка Tagged
                if interfaces[-1].tagged and interfaces[-1].untagged \
                        and interfaces[-1].untagged in interfaces[-1].tagged:
                    interfaces[-1].tagged.remove(interfaces[-1].untagged)

            if not interfaces[-1].tagged:
                interfaces[-1].mode = 'tagged-all'

        return interfaces

    def find_interfaces_huawei(self):
        return []

    def find_interfaces_zyxel(self):
        return []

    def find_interfaces_ubiquiti(self):
        return []


# Класс для группировки регулярного выражения и формата его выводимого результата
class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action


def hex2string(hex):
    if hex:
        return "".join([chr(int(x, 16)) for x in hex.split()]).encode('latin1').decode('utf-8')
    return ""


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False, custom_option=None, logger=None):
    # snmpwalk -Pe -v 2c -c public -On -Ox 10.10.3.13 1.3.6.1.2.1.47.1.1.1.1.11
    out = []  # список для хранения результатов
    try:
        process = ["snmpwalk", "-Pe", "-v", "2c", "-c", community_string, f"-On{'x' if hex else ''}",
                   *([custom_option] if custom_option else []), ip_address, *([oid] if oid else [])]
        if logger: logger.debug(' '.join(process))
        # Помещаем результат команды snmpwalk в переменную
        result = subprocess.run(process, capture_output=True, text=True)

        # Обработка ошибок
        if result.returncode != 0:
            return [], f'Fail SNMP (oid {oid})! Return code: {result.returncode}'
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
            'INDEX-DESC': RegexAction(
                r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
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

        return out, ''
    except Exception as e:
        return out, str(e)
        # return out, traceback.print_exc()


if __name__ == "__main__":
    print(snmpwalk('1.3.6.1.2.1.1.5.0', 'public', '10.10.3.13', 'DotSplit'))
