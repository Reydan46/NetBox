import re
import subprocess
import logging
from netaddr import IPAddress
import traceback
from collections import defaultdict
import oid.general


# Виртуальный IP интерфейс
class SVI:
    def __init__(self, ip_address, mask, index, description, MTU, MAC_address):
        self.index = index
        self.ip_address = ip_address
        self.mask = mask
        self.ip_with_prefix = f'{self.ip_address}/{IPAddress(self.mask).netmask_bits()}'
        self.description = description
        self.MTU = MTU
        self.MAC_address = MAC_address

    def __repr__(self):
        return f'{self.index} - {self.ip_with_prefix} ({self.MAC_address}) - {self.description} - {self.MTU}'


# Физический интерфейс
class Interface:
    def __init__(self, index, untagged=None, tagged=None, name=None, mode=None, mtu=None, mac_address=None, desc=None):
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
        self.mac_address = ''
        if mac_address:
            self.mac_address = mac_address
        self.desc = ''
        if desc:
            self.desc = desc
        self.object_interface_netbox = None


class SNMPDevice:
    def __init__(self, community_string, ip_address, model=None, logger=None):
        if logger:
            self.logger = logger
        else:
            # Объявляем logger, если таковой не задан
            self.logger = logging.getLogger('SNMPDevice')

        self.model_zyxel = []
        self.model_huawei = []
        self.model_cisco_sg_350 = []
        self.model_cisco_sg_300 = []
        self.model_cisco_catalyst = []

        self.error = ''
        self.model = ''
        if model:
            self.model = model
        self.community_string = community_string
        self.ip_address = ip_address

    @staticmethod
    def __hex_to_binary(hex_str):
        # Преобразует шестнадцатеричное число в двоичное и удаляет префикс '0b'
        binary_str = bin(int(hex_str, 16))[2:]
        # Дополняем нулями слева, чтобы каждый шестнадцатеричный символ соответствовал 4 двоичным
        binary_str = binary_str.zfill(len(hex_str) * 4)
        return binary_str

    @staticmethod
    def __binary_to_list(binary_str):
        return [str(i + 1) for i, bit in enumerate(binary_str) if bit == '1']

    def __hex_to_binary_list(self, hex_str):
        binary_str = self.__hex_to_binary(hex_str)
        return self.__binary_to_list(binary_str)

    @staticmethod
    def __indexes_to_dict(indexes):
        return {interface: value for interface, value in indexes}

    def __model_lists_reader(self):
        self.logger.info('Read models from file')

        self.model_zyxel = []
        self.model_huawei = []
        self.model_cisco_sg_350 = []
        self.model_cisco_sg_300 = []
        self.model_cisco_catalyst = []

        file = open('model.lists', 'r').read()
        for line in file.split('\n'):
            model_type, models = line.split(':')
            models = [i for i in models.split(',') if i]
            match model_type:
                case "cisco_catalyst":
                    self.model_cisco_catalyst = models
                case "cisco_sg_300":
                    self.model_cisco_sg_300 = models
                case "cisco_sg_350":
                    self.model_cisco_sg_350 = models
                case "huawei":
                    self.model_huawei = models
                case "zyxel":
                    self.model_zyxel = models

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
        value = self.getValue(snmpwalk(oid.general.hostname, self.community_string, self.ip_address, 'DotSplit'))

        if self.error:
            return None, self.error

        return value[0], self.error

    def getModel(self):
        value = self.getValue(snmpwalk(oid.general.model, self.community_string, self.ip_address))

        if self.error:
            return None, self.error

        re_out = re.search(r'(\b[A-Z][A-Z0-9]{3,}-[A-Z0-9]{2,6}\b)', value[0])
        self.model = re_out.group(1) if re_out else ''

        if not self.model:
            value = self.getValue(snmpwalk(oid.general.alt_model, self.community_string, self.ip_address))
            if self.error:
                return None, self.error
            self.model = next((i for i in value if i), '')

        return self.model, self.error

    def getSerialNumber(self):
        value = self.getValue(snmpwalk(oid.general.serial_number, self.community_string, self.ip_address))

        if self.error:
            return None, self.error

        return value[0], self.error

    def getSVIs(self):
        indexes = self.getValue(snmpwalk(oid.general.svi_indexes, self.community_string, self.ip_address, 'INT'))
        if self.error:
            return None, self.error
        ip_addresses = self.getValue(
            snmpwalk(oid.general.svi_ip_addresses, self.community_string, self.ip_address, 'IP'))
        if self.error:
            return None, self.error
        masks = self.getValue(snmpwalk(oid.general.svi_masks, self.community_string, self.ip_address, 'IP'))
        if self.error:
            return None, self.error
        SVIs = []
        for i, index in enumerate(indexes):
            if masks[i] == '0.0.0.0':
                continue

            description, self.error = snmpwalk(f"{oid.general.svi_description}.{index}", self.community_string,
                                               self.ip_address)
            if self.error:
                return
            MTU, self.error = snmpwalk(f"{oid.general.svi_mtu}.{index}", self.community_string,
                                       self.ip_address, 'INT')
            if self.error:
                return
            MAC_address, self.error = snmpwalk(f"{oid.general.svi_mac_address}.{index}", self.community_string,
                                               self.ip_address, 'MAC', hex=True)
            if self.error:
                return

            SVIs += [SVI(
                ip_address=ip_addresses[i],
                mask=masks[i],
                index=index,
                description=description[0],
                MTU=MTU[0],
                MAC_address=MAC_address[0]
            )]
        return SVIs, self.error

    def getInterfaces(self):
        self.error = ''
        interfaces = []

        if not self.model:
            self.error = 'Model is empty!'
            self.logger.error(self.error)
            return interfaces

        if not self.ip_address:
            self.error = 'IP address is Empty!'
            self.logger.error(self.error)
            return interfaces

        if not self.community_string:
            self.error = 'Community string is Empty!'
            self.logger.error(self.error)
            return interfaces

        self.__model_lists_reader()

        if self.model in self.model_cisco_catalyst:
            interfaces = self.getInterfaces_cisco_catalyst()
        elif self.model in self.model_cisco_sg_300:
            interfaces = self.getInterfaces_cisco_sg_300()
        elif self.model in self.model_cisco_sg_350:
            interfaces = self.getInterfaces_cisco_sg_350()
        elif self.model in self.model_huawei:
            interfaces = self.getInterfaces_huawei()
        elif self.model in self.model_zyxel:
            interfaces = self.getInterfaces_zyxel()
        else:
            self.error = f'Model {self.model} is not found in getInterfaces!'
            return interfaces, self.error

        int_name_output, self.error = \
            snmpwalk('1.3.6.1.2.1.2.2.1.2', self.community_string, self.ip_address, 'INDEX-DESC')
        if self.error:
            return interfaces, self.error
        int_name_dict = self.__indexes_to_dict(int_name_output)

        mtu_output, self.error = \
            snmpwalk('1.3.6.1.2.1.2.2.1.4', self.community_string, self.ip_address, 'INDEX-INT')
        if self.error:
            return interfaces, self.error
        mtu_dict = self.__indexes_to_dict(mtu_output)

        mac_output, self.error = \
            snmpwalk('1.3.6.1.2.1.2.2.1.6', self.community_string, self.ip_address, 'INDEX-MAC', hex=True)
        if self.error:
            return interfaces, self.error
        mac_dict = self.__indexes_to_dict(mac_output)

        desc_output, self.error = \
            snmpwalk('1.3.6.1.2.1.31.1.1.1.18', self.community_string, self.ip_address, 'INDEX-DESC')
        if self.error:
            return interfaces, self.error
        desc_dict = self.__indexes_to_dict(desc_output)

        for interface in interfaces:
            interface.name = int_name_dict[interface.index]
            interface.mtu = mtu_dict[interface.index]
            interface.mac = mac_dict[interface.index]
            interface.desc = desc_dict[interface.index]

        return interfaces, self.error

    def getInterfaces_cisco_catalyst(self):
        return []

    def getInterfaces_cisco_sg_300(self):
        interfaces = []
        mode_port_output, self.error = \
            snmpwalk('1.3.6.1.4.1.9.6.1.101.48.22.1.1', self.community_string, self.ip_address, 'INDEX-INT')

        if self.error:
            return interfaces

        mode_port_dict = self.__indexes_to_dict(mode_port_output)

        untag_port_output, self.error = \
            snmpwalk('1.3.6.1.2.1.17.7.1.4.5.1', self.community_string, self.ip_address, 'INDEX-INT')

        if self.error:
            return interfaces

        untag_port_dict = self.__indexes_to_dict(untag_port_output)

        hex_tag_port_output, error = \
            snmpwalk('1.3.6.1.2.1.17.7.1.4.2.1.4', self.community_string, self.ip_address, 'INDEX-HEX')

        if self.error:
            return interfaces

        hex_tag_port_dict = self.__indexes_to_dict(hex_tag_port_output)

        tag_port_dict = defaultdict(list)
        for vlan_id, hex_indexes in hex_tag_port_dict.items():
            if vlan_id == '1':
                continue
            for interface_index in self.__hex_to_binary_list(hex_indexes):
                tag_port_dict[interface_index].append(vlan_id)

        for index, value in mode_port_dict.items():
            if value == '2':
                interfaces.append(Interface(
                    index=index,
                    untagged=untag_port_dict[index],
                    mode='access',
                ))
            elif value == '3':
                interfaces.append(Interface(
                    index=index,
                    tagged=tag_port_dict[index],
                    untagged=untag_port_dict[index],
                    mode='trunk',
                ))

        return interfaces

    def getInterfaces_cisco_sg_350(self):
        return []

    def getInterfaces_huawei(self):
        return []

    def getInterfaces_zyxel(self):
        return []


# Класс для группировки регулярного выражения и формата его выводимого результата
class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False):
    # snmpwalk -v 2c -c public -Ox 10.10.3.13 1.3.6.1.2.1.47.1.1.1.1.11
    out = []  # список для хранения результатов
    try:
        process = ["snmpwalk", "-v", "2c", "-c", community_string, *(["-Ox"] if hex else []), ip_address,
                   *([oid] if oid else [])]
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
                lambda re_out: 'iso.' + re_out.group(1)
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

        # Если вывод snmpwalk не пустой (больше чем 4 символа - 'iso.')
        if len(result.stdout) > 4:
            # Построчно обрабатываем вывод snmpwalk
            for lineSNMP in result.stdout[4:].split('\niso.'):
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
