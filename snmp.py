import re
import subprocess
import logging
from netaddr import IPAddress
import traceback


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


class SNMPDevice:
    def __init__(self, community_string, ip_address, model=None, logger=None):
        self.zyxel = None
        self.huawei = None
        self.cisco_sg_350 = None
        self.cisco_sg_300 = None
        self.cisco_catalyst = None
        if logger:
            self.logger = logger
        else:
            # Объявляем logger, если таковой не задан
            self.logger = logging.getLogger('SNMPDevice')

        self.error = ''
        self.model = ''
        if model:
            self.model = model
        self.community_string = community_string
        self.ip_address = ip_address

    def __model_lists_reader(self):
        file = open('model.lists', 'r').read()
        for line in file.split('\n'):
            name, models = line.split(':')
            models = [i for i in models.split(',') if i]
            print('Name', name)
            print('Models', models)
            match name:
                case "cisco_catalyst":
                    self.cisco_catalyst = models
                case "cisco_sg_300":
                    self.cisco_sg_300 = models
                case "cisco_sg_350":
                    self.cisco_sg_350 = models
                case "huawei":
                    self.huawei = models
                case "zyxel":
                    self.zyxel = models

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
        value = self.getValue(snmpwalk("1.3.6.1.2.1.1.5.0", self.community_string, self.ip_address, 'DotSplit'))

        if self.error:
            return None, self.error

        return value[0], self.error

    def getModel(self):
        value = self.getValue(snmpwalk("1.3.6.1.2.1.1.1.0", self.community_string, self.ip_address))

        if self.error:
            return None, self.error

        re_out = re.search(r'(\b[A-Za-z][\w]{3,}-[\w]{2,6}\b)', value[0])
        self.model = re_out.group(1) if re_out else ''

        if not self.model:
            value = self.getValue(snmpwalk("1.3.6.1.2.1.47.1.1.1.1.13", self.community_string, self.ip_address))
            if self.error:
                return None, self.error
            self.model = next((i for i in value if i), '')

        return self.model, self.error

    def getSerialNumber(self):
        value = self.getValue(snmpwalk("1.3.6.1.2.1.47.1.1.1.1.11", self.community_string, self.ip_address))

        if self.error:
            return None, self.error

        return value[0], self.error

    def getSVIs(self):
        ip_addresses = self.getValue(snmpwalk("1.3.6.1.2.1.4.20.1.1", self.community_string, self.ip_address, 'IP'))
        if self.error:
            return None, self.error
        masks = self.getValue(snmpwalk("1.3.6.1.2.1.4.20.1.3", self.community_string, self.ip_address, 'IP'))
        if self.error:
            return None, self.error
        indexes = self.getValue(snmpwalk("1.3.6.1.2.1.4.20.1.2", self.community_string, self.ip_address, 'INT'))
        if self.error:
            return None, self.error
        SVIs = []
        for i, index in enumerate(indexes):
            if masks[i] == '0.0.0.0':
                continue

            description, self.error = snmpwalk(f"1.3.6.1.2.1.2.2.1.2.{index}", self.community_string,
                                               self.ip_address)
            if self.error:
                return
            MTU, self.error = snmpwalk(f"1.3.6.1.2.1.2.2.1.4.{index}", self.community_string,
                                       self.ip_address, 'INT')
            if self.error:
                return
            MAC_address, self.error = snmpwalk(f"1.3.6.1.2.1.2.2.1.6.{index}", self.community_string,
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

        if not self.model:
            self.error = 'Model is empty!'
            self.logger.error(self.error)
            return

        result = []

        self.__model_lists_reader()

        if self.model in self.cisco_catalyst:
            result = self.getInterfaces_cisco_catalyst()
        elif self.model in self.cisco_sg_300:
            result = self.getInterfaces_cisco_sg_300()
        elif self.model in self.cisco_sg_350:
            result = self.getInterfaces_cisco_sg_350()
        elif self.model in self.huawei:
            result = self.getInterfaces_huawei()
        elif self.model in self.zyxel:
            result = self.getInterfaces_zyxel()
        else:
            self.error = f'Model {self.model} is not found in getInterfaces!'
        return result, self.error

    def getInterfaces_cisco_catalyst(self):
        return []

    def getInterfaces_cisco_sg_300(self):
        return []

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
            'iFACE-INT': RegexAction(
                r'.(\d+) = \w+: (\d+)',
                lambda re_out: [re_out.group(1), re_out.group(2)]
            ),
            'iFACE-MAC': RegexAction(
                r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                lambda re_out: [re_out.group(1), re_out.group(2).strip().replace(" ", ':').upper()]
            ),
            'iFACE-DESC': RegexAction(
                r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
                lambda re_out: [re_out.group(1), re_out.group(2)]
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

        # Построчно обрабатываем вывод snmpwalk
        for lineSNMP in result.stdout.split('\niso'):
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
