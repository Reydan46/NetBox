import re
import subprocess
import logging
import traceback


class SNMPDevice:
    def __init__(self, community_string, ip_address, model=None, logger=None):
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
        self.hostname = ''

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

        self.hostname = value[0]
        return self.hostname, self.error

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

        self.hostname = value[0]
        return self.hostname, self.error


# Класс для группировки регулярного выражения и формата его выводимого результата
class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False):
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
