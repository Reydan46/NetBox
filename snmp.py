import re
import subprocess
import traceback

class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False):
    out = []  # список для хранения результатов
    try:
        process = ["snmpwalk", "-v", "2c", "-c", community_string, *(["-Ox"] if hex else []), ip_address, oid]
        # Помещаем результат команды snmpwalk в переменную
        result = subprocess.run(process, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                text=True)

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
                lambda re_out: int(re_out.group(1))
            ),
            'iFACE-INT': RegexAction(
                r'.(\d+) = \w+: (\d+)',
                lambda re_out: [int(re_out.group(1)), int(re_out.group(2))]
            ),
            'iFACE-MAC': RegexAction(
                r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                lambda re_out: [int(re_out.group(1)), re_out.group(2).strip().replace(" ", ':').upper()]
            ),
            'iFACE-DESC': RegexAction(
                r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
                lambda re_out: [int(re_out.group(1)), re_out.group(2)]
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
        for lineSNMP in result.stdout.split('\n'):
            if not lineSNMP:
                continue
                
            re_out = re.search(regex_action.pattern, lineSNMP)
            if re_out:
                output = regex_action.action(re_out)
                # Собираем результаты в список out
                out += [output]

        return out, ''
    except Exception as e:
        return out, str(e)
        #return out, traceback.print_exc()

if __name__ == "__main__":
    print(snmpwalk('1.3.6.1.2.1.1.5.0', 'public', '10.10.3.13', 'DotSplit'))