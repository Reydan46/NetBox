import re
import subprocess


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False):
    out = []
    try:
        process = ["snmpwalk", "-v", "2c", "-c", community_string]
        if hex:
            process += ["-Ox"]
        process += [ip_address, oid]
        result = subprocess.run(process, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                text=True)
        if result.returncode != 0:
            return [], f'Fail SNMP! Return code: {result.returncode}'
        elif 'No Such Object' in result.stdout:
            return [], 'No Such Object available on this agent at this OID'
        else:
            for lineSNMP in result.stdout.split('\n'):
                if lineSNMP == '':
                    continue
                if typeSNMP == 'DotSplit':
                    re_out = re.search(r'"([A-Za-z0-9\-_]+)(\.|\")', lineSNMP)
                    out += [re_out.group(1)]
                elif typeSNMP == 'IP':
                    re_out = re.search(r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', lineSNMP)
                    out += [re_out.group(1)]
                elif typeSNMP == 'INT':
                    re_out = re.search(r': (\d+)', lineSNMP)
                    out += [re_out.group(1)]
                elif typeSNMP == 'iFACE-INT':
                    re_out = re.search(r'.(\d+) = \w+: (\d+)', lineSNMP)
                    out += [[re_out.group(1), re_out.group(2)]]
                elif typeSNMP == 'iFACE-MAC':
                    re_out = re.search(r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})', lineSNMP)
                    if re_out:
                        out += [[re_out.group(1), re_out.group(2).strip().replace(" ", ':').upper()]]
                elif typeSNMP == 'iFACE-DESC':
                    re_out = re.search(r'.(\d+) = [\w\-]*:? ?"([^"]*)"', lineSNMP)
                    out += [[re_out.group(1), re_out.group(2)]]
                elif typeSNMP == 'MAC':
                    re_out = re.search(r': (([0-9A-Fa-f]{2} ?){6})', lineSNMP)
                    if re_out:
                        out += [re_out.group(1).strip().replace(" ", ':').upper()]
                else:
                    re_out = re.search(r'"([^"]*)"', lineSNMP)
                    out += [re_out.group(1)]
            return out, ''
    except Exception as e:
        return out, str(e)


def snmpwalk0(oid, community_string, ip_address, typeSNMP='', hex=False):
    try:
        process = ["snmpwalk", "-v", "2c", "-c", community_string]
        if hex:
            process += ["-Ox"]
        process += [ip_address, oid]
        result = subprocess.run(process, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                text=True)
        if result.returncode != 0:
            return ''
        else:
            return result.stdout
    except:
        return ''
