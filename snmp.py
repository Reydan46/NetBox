import re
import subprocess


def snmpwalk(oid, community_string, ip_address, typeSNMP='', hex=False):
    out = []
    try:
        process = ["snmpwalk", "-v", "2c", "-c", community_string, *(["-Ox"] if hex else []), ip_address, oid]
        result = subprocess.run(process, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                text=True)

        if result.returncode != 0:
            return [], f'Fail SNMP (oid {oid})! Return code: {result.returncode}'
        elif 'No Such Object' in result.stdout:
            return [], f'No Such Object available on this agent at this OID ({oid})'
        elif 'No Such Instance currently exists' in result.stdout:
            return [], f'No Such Instance currently exists at this OID ({oid})'

        typeSNMP_patterns = {
            'Debug': r'(.*)',
            'DotSplit': r'"([A-Za-z0-9\-_]+)(\.|\")',
            'IP': r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'INT': r': (\d+)',
            'iFACE-INT': r'.(\d+) = \w+: (\d+)',
            'iFACE-MAC': r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
            'iFACE-DESC': r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
            'MAC': r': (([0-9A-Fa-f]{2} ?){6})',
            'DEFAULT': r'"([^"]*)"'
        }

        pattern = typeSNMP_patterns.get(typeSNMP, typeSNMP_patterns['DEFAULT'])

        for lineSNMP in result.stdout.split('\n'):
            if not lineSNMP:
                continue
            re_out = re.search(pattern, lineSNMP)

            if re_out:
                if typeSNMP in ['Debug']:
                    output = re_out.group(1)
                elif typeSNMP in ['MAC']:
                    output = re_out.group(1).strip().replace(" ", ':').upper()
                elif typeSNMP in ['iFACE-MAC']:
                    output = [re_out.group(1), re_out.group(2).strip().replace(" ", ':').upper()]
                elif typeSNMP in ['iFACE-INT', 'iFACE-DESC']:
                    output = [re_out.group(1), re_out.group(2)]
                else:
                    output = re_out.group(1)

                out += [output]

        return out, ''
    except Exception as e:
        return out, str(e)
