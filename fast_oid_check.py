from snmp import snmpwalk
import traceback

while True:
    ip_address = input('Enter IP address: ')

    oidType = '2960'
    try:
        vlan_output, error = \
            snmpwalk('1.3.6.1.4.1.9.9.68.1.2.2.1.2', 'public', ip_address, 'iFACE-INT')
        if error:
            error = ''
            oidType = 'SG350'
            vlan_output, error = \
                snmpwalk('1.3.6.1.4.1.9.6.1.101.48.62.1.1', 'public', ip_address, 'iFACE-INT')
            if error:
                error = ''
                oidType = 'SG300'
                vlan_output, error = \
                    snmpwalk('1.3.6.1.4.1.9.6.1.101.48.70', 'public', ip_address, 'iFACE-DESC')
                print(vlan_output)
        print(oidType)
    except Exception as e:
        traceback.print_exc()