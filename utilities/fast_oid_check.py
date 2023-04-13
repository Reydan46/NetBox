import os
import sys
import oid.cisco_sg
import oid.cisco_catalyst

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from snmp import snmpwalk


def detect_type(ip_address):
    output, error = snmpwalk(oid.cisco_catalyst.mode_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_catalyst.native_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_catalyst.untag_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_catalyst.port_channel_index_port, 'public', ip_address, 'Debug')

    if not error:
        return 'catalist'

    output, error = snmpwalk(oid.cisco_sg.hex_tag_port, 'public', ip_address, 'Debug')
    if not error:
        output, error = snmpwalk(oid.cisco_sg.mode_port, 'public', ip_address, 'INDEX-INT')

    if not error:
        mode_port_states = [i[1] for i in output]
        if oid.cisco_sg.mode_port_state["cisco_sg_300"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_300"]["tagged"] in mode_port_states:
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_300"], 'public', ip_address, 'Debug')
            if not error:
                return 'SG300'
        elif oid.cisco_sg.mode_port_state["cisco_sg_350"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_350"]["tagged"] in mode_port_states:
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_350"], 'public', ip_address, 'Debug')
            if not error:
                return 'SG350'

    return ''


while True:
    ip_address = input('Enter IP address: ')

    oidType = detect_type(ip_address)
    if oidType:
        print(f'Detected type: {oidType}')
    else:
        print(f'No detected type!')
