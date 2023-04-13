import os
import sys
import logging

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

import oid.cisco_catalyst
import oid.cisco_sg
from snmp import snmpwalk
import oid.cisco_sg
import oid.cisco_catalyst

logger = logging.getLogger('NetBox')

logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.ERROR)

c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter("[%(asctime)s.%(msecs)03d ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


def detect_type(ip_address, logger):
    logger.info('oid.cisco_catalyst.mode_port')
    output, error = snmpwalk(oid.cisco_catalyst.mode_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_catalyst.native_port')
        output, error = snmpwalk(oid.cisco_catalyst.native_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_catalyst.hex_tag_port')
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_catalyst.untag_port')
        output, error = snmpwalk(oid.cisco_catalyst.untag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_catalyst.hex_tag_noneg_port')
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_catalyst.port_channel_index_port')
        output, error = snmpwalk(oid.cisco_catalyst.port_channel_index_port, 'public', ip_address, 'Debug',
                                 logger=logger)

    if not error:
        return 'catalist'

    logger.info('oid.cisco_sg.hex_tag_port')
    output, error = snmpwalk(oid.cisco_sg.hex_tag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.info('oid.cisco_sg.mode_port')
        output, error = snmpwalk(oid.cisco_sg.mode_port, 'public', ip_address, 'INDEX-INT', logger=logger)

    if not error:
        mode_port_states = [i[1] for i in output]
        if oid.cisco_sg.mode_port_state["cisco_sg_300"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_300"]["tagged"] in mode_port_states:
            logger.info('oid.cisco_sg.untag_port["cisco_sg_300"]')
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_300"], 'public', ip_address, 'Debug',
                                     logger=logger)
            if not error:
                return 'SG300'
        elif oid.cisco_sg.mode_port_state["cisco_sg_350"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_350"]["tagged"] in mode_port_states:
            logger.info('oid.cisco_sg.untag_port["cisco_sg_350"]')
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_350"], 'public', ip_address, 'Debug',
                                     logger=logger)
            if not error:
                return 'SG350'

    return ''


while True:
    ip_address = input('Enter IP address: ')

    oidType = detect_type(ip_address, logger)
    if oidType:
        logger.info(f'Detected type: {oidType}')
    else:
        logger.error(f'No detected type!')
