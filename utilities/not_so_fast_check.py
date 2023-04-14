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

len_line_print = 3
def detect_type(ip_address, logger):
    logger.info('Check: cisco_catalyst')
    logger.info('oid.cisco_catalyst.mode_port')
    output, error = snmpwalk(oid.cisco_catalyst.mode_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_catalyst.native_port')
        output, error = snmpwalk(oid.cisco_catalyst.native_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_catalyst.hex_tag_port')
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_catalyst.untag_port')
        output, error = snmpwalk(oid.cisco_catalyst.untag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_catalyst.hex_tag_noneg_port')
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_catalyst.port_channel_index_port')
        output, error = snmpwalk(oid.cisco_catalyst.port_channel_index_port, 'public', ip_address, 'Debug',
                                 logger=logger)

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        return 'catalist'
    logger.info('')

    logger.info('Check: cisco_sg\n')
    logger.info('oid.cisco_sg.hex_tag_port')
    output, error = snmpwalk(oid.cisco_sg.hex_tag_port, 'public', ip_address, 'Debug', logger=logger)
    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        logger.info('oid.cisco_sg.mode_port')
        output, error = snmpwalk(oid.cisco_sg.mode_port, 'public', ip_address, 'Debug', logger=logger)

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
        mode_port_states = [i.split(":")[-1].strip() for i in output if ":" in i]
        if oid.cisco_sg.mode_port_state["cisco_sg_300"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_300"]["tagged"] in mode_port_states:
            logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
            logger.info('oid.cisco_sg.untag_port["cisco_sg_300"]')
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_300"], 'public', ip_address, 'Debug',
                                     logger=logger)
            if not error:
                logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
                return 'SG300'
        elif oid.cisco_sg.mode_port_state["cisco_sg_350"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_350"]["tagged"] in mode_port_states:
            logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
            logger.info('oid.cisco_sg.untag_port["cisco_sg_350"]')
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_350"], 'public', ip_address, 'Debug',
                                     logger=logger)
            if not error:
                logger.debug('Output:\n' + '\n'.join(output[:len_line_print])+'\n')
                return 'SG350'
    logger.info('')

    return ''


while True:
    ip_address = input('Enter IP address: ')

    oidType = detect_type(ip_address, logger)
    if oidType:
        logger.info(f'Detected type: {oidType}')
    else:
        logger.error(f'No detected type!')
