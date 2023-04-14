import os
import sys
import logging
from string import Formatter

from prettytable import PrettyTable
from colorama import init, Fore

init()

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


def red(text):
    return f'{Fore.RED}{text}{Fore.RESET}'


def green(text):
    return f'{Fore.GREEN}{text}{Fore.RESET}'


len_line_print = 3
timeout_process = 1


def detect_type(ip_address, logger):
    result = []
    logger.info('Check: cisco_catalyst')
    name_oid = 'oid.cisco_catalyst.mode_port'
    logger.info(name_oid)
    output, error = snmpwalk(oid.cisco_catalyst.mode_port, 'public', ip_address, 'Debug', logger=logger,
                             timeout_process=timeout_process)
    result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.native_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_catalyst.native_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.hex_tag_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_port, 'public', ip_address, 'Debug', hex=True,
                                 logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.untag_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_catalyst.untag_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.hex_tag_noneg_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, 'public', ip_address, 'Debug', hex=True,
                                 logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.port_channel_index_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_catalyst.port_channel_index_port, 'public', ip_address, 'Debug',
                                 logger=logger)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        return 'catalist', result
    logger.info('')

    logger.info('Check: cisco_sg\n')
    name_oid = 'oid.cisco_sg.hex_tag_port'
    logger.info(name_oid)
    output, error = snmpwalk(oid.cisco_sg.hex_tag_port, 'public', ip_address, 'Debug', hex=True, logger=logger,
                             timeout_process=timeout_process)
    result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_sg.mode_port'
        logger.info(name_oid)
        output, error = snmpwalk(oid.cisco_sg.mode_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, red('no passed') if error else green('passed')])

    if not error:
        logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        mode_port_states = [i.split(":")[-1].strip() for i in output if ":" in i]
        if oid.cisco_sg.mode_port_state["cisco_sg_300"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_300"]["tagged"] in mode_port_states:
            logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
            name_oid = 'oid.cisco_sg.untag_port["cisco_sg_300"]'
            logger.info(name_oid)
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_300"], 'public', ip_address, 'Debug',
                                     logger=logger)
            result.append([name_oid, red('no passed') if error else green('passed')])

            if not error:
                logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
                return 'SG300', result
        elif oid.cisco_sg.mode_port_state["cisco_sg_350"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_350"]["tagged"] in mode_port_states:
            logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
            name_oid = 'oid.cisco_sg.untag_port["cisco_sg_350"]'
            logger.info(name_oid)
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_350"], 'public', ip_address, 'Debug',
                                     logger=logger)
            result.append([name_oid, red('no passed') if error else green('passed')])

            if not error:
                logger.debug('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
                return 'SG350', result
    logger.info('')

    return '', result


while True:
    ip_address = input('Enter IP address: ')

    oidType, result = detect_type(ip_address, logger)
    if oidType:
        logger.info(f'Detected type: {oidType}')
    else:
        logger.error(f'No detected type!')

    table = PrettyTable()
    table.field_names = ["OID", "Result"]
    for line in result:
        table.add_row(line)
    logger.info(f"Check result:\n{table}")
