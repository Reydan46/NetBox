import os
import sys
from log import logger, logging
from string import Formatter

from prettytable import PrettyTable
from colorama import init, Fore

from errors import Error, NonCriticalError

init()

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from snmp import SNMPDevice
import oid.general
import oid.cisco_sg
import oid.cisco_catalyst

logger.setLevel(logging.INFO)


def fail(): return f'{Fore.LIGHTRED_EX}not passed{Fore.RESET}'


def success(): return f'{Fore.LIGHTGREEN_EX}passed{Fore.RESET}'


def oid_name(text): return f'{Fore.LIGHTCYAN_EX}{text}{Fore.RESET}'


len_line_print = 3
timeout_process = 1


def snmpwalk(input_oid, community_string, ip_address, typeSNMP='', hex=False, custom_option=None, timeout_process=None,
             logger=None):
    output = []
    error = ''
    try:
        snmp_device = SNMPDevice(ip_address=ip_address, community_string=community_string)
        output = snmp_device.snmpwalk(input_oid, typeSNMP, hex, community_string, ip_address, custom_option,
                                      timeout_process)
    except:
        pass
    if Error.error_messages:
        error = Error.error_messages[0]
        Error.error_messages = []
    return output, error


def detect_type(ip_address, logger):
    result = []

    if ip_address.startswith('g '):
        ip_address = ip_address[2:]
        logger.info('Check: general')
        name_oid = 'oid.general.hostname'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.hostname, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.model'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.model, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.serial_number'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.serial_number, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.svi_ip_addresses'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.svi_ip_addresses, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.svi_masks'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.svi_masks, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.svi_indexes'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.svi_indexes, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.si_int_name'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.si_int_name, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.si_mtu'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.si_mtu, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.si_mac'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.si_mac, 'public', ip_address, 'Debug', hex=True, logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

        name_oid = 'oid.general.si_description'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.general.si_description, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')

    logger.info('Check: cisco_catalyst')
    name_oid = 'oid.cisco_catalyst.mode_port'
    logger.info(oid_name(name_oid))
    output, error = snmpwalk(oid.cisco_catalyst.mode_port, 'public', ip_address, 'Debug', logger=logger,
                             timeout_process=timeout_process)
    result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.native_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_catalyst.native_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.hex_tag_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_port, 'public', ip_address, 'Debug', hex=True,
                                 logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.untag_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_catalyst.untag_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.hex_tag_noneg_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_catalyst.hex_tag_noneg_port, 'public', ip_address, 'Debug', hex=True,
                                 logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_catalyst.port_channel_index_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_catalyst.port_channel_index_port, 'public', ip_address, 'Debug',
                                 logger=logger)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        return 'catalist', result
    logger.info('')

    logger.info('Check: cisco_sg\n')
    name_oid = 'oid.cisco_sg.hex_tag_port'
    logger.info(oid_name(name_oid))
    output, error = snmpwalk(oid.cisco_sg.hex_tag_port, 'public', ip_address, 'Debug', hex=True, logger=logger,
                             timeout_process=timeout_process)
    result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        name_oid = 'oid.cisco_sg.mode_port'
        logger.info(oid_name(name_oid))
        output, error = snmpwalk(oid.cisco_sg.mode_port, 'public', ip_address, 'Debug', logger=logger,
                                 timeout_process=timeout_process)
        result.append([name_oid, fail() if error else success()])

    if not error:
        logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
        mode_port_states = [i.split(":")[-1].strip() for i in output if ":" in i]
        if oid.cisco_sg.mode_port_state["cisco_sg_300"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_300"]["tagged"] in mode_port_states:
            logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
            name_oid = 'oid.cisco_sg.untag_port["cisco_sg_300"]'
            logger.info(oid_name(name_oid))
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_300"], 'public', ip_address, 'Debug',
                                     logger=logger)
            result.append([name_oid, fail() if error else success()])

            if not error:
                logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
                return 'SG300', result
        elif oid.cisco_sg.mode_port_state["cisco_sg_350"]["access"] in mode_port_states \
                or oid.cisco_sg.mode_port_state["cisco_sg_350"]["tagged"] in mode_port_states:
            logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
            name_oid = 'oid.cisco_sg.untag_port["cisco_sg_350"]'
            logger.info(oid_name(name_oid))
            output, error = snmpwalk(oid.cisco_sg.untag_port["cisco_sg_350"], 'public', ip_address, 'Debug',
                                     logger=logger)
            result.append([name_oid, fail() if error else success()])

            if not error:
                logger.warning('Output:\n' + '\n'.join(output[:len_line_print]) + '\n')
                return 'SG350', result
    logger.info('')

    return '', result


while True:
    ip_address = input('Enter IP address: ')

    oidType, result = detect_type(ip_address, logger)

    table = PrettyTable()
    table.field_names = ["OID", "Result"]
    for line in result:
        table.add_row(line)
    logger.info(f"Check result:\n{table}")
    if oidType:
        logger.info(
            f'{Fore.LIGHTYELLOW_EX}{ip_address}{Fore.RESET} - Detected type: {Fore.LIGHTYELLOW_EX}{oidType}{Fore.RESET}')
    else:
        logger.error(f'{Fore.LIGHTYELLOW_EX}{ip_address}{Fore.RESET} - {Fore.RED}No detected type!{Fore.RESET}')
