import sys
import logging
import csv
from device import NetworkDevice
from prettytable import PrettyTable

logger = logging.getLogger('NetBox')

logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.ERROR)

c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter("[%(asctime)s - %(funcName)21s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

# f_handler = logging.FileHandler('NetBox.log', mode='w')
# f_format = logging.Formatter("[%(asctime)s - %(funcName)21s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
# f_handler.setFormatter(f_format)
# logger.addHandler(f_handler)

# logger.debug('logger.debug')
# logger.info('logger.info')
# logger.warning('logger.warning')
# logger.error('logger.error')
# logger.exception('logger.exception')

devices_with_error = []
devices_file = open('devices.csv', newline='')
devices_reader = csv.DictReader(devices_file, delimiter=';')
for csv_device in devices_reader:
    if csv_device['pass']:
        logger.info(f"Passed device IP: {csv_device['ip device']}\n" + '#' * 120)
        continue
    logger.info(f"Processing device IP: {csv_device['ip device']}")
    network_device = NetworkDevice(
        ip_address=csv_device['ip device'],
        community_string=csv_device['community'],
        site_slug=csv_device['site slug'],
        role=csv_device['role'],
        logger=logger
    )
    if not network_device.error:
        network_device.ConfigureInNetBox()
    if network_device.error:
        devices_with_error += [network_device]
    logger.info('End processing device\n' + '#' * 120)

# Если были ошибки с устройствами - выводим
if devices_with_error:
    table = PrettyTable()
    table.field_names = ["IP", "Model", "Error"]
    for error_device in devices_with_error:
        table.add_row([error_device.ip_address, error_device.getModel(), error_device.error])
    logger.info(f"The following devices had errors:\n{table}")
else:
    logger.info("All devices were successfully created in NetBox")
