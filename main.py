import csv
import logging
import sys
from datetime import datetime

from prettytable import ALL, PrettyTable

from device import NetworkDevice

logger = logging.getLogger('NetBox')

logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.ERROR)

c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

f_handler = logging.FileHandler('NetBox.log', mode='w')
f_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)

# logger.debug('logger.debug')
# logger.info('logger.info')
# logger.warning('logger.warning')
# logger.error('logger.error')
# logger.exception('logger.exception')

start_time = datetime.now()

devices_with_error = []
devices_file = open('devices.csv', newline='')
devices_reader = csv.DictReader(devices_file, delimiter=';')
netbox_vlans = None
netbox_connection = None
models = {}

mode = 'all'
for csv_device in devices_reader:
    if csv_device['act'] == '+':
        mode = 'include'
        break
    elif csv_device['act'] == '-':
        mode = 'exclude'

# Переинициализируем файл устройств
devices_file.seek(0)
devices_reader.__init__(devices_file, delimiter=";")

for csv_device in devices_reader:
    if (mode == 'exclude' and csv_device['act'] == '-') or \
            (mode == 'include' and csv_device['act'] != '+'):
        logger.info(
            f"Passed device IP: {csv_device['ip device']}\n" + '#' * 120)
        continue
    logger.info(f"Processing device IP: {csv_device['ip device']}")

    network_device = NetworkDevice(
        ip_address=csv_device['ip device'].strip(),
        community_string=csv_device['community'],
        site_slug=csv_device['site slug'],
        role=csv_device['role'],
        logger=logger
    )
    if not network_device.error:
        network_device.setModels(models)
        network_device.setNetboxConnection(netbox_connection)
        network_device.setNetboxVlans(netbox_vlans)

        network_device.ConfigureInNetBox()

        models = network_device.getModels()
        netbox_connection = network_device.getNetboxConnection()
        netbox_vlans = network_device.getNetboxVlans()
    if network_device.error:
        devices_with_error += [network_device]
    logger.info('End processing device\n' + '#' * 120)

# Если были ошибки с устройствами - выводим
if devices_with_error:
    table = PrettyTable(["IP", "Model", "Error"])
    table.align["Error"] = "l"
    table.max_width = 70
    table.valign["Error"] = "t"
    for error_device in devices_with_error:
        table.add_row([error_device.ip_address,
                      error_device.getModel(), error_device.error])
    logger.info(f"The following devices had errors:\n{table}")
else:
    logger.info("All devices were successfully created in NetBox")
logger.info(f"Duration executing:  {datetime.now() - start_time}")
