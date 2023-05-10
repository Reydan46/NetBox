import csv
import logging
import sys
from datetime import datetime

from prettytable import ALL, PrettyTable

from device import NetworkDevice

# Initialize logger with the name 'NetBox'
logger = logging.getLogger('NetBox')

# Set logging level (uncomment the desired level)
logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.INFO)
# logger.setLevel(logging.WARNING)
# logger.setLevel(logging.ERROR)

# Configure console (stream) handler to print log messages
c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

# Configure file handler to store log messages in 'NetBox.log' with mode 'w' (overwrite)
f_handler = logging.FileHandler('NetBox.log', mode='w')
f_format = logging.Formatter(
    "[%(asctime)s.%(msecs)03d - %(funcName)23s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)

# Uncomment the following lines to test different logging levels
# logger.debug('logger.debug')
# logger.info('logger.info')
# logger.warning('logger.warning')
# logger.error('logger.error')
# logger.exception('logger.exception')

# Сохраняем текущее время для расчета времени выполнения скрипта
start_time = datetime.now()

# Читаем csv файл со списком устройств
devices_with_error = []
devices_file = open('devices.csv', newline='')
devices_reader = csv.DictReader(devices_file, delimiter=';')

# Читаем столбец действия (act)
# "+" - работать только с этим хостом
# "-" - исключить хост из обработки
# Note: "плюсы" имеют приоритет перед "минусами"
act = 'all'
for csv_device in devices_reader:
    if csv_device['act'] == '+':
        act = 'include'
        break
    elif csv_device['act'] == '-':
        act = 'exclude'

# Возврат в начало файла
devices_file.seek(0)
devices_reader.__init__(devices_file, delimiter=";")

# Проходим по списку девайсов из csv
for csv_device in devices_reader:
    # Условия для пропуска устройства
    if (act == 'exclude' and csv_device['act'] == '-') or \
            (act == 'include' and csv_device['act'] != '+'):
        logger.info(
            f"Passed device IP: {csv_device['ip device']}\n" + '#' * 120)
        continue
    
    logger.info(f"Processing device IP: {csv_device['ip device']}")
    
    # Создаем объект класса device.NetworkDevice с параметрами полученными из csv
    network_device = NetworkDevice(
        ip_address=csv_device['ip device'].strip(),
        community_string=csv_device['community'],
        site_slug=csv_device['site slug'],
        role=csv_device['role'],
        logger=logger
    )

    if network_device.error:
        devices_with_error += [network_device]
    else:
        network_device.ConfigureInNetBox()
    
    logger.info('End processing device\n' + '#' * 120)

# Если были ошибки с устройствами - выводим
if devices_with_error:
    table = PrettyTable(["IP", "Model", "Error"])
    table.align["Error"] = "l"
    table.max_width = 75
    table.valign["Error"] = "t"
    for error_device in devices_with_error:
        table.add_row([error_device.ip_address,
                      error_device.getModel(), error_device.error])
    logger.info(f"The following devices had errors:\n{table}")
else:
    logger.info("All devices were successfully created in NetBox")
logger.info(f"Duration executing:  {datetime.now() - start_time}")
