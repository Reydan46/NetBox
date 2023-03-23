import sys
import logging
import csv
from aclModifier import configure_access_list
from deviceResearch import get_device_info, create_netbox_device
from ipAddition import create_ip_interface
from vlanExtractor import write_info_interfaces
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

f_handler = logging.FileHandler('NetBox.log', mode='w')
f_format = logging.Formatter("[%(asctime)s - %(funcName)21s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)


# logger.debug('logger.debug')
# logger.info('logger.info')
# logger.warning('logger.warning')
# logger.error('logger.error')
# logger.exception('logger.exception')

class DeviceError:
    def __init__(self, ip, model='Undefined', error='Unknown'):
        self.ip = ip
        self.model = model
        self.error = error


devices_with_error = []

# Открываем и считываем файл с устройствами
devices_file = open('devices.csv', newline='')
devices_reader = csv.DictReader(devices_file, delimiter=';')
for device in devices_reader:
    # Опускаем флаг ошибки
    err = False

    error_message = ''
    model = 'Undefined'

    try:
        if device['pass']:
            logger.info(f"Passed device IP: {device['ip device']}")
            continue

        logger.info(f"Processing device IP: {device['ip device']}")

        # Конфигурируем access list
        error_message = configure_access_list(
            ip_address=device['ip device'],
            username=device['username'],
            password=device['password'],
            allowed_ip=device['ip script'],
            logger=logger
        )
        logger.info(error_message)
        if error_message:
            err = True
        else:
            # Получаем информацию об устройстве
            (hostname, model, serial_number), error_message = get_device_info(
                community_string=device['community'],
                ip_address=device['ip device'],
                logger=logger
            )
            if error_message:
                err = True
            else:
                # Создаём устройство в NetBox
                created_device, error_message = create_netbox_device(
                    hostname=hostname,
                    model=model,
                    serial_number=serial_number,
                    site_slug=device['site_slug'],
                    device_role_name=device['role'],
                    logger=logger
                )
                if error_message:
                    err = True
                else:
                    # Создаём IP и устанавливаем его устройству в NetBox
                    create_ip_interface(
                        community_string=device['community'],
                        ip_address=device['ip device'],
                        hostname=hostname,
                        logger=logger
                    )

                    # Получаем информацию об интерфейсах и отправляем её в NetBox
                    write_info_interfaces(
                        ip_address=device['ip device'],
                        community_string=device['community'],
                        site_slug=device['site_slug'],
                        logger=logger
                    )
    except Exception as e:
        err = True
        if not error_message:
            error_message = '~' + str(e)

    if err:
        devices_with_error.append(
            DeviceError(
                ip=device['ip device'],
                model=model,
                error=error_message
            )
        )

# Если были ошибки с устройствами - выводим
if devices_with_error:
    table = PrettyTable()
    table.field_names = ["IP", "Model", "Error"]
    for error_device in devices_with_error:
        table.add_row([error_device.ip, error_device.model, error_device.error])
    logger.info(f"The following devices had errors:\n{table}")
else:
    logger.info("All devices were successfully created in NetBox")
