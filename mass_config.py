import logging
import os
import sys

import jinja2
import wexpect as expect
from cryptography.fernet import Fernet


class NetworkDevice:
    def __init__(self, ip_address, community_string=None, site_slug=None, role=None, logger=None):
        # Проверяем наличие логгера
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger('NetworkDevice')

        self.__password_salt = None
        self.__password_decoder = None

        self.hostname = ""
        self.model = ""
        self.serial_number = ""
        self.site_slug = ""
        self.role = ""

        self.interfaces = []

        self.community_string = ""
        self.error = ""

        # Сохраняем не None значения атрибутов
        self.ip_address = ip_address
        if community_string:
            self.community_string = community_string
        if site_slug:
            self.site_slug = site_slug
        if role:
            self.role = role

        # Получаем переменную окружения для расшифровки пароля
        self.__password_salt = os.environ.get('NETBOX_PASSWORD_SALT')
        if not self.__password_salt:
            self.error = 'Password SALT is empty!'
            self.logger.error(self.error)
            return
        try:
            self.__password_decoder = Fernet(self.__password_salt)
        except Exception as e:
            self.error = f'Could not initiate Password Decoder: {e}'
            self.logger.error(self.error)
            return

    def getPassword(self, password):
        return self.__password_decoder.decrypt(password).decode('utf-8')

    def configure_access_list(self, allowed_ip, username=None, password=None):
        self.logger.info('Configure access list')

        self.error = ''
        device_type = ''

        self.cred = {
            "username": "",
            "password": ""
        }

        if username:
            self.cred.update({"username": username})
        if password:
            self.cred.update({"password": password})

        # Хардкодим имя пользователя и пароль
        if not self.cred["username"] and not self.cred["password"]:
            self.cred = {"username": "network-backup",
                         "password": 'gAAAAABkJWTLKA-pCESIgNea34_AQ_OhMapaKSKp24RZSyf_ei-T5JZX0dBW_TzfueuNopnqWFmduhuLDHr-sj4mLRGq5z8J4qDyaFomECh7iS0udKIEN1w='}

        # Если все необходимые параметры заданы
        if allowed_ip:
            # Объявление окружения Jinja и загрузка шаблонов
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader('./templates'),
            )
            # Назначение шаблонов и команд по типам устройств
            configs = {
                '2960': {
                    'ACL_TEMPLATE_FILENAME': 'acl_cisco_cat.j2',
                    'CONFIGURE_MODE_COMMAND': 'conf t',
                    'END_COMMAND': 'end',
                    'SAVE_COMMAND': 'wr'
                },
                'SG': {
                    'ACL_TEMPLATE_FILENAME': 'acl_cisco_sg.j2',
                    'CONFIGURE_MODE_COMMAND': 'conf t',
                    'END_COMMAND': 'end',
                    'SAVE_COMMAND': 'wr'
                },
                'Hui': {
                    'ACL_TEMPLATE_FILENAME': 'acl_huawei.j2',
                    'CONFIGURE_MODE_COMMAND': 'system-view',
                    'END_COMMAND': 'return',
                    'SAVE_COMMAND': 'save'
                }
            }

            ssh_options = '-oKexAlgorithms=+diffie-hellman-group-exchange-sha1 -oStrictHostKeyChecking=accept-new'

            # connect via SSH to the device
            self.logger.info(
                f'Connecting via ssh: {self.cred["username"]}@{self.ip_address}')
            ssh = expect.spawn(
                f'ssh {ssh_options} {self.cred["username"]}@{self.ip_address}', timeout=15)

            # Если подключение успешно
            if ssh.isalive():
                try:
                    # Аутентификация
                    count = 0
                    index = -1
                    while index != 0 and count < 5:
                        count += 1
                        index = ssh.expect(
                            ['assword:', 'ame:', 'ogin:', 'ser:'])
                        if index == 0:
                            ssh.sendline(self.getPassword(
                                self.cred["password"]))
                        else:
                            ssh.sendline(self.cred["username"])

                    # Определение вендора
                    vendorCheck = ssh.expect(
                        ['#', '>', 'Layer 2 Managed Switch', 'Zyxel'])
                    if vendorCheck == 0:  # Cisco
                        # Determine the device type by running the 'show inventory' command
                        ssh.sendline('show inventory')
                        ssh.expect('#')
                        output_inventory = '\n'.join(
                            ['=' * 57] + [i for i in ssh.before.splitlines() if i] + ['=' * 57])
                        self.logger.debug(f'Console:\n{output_inventory}')
                        if 'WS-C2960' in output_inventory:
                            device_type = '2960'
                        elif 'SG250' in output_inventory \
                                or 'SG300' in output_inventory \
                                or 'SG350' in output_inventory:
                            device_type = 'SG'
                        ssh.sendline(configs[device_type]['CONFIGURE_MODE_COMMAND'])
                        ssh.expect('#')
                    elif vendorCheck == 1:  # Huawei
                        device_type = 'Hui'
                    elif vendorCheck == 2 or vendorCheck == 3:  # Zyxel
                        device_type = 'Zyxel'
                        ssh.close()
                        return device_type

                    # Конфигурация
                    if device_type:
                        ssh.sendline(configs[device_type]['CONFIGURE_MODE_COMMAND'])
                        ssh.expect(['#', ']'])
                        acl_template = env.get_template(
                            configs[device_type]['ACL_TEMPLATE_FILENAME'])
                        ssh.sendline(acl_template.render(
                            allowed_ip=allowed_ip))
                        ssh.expect(['#', ']'])
                        ssh.sendline(configs[device_type]['END_COMMAND'])
                        ssh.expect('[>#]')
                        ssh.sendline(configs[device_type]['SAVE_COMMAND'])
                        checkStatus = ssh.expect(
                            ['Building configuration...', '(Y/N)', '[Y/N]'])
                        if checkStatus == 1:  # SG
                            ssh.sendline('y')
                            ssh.expect('#')
                        elif checkStatus == 2:  # Huawei
                            ssh.sendline('y')
                            ssh.expect('>')
                    else:
                        self.error = f'Invalid device type: {device_type}'

                    # Закрыть соединение
                    ssh.close()

                except Exception as e:
                    if 'Connection timed out' in ssh.before:
                        self.error = 'Connection timed out'
                    # elif 'Timeout exceeded' in str(e):
                    #     self.error = 'Timeout data wait'
                    elif 'Permission denied' in ssh.before:
                        self.error = 'Permission denied (wrong username?)'
                    elif 'User Name:' in ssh.before:
                        self.error = 'Permission denied (maybe no radius?)'
                    else:
                        # error = ssh.before
                        self.error = str(e)
            else:
                self.error = 'Unable to connect'
        else:
            if not allowed_ip:
                self.error = 'Allowed IP is Empty!'
            elif not self.cred["username"]:
                self.error = 'Username is Empty!'
            elif not self.cred["password"]:
                self.error = 'Password is Empty!'

        return device_type


if __name__ == '__main__':
    logger = logging.getLogger('NetBox')

    logger.setLevel(logging.DEBUG)
    # logger.setLevel(logging.INFO)
    # logger.setLevel(logging.WARNING)
    # logger.setLevel(logging.ERROR)

    c_handler = logging.StreamHandler(sys.stdout)
    c_format = logging.Formatter(
        "[%(asctime)s - %(funcName)21s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
    c_handler.setFormatter(c_format)
    logger.addHandler(c_handler)

    obj = NetworkDevice('10.10.3.11', logger=logger)
    # ,'admin','gAAAAABkLnDjUwYicVI-uiF5HMdQmzzjlSCRkQe1A-66-lzUuF0VuqtUrdIty6o6OY--EDnFuFh0KNKBnJ371maY07_sAjGgKg==')
    deviceType = obj.configure_access_list('10.10.7.23')
    print(deviceType)
