import wexpect as expect


def configure_access_list(ip_address, username, password, allowed_ip, logger=None):
    """
    Configures the Standard IP access list ACL_SNMP on the switch using expect
    """
    # Устанавливаем переменные по умолчанию
    error = ''
    device_type = ''

    ssh_options = '-oKexAlgorithms=+diffie-hellman-group-exchange-sha1 -oStrictHostKeyChecking=accept-new'

    if logger: logger.info(f'Connecting via ssh: {username}@{ip_address}')
    ssh = expect.spawn(f'ssh {ssh_options} {username}@{ip_address}')

    # Если процесс не завершился мгновенно (если всё хорошо)
    if ssh.isalive():
        try:
            ssh.expect('assword:')
            ssh.sendline(password)

            # Wait for the command prompt to appear
            ssh.expect('[>#]')

            # Determine the device type by running the 'show inventory' command
            ssh.sendline('show inventory')
            ssh.expect('[>#]')
            output_inventory = '\n'.join(['#' * 57] + [i for i in ssh.before.splitlines() if i] + ['#' * 57])

            if logger: logger.debug(f'Console:\n{output_inventory}')

            if 'WS-C2960' in output_inventory:
                device_type = '2960'
            elif 'SG250' in output_inventory \
                    or 'SG300' in output_inventory \
                    or 'SG350' in output_inventory:
                device_type = 'SG'

            # Если модель устройства определена
            if device_type:
                if logger: logger.info(f'Device type: {device_type}')
                # Configure the access list using the appropriate commands for the device type
                ssh.sendline('config terminal')
                ssh.expect('[#]')

                ssh.sendline('no logging con')
                if device_type == '2960':
                    ssh.sendline('ip access-list standard ACL_SNMP')
                    ssh.sendline(f'permit {allowed_ip}')
                elif device_type == 'SG':
                    ssh.sendline(f'snmp-server community public ro {allowed_ip} view Default')
            else:
                error = f'Invalid device type: {device_type}'

            ssh.expect('[#]')
            ssh.sendline('end')

            # Close the SSH session
            ssh.close()
        except Exception as e:
            if 'Connection timed out' in ssh.before:
                error = 'Connection timed out'
            elif 'Permission denied' in ssh.before:
                error = 'Permission denied (wrong username?)'
            elif 'User Name:' in ssh.before:
                error = 'Permission denied (maybe no radius?)'
            else:
                # error = ssh.before
                error = str(e)
    else:
        error = 'Unable to connect'

    return device_type, error


if __name__ == '__main__':
    import getpass

    switch_ip_address = input("Enter the switch IP address: ")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    allowed_ip = input("Enter the IP address to allow: ")

    configure_access_list(switch_ip_address, username, password, allowed_ip)
