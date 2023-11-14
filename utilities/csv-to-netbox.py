import csv
import os
import sys

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from log import logger
from netbox import NetboxDevice
from error_handling import print_errors
from errors import Error, NonCriticalError


class VM:
    def __init__(self, site, name, ip, fqdn, user, access, description, os, os_last_update, vmtools_version, backup):
        self.site = site
        self.name = name
        self.ip = ip
        self.fqdn = fqdn
        self.user = user
        self.access = access
        self.description = description
        self.os = os
        self.os_last_update = os_last_update
        self.vmtools_version = vmtools_version
        self.backup = backup


# `data` folder contains csv files with name start with `VMs_`. It neccessary to read them all
csv_folder = "data"
csv_files = [file for file in os.listdir(csv_folder) if file.startswith("VMs_")]
for file in csv_files:
    file_path = os.path.join(csv_folder, file)
    with open(file_path, "r", encoding='utf-8') as csv_file:
        logger.info(f"Reading file: {file_path}")
        csv_content = csv.DictReader(csv_file, delimiter=',')
        for row in csv_content:
            vm = VM(
                site = row['Office'],
                name = row['VMName'],
                ip = row['IPAddress'],
                fqdn = row['FQDN'],
                user = row['User'],
                access = row['Access'],
                description = row['Description'],
                os = row['OSVersion'],
                os_last_update = row['OSLastUpdate'],
                vmtools_version = row['VMwareToolsVersion'],
                backup = row['Backup'],
            )
            logger.debug(f"VM processed")