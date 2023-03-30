import sys
import logging
import csv
from prettytable import PrettyTable

from snmp import snmpwalk

logger = logging.getLogger('NetBox')
logger.setLevel(logging.DEBUG)
c_handler = logging.StreamHandler(sys.stdout)
c_format = logging.Formatter("[%(asctime)s - %(funcName)30s() ] %(message)s", datefmt='%d.%m.%Y %H:%M:%S')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

ip_address = '10.10.3.13'  # WS-C2960
ip_address = '10.10.3.24'  # WS-C2960
ip_address = '10.10.3.11'  # SG

username = 'network-backup'
password = 'ofsF|P%*{L7}yAhv8pKl'

community_string = 'public'
site_slug = 'ust'

ip_address = '10.13.3.100'
ip_address = '10.13.3.3'
username = 'network-backup'
password = 'gAAAAABkJWTLKA-pCESIgNea34_AQ_OhMapaKSKp24RZSyf_ei-T5JZX0dBW_TzfueuNopnqWFmduhuLDHr-sj4mLRGq5z8J4qDyaFomECh7iS0udKIEN1w='
allowed_ip = '10.10.7.13'
#allowed_ip = '10.10.5.37'
community_string = 'public'
site_slug = 'chb'
role = 'Aggregation switch'

# Hostname
oid = "1.3.6.1.2.1.1.5.0"
hostname, error_message = snmpwalk(oid, community_string, ip_address, 'DotSplit')
# Model
oid = "1.3.6.1.2.1.47.1.1.1.1.13"
model, error_message = snmpwalk(oid, community_string, ip_address)
# Serial Number
oid = "1.3.6.1.2.1.47.1.1.1.1.11"
serial_number, error_message = snmpwalk(oid, community_string, ip_address)

# IP address
oid = "1.3.6.1.2.1.4.20.1.1"
snmpwalk(oid, community_string, ip_address, 'IP')
# Mask
oid = "1.3.6.1.2.1.4.20.1.3"
snmpwalk(oid, community_string, ip_address, 'IP')
# Index
oid = "1.3.6.1.2.1.4.20.1.2"
index = snmpwalk(oid, community_string, ip_address, 'INT')[0][0]

# Description
oid = f"1.3.6.1.2.1.2.2.1.2.{index}"
snmpwalk(oid, community_string, ip_address)
# MTU
oid = f"1.3.6.1.2.1.2.2.1.4.{index}"
snmpwalk(oid, community_string, ip_address, 'INT')
# MAC_address
oid = f"1.3.6.1.2.1.2.2.1.6.{index}"
snmpwalk(oid, community_string, ip_address, 'MAC', hex=True)

# Vlan Output
oid = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'
snmpwalk(oid, community_string, ip_address, 'iFACE-INT')
# Vlan Output (SG)
oid = '1.3.6.1.4.1.9.6.1.101.48.62.1.1'
snmpwalk(oid, community_string, ip_address, 'iFACE-INT')
# MTU Output
oid = '1.3.6.1.2.1.2.2.1.4'
snmpwalk(oid, community_string, ip_address, 'iFACE-INT')
# MAC Output
oid = '1.3.6.1.2.1.2.2.1.6'
snmpwalk(oid, community_string, ip_address, 'iFACE-MAC', hex=True)
# Desc Output
oid = '1.3.6.1.2.1.31.1.1.1.18'
snmpwalk(oid, community_string, ip_address, 'iFACE-DESC')

# Mode Output
oid = '1.3.6.1.4.1.9.9.46.1.6.1.1.14'
snmpwalk(oid, community_string, ip_address, 'iFACE-INT')
# Mode Output (SG)
oid = '1.3.6.1.4.1.9.6.1.101.48.65.1.1'
snmpwalk(oid, community_string, ip_address, 'iFACE-INT')

# Name interface
int_index = '10101'
oid = f"1.3.6.1.2.1.2.2.1.2.{int_index}"
snmpwalk(oid, community_string, ip_address)



(hostname, model, serial_number), error_message = get_device_info(community_string, ip_address)
site_slug = 'ust'
device_role_name = 'poe-switch'
created_device, error_message = create_netbox_device(
    hostname=hostname,
    model=model,
    serial_number=serial_number,
    site_slug=site_slug,
    role=device_role_name,
    logger=logger
)
error_message = create_ip_interface(
    community_string=community_string,
    ip_address=ip_address,
    hostname=hostname,
    logger=logger
)

interfaces, error_message = get_interfaces(
    ip_address=ip_address,
    community_string=community_string,
    logger=logger
)
