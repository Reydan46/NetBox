import re
from typing import List
import requests
import pynetbox
from snmp import snmpwalk


class Interface:
    def __init__(self, index: str, vlan_id: int, name: str):
        self.index = index
        self.vlan_id = vlan_id
        self.mode = 'access'  # set mode to 'access' by default
        self.name = name
        self.mtu = 1500
        self.mac_address = ''
        self.desc = ''


def iFACES2dict(iFaces):
    out = {}
    for interface, value in iFaces:
        out.update({interface: value})
    return out


def get_interfaces(ip_address, community_string, logger=None):
    if logger: logger.info('Getting interfaces device')
    error_message = ''

    sg = False
    vlan_output, error_message = snmpwalk('1.3.6.1.4.1.9.9.68.1.2.2.1.2', community_string, ip_address, 'iFACE-INT')
    if error_message:
        vlan_output, error_message = snmpwalk('1.3.6.1.4.1.9.6.1.101.48.62.1.1', community_string, ip_address,
                                              'iFACE-INT')
        sg = True
    vlan_dict = iFACES2dict(vlan_output)

    mtu_output, error_message = snmpwalk('1.3.6.1.2.1.2.2.1.4', community_string, ip_address, 'iFACE-INT')
    mtu_dict = iFACES2dict(mtu_output)

    mac_output, error_message = snmpwalk('1.3.6.1.2.1.2.2.1.6', community_string, ip_address, 'iFACE-MAC', hex=True)
    mac_dict = iFACES2dict(mac_output)

    desc_output, error_message = snmpwalk('1.3.6.1.2.1.31.1.1.1.18', community_string, ip_address, 'iFACE-DESC')
    desc_dict = iFACES2dict(desc_output)

    int_mode_output, error_message = snmpwalk('1.3.6.1.4.1.9.9.46.1.6.1.1.14', community_string, ip_address,
                                              'iFACE-INT')
    if error_message:
        int_mode_output, error_message = snmpwalk('1.3.6.1.4.1.9.6.1.101.48.65.1.1', community_string, ip_address,
                                                  'iFACE-INT')
    int_mode_dict = iFACES2dict(int_mode_output)

    interfaces = []
    for int_index in int_mode_dict.keys():
        #############################################
        # Временно отбираем только порты в access
        # Для всего - 2
        # Для SG    - 4
        #############################################
        if not sg and int_mode_dict[int_index] != '2':
            continue
        if sg and int_mode_dict[int_index] != '4':
            continue
        #############################################

        if int_index in vlan_dict.keys():
            if vlan_dict[int_index] in ['0', '1']:
                continue  # skip interfaces with vlan_id of 0 or 1

            int_name, error_message = snmpwalk(f"1.3.6.1.2.1.2.2.1.2.{int_index}", community_string, ip_address)

            interface_obj = Interface(int_index, vlan_dict[int_index], int_name[0])
            interface_obj.mtu = mtu_dict[int_index]
            interface_obj.mac_address = mac_dict[int_index]
            interface_obj.desc = desc_dict[int_index]

            interfaces.append(interface_obj)

    return interfaces, error_message


def send_to_netbox(svi_object, site, ip_address, logger=None):
    # Connect to the NetBox API
    netbox_url = "http://ust-netbox/"
    netbox_token = "0123456789abcdef0123456789abcdef01234567"
    netbox = pynetbox.api(url=netbox_url, token=netbox_token)

    # Retrieve the IP address object by IP address
    ip_object = netbox.ipam.ip_addresses.get(address=ip_address)

    # Get the interface object using the assigned object ID of the IP address
    interface_object = netbox.dcim.interfaces.get(id=ip_object.assigned_object_id)

    # Get the device object using the device ID of the interface
    device = netbox.dcim.devices.get(id=interface_object.device.id)

    # Get the ID of the VLAN with the specified VLAN ID and associated with the specified site
    vlan = netbox.ipam.vlans.get(site=site, vid=svi_object.vlan_id)

    # Get the existing interface object
    netbox_interface = netbox.dcim.interfaces.get(device=device.name, name=svi_object.name)

    type_mapping = {
        '1000BASE-T (1GE)': '1000base-t',
        '10GBASE-T (10GE)': '10gbase-t',
        # add more mappings as needed
    }

    url = "http://ust-netbox/api/dcim/interfaces/"
    headers = {
        "Authorization": "Token 0123456789abcdef0123456789abcdef01234567",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "device": device.id,
        "name": svi_object.name,
        "mtu": svi_object.mtu,
        "mac_address": svi_object.mac_address,
        "description": svi_object.desc,
        "mode": svi_object.mode,
        "untagged_vlan": vlan.id,
        "type": "other"
    }

    if netbox_interface:
        type_str = str(netbox_interface.type)
        payload.update({"type": type_mapping.get(type_str, 'other')})

        response = requests.patch(f"{url}{netbox_interface.id}/", headers=headers, json=payload)
        if response.status_code == 200:
            if logger: logger.info(f"Data sent successfully to Netbox for interface with index {svi_object.index}")
        else:
            if logger: logger.error(
                f"Error sending data to Netbox. Status code: {response.status_code}. Response content: {response.content}")
    else:
        response = requests.post(f"{url}", headers=headers, json=payload)
        if response.status_code == 201:
            if logger: logger.info(f"Data sent successfully to Netbox for interface with index {svi_object.index}")
        else:
            if logger: logger.error(
                f"Error sending data to Netbox. Status code: {response.status_code}. Response content: {response.content}")


def write_info_interfaces(ip_address, community_string, site_slug, logger=None):
    interfaces, error_message = get_interfaces(ip_address, community_string)

    if logger: logger.info("Interfaces:")
    for interface_obj in interfaces:
        if logger: logger.info(f"- Index: {interface_obj.index}, VLAN ID: {interface_obj.vlan_id}")
        send_to_netbox(interface_obj, site_slug, ip_address, logger=logger)


if __name__ == "__main__":
    ip_address = input("Enter the IP address: ")
    community_string = input("Enter the community string [public]: ") or 'public'
    site_slug = input("Enter slug of site: ")
