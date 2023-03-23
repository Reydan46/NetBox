import pynetbox
from netaddr import IPAddress
from snmp import snmpwalk


def create_ip_interface(community_string, ip_address, hostname, logger=None):
    if logger: logger.info('Create IP interface and set to Device')
    # Connect to the NetBox API
    netbox_url = "http://ust-netbox/"
    netbox_token = '0123456789abcdef0123456789abcdef01234567'
    netbox = pynetbox.api(url=netbox_url, token=netbox_token)

    # Get the device object in NetBox
    device = netbox.dcim.devices.get(name=hostname)

    # Use snmpwalk to get the IP address, mask, IfIndex, and ifDescr values
    ip_addresses, error_message = snmpwalk("1.3.6.1.2.1.4.20.1.1", community_string, ip_address, 'IP')
    if error_message:
        return error_message
    masks, error_message = snmpwalk("1.3.6.1.2.1.4.20.1.3", community_string, ip_address, 'IP')
    if error_message:
        return error_message
    indexes, error_message = snmpwalk("1.3.6.1.2.1.4.20.1.2", community_string, ip_address, 'INT')
    if error_message:
        return error_message

    # Create IP address objects and assign them to interfaces in NetBox
    for i, ip in enumerate(ip_addresses):
        mask = masks[i]
        if mask == '0.0.0.0':
            continue
        index = indexes[i]

        description, error_message = snmpwalk(f"1.3.6.1.2.1.2.2.1.2.{index}", community_string, ip_address)
        MTU, error_message = snmpwalk(f"1.3.6.1.2.1.2.2.1.4.{index}", community_string, ip_address, 'INT')
        MAC_address, error_message = snmpwalk(f"1.3.6.1.2.1.2.2.1.6.{index}", community_string, ip_address, 'MAC',
                                              hex=True)
        description = description[0]
        MTU = MTU[0]
        MAC_address = MAC_address[0]

        # Check if the interface already exists in NetBox
        netbox_interface = netbox.dcim.interfaces.get(name=description, device=device.name)
        if netbox_interface:
            if logger: logger.info(f"Interface '{description}' already exists in NetBox (skipping creation)")
        else:
            netbox_interface = netbox.dcim.interfaces.create(
                name=description,
                device=device.id,
                type="virtual",
                mtu=MTU,
                mac_address=MAC_address
            )
            if logger: logger.info(f"Interface '{description}' created in NetBox!")

        ip_with_prefix = f'{ip_address}/{IPAddress(mask).netmask_bits()}'

        if logger: logger.info(f'IP Address: {ip}')
        if logger: logger.info(f'Subnet Mask: {mask}')
        if logger: logger.info(f'IP Address with Prefix: {ip_with_prefix}')

        # Check if the IP address already exists in NetBox
        netbox_ip_address = netbox.ipam.ip_addresses.get(address=ip_with_prefix)
        if netbox_ip_address:
            if logger: logger.info(f"IP address '{ip_with_prefix}' already exists in NetBox (skipping creation)")
        else:
            # Create the IP address object in NetBox
            netbox_ip_address = netbox.ipam.ip_addresses.create(
                address=ip_with_prefix,
                status='active',
                assigned_object_type="dcim.interface",
                assigned_object_id=netbox_interface.id,
            )
            logger.info(f"IP address '{ip_with_prefix}' created in NetBox!")
    return ''


if __name__ == '__main__':
    # Set the SNMP community string and the IP address of the device to query
    community_string = input("Enter name of community: [public]") or "public"
    ip_address = input("Enter IP address of device: ")
    hostname = input("Enter the device name from the Netbox: ")

    create_ip_interface(community_string, ip_address, hostname)
