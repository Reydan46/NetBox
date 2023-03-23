import pynetbox
from snmp import snmpwalk


def get_device_info(community_string, ip_address, logger=None):
    if logger: logger.info('Get Device Info')
    hostname_out, error_message = snmpwalk("1.3.6.1.2.1.1.5.0", community_string, ip_address, 'DotSplit')
    model = ['']
    serial_number = ['']
    if error_message:
        hostname = ['']
    else:
        hostname = [i for i in hostname_out if i]
        if logger: logger.info(f'Hostname: {hostname[0]}')
    if not error_message:
        model_out, error_message = snmpwalk("1.3.6.1.2.1.47.1.1.1.1.13", community_string, ip_address)
        if error_message:
            model = ['']
        else:
            model = [i for i in model_out if i]
            if logger: logger.info(f'Model: {model[0]}')
    if not error_message:
        serial_number_out, error_message = snmpwalk("1.3.6.1.2.1.47.1.1.1.1.11", community_string, ip_address)
        if error_message:
            serial_number = ['']
        else:
            serial_number = [i for i in serial_number_out if i]
            if logger: logger.info(f'Serial Number: {serial_number[0]}')

    return (hostname[0], model[0], serial_number[0]), error_message


def create_netbox_device(hostname, model, serial_number, site_slug, device_role_name, logger=None):
    if logger: logger.info('Create Device in NetBox')
    # Connect to the NetBox API
    netbox_url = "http://ust-netbox/"
    netbox_token = '0123456789abcdef0123456789abcdef01234567'
    netbox = pynetbox.api(url=netbox_url, token=netbox_token)

    device_type = ''
    site = ''
    device_role = ''

    if model:
        device_type = netbox.dcim.device_types.get(model=model)
    if site_slug:
        site = netbox.dcim.sites.get(slug=site_slug)
    if device_role_name:
        device_role = netbox.dcim.device_roles.get(name=device_role_name)

    if not device_type:
        return None, f'Device type (model) not found in NetBox!'
    if not site:
        return None, f'Site slug "{site_slug}" not found in NetBox!'
    if not device_role:
        return None, f'Device role "{device_role_name}" not found in NetBox!'

    # Check if the device already exists in NetBox
    devices = netbox.dcim.devices.filter(name=hostname)
    if devices:
        if logger: logger.info(f"Device '{hostname}' already exists in NetBox (skipping creation)")
        return next(iter(devices)), ''

    # Create the device in NetBox
    device = netbox.dcim.devices.create(
        name=hostname,
        device_type=device_type.id,
        serial=serial_number,
        site=site.id,
        device_role=device_role.id,
        status="active",
    )
    if logger: logger.info(f'Device "{hostname}" created in NetBox')

    return device, ''


if __name__ == "__main__":
    # Set the SNMP community string and the IP address of the device to query
    community_string = input("Enter name of community: [public]") or "public"
    ip_address = input("Enter IP address of device: ")

    # Get device info using SNMP
    hostname, model, serial_number = get_device_info(community_string, ip_address)

    # Create device in NetBox
    site_slug = input("Enter slug of site: ")
    device_role_name = input("Enter device role: ")
    create_netbox_device(hostname, model, serial_number, site_slug, device_role_name)
