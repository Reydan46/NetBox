# Utility for polling network devices via SNMP and filling the database in NetBox



To work you need:

1. Create system variables:

* **NETBOX_PASSWORD_SALT** - Key used to decrypt passwords (see below for how to generate them)
* **NETBOX_URL** - Path to a NetBox instance
* **NETBOX_TOKEN** - Token of access to the NetBox.

2. Create devices.csv file (by template devices.template.csv), where:

* **pass** - Pass device when checking (any value means pass)
* **ip device** - IP address of the device
* **username** - SSH login username (leave empty for `network-admin` credentials using)
* **enc_password** - Encrypted SSH password of the user (leave empty for `network-admin` credentials using)
* **allowed ip** - IP-address which will have access to use SNMP
* **community** - SNMP Community String
* **site slug** - The site name for the device in the NetBox
* **role** - The role for the device in the NetBox

---


## How to add a system environment variable using PowerShell as Administrator:
```
[Environment]::SetEnvironmentVariable("NETBOX_URL", "VARIABLE_VALUE", "Machine")
[Environment]::SetEnvironmentVariable("NETBOX_PASSWORD_SALT", "VARIABLE_VALUE", "Machine")
[Environment]::SetEnvironmentVariable("NETBOX_TOKEN", "VARIABLE_VALUE", "Machine")
```
Replace "VARIABLE_VALUE" with the value you want to assign to the variable.

## How to get SALT to encrypt passwords (NETBOX_PASSWORD_SALT)
```
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key)
```

## How to get an encrypted password to use in devices.csv (enc_password)
``` 
from cryptography.fernet import Fernet
password_salt = os.environ.get('NETBOX_PASSWORD_SALT')
password_encoder = Fernet(__password_salt)
password=b"SuperP@ssw0rd"
encrypted_password = password_encoder.encrypt(password).decode('utf-8')
print(encrypted_password)
```
