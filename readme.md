**Utility for polling network devices via SNMP and filling the database in NetBox**
-
---

To work you need:

1. Create system variables:

* **NETBOX_PASSWORD_SALT** - Key used to decrypt passwords (see below for how to generate them)
* **NETBOX_URL** - Path to a NetBox instance
* **NETBOX_TOKEN** - Token of access to the NetBox.

2. Create devices.csv file (by template devices.template.csv), where:

* **pass** - Pass device when checking (any value means pass)
* **ip device** - IP address of the device
* **username** - SSH login username (network-backup is used if absent)
* **password** - SSH password of the user (network-backup password is used if absent)
* **allowed ip** - IP-address which will have access to use SNMP
* **community** - SNMP Comunniti String
* **site slug** - The site name for the device in the NetBox
* **role** - The role for the device in the NetBox

---

1. How to get SALT to encrypt passwords

```
from cryptography.fernet import Fernet
key = Fernet.generate_key()
```

2. How to get an encrypted password to use in devices.csv

``` 
from cryptography.fernet import Fernet
password_salt = os.environ.get('NETBOX_PASSWORD_SALT')
password_encoder = Fernet(__password_salt)
password=b"SuperP@ssw0rd"
encrypted_password = password_encoder.encrypt(password).decode('utf-8')
```