# PAM module for OAuth 2.0 Device flow

## Instalation (Ubuntu 18.04)

```
make
mkdir /lib/security
cp pam_oauth2_device.so /lib/security/
vim /etc/pam_oauth2_device/config.json
```

See `config_template.json` (LDAP, cloud and group sections are optional).

## Example Configuration (SSH, Ubuntu 18.04)

Edit `/etc/pam.d/sshd` and comment out other common-auth sections

```
auth required pam_oauth2_device.so /etc/pam_oauth2_device/config.json
```

Edit `/etc/ssh/sshd_config`

```
PermitRootLogin yes
RSAAuthentication no
PubkeyAuthentication no
PasswordAuthentication no
ChallengeResponseAuthentication yes
UsePAM yes
```

```
systemctl restart sshd
```

## Configuration config.json

**oauth** - required section for your OAuth2 client configuration. The ```local_username_suffix``` option is used within the cloud and group configuration sections. If added, it appends this suffix to all username checks

**qr** - allowed correction levels are

  * 0 - low
  * 1 - medium
  * 2 - high

**group** - if enabled, on login the users IAM groups will be checked against the group specified. If they are in this group, they will be allowed in with their IAM username (plus a suffix if appropriate).

**cloud** - for the STFC cloud - if enabled, the VM that has this module on will be part of an OpenStack project which is checked against the IRIS IAM group mappings at the endpoint specified. If the user logging in is in an IRIS IAM group which the VM project is a part of, then they will be allowed into the shared account specified.

**users** - user mapping. From claim configured in *username_attribute* to the local account name

## Development

### Instalation (Ubuntu 18.04)

```
apt install pamtester
```

### Configuration (Ubuntu 18.04)

Edit `/etc/pam.d/pamtester`

```
auth required pam_oauth2_device.so
```

### Deploy

```
cp pam_oauth2_device.so /lib/security/
```

### Test

```
pamtester -v pamtester username authenticate
```
