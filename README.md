# PAM module for OAuth 2.0 Device flow

This is a PAM module that lets you log in via SSH to servers using OpenID Connect credentials, instead of SSH Keys or a username and password combination.

It uses the OAuth2 Device Flow, which means that during the login process, you will click a link and log in to your OpenID Connect Provider, which will then authenticate you for the SSH session. 

This module will then check if you're in the right group(s) or have a specified username, and allow or deny access.

A demo video is avaliable here: https://drive.google.com/file/d/1WzDRL0RFDXfvUgabbXNzBppV-DKXyUN1/view?usp=sharing

## Installation (SL/CentOS 7)

```
yum intall epel-release
yum install openldap-devel
yum install libcurl-devel
yum install pam-devel
yum install libldb-devel
yum install http://ftp.scientificlinux.org/linux/scientific/7x/external_products/softwarecollections/yum-conf-softwarecollections-2.0-1.el7.noarch.rpm
yum install devtoolset-8 # this is needed as we need a more up to date g++ version than is supplied by default in SL repos.
scl enable devtoolset-8 bash
git clone https://github.com/stfc/pam_oauth2_device.git
cd pam_oauth2_device/
make
cp pam_oauth2_device.so /lib64/security/pam_oauth2_device.so
cp config_template.json config.json
```
You MUST edit the configuration before this module will work!

## SSH Configuration

Make sure the module works correctly before changing your SSH config or you may be locked out!

Edit `/etc/pam.d/sshd` and comment out the other `auth` sections.

```
auth required pam_oauth2_device.so /etc/pam_oauth2_device/config.json
```

Edit `/etc/ssh/sshd_config` and make sure that the following configuration options are set

```
ChallengeResponseAuthentication yes
UsePAM yes
```

```
systemctl restart sshd
```

## Configuration config.json

The configuration should be located at `/etc/pam_oauth2_device/config.json`.

**oauth** - required section for your OAuth2 client configuration. You will be able to get most configuration attributes from your IAM administrator. The ```local_username_suffix``` option is used within the cloud and group configuration sections. If added, it appends this suffix to all username checks. e.g. if the suffix is set to "_irisiam" then it is expected that usernames on the system will follow the format: "<iam-username>_irisiam"

**qr** - allowed correction levels are

  * -1 - no QR printed
  * 0 - low
  * 1 - medium
  * 2 - high

If no **qr** information is provided, one isn't printed.

**group** - if enabled, on login the users IAM groups will be checked against the group specified. If they are in this group, they will be allowed in with their IAM username (plus a suffix if set above). e.g. if the group is set to "my-service", any IAM user in the group "my-service" will be allowed access. If a user is ONLY in a subgroup, e.g. "my-service/special", they will NOT be allowed access.

**cloud** - this is designed for VMs in the STFC cloud. For this to work, the module will need to be installed on an OpenStack VM, and be enabled. The **group** section should be disabled. All OpenStack VMs will be part of a project on the OpenStack service. If the user logging in is in an IRIS IAM group which the VM project is a part of, then they will be allowed into the shared account specified.
e.g. The user is trying to access the shared "centos" account, which has been specified using the "username" attribute. The VM is in the IRIS AAI project in OpenStack, which maps to the IAM group "iris-iam-admins". If the user trying to gain access is in the "iris-iam-admins" IAM group, then they will be allowed access to the "centos" account.

The "endpoint" attribute should be set to the location of the irisiam-mapper.py CGI script.

**users** - user mapping. From claim configured in *username_attribute* to the local account name. e.g. you could map the IAM username "willfurnell" or "will.furnell@stfc.ac.uk" to the local account "root". This must be done on a per-user basis, so isn't suitable for large numbers of users.

**client_debug** - boolean value; if set to true, additional debugging information is printed to stdout by the module.  Useful for debugging.

## Testing the module works

You are advised to do this before making changes to your SSH config.

### Installation

Follow instructions above, and additionally install pamtester.

```
yum install pamtester
```

### Configuration (Ubuntu 18.04)

Edit `/etc/pam.d/pamtester`

```
auth required pam_oauth2_device.so
```

### Test

Run
```
pamtester -v pamtester localusername authenticate
```
and follow the onscreen prompts.

You can check `/var/log/secure` to find what's wrong if there are errors authenticating.
