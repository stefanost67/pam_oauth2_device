#ifndef PAM_OAUTH2_DEVICE_CONFIG_HPP
#define PAM_OAUTH2_DEVICE_CONFIG_HPP

#include <map>
#include <set>
#include <string>
#include <vector>

class Config
{
public:
    void load(const char *path);
    std::string client_id,
        client_secret,
        scope,
        device_endpoint,
        token_endpoint,
        userinfo_endpoint,
        username_attribute,
        ldap_host,
        ldap_basedn,
        ldap_user,
        ldap_passwd,
        ldap_filter,
        ldap_attr,
        smtp_server_url,
        smtp_username,
        smtp_password,
        mail_from,
        mail_from_username,
        mail_cc,
        group_service_name,
        cloud_endpoint,
        cloud_username,
        local_username_suffix;
    int qr_error_correction_level;
    bool group_access,
         cloud_access,
         enable_email,
         http_basic_auth,
         debug;
    std::map<std::string, std::set<std::string>> usermap;
    std::vector<std::string> groups;
};

#endif // PAM_OAUTH2_DEVICE_CONFIG_HPP
