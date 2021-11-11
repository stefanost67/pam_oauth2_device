#include <fstream>
#include <set>

#include "config.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

void Config::load(const char *path)
{
    std::ifstream config_fstream(path);
    json j;
    config_fstream >> j;

    client_id = j.at("oauth").at("client").at("id").get<std::string>();
    client_secret = j.at("oauth").at("client").at("secret").get<std::string>();
    scope = j.at("oauth").at("scope").get<std::string>();
    device_endpoint = j.at("oauth").at("device_endpoint").get<std::string>();
    token_endpoint = j.at("oauth").at("token_endpoint").get<std::string>();
    userinfo_endpoint = j.at("oauth").at("userinfo_endpoint").get<std::string>();
    username_attribute = j.at("oauth").at("username_attribute").get<std::string>();
    local_username_suffix = j.at("oauth").at("local_username_suffix").get<std::string>();

    qr_error_correction_level = (j.find("qr") != j.end()) ?
        j.at("qr").at("error_correction_level").get<int>() : -1;

    enable_email =  (j.find("enable_email") != j.end()) ?
        j.at("enable_email").get<bool>() : false;   

    smtp_server_url = j.at("send_mail").at("smtp_server_url").get<std::string>();
    smtp_username = j.at("send_mail").at("smtp_username").get<std::string>();
    smtp_password = j.at("send_mail").at("smtp_password").get<std::string>();
    mail_from = j.at("send_mail").at("from_address").get<std::string>();
    mail_cc = j.at("send_mail").at("cc_address").get<std::string>();
    mail_from_username = j.at("send_mail").at("from_username").get<std::string>();


    client_debug = (j.find("client_debug") != j.end()) ? j.at("client_debug").get<bool>() : false;

    http_basic_auth = (j.find("http_basic_auth") != j.end()) ?
        j.at("http_basic_auth").get<bool>() : true;

    if (j.find("cloud") != j.end()) {
        cloud_access = j.at("cloud").at("access").get<bool>();
        cloud_endpoint = j.at("cloud").at("endpoint").get<std::string>();
        cloud_username = j.at("cloud").at("username").get<std::string>();
    }

    if (j.find("group") != j.end())
    {
        group_access = j.at("group").at("access").get<bool>();
        group_service_name = j.at("group").at("service_name").get<std::string>();
    }

    if (j.find("ldap") != j.end())
    {
        ldap_host = j.at("ldap").at("host").get<std::string>();
        ldap_basedn = j.at("ldap").at("basedn").get<std::string>();
        ldap_user = j.at("ldap").at("user").get<std::string>();
        ldap_passwd = j.at("ldap").at("passwd").get<std::string>();
        ldap_filter = j.at("ldap").at("filter").get<std::string>();
        ldap_attr = j.at("ldap").at("attr").get<std::string>();
    }
    if (j.find("users") != j.end())
    {
        for (auto &element : j["users"].items())
        {
            for (auto &local_user : element.value())
            {
                if (usermap.find(element.key()) == usermap.end())
                {
                    std::set<std::string> userset;
                    userset.insert((std::string)local_user);
                    usermap[element.key()] = userset;
                }
                else
                {
                    usermap[element.key()].insert((std::string)local_user);
                }
            }
        }
    }
}
