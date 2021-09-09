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

    client_debug = (j.find("client_debug") != j.end()) ? j.at("client_debug").get<bool>() : false;

    http_basic_auth = (j.find("http_basic_auth") != j.end()) ?
        j.at("http_basic_auth").get<bool>() : true;

    if (j.find("cloud") != j.end()) {
        auto cloud_section = j.at("cloud");
        cloud_access = cloud_section.at("access").get<bool>();
        cloud_endpoint = cloud_section.at("endpoint").get<std::string>();
        cloud_username = cloud_section.at("username").get<std::string>();
	// Absent in older config files
	if(cloud_section.find("metadata_file") != cloud_section.end())
	    metadata_file = cloud_section.at("metadata_file").get<std::string>();
    }

    if (j.find("group") != j.end())
    {
        group_access = j.at("group").at("access").get<bool>();
        group_service_name = j.at("group").at("service_name").get<std::string>();
    }

    if (j.find("ldap") != j.end())
    {
	auto ldap = j.at("ldap");
        ldap_host = ldap.at("host").get<std::string>();
        ldap_basedn = ldap.at("basedn").get<std::string>();
        ldap_user = ldap.at("user").get<std::string>();
        ldap_passwd = ldap.at("passwd").get<std::string>();
	if(ldap.find("scope") != ldap.end())
	    ldap_scope = ldap.at("scope").get<std::string>();
	if(ldap.find("preauth") != ldap.end())
	    ldap_preauth = ldap.at("preauth").get<std::string>();
        ldap_filter = ldap.at("filter").get<std::string>();
        ldap_attr = ldap.at("attr").get<std::string>();
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
