#include <security/pam_appl.h>
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>

#include <chrono>
#include <sstream>
#include <thread>
#include <vector>
#include <iterator>
#include <iostream>
#include <string>
//#include <regex>
#include <cstdio>
#include <fstream>

#include "include/config.hpp"
#include "include/metadata.hpp"
#include "include/ldapquery.h"
#include "include/nayuki/QrCode.hpp"
#include "include/nlohmann/json.hpp"
#include "include/pam_oauth2_curl.hpp"
#include "include/pam_oauth2_excpt.hpp"
#include "pam_oauth2_device.hpp"

using json = nlohmann::json;


//! Function to parse the PAM args (as supplied in the PAM config), updating our config
void parse_args(Config &config, int flags, int argc, const char **argv);


void Userinfo::add_group(const std::string &group)
{
    // there doesn't seem to be an insert for sorted sequences? anyway, it's not hugely important here
    groups_.push_back(group);
    std::sort(groups_.begin(), groups_.end());
}

void Userinfo::set_groups(const std::vector<std::string> &groups)
{
    groups_ = groups;    // copies vector and strings
    std::sort(groups_.begin(), groups_.end());
}


bool Userinfo::is_member(const std::string &group) const
{
    return std::binary_search(groups_.cbegin(), groups_.cend(), group);
}


bool Userinfo::intersects(std::vector<std::string>::const_iterator beg, std::vector<std::string>::const_iterator end) const
{
    if(!std::is_sorted(beg, end))
        throw "Cannot happen IYWHQ";
    std::vector<std::string> target;
    // Intersection is tidier but needs both its entries to be sorted
    std::set_intersection(groups_.cbegin(), groups_.cend(), beg, end,
	    // no CTAD in C++11
			  std::back_insert_iterator<std::vector<std::string>>(target));

    return !target.empty();

}


std::string getQr(const char *text, const int ecc = 0, const int border = 1)
{
    qrcodegen::QrCode::Ecc error_correction_level;
    switch (ecc)
    {
    case 1:
        error_correction_level = qrcodegen::QrCode::Ecc::MEDIUM;
        break;
    case 2:
        error_correction_level = qrcodegen::QrCode::Ecc::HIGH;
        break;
    default:
        error_correction_level = qrcodegen::QrCode::Ecc::LOW;
        break;
    }
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
        text, error_correction_level);

    std::ostringstream oss;
    int i, j, size, top, bottom;
    size = qr.getSize();
    for (j = -border; j < size + border; j += 2)
    {
        for (i = -border; i < size + border; ++i)
        {
            top = qr.getModule(i, j);
            bottom = qr.getModule(i, j + 1);
            if (top && bottom)
            {
                oss << "\033[40;97m \033[0m";
            }
            else if (top && !bottom)
            {
                oss << "\033[40;97m\u2584\033[0m";
            }
            else if (!top && bottom)
            {
                oss << "\033[40;97m\u2580\033[0m";
            }
            else
            {
                oss << "\033[40;97m\u2588\033[0m";
            }
        }

        oss << std::endl;
    }
    return oss.str();
}

std::string DeviceAuthResponse::get_prompt(const int qr_ecc = 0)
{
    bool complete_url = !verification_uri_complete.empty();
    std::ostringstream prompt;
    prompt << "Authenticate at\n-----------------\n"
           << (complete_url ? verification_uri_complete : verification_uri)
           << "\n-----------------\n";
    if (!complete_url)
    {
        prompt << "With code " << user_code
               << "\n-----------------\n";
    }

    if (qr_ecc >= 0) {
        prompt << "Or scan the QR code to authenticate with a mobile device"
               << std::endl
               << std::endl
               << getQr((complete_url ? verification_uri_complete : verification_uri).c_str(), qr_ecc)
               << std::endl
               << "Hit enter when you have finished authenticating\n";
    } else {
        prompt << "Hit enter when you have finished authenticating\n";
    }
    return prompt.str();
}


void make_authorization_request(const Config &config,
                                std::string const &client_id,
                                std::string const &client_secret,
                                std::string const &scope,
                                std::string const &device_endpoint,
                                DeviceAuthResponse *response)
{
    pam_oauth2_curl curl(config);
    pam_oauth2_curl::params params;
    curl.add_params(params, "client_id", client_id);
    curl.add_params(params, "scope", scope);
    std::string result{curl.call(config, device_endpoint, params)};

    try
    {
        puts(result.c_str());
        if (config.client_debug) fprintf(stderr, "Response to authorization request: %s\n", result.c_str());
        auto data = json::parse(result);
        response->user_code = data.at("user_code");
        response->device_code = data.at("device_code");
        response->verification_uri = data.at("verification_uri");
        if (data.find("verification_uri_complete") != data.end())
        {
            response->verification_uri_complete = data.at("verification_uri_complete");
        }
    }
    catch (json::exception &e)
    {
        throw ResponseError("Couldn't parse auz response from server");
    }
}

void poll_for_token(Config const &config,
                    std::string const &client_id,
                    std::string const &client_secret,
                    std::string const &token_endpoint,
                    std::string const &device_code,
                    std::string &token)
{
    int timeout = 300,
        interval = 3;
    json data;

    pam_oauth2_curl curl(config);

    pam_oauth2_curl::params params;
    curl.add_params(params, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
    curl.add_params(params, "device_code", device_code);

    while (true)
    {
        timeout -= interval;
        if (timeout < 0)
        {
            throw TimeoutError("Timeout waiting for token");
        }

        std::this_thread::sleep_for(std::chrono::seconds(interval));

	std::string result{curl.call(config, token_endpoint, params)};

	try
        {
            if (config.client_debug) fprintf(stderr, "Response from token poll: %s\n", result.c_str());
            data = json::parse(result);
            if (data["error"].empty())
            {
                token = data.at("access_token");
                break;
            }
            else if (data["error"] == "authorization_pending")
            {
                // Do nothing
            }
            else if (data["error"] == "slow_down")
            {
                ++interval;
            }
            else
            {
                throw ResponseError("Token response: unknown server error");
            }
        }
        catch (json::exception &e)
        {
            throw ResponseError("Token response: could not parse server response");
        }
    }
}



Userinfo
get_userinfo(const Config &config,
                  std::string const &userinfo_endpoint,
                  std::string const &token,
                  std::string const &username_attribute)
{
    pam_oauth2_curl curl(config);

    std::string result{curl.call(config, userinfo_endpoint, pam_oauth2_curl::credential(token))};
    try
    {
        if (config.client_debug) fprintf(stderr, "Userinfo token: %s\n", result.c_str());
        auto data = json::parse(result);
        Userinfo ui(data.at("sub"), data.at(username_attribute), data.at("name"));
        ui.set_groups( data.at("groups").get<std::vector<std::string>>() );
        return ui;
    }
    catch (json::exception &e)
    {
        throw ResponseError("Userinfo: could not parse server response");
    }
    throw "Cannot happen QPAIJ";
}

void show_prompt(pam_handle_t *pamh,
                 int qr_error_correction_level,
                 DeviceAuthResponse *device_auth_response)
{
    int pam_err;
    char *response;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    std::string prompt;

    pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (pam_err != PAM_SUCCESS)
        throw PamError("Prompt: failed to get PAM_CONV");
    prompt = device_auth_response->get_prompt(qr_error_correction_level);
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt.c_str();
    msgp = &msg;
    response = NULL;
    pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL)
    {
        if (pam_err == PAM_SUCCESS)
        {
            response = resp->resp;
        }
        else
        {
            free(resp->resp);
        }
        free(resp);
    }
    if (response)
        free(response);
}

bool is_authorized(Config *config,
                   std::string const &username_local,
                   Userinfo const &userinfo,
                   char const *metadata_path = nullptr)
{
    Metadata metadata;

    // utility username check used by cloud_access and group_access
    auto check_username = [&config](std::string const &remote, std::string local) -> bool
    {
	local += config->local_username_suffix;
	return remote == local;
    };

    // Try and see if any IAM groups the user is a part of are also linked to the OpenStack project this VM is a part of
    if (config->cloud_access && check_username(config->cloud_username, username_local))
    {
        try
        {
            // The default path for the metadata file (containing project_id) was hardcoded into previous versions
            constexpr const char *legacy_metadata_path = "/mnt/context/openstack/latest/meta_data.json";
            if(!metadata_path) {
                if(config->metadata_file.empty()) {
		    fputs("Warning: using hardwired legacy metadata (configure \"metadata_file\" in the \"cloud\" section in config)\n",
			  stderr);
		    metadata_path = legacy_metadata_path;
		} else {
                    metadata_path = config->metadata_file.c_str();
                }
            }
            metadata.load( metadata_path );
        }
        catch (json::exception &e)
        {
            // An exception means it's probably safer to not allow access
            throw ConfigError("Is_Auz/cloud: Failed to parse project_id in config:cloud.metadata_file");
        }

	pam_oauth2_curl curl(*config);

	std::string url{config->cloud_endpoint};
	url.append("/");
	url.append(metadata.project_id);

	// Call with empty credential
	std::string result{curl.call(*config, url, pam_oauth2_curl::credential())};
        try
        {
            if (config->client_debug) fputs(result.c_str(), stderr);
            auto data = json::parse(result);
            std::vector<std::string> groups = data.at("groups").get<std::vector<std::string>>();
            std::sort(groups.begin(), groups.end());

	    // If server's view of groups overlaps with the user's groups (userinfo.groups already sorted)
	    if(userinfo.intersects(groups.cbegin(), groups.cend()))
	    {
	        if(config->client_debug)
		    fprintf(stderr, "cloud access: %s is authorised\n", username_local.c_str());
	        return true;
	    }
        }
        catch (json::exception &e)
        {
            throw ResponseError("Is_Auz/cloud: failed to parse allowed groups from server");
        }
    }

    // Try to authorize against group name in userinfo
    if ( config->group_access \
	 && check_username(userinfo.username(), username_local) \
	 && userinfo.is_member(config->group_service_name) )
    {
	fprintf(stderr, "group access: %s is authorised\n", username_local.c_str());
	return true;
    }

    // Try to authorize against local config, looking for the remote username...
    std::map<std::string,std::set<std::string>>::const_iterator local = config->usermap.find(userinfo.username());
    // if present, check if it contains the local username(s)
    if(local != config->usermap.cend())
    {
        std::string u{username_local};
        if( local->second.find(u) != local->second.cend() )
        {
            fprintf(stderr, "usermap: %s is authorised\n", username_local.c_str());
            return true;
        }
    }

    // Try to authorize against LDAP
    if (!config->ldap_host.empty())
    {
	std::string uname = userinfo.username();
	const char *username_remote = uname.c_str();

	size_t filter_length = config->ldap_filter.length() + strlen(username_remote) + 1;
        char *filter = new char[filter_length];
        snprintf(filter, filter_length, config->ldap_filter.c_str(), username_remote);
        int rc = ldap_check_attr(config->ldap_host.c_str(), config->ldap_basedn.c_str(),
                                 config->ldap_user.c_str(), config->ldap_passwd.c_str(),
                                 filter, config->ldap_attr.c_str(), username_local.c_str());
        delete[] filter;
        if (rc == LDAPQUERY_TRUE) {
            fprintf(stderr, "ldap: %s is authorised\n", username_local.c_str());
            return true;
        }
    }

    fprintf(stderr, "is_authorized: %s is not authorised\n", username_local.c_str());
    return false;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook, custom logic */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username_local;
    std::string token;
    Config config;
    DeviceAuthResponse device_auth_response;

    std::ofstream debug("/tmp/pad.log", std::ios_base::out);
    // endl will flush the stream
    if(debug)
	debug << "started" << std::endl;

    try
    {
        (argc > 0) ? config.load(argv[0]) : config.load("/etc/pam_oauth2_device/config.json");
    }
    catch (json::exception &e)
    {
        fputs("Failed to load config.\n", stderr);
        return PAM_AUTH_ERR;
    }

    if(debug)
	debug << "read config" << std::endl;

    try
    {
        if (pam_get_user(pamh, &username_local, "Username: ") != PAM_SUCCESS)
            throw PamError("PAM_AUTH: could not get local username");
        make_authorization_request(
            config,
            config.client_id, config.client_secret,
            config.scope, config.device_endpoint,
            &device_auth_response);
        show_prompt(pamh, config.qr_error_correction_level, &device_auth_response);
        poll_for_token(config, config.client_id, config.client_secret,
                       config.token_endpoint,
                       device_auth_response.device_code, token);
        Userinfo ui{get_userinfo(config, config.userinfo_endpoint, token,
				 config.username_attribute)};
	if (is_authorized(&config, username_local, ui)) {
	    if(debug)
	    debug << "success" << std::endl;
	    return PAM_SUCCESS;
	}
    }
    catch (PamError &e)
    {
	    if(debug)
	debug << "pam error" << std::endl;
        return PAM_SYSTEM_ERR;
    }
    catch (TimeoutError &e)
    {
	    if(debug)
	debug << "timeout error" << std::endl;
        return PAM_AUTH_ERR;
    }
    catch (NetworkError &e)
    {
	    if(debug)
	debug << "timeout error" << std::endl;
        return PAM_AUTH_ERR;
    }
	    if(debug)
    debug << "denied error" << std::endl;

    return PAM_AUTH_ERR;
}



void
parse_args(Config &config, [[maybe_unused]] int flags, int argc, const char **argv)
{
    // FIXME make smarter: For now we just look for "debug" as it is a common argument to PAM modules
    // TODO Note the config file can also assert debug for now
    for(int i = 1; i < argc; ++i)
        if(!strcasecmp(argv[i], "debug"))
            config.client_debug = true;
}