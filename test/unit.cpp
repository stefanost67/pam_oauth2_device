/************************************************************
 * *** Unit testing for pam_oauth2_device
 */


#include <vector>
#include <string>
#include <security/pam_appl.h>
#include "config.hpp"
#include "pam_oauth2_device.hpp"

/* Helper function prototypes */





/* prototypes for "private" (compilation unit) functions */
std::string getQr(const char *text, const int ecc = 0, const int border = 1);

class DeviceAuthResponse;

void make_authorization_request(const char *client_id,
				const char *client_secret,
				const char *scope,
				const char *device_endpoint,
				DeviceAuthResponse *response);

void poll_for_token(const char *client_id,
		    const char *client_secret,
		    const char *token_endpoint,
		    const char *device_code,
		    std::string &token);

void get_userinfo(const char *userinfo_endpoint,
		  const char *token,
		  const char *username_attribute,
		  Userinfo *userinfo);

void show_prompt(pam_handle_t *pamh,
		 int qr_error_correction_level,
		 DeviceAuthResponse *device_auth_response);

bool is_authorized(Config *config,
		   const char *username_local,
		   Userinfo *userinfo);


