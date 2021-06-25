/************************************************************
 * *** Unit testing for pam_oauth2_device
 * Normally we test the public API but in this case we need to test the private API as well
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <security/pam_appl.h>
#include "config.hpp"
#include "pam_oauth2_device.hpp"
#include <fstream>
#include <algorithm>
#include <iterator>

/* Helper function prototypes */

/** \brief Check whether the contents of a file matches exactly that of the string being passed to it
 * \param filename - the name of the file to be scanned relative to CWD
 * \param string - the string to compare
 * @return -1 if matching, -1000 if file is absent; or location of first mismatch if not matching
 */
ssize_t cmp_file_string(char const *, std::string const &);



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


TEST(PamOAuth2Unit, QrCodeTest)
{
    char const *text = "I want to think audibly this evening. I do not want to make a speech and if you find me this evening speaking without reserve, pray, consider"
		       " that you are only sharing the thoughts of a man who allows himself to think audibly, and if you think that I seem to transgress the limits"
		       " that courtesy imposes upon me, pardon me for the liberty I may be taking.";
    char const *loremipsum = "loremipsum";
EXPECT_EQ(cmp_file_string("data/qr1.0.txt", getQr(loremipsum, 0, 1)), -1);
EXPECT_EQ(cmp_file_string("data/qr1.1.txt", getQr(loremipsum, 1, 1)), -1);
EXPECT_EQ(cmp_file_string("data/qr1.2.txt", getQr(loremipsum, 2, 1)), -1);
EXPECT_EQ(cmp_file_string("data/qr2.0.txt", getQr(text, 0, 1)), -1);
EXPECT_EQ(cmp_file_string("data/qr2.1.txt", getQr(text, 1, 1)), -1);
EXPECT_EQ(cmp_file_string("data/qr2.2.txt", getQr(text, 2, 1)), -1);
}




ssize_t
cmp_file_string(char const *filename, std::string const &string)
{
    std::ifstream foo(filename, std::ios_base::binary);
    if(!foo)
        return -1000;
    ssize_t index = 0;
    // istream_iterator doesn't work because it parses the input
    auto p = string.cbegin();
    auto const q = string.cend();
    while(p != q) {
        // get returns EOF at, er, EOF, and EOF is never a character
        char c1, c2;
        c1 = foo.get();
        c2 = *p++;
        if(c1 != c2) {
            return index;
        }
    }
    return -1;    // match
}
