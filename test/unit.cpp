/************************************************************
 * *** Unit testing for pam_oauth2_device
 * Normally we test the public API but in this case we need to test the private API as well
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <security/pam_appl.h>
#include "config.hpp"
#include "metadata.hpp"
#include "pam_oauth2_device.hpp"
#include "temp_file.hpp"
#include <fstream>
#include <algorithm>
#include <iterator>
#include <cstdlib>


/* Helper function prototypes */

/** \brief Check whether the contents of a file matches exactly that of the string being passed to it
 * \param filename - the name of the file to be scanned relative to CWD
 * \param string - the string to compare
 * @return -1 if matching, -1000 if file is absent; or location of first mismatch if not matching
 */
ssize_t cmp_file_string(char const *, std::string const &);

enum class ConfigSection { TEST_CLOUD, TEST_GROUP, TEST_USERMAP, TEST_LDAP };

/** \brief Make a dummy Config class for testing */
Config make_dummy_config(ConfigSection, Userinfo const &);

/** \brief make a dummy userinfo class */
Userinfo make_dummy_userinfo(std::string const &);

/** Test function for cloud section of is_authorized() */
bool is_authorized_cloud(Userinfo &ui, char const *username_local, std::vector<std::string> const &groups);


/* copied prototypes for "private" (compilation unit) functions from pam_oauth2_device.cpp */
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
		   Userinfo *userinfo,
		   char const *metadata_path = nullptr);


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

TEST(PamOAuth2Unit, IsAuthorized)
{
    Userinfo ui{make_dummy_userinfo("fred")};
    std::vector<std::string> groups;
    // No groups
EXPECT_TRUE( !is_authorized_cloud(ui, "fred", groups));
// Groups, correct username
groups.push_back("bleps");
groups.push_back("plamf");
EXPECT_TRUE( is_authorized_cloud(ui, "fred", groups));
// Right groups, wrong username
EXPECT_TRUE( !is_authorized_cloud(ui, "barney", groups));
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



Config
make_dummy_config(ConfigSection section, Userinfo const &ui)
{
    Config cf;
    // All members are public! and have no explicit initialisers
    // Boolean selectors of test section
    cf.cloud_access = cf.group_access = false;
    switch (section) {
	case ConfigSection::TEST_CLOUD:
	    cf.cloud_access = true;
	    // The following three variables are needed: cloud_username, local_username_suffix, cloud_endpoint
	    cf.local_username_suffix = ".test";
	    cf.cloud_username = ui.username + cf.local_username_suffix;
	    // endpoint is set later as we don't know it yet
	    break;
	case ConfigSection::TEST_GROUP:
	    cf.group_access = true;
	    break;
	case ConfigSection::TEST_LDAP:
	    break;
	case ConfigSection::TEST_USERMAP:
	    break;
	// no default
    }
    return cf;
}


Userinfo
make_dummy_userinfo(std::string const &username)
{
    Userinfo ui;
    ui.sub = "0123456789abcdef";
    ui.username = username.empty() ? "jdoe" : username;
    ui.name = "J. Doe";
    ui.groups.push_back("bleps");
    ui.groups.push_back("splomp");
    ui.groups.push_back("plempf");
    return ui;
}



Metadata
make_dummy_metadata()
{
    Metadata md;
    // This is currently a public member! but will not test the load function
    md.project_id = "iristest";
    return md;
}


bool
is_authorized_cloud(Userinfo &ui, char const *username_local, std::vector<std::string> const &groups)
{
    Config cf{make_dummy_config(ConfigSection::TEST_CLOUD, ui)};
    TempFile metadata("{\"project_id\":\"iristest\"}");
    // Slightly hacky JSON construction
    std::string contents{"{\"groups\":[\""};
    if(!groups.empty()) {
        auto end = groups.cend()-1;
	std::for_each(groups.cbegin(), end, [&contents](std::string const &grp) { contents += grp; contents += "\",\""; });
        contents += *end;
    }
    contents += "\"]}";
    // The project id is the name of the file
    TempFile cloud( "iristest", contents.c_str()); // FIXME should take a string constructor
    // curl can read a local file!
    cf.cloud_endpoint = "file://" +  cloud.dirname();
    // Finally, call the function.
    bool ret = is_authorized(&cf, username_local, &ui, metadata.filename().c_str());
    return ret;
}
