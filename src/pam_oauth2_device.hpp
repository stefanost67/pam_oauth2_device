#ifndef PAM_OAUTH2_DEVICE_HPP
#define PAM_OAUTH2_DEVICE_HPP

#include <string>
#include <cstdio>



class Userinfo
{
private:
    std::string sub_,
        username_,
        name_;
    // groups will be sorted alphabetically
    std::vector<std::string> groups_;
public:
    Userinfo(std::string const &sub, std::string const &username, std::string const &name): sub_(sub), username_(username), name_(name) {}
    void add_group(std::string const &group);
    void set_groups(std::vector<std::string> const &groups);

    std::string name() const { return name_; }
    std::string sub() const { return sub_; }
    std::string username() const { return username_; }

    // functions for querying the groups
    bool is_member(std::string const &group) const;
    bool intersects(std::vector<std::string>::const_iterator beg,
		    std::vector<std::string>::const_iterator end) const;
};


class DeviceAuthResponse
{
public:
    std::string user_code,
        verification_uri,
        verification_uri_complete,
        device_code;
    std::string get_prompt(const int qr_ecc);
};

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

Userinfo get_userinfo(const char *userinfo_endpoint,
		      const char *token,
		      const char *username_attribute);

#endif // PAM_OAUTH2_DEVICE_HPP