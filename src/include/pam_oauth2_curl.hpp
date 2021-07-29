//
// Created by jens on 23/07/2021.
// PIMPL/RAII abstraction of the curl library for pam_oauth2_device
//
// NOTES:
// 1. Functions can throw exceptions which are currently defined in pam_oauth2_device.hpp
// 2. Not thread safe since curl_global_init is not thread safe, and the calls use the same curl handle throughout
//

#ifndef __PAM_OAUTH2_DEVICE_PAM_OAUTH2_CURL_HPP
#define __PAM_OAUTH2_DEVICE_PAM_OAUTH2_CURL_HPP

#include <string>
#include <vector>
#include <utility>
#include <memory>


// pimpl (defined in pam_oauth2_curl.cpp)
class pam_oauth2_curl_impl;
// defined in config.hpp
class Config;

class pam_oauth2_curl {
private:
    std::unique_ptr<pam_oauth2_curl_impl> impl_;
public:
    pam_oauth2_curl(Config const &config);
    // ~pam_oauth2_curl();
    pam_oauth2_curl(pam_oauth2_curl const &) = delete;
    pam_oauth2_curl(pam_oauth2_curl &&) = delete;
    pam_oauth2_curl &operator=(pam_oauth2_curl const &) = delete;
    pam_oauth2_curl &operator=(pam_oauth2_curl &&) = delete;

    std::string get(std::string const &url, std::string const &token);
    std::string post(std::string const &url, std::string const &username, std::string const &password, std::vector<std::pair<std::string,std::string>> const &postdata);
};


#endif //__PAM_OAUTH2_DEVICE_PAM_OAUTH_2_CURL_HPP
