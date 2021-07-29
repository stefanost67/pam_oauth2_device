//
// Created by jens on 26/07/2021.
// This is a separate header file to make it easier to regression test the implementation
//

#ifndef __PAM_OAUTH2_DEVICE_PAM_OAUTH2_CURL_IMPL_HPP
#define __PAM_OAUTH2_DEVICE_PAM_OAUTH2_CURL_IMPL_HPP

#include <curl/curl.h>
#include <vector>
#include <utility>

// namespace pam_oauth2_curl_impl {

//@brief callback for curl
size_t WriteCallback(char const *contents, size_t size, size_t nmemb, void *userp);


struct call_data {
    std::string callback_data;
    std::string post_data;
};



struct pam_oauth2_curl_impl {
    CURL *curl;
    CURLcode ret;
    std::vector<call_data> calls;
    static std::string make_post_data(std::vector<std::pair<std::string,std::string>> const &data);
    // RFC 3986 section 2.2 (and 2.4 for '%').
    static std::string reserved;

public:
    pam_oauth2_curl_impl();
    ~pam_oauth2_curl_impl();
    //@ RFC3986 encode
    static std::string encode(std::string const &in);
};


//} // namespace pam_oauth2_curl_impl

#endif //__PAM_OAUTH2_DEVICE_PAM_OAUTH2_CURL_IMPL_HPP
