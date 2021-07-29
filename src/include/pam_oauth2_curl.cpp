//
// Created by jens on 23/07/2021.
//

#include "pam_oauth2_curl.hpp"
#include "pam_oauth2_curl_impl.hpp"
#include <curl/curl.h>
#include <utility>
#include <vector>
#include "config.hpp"
#include "pam_oauth2_excpt.hpp"


// This is where make_unique could have been useful but it is not available till C++14
pam_oauth2_curl::pam_oauth2_curl(Config const &config): impl_(new pam_oauth2_curl_impl())
{
    if(!impl_)
        throw NetworkError();
    // shared options for all calls
    if(curl_easy_setopt(impl_->curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK)
        throw NetworkError();
    if(curl_easy_setopt(impl_->curl, CURLOPT_SSL_VERIFYHOST, 1) != CURLE_OK)
        throw NetworkError();
    if(curl_easy_setopt(impl_->curl, CURLOPT_CAPATH, "/etc/grid-security/certificates") != CURLE_OK)
        throw NetworkError();
}


std::string
pam_oauth2_curl::get(const std::string &url, const std::string &token)
{
    call_data readBuffer;
    curl_easy_setopt(impl_->curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(impl_->curl, CURLOPT_WRITEDATA, &readBuffer);

    // auth_header must be defined outside of if() to remain in scope throughout because we use its c_str
    std::string auth_header = "Authorization: Bearer ";
    struct curl_slist *headers = nullptr;
    if(!token.empty()) {
	auth_header += token;
	headers = curl_slist_append(headers, auth_header.c_str());
	if(!headers)
	    throw std::bad_alloc();
	curl_easy_setopt(impl_->curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(impl_->curl);
    // reset to no (unusual) header, so handle can be reused
    curl_easy_setopt(impl_->curl, CURLOPT_HTTPHEADER, nullptr);
    if(headers) {
	curl_slist_free_all(headers);
	headers = nullptr;
    }

    if(res != CURLE_OK)
	throw NetworkError();
    return readBuffer.callback_data;
}


std::string
pam_oauth2_curl::post(const std::string &url, const std::string &username, const std::string &password,
		      std::vector<std::pair<std::string,std::string>> const &postdata)
{
    call_data readBuffer;
    std::string params{pam_oauth2_curl_impl::make_post_data(postdata)};
    curl_easy_setopt(impl_->curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_PASSWORD, password.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_POSTFIELDS, params.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(impl_->curl, CURLOPT_WRITEDATA, &readBuffer);
    CURLcode res = curl_easy_perform(impl_->curl);
    if(res != CURLE_OK)
        throw NetworkError();
    return readBuffer.callback_data;
}



pam_oauth2_curl_impl::pam_oauth2_curl_impl(): curl{curl_easy_init()}, ret(CURLE_OK)
{
    if(!curl)
	throw NetworkError();

}


pam_oauth2_curl_impl::~pam_oauth2_curl_impl()
{
    if(curl) {
	curl_easy_cleanup(curl);
	curl = nullptr;
    }
}

// RFC 3986 reserved characters to be % encoded
std::string pam_oauth2_curl_impl::reserved = ":/?#[]@!$&'()*+,;=%";


/* Normally I would not write this myself but ... */
std::string
pam_oauth2_curl_impl::encode(std::string const &in)
{
    std::string result;
    result.reserve(in.size());
    std::string::size_type u = 0, v;
    while( (v = in.find_first_of(reserved, u)) != std::string::npos ) {
	if(v > u)
	    result.append(in, u, v-u);
	char y[4];
	// The input count includes the NUL but the return value does not count the NUL
	if(snprintf(y, 4, "%%%02X", static_cast<uint8_t>(in[v])) >= 4)
	    throw "Cannot happen IXRQJ";
	result.append(y);
	u = v+1;
    }
    // and the final bit
    result.append(in, u, v);
    return result;
}


std::string
pam_oauth2_curl_impl::make_post_data(std::vector <std::pair<std::string, std::string>> const &data)
{
    std::string tmp;
    for( auto const &p : data ) {
        if(!tmp.empty())
            tmp.append("&");
        if(p.first.find_first_of(reserved) != std::string::npos) // illegal char
            throw "Cannot happen UQPAL";
        tmp.append(p.first);
        tmp.append("=");
        tmp.append(pam_oauth2_curl_impl::encode(p.second));
    }
    return tmp;
}



size_t
WriteCallback(char const *contents, size_t size, size_t nmemb, void *userp)
{
    ((call_data *)userp)->callback_data.append((char const *)contents, size * nmemb);
    return size * nmemb;
}
