#ifndef SEND_MAIL_HPP
#define SEND_MAIL_HPP

#include <string>
#include <curl/curl.h>

class Email
{
public:
    Email(const std::string &to,
          const std::string &from,
          const std::string &nameFrom,
          const std::string &subject,
          const std::string &body,
          const std::string &cc = ""
         );
    
    
    CURLcode send(const std::string &url, 
                  const bool &insecure = false,
                  const std::string &ca_path = "",
                  const std::string &username = "", 
                  const std::string &password = "");
private:
    // data
    std::string to_, from_, cc_, nameFrom_, subject_, body_;
    std::string dateTimeNow() const;
    std::string setPayloadText();
    std::string generateMessageId() const;
    
    // static functions
    static size_t payloadSource(void *ptr, size_t size, size_t nmemb, void *userp);
};


#endif
