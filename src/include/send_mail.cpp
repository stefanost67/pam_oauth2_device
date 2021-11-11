#include "send_mail.hpp"


Email::Email(const std::string &to,
          const std::string &from,
          const std::string &nameFrom,
          const std::string &subject,
          const std::string &body,
          const std::string &cc
         )
 {
    to_ = to;
    from_ = from;
    cc_ = cc;
    nameFrom_ = nameFrom;
    subject_ = subject;
    body_ = body;
 }; 


std::string Email::setPayloadText()
{
    std::string text;
 
    text += "To: <"   + to_   + ">\r\n";
    text += "From: <" + from_ + "> (" + nameFrom_ + ")\r\n";
    text += "Subject: "      + subject_ + "\r\n";
    text += "\r\n";
    text += body_ + "\r\n";
    text += "\r\n";
    text += "\r\n"; // "It could be a lot of lines, could be MIME encoded, whatever.\r\n";
    text += "\r\n"; // "Check RFC5322.\r\n";
 
    return text;
}


struct Message
{
    std::string msg;
    size_t bytesleft;
 
    Message(std::string &&m) : msg(m), bytesleft(msg.size()) {};
    Message(std::string  &m) = delete;
};

size_t Email::payloadSource(void *ptr, size_t size, size_t nmemb, void *userp){
    
    Message *text = reinterpret_cast<Message *>(userp);
 
    if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1) || (text->bytesleft == 0)) {
        return 0;
    }
 
    if ((nmemb * size) >= text->msg.size()) {
        text->bytesleft = 0;
        return text->msg.copy(reinterpret_cast<char *>(ptr), text->msg.size());
    }
 
    return 0;
};

CURLcode Email::send(const std::string &url, 
                  const std::string &username, 
                  const std::string &password)
{
    CURLcode ret = CURLE_OK;
    struct curl_slist *recipients = NULL;
    CURL *curl = curl_easy_init();

    Message textData(setPayloadText());

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_USERNAME,     from_.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD,     password.c_str());
        curl_easy_setopt(curl, CURLOPT_URL,          url     .c_str());
 
        curl_easy_setopt(curl, CURLOPT_USE_SSL,      (long)CURLUSESSL_ALL);
        //curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");
 
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM,    ("<" + from_ + ">").c_str());
        
        recipients = curl_slist_append(recipients,   ("<" + to_   + ">").c_str());
        
        if (!cc_.empty()){
            recipients = curl_slist_append(recipients,   ("<" + cc_   + ">").c_str());
        }    
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT,    recipients);
        
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payloadSource);
        curl_easy_setopt(curl, CURLOPT_READDATA,     &textData);
        curl_easy_setopt(curl, CURLOPT_UPLOAD,       1L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE,      1L);
 
        ret = curl_easy_perform(curl);
    }    

    return ret;
};    

