//
// Created by jens on 27/07/2021.
//
// Exceptions and logging - definitions

#ifndef __PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP
#define __PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP


#include <exception>
#include "pam_oauth2_log.hpp"


class BaseError : public std::exception
{
    // TODO temporary solution?
    std::string msg_;
    // Severity level to log this exception at
    pam_oauth2_log::log_level_t severity_;
    // The logger is our friend
    friend class pam_oauth2_log;
public:
    BaseError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : msg_(msg), severity_(severity) { }

    char const *what() const noexcept override { return msg_.c_str(); }

    // Disable copy
    BaseError(BaseError const &) = delete;
    BaseError &operator=(BaseError const &) = delete;
    // Allow moves
    BaseError(BaseError &&) = default;
    BaseError &operator=(BaseError &&) = default;

    //! Return a four character string with the name (or near enough) of the class
    virtual char const *type() const noexcept { return "BASE"; }
};


struct ConfigError : public BaseError
{
    ConfigError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : BaseError(msg, severity) { }
    char const *type() const noexcept override { return "CONF"; }
};


struct PamError : public BaseError
{
    PamError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : BaseError(msg, severity) { }
    char const *type() const noexcept override { return "PAM "; }
};

struct NetworkError : public BaseError
{
    NetworkError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : BaseError(msg, severity) { }
    char const *type() const noexcept override { return "NETW"; }
};

struct TimeoutError : public NetworkError
{
    TimeoutError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : NetworkError(msg, severity) { }
    char const *type() const noexcept override { return "TIME"; }
};

struct ResponseError : public NetworkError
{
    ResponseError(char const *msg, pam_oauth2_log::log_level_t severity = pam_oauth2_log::log_level_t::ERR) : NetworkError(msg, severity) { }
    char const *type() const noexcept override { return "RESP"; }
};


#endif //__PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP
