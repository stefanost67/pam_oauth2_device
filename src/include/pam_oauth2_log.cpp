//
// Created by jens on 18/08/2021.
//

#include "pam_oauth2_log.hpp"
#include "pam_oauth2_excpt.hpp"
#include <syslog.h>
#include <security/pam_ext.h>



pam_oauth2_log::pam_oauth2_log(pam_handle *ph, log_level_t lev) noexcept : ph_(ph), lev_(lev), log_(nullptr)
{
    if(lev == log_level_t::DEBUG)
        // TODO needs more thought
        log_ = stderr;
}


pam_oauth2_log::~pam_oauth2_log()
{
    if(log_) {
        fclose(log_);
        log_ = nullptr;
    }
}



//constexpr
bool
pam_oauth2_log::log_this(log_level_t severity) const noexcept
{
    // The disadvantage of closed class enums? This would be easier in later standards
    switch(lev_)
    {
        case log_level_t::DEBUG:
            if(severity == log_level_t::DEBUG)
                return true;
        case log_level_t::INFO:
            if(severity == log_level_t::INFO)
                return true;
        case log_level_t::WARN:
            if(severity == log_level_t::WARN)
                return true;
        case log_level_t::ERR:
            if(severity == log_level_t::ERR)
                return true;
    }
    return false;
}


//constexpr
int
pam_oauth2_log::syslog_pri(log_level_t level) const noexcept
{
    // Facility for pam modules
    int pri = LOG_AUTHPRIV;
    switch(level)
    {
        case log_level_t::DEBUG:
            pri |= LOG_DEBUG;
            break;
        case log_level_t::INFO:
            pri |= LOG_INFO;
            break;
        case log_level_t::WARN:
            pri |= LOG_WARNING;
            break;
        case log_level_t::ERR:
            pri |= LOG_ERR;
    }
    return pri;
}



void
pam_oauth2_log::log(BaseError const &e) noexcept
{
    if(lev_ == log_level_t::OFF)
        return;
    // Simple log
    pam_syslog(ph_, syslog_pri(e.severity_), e.what());
    if(log_)
    {
        // short message
	fprintf(log_, "[%4s] %s\n", e.type(), e.what());
        if(!e.details_.empty())
        {
            // todo? make this better formatted
            fprintf(log_, "%s\n", e.details_.c_str());
        }
    }
}


void
pam_oauth2_log::log(log_level_t level, const char *msg) noexcept
{
    if(lev_ == log_level_t::OFF)
        return;
    pam_syslog(ph_, syslog_pri(level), "%s", msg);
    if(log_)
        fprintf(log_, "%s\n", msg);
}


void
pam_oauth2_log::log(std::exception const &e) noexcept
{
    if(lev_ == log_level_t::OFF)
        return;
    pam_syslog(ph_, LOG_ERR, "system excpt %s", e.what());
    if(log_)
        fprintf(log_, "system exception %s\n", e.what());
}