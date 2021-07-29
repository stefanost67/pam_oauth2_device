//
// Created by jens on 27/07/2021.
//

#ifndef __PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP
#define __PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP


#include <exception>


class BaseError : public std::exception
{
public:
    const char *what() const noexcept
    {
	fputs("Base error", stderr);
	return "Base Error";
    }
};

class PamError : public BaseError
{
public:
    const char *what() const noexcept
    {
	fputs("PAM error", stderr);
	return "PAM Error";
    }
};

class NetworkError : public BaseError
{
public:
    const char *what() const noexcept
    {
	fputs("Network error", stderr);
	return "Network Error";
    }
};

class TimeoutError : public NetworkError
{
public:
    const char *what() const noexcept
    {
	fputs("Timeout error", stderr);
	return "Timeout Error";
    }
};

class ResponseError : public NetworkError
{
public:
    const char *what() const noexcept
    {
	fputs("Response error", stderr);
	return "Response Error";
    }
};


#endif //__PAM_OAUTH2_DEVICE_PAM_OAUTH2_EXCPT_HPP
