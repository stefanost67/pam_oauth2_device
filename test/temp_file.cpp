//
// Created by jens.jen@stfc.ac.uk on 25/06/2021.
// Fairly Unix specific, but this was just designed to be a simple RAII file
//

#include "temp_file.hpp"

#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <exception>
//#include <algorithm>


// As it says on the label. Returns true if successful.
static bool write_data_to_file(FILE *fp, char const *data) noexcept;


TempFile::TempFile(const char *contents)
{
    constexpr char const *tempname = "/tmp/pam_oauth2_XXXXXX";
    static_assert(strlen(tempname) < max_name_);
    strncpy(fname_, tempname, max_name_);
    int fd = mkstemp(fname_);
    if(fd < 0)
        throw "Failed to create temp file";
    FILE *foo = fdopen(fd, "w");  // foo inherits the file descriptor
    if(!foo)
        throw "Failed to create file object (out of memory?)";
    if(!write_data_to_file(foo, contents)) {
	fclose(foo);
	unlink(fname_);
	throw "Unable to write data to file";
    }
    fclose(foo);
}


/*
TempFile::TempFile(std::string const &s)
{
}
*/


/*
TempFile::TempFile(char const *filename, std::string const &contents)
{
    if(strlen(filename) >= max_name_)
	throw "Filename too long";
    strncpy(fname_, filename, max_name_);
}
*/

TempFile::TempFile(const char *filename, const char *contents)
{
    if(strlen(filename) >= max_name_)
        throw "Filename too long";
    strncpy(fname_, filename, max_name_);
    FILE *f = fopen(filename, "w");
    if(!f)
        throw "failed to create file for writing";
    if(!write_data_to_file(f, contents)) {
	fclose(f);
	unlink(filename);
	throw "Failed to write data to file";
    }
    fclose(f);
}


TempFile::~TempFile()
{
    // RAII
    unlink(fname_);
}


std::string TempFile::filename() const
{
    std::string name{fname_};
    // Temporary names would be full path but not necessarily constructed files
    if(*name.cbegin() != '/') {
        char buf[FILENAME_MAX];
        char const *ret = getcwd(buf, FILENAME_MAX);
        if(!ret)
	    throw std::bad_alloc(); // can't happen?
        std::string cwd{buf};
        cwd += '/';
        return cwd+name;
    }
    return name;
}



std::string
TempFile::dirname() const
{
    char const *p = fname_, *q = strrchr(fname_, '/');
    if(q) {
        std::string path(fname_, q-p);
        return path;
    }
    char buf[FILENAME_MAX];
    if(!getcwd(buf, FILENAME_MAX))
        throw std::bad_alloc();
    std::string path(buf);
    return path;
}


bool
write_data_to_file(FILE *fp, char const *data) noexcept
{
    size_t len = strlen(data);
    return len == fwrite(data, 1, len, fp);
}
