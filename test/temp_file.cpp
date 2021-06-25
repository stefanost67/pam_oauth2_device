//
// Created by jens on 25/06/2021.
//

#include "temp_file.hpp"

#include <cstdlib>
#include <cstring>
#include <unistd.h>


TempFile::TempFile(const char *contents)
{
    constexpr char const *tempname = "/tmp/pam_ouath2_XXXXXX";
    static_assert(strlen(tempname) < max_name_);
    strncpy(fname_, tempname, max_name_);
    int fd = mkstemp(fname_);
    if(fd < 0)
        throw "Failed to create temp file";
    FILE *foo = fdopen(fd, "w");
    if(!foo)
        throw "Failed to create file object (out of memory?)";
    size_t len = strlen(contents);
    if( len == fwrite(contents, 1, len, foo)) {
        fclose(foo);
    } else {
        unlink(fname_);
        throw "Failed to write contents to file";
    }
}


TempFile::TempFile(std::string const &s)
{
    // cheating version
    TempFile(s.c_str());
}


TempFile::~TempFile()
{
    // RAII
    unlink(fname_);
}
