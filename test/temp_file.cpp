//
// Created by jens on 25/06/2021.
//

#include "temp_file.hpp"

#include <cstdlib>
#include <cstring>
#include <unistd.h>


// As it says on the label. Returns true if successful.
static bool write_data_to_file(FILE *fp, char const *data) noexcept;


TempFile::TempFile(const char *contents)
{
    constexpr char const *tempname = "/tmp/pam_ouath2_XXXXXX";
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



bool
write_data_to_file(FILE *fp, char const *data) noexcept
{
    size_t len = strlen(data);
    return len == fwrite(data, 1, len, fp);
}
