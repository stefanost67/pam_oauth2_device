//
// Created by jens on 25/06/2021.
//
// This class uses RAII to create a temporary file with a specific content.
// This is used to create files for testing which are cleared after the test has finished.


#ifndef __PAM_OAUTH2_DEVICE_TEMP_FILE_HPP
#define __PAM_OAUTH2_DEVICE_TEMP_FILE_HPP

#include <string>

/** \brief Create a temporary file with specified content using RAII */

class TempFile {
private:
    constexpr static const size_t max_name_ = 24;
    char fname_[max_name_];
public:
    TempFile(std::string const &contents);
    TempFile(char const *contents);
    TempFile(TempFile const &) = delete;
    TempFile(TempFile &&) = delete;
    TempFile operator=(TempFile const &) = delete;
    TempFile &operator=(TempFile &&) = delete;
    ~TempFile();

    /** Return the name of the file */
    char const *filename() noexcept { return fname_; }
};


#endif //__PAM_OAUTH2_DEVICE_TEMP_FILE_HPP
