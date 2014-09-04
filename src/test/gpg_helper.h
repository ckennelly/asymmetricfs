#ifndef __ASYMMETRICFS__GPG_HELPER_H__
#define __ASYMMETRICFS__GPG_HELPER_H__

/**
 * asymmetricfs - An asymmetric encryption-aware filesystem
 * (c) 2014 Chris Kennelly <chris@ckennelly.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/filesystem/path.hpp>
#include <exception>
#include "gpg_recipient.h"
#include <string>
#include "temporary_directory.h"

// key_specification bundles the parameters used for generating a GPG key.
class key_specification {
public:
    unsigned key_size;

    // Key owner identification.
    std::string name;
    std::string email;
    std::string comment;
};

class gnupg_error {
public:
    virtual ~gnupg_error() = 0;
    virtual const std::string& what() const = 0;
};

class gnupg_generation_error : public gnupg_error {
public:
    gnupg_generation_error(const std::string& message);
    ~gnupg_generation_error();

    const std::string& what() const;
private:
    std::string what_;
};

// gnupg_key manages the lifetime of a generated GPG key.  When it is
// destroyed, the keys are cleaned up.
class gnupg_key {
public:
    // Generate a temporary key with the requested parameters.  It throws
    // gnupg_generation_error on error.
    gnupg_key(const key_specification&);

    boost::filesystem::path public_keyring() const;
    boost::filesystem::path secret_keyring() const;
    boost::filesystem::path home() const;

    // Returns the thumbprint of the generated key.  As gpg_recipient validates
    // its value, the GNUPGHOME environment variable should be set to the value
    // of home() for this instance.
    gpg_recipient thumbprint() const;

    // Returns the full fingerprint of the generated key.
    const std::string& fingerprint() const;

    // Moveable
    gnupg_key(gnupg_key&&);
    gnupg_key& operator=(gnupg_key&&);

    ~gnupg_key();
private:
    // Noncopyable
    gnupg_key(const gnupg_key&) = delete;
    gnupg_key& operator=(const gnupg_key&) = delete;

    key_specification spec_;
    temporary_directory key_directory_;
    std::string thumbprint_;
    std::string fingerprint_;

    boost::filesystem::path public_keyring_;
    boost::filesystem::path secret_keyring_;
};

#endif // __ASYMMETRICFS__GPG_HELPER_H__
