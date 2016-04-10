#ifndef __ASYMMETRICFS__GPG_RECIPIENT_H__
#define __ASYMMETRICFS__GPG_RECIPIENT_H__

/**
 * asymmetricfs - An asymmetric encryption-aware filesystem
 * (c) 2013 Chris Kennelly <chris@ckennelly.com>
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

#include <boost/any.hpp>
#include <exception>
#include <string>
#include <vector>

class invalid_gpg_recipient : public std::exception {
public:
    explicit invalid_gpg_recipient(const std::string & r);

    const std::string & recipient() const;
    const char * what() const noexcept;
private:
    const std::string r_;
};

class gpg_recipient {
public:
    explicit gpg_recipient(const std::string & r);

    // Validates the recipient is on the public keyring.  Throws
    // invalid_gpg_recipient on error.
    void validate(const std::string& gpg_path) const;

    operator std::string() const;
private:
    std::string r_;
};

void validate(boost::any & v, const std::vector<std::string> & values,
    gpg_recipient * target, int);

#endif
