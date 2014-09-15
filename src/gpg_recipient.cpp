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

#include <boost/program_options.hpp>
#include <fcntl.h>
#include "gpg_recipient.h"
#include <string>
#include "subprocess.h"
#include <vector>

invalid_gpg_recipient::invalid_gpg_recipient(const std::string & r) : r_(r) { }

invalid_gpg_recipient::~invalid_gpg_recipient() throw() { }

const std::string & invalid_gpg_recipient::recipient() const {
    return r_;
}

const char * invalid_gpg_recipient::what() const throw() {
    return "Invalid gpg recipient.";
}

gpg_recipient::gpg_recipient(const std::string& r) : r_(r) {}

void gpg_recipient::validate(const std::string& gpg_path) const {
    /* Start gpg. */
    int in  = ::open("/dev/null", O_RDONLY);
    if (in < 0) {
        throw std::runtime_error("Unable to open /dev/null.");
    }

    int out = ::open("/dev/null", O_WRONLY);
    if (out < 0) {
        ::close(in);
        throw std::runtime_error("Unable to open /dev/null.");
    }

    int ret;
    {
        subprocess s(in, out, gpg_path, {"gpg", "--list-keys", r_});
        ret = s.wait();
    }

    ::close(in);
    ::close(out);

    if (ret != 0) {
        /* Invalid address. */
        throw invalid_gpg_recipient(r_);
    }
}

gpg_recipient::operator std::string() const {
    return r_;
}

void validate(boost::any & v, const std::vector<std::string> & values,
        gpg_recipient * target, int) {
    (void) target;

    boost::program_options::validators::check_first_occurrence(v);
    const std::string& r =
        boost::program_options::validators::get_single_string(values);

    try {
        v = boost::any(gpg_recipient(r));
    } catch (invalid_gpg_recipient&) {
        using boost::program_options::validation_error;

        throw validation_error(validation_error::invalid_option_value);
    }
}
