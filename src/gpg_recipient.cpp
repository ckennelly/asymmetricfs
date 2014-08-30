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
#include "subprocess.h"

invalid_gpg_recipient::invalid_gpg_recipient(const std::string & r) : r_(r) { }

invalid_gpg_recipient::~invalid_gpg_recipient() throw() { }

const std::string & invalid_gpg_recipient::recipient() const {
    return r_;
}

const char * invalid_gpg_recipient::what() const throw() {
    return "Invalid gpg recipient.";
}

gpg_recipient::gpg_recipient(const std::string & r) {
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
        subprocess s(in, out, "gpg", {"gpg", "--list-keys", r});
        ret = s.wait();
    }

    if (ret == 0) {
        /* Valid address. */
        r_ = r;
    } else {
        throw invalid_gpg_recipient(r);
    }
}

gpg_recipient::operator std::string() const {
    return r_;
}

void validate(boost::any & v, const std::vector<std::string> & values,
        gpg_recipient * target, int) {
    (void) target;

    using namespace boost::program_options;

    validators::check_first_occurrence(v);
    const std::string & r = validators::get_single_string(values);

    try {
        v = boost::any(gpg_recipient(r));
    } catch (invalid_gpg_recipient & ex) {
        throw validation_error(validation_error::invalid_option_value);
    }
}
