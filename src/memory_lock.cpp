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

#include <cstddef>
#include <boost/program_options.hpp>
#include <ostream>
#include "memory_lock.h"
#include <string>
#include <vector>

std::ostream& operator<<(std::ostream& o, const memory_lock& m) {
    switch (m) {
        case memory_lock::all:
            return o << "all";
        case memory_lock::buffers:
            return o << "buffers";
        case memory_lock::none:
            return o << "none";
    }

    return o;
}

void validate(boost::any& v, const std::vector<std::string>& values,
        memory_lock* target, int) {
    (void) target;

    boost::program_options::validators::check_first_occurrence(v);
    const std::string& m =
        boost::program_options::validators::get_single_string(values);

    if (m == "all") {
        v = boost::any(memory_lock::all);
    } else if (m == "buffers") {
        v = boost::any(memory_lock::buffers);
    } else if (m == "none") {
        v = boost::any(memory_lock::none);
    } else {
        using boost::program_options::validation_error;

        throw validation_error(validation_error::invalid_option_value);
    }
}
