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

#include <algorithm>
#include <boost/filesystem/operations.hpp>
#include "temporary_directory.h"

temporary_directory::temporary_directory() :
        path_(boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path()) {
    boost::filesystem::create_directory(path_);
}

temporary_directory::temporary_directory(temporary_directory&& rhs) :
    path_(rhs.path_) {}

temporary_directory::~temporary_directory() {
    boost::filesystem::remove_all(path_);
}

temporary_directory& temporary_directory::operator=(temporary_directory&& rhs) {
    std::swap(path_, rhs.path_);
    return *this;
}

const boost::filesystem::path& temporary_directory::path() const {
    return path_;
}
