#ifndef __ASYMMETRICFS__TEMPORARY_DIRECTORY_H__
#define __ASYMMETRICFS__TEMPORARY_DIRECTORY_H__

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
#include <string>

/**
 * temporary_directory creates a temporary directory that will be deleted on
 * destruction.
 */
class temporary_directory {
public:
    temporary_directory();
    ~temporary_directory();

    const boost::filesystem::path& path() const;

    // Moveable
    temporary_directory(temporary_directory&&);
    temporary_directory& operator=(temporary_directory&&);
private:
    // Noncopyable
    temporary_directory(const temporary_directory&) = delete;
    temporary_directory& operator=(const temporary_directory&) = delete;

    boost::filesystem::path path_;
};

#endif // __ASYMMETRICFS__TEMPORARY_DIRECTORY_H__
