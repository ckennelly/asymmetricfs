#ifndef __ASYMMETRICFS__MEMORY_LOCK_H__
#define __ASYMMETRICFS__MEMORY_LOCK_H__

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

#include <boost/any.hpp>
#include <string>
#include <vector>

enum class memory_lock {
    all,
    buffers,
    none
};

std::ostream& operator<<(std::ostream&, const memory_lock&);

void validate(boost::any& v, const std::vector<std::string>& values,
    memory_lock* target, int);

#endif // __ASYMMETRICFS__MEMORY_LOCK_H__
