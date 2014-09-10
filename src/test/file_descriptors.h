#ifndef __ASYMMETRICFS__FILE_DESCRIPTORS_H__
#define __ASYMMETRICFS__FILE_DESCRIPTORS_H__

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

#include <map>
#include <string>

// get_file_descriptors enumerates the open file descriptors of the current
// process.  return_self indicates whether to return the file descriptor used
// to read the list of current file descriptors.
std::map<int, std::string> get_file_descriptors(bool return_self = false);

#endif // __ASYMMETRICFS__FILE_DESCRIPTORS_H__
