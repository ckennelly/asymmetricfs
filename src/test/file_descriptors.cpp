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

#include <dirent.h>
#include <errno.h>
#include <stdexcept>
#include "test/file_descriptors.h"
#include <unistd.h>

std::map<int, std::string> get_file_descriptors(bool return_self) {
    const char* path = "/proc/self/fd";

    DIR* dir = opendir(path);
    if (dir == nullptr) {
        throw std::runtime_error("Unable to open directory.");
    }

    int root = dirfd(dir);

    std::map<int, std::string> ret;
    struct dirent *result;
    errno = 0;
    while ((result = readdir(dir)) != nullptr) {
        const std::string name(result->d_name);
        if (name == "." || name == "..") {
            continue;
        }

        const int fd = std::stoi(name);
        if (!(return_self) && root == fd) {
            continue;
        }

        std::string target;
        char buf[1024];
        ssize_t size = readlinkat(root, result->d_name, buf, sizeof(buf));
        if (size >= 0) {
            target.assign(buf, size_t(size));
        }

        ret.insert(std::make_pair(fd, target));
    }

    closedir(dir);
    if (errno != 0) {
        throw std::runtime_error("Error while reading directory.");
    }

    return ret;
}
