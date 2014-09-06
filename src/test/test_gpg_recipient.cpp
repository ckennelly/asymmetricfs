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
#include "gpg_recipient.h"
#include <gtest/gtest.h>
#include <map>
#include <stdexcept>

class GPGRecipientTest : public ::testing::Test {
protected:
    std::map<int, std::string> get_file_descriptors() {
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
            char buf[1024];
            ssize_t size = readlinkat(root, result->d_name, buf, sizeof(buf));

            const std::string name(result->d_name);
            if (name == "." || name == "..") {
                continue;
            }

            const int fd = std::stoi(name);
            const std::string target(buf, size);

            ret.insert(std::make_pair(fd, target));
        }

        closedir(dir);
        if (errno != 0) {
            throw std::runtime_error("Error while reading directory.");
        }

        return ret;
    }
};

TEST_F(GPGRecipientTest, NoDescriptorsLeaked) {
    // Verify we do not leak descriptors when using gpg_recipient.
    auto starting = get_file_descriptors();

    // TODO:  While implausible, it's possible this is a valid key in someone's
    // public keyring (pgp.mit.edu says there are two, in fact), so we should
    // validate with an empty keyring.
    EXPECT_THROW({gpg_recipient g("0x00000000");}, invalid_gpg_recipient);

    auto ending = get_file_descriptors();

    // Verify open file descriptors are unchanged.
    EXPECT_EQ(starting, ending);
}
