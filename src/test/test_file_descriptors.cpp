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

#include <iostream>
#include "test/file_descriptors.h"
#include <gtest/gtest.h>

TEST(FileDescriptorsTest, ReturnSelf) {
    auto self = get_file_descriptors(true);
    auto exclude_self = get_file_descriptors(false);

    EXPECT_NE(exclude_self, self);

    // We expect STDIN, STDOUT, STDERR to be open.
    EXPECT_LE(3u, exclude_self.size());
    EXPECT_LE(4u, self.size());
    EXPECT_EQ(exclude_self.size() + 1, self.size());

    // An unexpected file descriptor appeared when this test was first
    // introduced (https://travis-ci.org/ckennelly/asymmetricfs/jobs/34884772),
    // so we enumerate the open file descriptors for test debugging purposes.
    std::cout << "Exclude Self:" << std::endl;
    for (const auto& kv : exclude_self) {
        std::cout << kv.first << " -> " << kv.second << std::endl;
    }

    std::cout << "Self:" << std::endl;
    for (const auto& kv : exclude_self) {
        std::cout << kv.first << " -> " << kv.second << std::endl;
    }
}
