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

#include <boost/filesystem/operations.hpp>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "temporary_directory.h"

static void touch(const boost::filesystem::path& path) {
    int fd = open(path.string().c_str(), O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK);
    ASSERT_LT(0, fd);
    close(fd);
}

// This creates a temporary directory, verifies it exists, and then verifies it
// has been deleted after the temporary_directory instance is no longer
// in-scope.
TEST(TemporaryDirectory, AutomaticDestruction) {
    boost::filesystem::path p;

    {
        temporary_directory t;
        p = t.path();

        EXPECT_TRUE(boost::filesystem::exists(p));
    }

    EXPECT_FALSE(boost::filesystem::exists(p));
}

// This test verifies that files in the directory are cleaned up after the
// instance is destroyed.
TEST(TemporaryDirectory, RecursiveCleanup) {
    boost::filesystem::path test_file;

    {
        temporary_directory t;
        test_file = t.path() / "foo";

        touch(test_file);

        EXPECT_TRUE(boost::filesystem::exists(test_file));
    }

    EXPECT_FALSE(boost::filesystem::exists(test_file));
}
