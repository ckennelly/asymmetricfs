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

#include <gtest/gtest.h>
#include "subprocess.h"

TEST(Subprocess, ExitCodeSuccess) {
    subprocess s(-1, -1, "/bin/true", NULL);

    int ret = s.wait();
    EXPECT_EQ(0, ret);
}

TEST(Subprocess, ExitCodeFailure) {
    subprocess s(-1, -1, "/bin/false", NULL);

    int ret = s.wait();
    EXPECT_EQ(1, ret);
}

TEST(Subprocess, Communicate) {
    char dash[] = "-";
    char* argv[] = {dash, nullptr};

    subprocess s(-1, -1, "/bin/cat", argv);

    const char write_buffer[] = "foo";
    size_t write_size = sizeof(write_buffer);

    char read_buffer[256];
    size_t read_size = sizeof(read_buffer);

    int ret = s.communicate(read_buffer, &read_size, write_buffer, &write_size);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, write_size);
    EXPECT_EQ(sizeof(read_buffer) - sizeof(write_buffer), read_size);
    EXPECT_EQ(0, memcmp(write_buffer, read_buffer, sizeof(write_buffer)));

    ret = s.wait();
    EXPECT_EQ(0, ret);
}
