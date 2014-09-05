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
#include "gpg_helper.h"
#include "implementation.h"
#include "test/temporary_directory.h"

class ImplementationTest : public ::testing::Test {
protected:
    ImplementationTest(bool read) :
            key(key_specification{1024, "Testing", "test@example.com", ""}) {
        fs.set_target(backing.path().string() + "/");
        fs.set_read(read);

        setenv("GNUPGHOME", key.home().string().c_str(), 1);
        fs.set_recipients({key.thumbprint()});

        fs.init(nullptr);
        EXPECT_TRUE(fs.ready());
    }

    ~ImplementationTest() {
        unsetenv("GNUPGHOME");
    }

    temporary_directory backing;
    gnupg_key key;
    asymmetricfs fs;
};

class ReadWriteModeTest : public ImplementationTest {
protected:
    ReadWriteModeTest() : ImplementationTest(true) {}
};

class WriteOnlyModeTest : public ImplementationTest {
protected:
    WriteOnlyModeTest() : ImplementationTest(false) {}
};

TEST_F(ReadWriteModeTest, ReadWrite) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");
    // Open a test file in the filesystem, write to it.
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_RDWR;
        ret = fs.create(filename.c_str(), 0600, &info);
        EXPECT_EQ(0, ret);
        ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
        EXPECT_EQ(contents.size(), ret);

        // Verify the contents are there before closing.
        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        ASSERT_EQ(contents.size(), ret);
        buffer.resize(ret);
        EXPECT_EQ(contents, buffer);

        // Close the file.
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Reopen and verify contents.
    {
        struct fuse_file_info info;
        info.flags = 0;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        ASSERT_EQ(contents.size(), ret);
        buffer.resize(ret);
        EXPECT_EQ(contents, buffer);

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_F(ReadWriteModeTest, Append) {
    int ret;

    const std::string filename("/test");
    const std::string contents1("abcdefg");
    const std::string contents2("hijklmn");
    // Open a test file in the filesystem, write to it.
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_RDWR;
        ret = fs.create(filename.c_str(), 0600, &info);
        EXPECT_EQ(0, ret);
        ret = fs.write(nullptr, contents1.data(), contents1.size(), 0, &info);
        EXPECT_EQ(contents1.size(), ret);

        // Verify the contents are there before closing.
        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        ASSERT_EQ(contents1.size(), ret);
        buffer.resize(ret);
        EXPECT_EQ(contents1, buffer);

        // Close the file.
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Append to test file.
    {
        struct fuse_file_info info;
        info.flags = O_APPEND | O_WRONLY;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        ret = fs.write(nullptr, contents2.data(), contents2.size(), 0, &info);
        EXPECT_EQ(contents2.size(), ret);

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Reopen and verify contents.
    {
        struct fuse_file_info info;
        info.flags = 0;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        ASSERT_EQ(contents1.size() + contents2.size(), ret);
        buffer.resize(ret);
        EXPECT_EQ(contents1 + contents2, buffer);

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_F(ReadWriteModeTest, TwoHandles) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    struct fuse_file_info info[2];
    info[0].flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info[0]);
    EXPECT_EQ(0, ret);
    ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info[0]);
    EXPECT_EQ(contents.size(), ret);

    // Open the file a second time.
    info[1].flags = O_RDONLY;
    ret = fs.open(filename.c_str(), &info[1]);
    EXPECT_EQ(0, ret);

    // Verify the content from second handle.
    std::string buffer(1 << 16, '\0');
    ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info[1]);
    ASSERT_EQ(contents.size(), ret);
    buffer.resize(ret);
    EXPECT_EQ(contents, buffer);

    // Close the files.
    ret = fs.release(nullptr, &info[0]);
    EXPECT_EQ(0, ret);

    ret = fs.release(nullptr, &info[1]);
    EXPECT_EQ(0, ret);
}

typedef std::map<std::string, struct stat> stat_map;

static int filler(
        void *buf_, const char *name_, const struct stat *stbuf, off_t off) {
    auto buf = static_cast<stat_map*>(buf_);
    const std::string name(name_);
    (void) off;

    bool r = buf->insert(std::make_pair(name, *stbuf)).second;
    EXPECT_TRUE(r);
    return 0;
}

TEST_F(WriteOnlyModeTest, ListEmptyDirectory) {
    int ret;
    // Open directory.
    struct fuse_file_info info;
    ret = fs.opendir("/", &info);
    EXPECT_EQ(0, ret);

    // Read directory
    {
        stat_map buffer;
        ret = fs.readdir(nullptr, &buffer, filler, 0, &info);
        EXPECT_EQ(0, ret);
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }

    // Touch a file.
    const std::string filename("foo");
    {
        struct fuse_file_info finfo;
        finfo.flags = O_WRONLY;
        ret = fs.create(("/" + filename).c_str(), 0600, &finfo);
        EXPECT_EQ(0, ret);

        ret = fs.release(nullptr, &finfo);
        EXPECT_EQ(0, ret);
    }

    // Reread directory
    {
        stat_map buffer;
        ret = fs.readdir(nullptr, &buffer, filler, 0, &info);
        EXPECT_EQ(0, ret);
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[filename].st_mode));
    }

    ret = fs.releasedir(nullptr, &info);
    EXPECT_EQ(0, ret);
}

class PermissionsTest : public ImplementationTest {
protected:
    PermissionsTest() : ImplementationTest(true) {}
};

TEST_F(PermissionsTest, Chmod) {
    const std::string filename("/test");

    const mode_t initial = 0600;
    const mode_t final = 0400;

    // Touch
    int ret;
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_WRONLY;
        ret = fs.create(filename.c_str(), initial, &info);
        EXPECT_EQ(0, ret);
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Stat
    {
        struct stat buf;
        ret = fs.getattr(filename.c_str(), &buf);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(initial, buf.st_mode & 07777);
    }

    // Chmod
    {
        ret = fs.chmod(filename.c_str(), final);
        EXPECT_EQ(0, ret);
    }

    // Stat
    {
        struct stat buf;
        ret = fs.getattr(filename.c_str(), &buf);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(final, buf.st_mode & 07777);
    }
}