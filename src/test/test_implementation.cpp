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
#include <gtest/gtest.h>
#include "gpg_helper.h"
#include "implementation.h"
#include <map>
#include "test/temporary_directory.h"

enum class IOMode {
    ReadWrite,
    WriteOnly
};

std::ostream& operator<<(std::ostream& o, const IOMode& m) {
    switch (m) {
        case IOMode::ReadWrite:
            return o << "read-write";
        case IOMode::WriteOnly:
            return o << "write-only";
    }

    return o;
}

class IOTest : public ::testing::TestWithParam<IOMode> {
protected:
    IOTest() : key(key_specification{1024, "Testing", "test@example.com", ""}) {
        fs.set_target(backing.path().string() + "/");

        switch (GetParam()) {
            case IOMode::ReadWrite:
                fs.set_read(true);
                break;
            case IOMode::WriteOnly:
                fs.set_read(false);
                break;
        }

        setenv("GNUPGHOME", key.home().string().c_str(), 1);
        fs.set_recipients({key.thumbprint()});

        fs.init(nullptr);
        EXPECT_TRUE(fs.ready());
    }

    ~IOTest() {
        unsetenv("GNUPGHOME");
    }

    temporary_directory backing;
    gnupg_key key;
    asymmetricfs fs;
};

TEST_P(IOTest, ReadInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;
    char buf[16];
    EXPECT_EQ(-EBADF, fs.read(nullptr, buf, sizeof(buf), 0, &info));
}

TEST_P(IOTest, ReadWrite) {
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
        if (GetParam() == IOMode::ReadWrite) {
            ASSERT_EQ(contents.size(), ret);
            buffer.resize(ret);
            EXPECT_EQ(contents, buffer);
        } else {
            EXPECT_EQ(-EACCES, ret);
        }

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_P(IOTest, WriteInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;

    char buf[16];
    EXPECT_EQ(-EBADF, fs.write(nullptr, buf, sizeof(buf), 0, &info));
}

TEST_P(IOTest, WriteZeroBytes) {
    int ret;

    const std::string filename("/test");
    struct fuse_file_info info;
    info.flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info);

    char buf[16];
    ret = fs.write(nullptr, buf, 0, 0, &info);
    EXPECT_EQ(0, ret);

    ret = fs.release(nullptr, &info);
    EXPECT_EQ(0, ret);
}

TEST_P(IOTest, WriteInvalidOffset) {
    int ret;

    const std::string filename("/test");

    struct fuse_file_info info;
    info.flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info);

    char buf[16];
    ret = fs.write(nullptr, buf, sizeof(buf), -1, &info);
    EXPECT_EQ(-EINVAL, ret);

    ret = fs.release(nullptr, &info);
    EXPECT_EQ(0, ret);
}

TEST_P(IOTest, Append) {
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
        if (GetParam() == IOMode::ReadWrite) {
            ASSERT_EQ(contents1.size() + contents2.size(), ret);
            buffer.resize(ret);
            EXPECT_EQ(contents1 + contents2, buffer);
        } else {
            EXPECT_EQ(-EACCES, ret);
        }

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_P(IOTest, TwoHandles) {
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

TEST_P(IOTest, TruncateInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;
    int ret = fs.ftruncate(nullptr, 0, &info);
    EXPECT_EQ(-EBADF, ret);
}

TEST_P(IOTest, TruncateInvalidOffset) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    struct fuse_file_info info;
    info.flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info);
    EXPECT_EQ(0, ret);
    ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
    EXPECT_EQ(contents.size(), ret);

    // Truncate at an invalid offset.
    ret = fs.ftruncate(nullptr, -1, &info);
    EXPECT_EQ(-EINVAL, ret);

    // Release
    ret = fs.release(nullptr, &info);
    EXPECT_EQ(0, ret);
}

TEST_P(IOTest, TruncateZeroFromCreation) {
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

        // Stat file
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(contents.size(), buf.st_size);

        // Truncate
        ret = fs.ftruncate(nullptr, 0, &info);
        EXPECT_EQ(0, ret);

        // Re-stat.
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(0, buf.st_size);

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Re-stat.
    {
        struct stat buf;
        ret = fs.getattr(filename.c_str(), &buf);
        EXPECT_EQ(0, ret);
        EXPECT_LE(0, buf.st_size); // getattr returns the size on-disk, rather
                                   // than decrypted.  TODO:  Do not write
                                   // empty files.
    }

    // Re-open if in ReadWrite mode.
    if (GetParam() == IOMode::ReadWrite) {
        struct fuse_file_info info;
        info.flags = O_RDONLY;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        // Re-stat.
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(0, buf.st_size);

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_P(IOTest, TruncateZeroFromExisting) {
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

        // Stat file
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(contents.size(), buf.st_size);

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Re-open, truncate.
    {
        struct fuse_file_info info;
        info.flags = O_WRONLY;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        // Truncate
        ret = fs.ftruncate(nullptr, 0, &info);
        EXPECT_EQ(0, ret);

        // Re-stat.
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(0, buf.st_size);

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_P(IOTest, TruncatePartial) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");
    off_t offset = 3;

    // Open a test file in the filesystem, write to it.
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_RDWR;
        ret = fs.create(filename.c_str(), 0600, &info);
        EXPECT_EQ(0, ret);
        ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
        EXPECT_EQ(contents.size(), ret);

        // Stat file
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(contents.size(), buf.st_size);

        // Truncate
        ret = fs.ftruncate(nullptr, offset, &info);
        if (GetParam() == IOMode::ReadWrite) {
            EXPECT_EQ(0, ret);

            // Re-stat.
            ret = fs.fgetattr(nullptr, &buf, &info);
            EXPECT_EQ(0, ret);
            EXPECT_EQ(offset, buf.st_size);
        } else {
            // TODO:  Permit truncations of newly created files.
            EXPECT_EQ(-EACCES, ret);
        }

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Re-open.
    if (GetParam() == IOMode::ReadWrite) {
        struct fuse_file_info info;
        info.flags = O_RDONLY;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        // Re-stat.
        struct stat buf;
        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(offset, buf.st_size);

        // Read contents.
        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        ASSERT_EQ(offset, ret);
        buffer.resize(ret);
        EXPECT_EQ(contents.substr(0, offset), buffer);

        // Release
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }
}

TEST_P(IOTest, TruncatePathZeroInvalidFile) {
    const std::string filename("/test");
    int ret = fs.truncate(filename.c_str(), 0);
    EXPECT_EQ(-ENOENT, ret);
}

TEST_P(IOTest, TruncatePathPartialInvalidFile) {
    const std::string filename("/test");
    int ret = fs.truncate(filename.c_str(), 3);
    if (GetParam() == IOMode::ReadWrite) {
        EXPECT_EQ(-ENOENT, ret);
    } else {
        EXPECT_EQ(-EACCES, ret);
    }
}

TEST_P(IOTest, TruncatePathInvalidOffset) {
    const std::string filename("/test");
    int ret = fs.truncate(filename.c_str(), -1);
    EXPECT_EQ(-EINVAL, ret);
}

TEST_P(IOTest, TruncatePath) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Touch a file and write to it.
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_RDWR;
        ret = fs.create(filename.c_str(), 0600, &info);
        EXPECT_EQ(0, ret);
        ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
        EXPECT_EQ(contents.size(), ret);
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Stat file
    struct stat buf;
    ret = fs.getattr(filename.c_str(), &buf);
    EXPECT_EQ(0, ret);
    EXPECT_LT(0, buf.st_size);

    // Truncate by path.
    ret = fs.truncate(filename.c_str(), 0);
    EXPECT_EQ(0, ret);

    // Stat file.
    ret = fs.getattr(filename.c_str(), &buf);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, buf.st_size);
}

TEST_P(IOTest, TruncatePathPartial) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");
    const off_t offset = 3;

    // Touch a file and write to it.
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_RDWR;
        ret = fs.create(filename.c_str(), 0600, &info);
        EXPECT_EQ(0, ret);
        ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
        EXPECT_EQ(contents.size(), ret);
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Stat file
    struct stat buf;
    ret = fs.getattr(filename.c_str(), &buf);
    EXPECT_EQ(0, ret);
    EXPECT_LT(0, buf.st_size);

    // Truncate by path.
    ret = fs.truncate(filename.c_str(), offset);
    if (GetParam() == IOMode::ReadWrite) {
        EXPECT_EQ(0, ret);

        // Verify file contents.
        struct fuse_file_info info;
        info.flags = O_RDONLY;
        ret = fs.open(filename.c_str(), &info);
        EXPECT_EQ(0, ret);

        ret = fs.fgetattr(nullptr, &buf, &info);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(offset, buf.st_size);

        std::string buffer(1 << 16, '\0');
        ret = fs.read(nullptr, &buffer[0], buffer.size(), 0, &info);
        EXPECT_EQ(offset, ret);
        buffer.resize(offset);
        EXPECT_EQ(contents.substr(0, offset), buffer);

        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    } else {
        EXPECT_EQ(-EACCES, ret);
    }
}


TEST_P(IOTest, TruncatePathOpenFile) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    struct fuse_file_info info;
    info.flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info);
    EXPECT_EQ(0, ret);
    ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
    EXPECT_EQ(contents.size(), ret);

    // Stat file
    struct stat buf;
    ret = fs.fgetattr(nullptr, &buf, &info);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(contents.size(), buf.st_size);

    // Truncate by path.
    ret = fs.truncate(filename.c_str(), 0);
    EXPECT_EQ(0, ret);

    // Stat file.
    ret = fs.fgetattr(nullptr, &buf, &info);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, buf.st_size);

    // Release
    ret = fs.release(nullptr, &info);
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

TEST_P(IOTest, ListEmptyDirectory) {
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

TEST_P(IOTest, Chmod) {
    const std::string filename("/test");

    const mode_t initial = 0600;
    const mode_t final = 0400;

    const mode_t mask = GetParam() == IOMode::ReadWrite ? 07777 : 07333;

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
        EXPECT_EQ(initial & mask, buf.st_mode & 07777);
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
        EXPECT_EQ(final & mask, buf.st_mode & 07777);
    }
}

TEST_P(IOTest, Chown) {
    const std::string filename("/test");

    // Touch
    int ret;
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_WRONLY;
        ret = fs.create(filename.c_str(), 0777, &info);
        EXPECT_EQ(0, ret);
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Stat
    struct stat buf;
    {
        ret = fs.getattr(filename.c_str(), &buf);
        EXPECT_EQ(0, ret);
    }

    // Chown (to the same values).
    {
        ret = fs.chown(filename.c_str(), buf.st_uid, buf.st_gid);
        EXPECT_EQ(0, ret);
    }

    // Verify unchanged permissions.
    {
        struct stat buf2;
        ret = fs.getattr(filename.c_str(), &buf2);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(buf.st_uid, buf2.st_uid);
        EXPECT_EQ(buf.st_gid, buf2.st_gid);
    }
}

TEST_P(IOTest, ChownToRoot) {
    const std::string filename("/test");

    // Touch
    int ret;
    {
        struct fuse_file_info info;
        info.flags = O_CREAT | O_WRONLY;
        ret = fs.create(filename.c_str(), 0777, &info);
        EXPECT_EQ(0, ret);
        ret = fs.release(nullptr, &info);
        EXPECT_EQ(0, ret);
    }

    // Stat
    struct stat buf;
    {
        ret = fs.getattr(filename.c_str(), &buf);
        EXPECT_EQ(0, ret);
    }

    // Chown (to root).
    {
        ret = fs.chown(filename.c_str(), 0, 0);
        EXPECT_EQ(-EPERM, ret);
    }
}

TEST_P(IOTest, StatWhileOpen) {
    // We create a file and stat it by path (rather than descriptor) while
    // keeping the descriptor open.
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    struct fuse_file_info info;
    info.flags = O_CREAT | O_RDWR;
    ret = fs.create(filename.c_str(), 0600, &info);
    EXPECT_EQ(0, ret);
    ret = fs.write(nullptr, contents.data(), contents.size(), 0, &info);
    EXPECT_EQ(contents.size(), ret);

    // Stat
    struct stat buf;
    ret = fs.getattr(filename.c_str(), &buf);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(contents.size(), buf.st_size);

    // Release
    ret = fs.release(nullptr, &info);
    EXPECT_EQ(0, ret);
}

INSTANTIATE_TEST_CASE_P(IOTests, IOTest,
                        ::testing::Values(IOMode::ReadWrite,
                                          IOMode::WriteOnly));

class ImplementationTest : public ::testing::Test {
protected:
    asymmetricfs fs;
};

TEST_F(ImplementationTest, EmptyTarget) {
    EXPECT_FALSE(fs.set_target(""));
}

TEST_F(ImplementationTest, LinkNotSupported) {
    EXPECT_EQ(-EPERM, fs.link(nullptr, nullptr));
}

TEST_F(ImplementationTest, StatFS) {
    temporary_directory target;
    fs.set_target(target.path().string());

    struct fuse_conn_info conn;
    fs.init(&conn);

    struct statvfs buf;
    int ret = fs.statfs(nullptr, &buf);
    EXPECT_EQ(0, ret);
    EXPECT_LE(0, buf.f_blocks);
    EXPECT_LE(0, buf.f_bfree);
}
