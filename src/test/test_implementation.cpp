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
#include "implementation.h"
#include <iostream>
#include <map>
#include <string>
#include "test/file_descriptors.h"
#include "test/gpg_helper.h"
#include "test/temporary_directory.h"
#include <time.h>

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

// Global parameters.
std::string wrapper_path;

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

    int access(const std::string& path, int mode) {
        return fs.access(path.c_str(), mode);
    }

    int getattr(const std::string& path, struct stat* buf) {
        return fs.getattr(path.c_str(), buf);
    }

    size_t file_size(const std::string& path) {
        struct stat buf;
        EXPECT_EQ(0, getattr(path, &buf));
        return size_t(buf.st_size);
    }

    int truncate(const std::string& path, off_t offset) {
        return fs.truncate(path.c_str(), offset);
    }

    typedef std::map<std::string, struct stat> stat_map;
    int readdir(const std::string& path, stat_map* buffer) {
        // Open directory.
        int ret;
        struct fuse_file_info info;
        ret = fs.opendir(path.c_str(), &info);
        EXPECT_EQ(0, ret);

        int response = fs.readdir(nullptr, buffer, IOTest::filler, 0, &info);

        ret = fs.releasedir(nullptr, &info);
        EXPECT_EQ(0, ret);
        return response;
    }

    temporary_directory backing;
    gnupg_key key;
    asymmetricfs fs;
private:
    static int filler(
            void *buf_, const char *name_, const struct stat *stbuf,
            off_t off) {
        auto buf = static_cast<stat_map*>(buf_);
        const std::string name(name_);
        (void) off;

        bool r = buf->insert(std::make_pair(name, *stbuf)).second;
        EXPECT_TRUE(r);
        return 0;
    }
};

class scoped_file {
public:
    // Opens the file at path in the filesystem, using the flags specified at
    // info->flags.  If O_CREAT is set, create() is called in the underlying
    // filesystem using mode 0600.
    scoped_file(asymmetricfs& fs, const std::string& filename, int flags) :
            fs_(fs) {
        int ret;

        info.flags = flags;
        if (flags & O_CREAT) {
            ret = fs_.create(filename.c_str(), 0600, &info);
        } else {
            ret = fs_.open(filename.c_str(), &info);
        }
        EXPECT_EQ(0, ret);
    }

    std::string read(off_t offset = 0, size_t max_size = 1 << 16) {
        std::string buffer;
        EXPECT_LE(0, read(&buffer, offset, max_size));
        return buffer;
    }

    int read(std::string* buffer, off_t offset = 0, size_t max_size = 1 << 16) {
        buffer->resize(max_size, '\0');
        int ret = fs_.read(nullptr, &(*buffer)[0], max_size, offset, &info);
        if (ret >= 0) {
            EXPECT_GE(max_size, ret);
            if (size_t(ret) <= max_size) {
                buffer->resize(ret);
            }
        }
        return ret;
    }

    void stat(struct stat* buf) {
        ASSERT_EQ(0, fs_.fgetattr(nullptr, buf, &info));
    }

    size_t file_size() {
        struct stat buf;
        stat(&buf);
        return size_t(buf.st_size);
    }

    int truncate(off_t offset) {
        return fs_.ftruncate(nullptr, offset, &info);
    }

    void write(const std::string& data) {
        ASSERT_EQ(data.size(),
                  fs_.write(nullptr, data.data(), data.size(), 0, &info));
    }

    ~scoped_file() {
        (void) fs_.release(nullptr, &info);
    }

    fuse_file_info info;
private:
    asymmetricfs& fs_;

    scoped_file(const scoped_file&) = delete;
    scoped_file& operator=(const scoped_file&) = delete;
};

TEST_P(IOTest, Access) {
    // We touch file_closed and immediately close it.  We touch file_open and
    // keep it open throughout the test.
    const std::string file_closed("/foo");
    const std::string file_open("/bar");

    {
        scoped_file c(fs, file_closed, O_CREAT | O_RDWR);
    }

    scoped_file o(fs, file_open, O_CREAT | O_RDWR);
    for (int i = 0; i < 4; i++) {
        SCOPED_TRACE(i);

        // Create mode.
        int mode = 0;
        if (i & 1) {
            mode |= W_OK;
        }
        if (i & 2) {
            mode |= R_OK;
        }

        // Compute expected outcomes.
        int expected_closed, expected_open;
        if (GetParam() == IOMode::ReadWrite) {
            expected_closed = 0;
            expected_open = 0;
        } else {
            if (mode & R_OK) {
                expected_closed = -EACCES;
            } else {
                expected_closed = 0;
            }
            expected_open = 0;
        }

        // Check access permissions for both files.
        EXPECT_EQ(expected_closed, access(file_closed, mode));
        EXPECT_EQ(expected_open, access(file_open, mode));
    }
}

TEST_P(IOTest, AccessInvalidFile) {
    EXPECT_EQ(-ENOENT, access("/foo", W_OK | X_OK));
}

TEST_P(IOTest, ReadInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;
    char buf[16];
    EXPECT_EQ(-EBADF, fs.read(nullptr, buf, sizeof(buf), 0, &info));
}

TEST_P(IOTest, ReadWrite) {
    const std::string filename("/test");
    const std::string contents("abcdefg");
    // Open a test file in the filesystem, write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);

        // Verify the contents are there before closing.
        EXPECT_EQ(contents, f.read());
    }

    // Reopen and verify contents.
    {
        scoped_file f(fs, filename, 0);

        std::string buffer;
        int ret = f.read(&buffer);
        if (GetParam() == IOMode::ReadWrite) {
            ASSERT_EQ(contents.size(), ret);
            buffer.resize(ret);
            EXPECT_EQ(contents, buffer);
        } else {
            EXPECT_EQ(-EACCES, ret);
        }
    }
}

TEST_P(IOTest, WriteInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;

    char buf[16];
    EXPECT_EQ(-EBADF, fs.write(nullptr, buf, sizeof(buf), 0, &info));
}

TEST_P(IOTest, WriteZeroBytes) {
    scoped_file f(fs, "/test", O_CREAT | O_RDWR);

    char buf[16];
    int ret = fs.write(nullptr, buf, 0, 0, &f.info);
    EXPECT_EQ(0, ret);
}

TEST_P(IOTest, WriteInvalidOffset) {
    scoped_file f(fs, "/test", O_CREAT | O_RDWR);

    char buf[16];
    int ret = fs.write(nullptr, buf, sizeof(buf), -1, &f.info);
    EXPECT_EQ(-EINVAL, ret);
}

TEST_P(IOTest, Append) {
    const std::string filename("/test");
    const std::string contents1("abcdefg");
    const std::string contents2("hijklmn");
    // Open a test file in the filesystem, write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents1);

        // Verify the contents are there before closing.
        EXPECT_EQ(contents1, f.read());
    }

    // Append to test file.
    {
        scoped_file f(fs, filename, O_APPEND | O_WRONLY);
        f.write(contents2);
    }

    // Reopen and verify contents.
    {
        scoped_file f(fs, filename, 0);

        std::string buffer;
        int ret = f.read(&buffer);
        if (GetParam() == IOMode::ReadWrite) {
            ASSERT_EQ(contents1.size() + contents2.size(), ret);
            buffer.resize(ret);
            EXPECT_EQ(contents1 + contents2, buffer);
        } else {
            EXPECT_EQ(-EACCES, ret);
        }
    }
}

TEST_P(IOTest, TwoHandles) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    scoped_file f0(fs, filename, O_CREAT | O_RDWR);
    f0.write(contents);

    // Open the file a second time.
    scoped_file f1(fs, filename, O_RDONLY);

    // Verify the content from second handle.
    EXPECT_EQ(contents, f1.read());
}

TEST_P(IOTest, TruncateInvalidDescriptor) {
    struct fuse_file_info info;
    info.fh = -1;
    int ret = fs.ftruncate(nullptr, 0, &info);
    EXPECT_EQ(-EBADF, ret);
}

TEST_P(IOTest, TruncateInvalidOffset) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    scoped_file f(fs, filename, O_CREAT | O_RDWR);
    f.write(contents);

    // Truncate at an invalid offset.
    EXPECT_EQ(-EINVAL, f.truncate(-1));
}

TEST_P(IOTest, TruncateReadOnlyFile) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
        f.write(contents);
    }

    EXPECT_EQ(0, fs.chmod(filename.c_str(), 0400));

    if (GetParam() == IOMode::ReadWrite) {
        scoped_file f(fs, filename, O_RDONLY);
        EXPECT_EQ(-EINVAL, f.truncate(0));
    }
}

TEST_P(IOTest, TruncateZeroFromCreation) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);

        EXPECT_EQ(contents.size(), f.file_size());

        // Truncate
        EXPECT_EQ(0, f.truncate(0));

        // Re-stat.
        EXPECT_EQ(0u, f.file_size());
    }

    // Re-stat.
    EXPECT_LE(0u, file_size(filename)); // getattr returns the size on-disk,
                                        // rather than decrypted.  TODO:  Do not
                                        // write empty files.

    // Re-open if in ReadWrite mode.
    if (GetParam() == IOMode::ReadWrite) {
        scoped_file f(fs, filename, O_RDONLY);
        EXPECT_EQ(0u, f.file_size());
    }
}

TEST_P(IOTest, TruncateZeroFromExisting) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);
        EXPECT_EQ(contents.size(), f.file_size());
    }

    // Re-open, truncate.
    {
        scoped_file f(fs, filename, O_WRONLY);
        EXPECT_EQ(0, f.truncate(0));
        EXPECT_EQ(0u, f.file_size());
    }
}

TEST_P(IOTest, TruncatePartial) {
    const std::string filename("/test");
    const std::string contents("abcdefg");
    size_t offset = 3;

    // Open a test file in the filesystem, write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);

        EXPECT_EQ(contents.size(), f.file_size());

        // Truncate
        int ret = f.truncate(off_t(offset));
        if (GetParam() == IOMode::ReadWrite) {
            EXPECT_EQ(0, ret);
            EXPECT_EQ(offset, f.file_size());
        } else {
            // TODO:  Permit truncations of newly created files.
            EXPECT_EQ(-EACCES, ret);
        }
    }

    // Re-open.
    if (GetParam() == IOMode::ReadWrite) {
        scoped_file f(fs, filename, O_RDONLY);
        EXPECT_EQ(offset, f.file_size());

        // Read contents.
        EXPECT_EQ(contents.substr(0, offset), f.read());
    }
}

TEST_P(IOTest, TruncatePathZeroInvalidFile) {
    EXPECT_EQ(-ENOENT, truncate("/test", 0));
}

TEST_P(IOTest, TruncatePathPartialInvalidFile) {
    int ret = truncate("/test", 3);
    if (GetParam() == IOMode::ReadWrite) {
        EXPECT_EQ(-ENOENT, ret);
    } else {
        EXPECT_EQ(-EACCES, ret);
    }
}

TEST_P(IOTest, TruncatePathInvalidOffset) {
    EXPECT_EQ(-EINVAL, truncate("/test", -1));
}

TEST_P(IOTest, TruncatePath) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Touch a file and write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);
    }

    EXPECT_LT(0u, file_size(filename));

    // Truncate by path.
    EXPECT_EQ(0, truncate(filename, 0));

    EXPECT_EQ(0u, file_size(filename));
}

TEST_P(IOTest, TruncatePathPartial) {
    int ret;

    const std::string filename("/test");
    const std::string contents("abcdefg");
    const size_t offset = 3;

    // Touch a file and write to it.
    {
        scoped_file f(fs, filename, O_CREAT | O_RDWR);
        f.write(contents);
    }

    EXPECT_LT(0u, file_size(filename));

    // Truncate by path.
    ret = truncate(filename, off_t(offset));
    if (GetParam() == IOMode::ReadWrite) {
        EXPECT_EQ(0, ret);

        // Verify file contents.
        scoped_file f(fs, filename, O_RDONLY);
        EXPECT_EQ(offset, f.file_size());

        EXPECT_EQ(contents.substr(0, offset), f.read());
    } else {
        EXPECT_EQ(-EACCES, ret);
    }
}

TEST_P(IOTest, TruncatePathOpenFile) {
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    scoped_file f(fs, filename, O_CREAT | O_RDWR);
    f.write(contents);

    EXPECT_EQ(contents.size(), f.file_size());

    // Truncate by path.
    EXPECT_EQ(0, truncate(filename, 0));

    EXPECT_EQ(0u, f.file_size());
}

TEST_P(IOTest, ListEmptyDirectory) {
    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }

    // Touch a file.
    const std::string filename("foo");
    {
        scoped_file f(fs, "/" + filename, O_CREAT | O_WRONLY);
    }

    // Reread directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[filename].st_mode));
    }
}

TEST_P(IOTest, CreateRemoveDirectory) {
    const std::string directory("foo");
    const std::string full_directory("/" + directory);

    int ret;
    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }

    // mkdir
    {
        ret = fs.mkdir(full_directory.c_str(), 0700);
        EXPECT_EQ(0, ret);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[directory].st_mode));
    }

    // rmdir
    {
        ret = fs.rmdir(full_directory.c_str());
        EXPECT_EQ(0, ret);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }
}

TEST_P(IOTest, Chmod) {
    const std::string filename("/test");

    const mode_t initial = 0600;
    const mode_t final = 0400;

    const mode_t mask = GetParam() == IOMode::ReadWrite ? 07777 : 07333;

    // Touch
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    // Stat
    {
        struct stat buf;
        EXPECT_EQ(0, getattr(filename, &buf));
        EXPECT_EQ(initial & mask, buf.st_mode & 07777);
    }

    // Chmod
    EXPECT_EQ(0, fs.chmod(filename.c_str(), final));

    // Stat
    {
        struct stat buf;
        EXPECT_EQ(0, getattr(filename, &buf));
        EXPECT_EQ(final & mask, buf.st_mode & 07777);
    }
}

TEST_P(IOTest, ChmodInvalidFile) {
    EXPECT_EQ(-ENOENT, fs.chmod("/test", 0600));
}

TEST_P(IOTest, Chown) {
    const std::string filename("/test");

    // Touch
    int ret;
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    // Stat
    struct stat buf;
    {
        EXPECT_EQ(0, getattr(filename, &buf));
    }

    // Chown (to the same values).
    {
        ret = fs.chown(filename.c_str(), buf.st_uid, buf.st_gid);
        EXPECT_EQ(0, ret);
    }

    // Verify unchanged permissions.
    {
        struct stat buf2;
        EXPECT_EQ(0, getattr(filename, &buf2));
        EXPECT_EQ(buf.st_uid, buf2.st_uid);
        EXPECT_EQ(buf.st_gid, buf2.st_gid);
    }
}

TEST_P(IOTest, ChownToRoot) {
    const std::string filename("/test");

    // Touch
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    // Stat
    struct stat buf;
    EXPECT_EQ(0, getattr(filename, &buf));

    // Chown (to root).
    EXPECT_EQ(-EPERM, fs.chown(filename.c_str(), 0, 0));
}

TEST_P(IOTest, ClosedFileDescriptors) {
    // This test verifies that file descriptors other than stdin, stdout, and
    // stderr are closed when running GPG.  If no wrapper path is specified
    // during test execution, this test is skipped.
    if (wrapper_path == "") {
        return;
    }

    // When run under CTest, an additional file descriptor pointing at
    // .../Testing/Temporary/LastTest.log.tmp will be opened.  Before executing
    // this test, we scan the open file descriptors for this file and mark it
    // to be closed on exec.
    const std::string suffix("/Testing/Temporary/LastTest.log.tmp");
    auto fds = get_file_descriptors(false);
    for (const auto& kv : fds) {
        const int fd = kv.first;
        const std::string& target = kv.second;
        if (target.size() < suffix.size()) {
            continue;
        }

        if (target.compare(
                target.size() - suffix.size(), suffix.size(), suffix) != 0) {
            continue;
        }

        std::cout << "Found CTest-related fd: " << fd << std::endl;
        int flags = fcntl(fd, F_GETFD);
        flags |= FD_CLOEXEC;
        fcntl(fd, F_SETFD, flags);
    }

    fs.set_gpg(wrapper_path);

    const std::string path_a("/a");
    const std::string a("a-contents");

    const std::string path_b("/b");
    const std::string b("b-contents");

    {
        scoped_file f(fs, path_a, O_WRONLY | O_CREAT);
        f.write(a);

        {
            scoped_file g(fs, path_b, O_WRONLY | O_CREAT);
            g.write(b);
        }
    }

    // The files should have non-zero size, even if we can't read them.  If the
    // GPG wrapper aborted, the files will be empty.
    EXPECT_NE(0u, file_size(path_a));
    EXPECT_NE(0u, file_size(path_b));

    // If we are in read-write mode, check the contents.
    if (GetParam() == IOMode::ReadWrite) {
        scoped_file f(fs, path_a, O_RDONLY);
        scoped_file g(fs, path_b, O_RDONLY);

        EXPECT_EQ(a, f.read());
        EXPECT_EQ(b, g.read());
    }
}

TEST_P(IOTest, CreateExisting) {
    const std::string filename("/foo");
    const int flags = O_CREAT | O_EXCL | O_WRONLY;
    {
        scoped_file f(fs, filename, flags);
    }

    {
        struct fuse_file_info info;
        info.flags = flags;
        EXPECT_EQ(-EEXIST, fs.create(filename.c_str(), 0600, &info));
    }
}

TEST_P(IOTest, Rename) {
    const std::string oldname("foo");
    const std::string newname("bar");

    const std::string full_oldname("/" + oldname);
    const std::string full_newname("/" + newname);

    int ret;

    // Touch a file.
    {
        scoped_file f(fs, full_oldname, O_CREAT | O_WRONLY);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[oldname].st_mode));
    }

    // Rename
    {
        ret = fs.rename(full_oldname.c_str(), full_newname.c_str());
        EXPECT_EQ(0, ret);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[newname].st_mode));
    }

    // Stat files
    {
        struct stat buf;
        EXPECT_EQ(-ENOENT, getattr(full_oldname, &buf));

        EXPECT_EQ(0, getattr(full_newname, &buf));
        EXPECT_TRUE(S_ISREG(buf.st_mode));
        EXPECT_EQ(0, buf.st_size);
    }
}

TEST_P(IOTest, OpenWriteOnlyFile) {
    // We create a file and then modify the underlying backing filesystem to
    // make the actual contents write-only.  asymmetricfs normally tries to
    // open files for reading as well, but reattempts on failure.
    const std::string filename("/foo");
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    EXPECT_EQ(0, fs.chmod(filename.c_str(), 0200));

    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }
}

TEST_P(IOTest, OpenInaccessibleFile) {
    // We create a file and then modify the underlying backing filesystem to
    // make the actual contents inaccessible.  asymmetricfs normally tries to
    // open files for reading as well, but reattempts on failure.
    const std::string filename("/foo");
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    EXPECT_EQ(0, fs.chmod(filename.c_str(), 0000));

    {
        struct fuse_file_info info;
        info.flags = O_WRONLY;
        EXPECT_EQ(-EACCES, fs.open(filename.c_str(), &info));

        info.flags = O_RDONLY;
        EXPECT_EQ(-EACCES, fs.open(filename.c_str(), &info));

        info.flags = O_RDWR;
        EXPECT_EQ(-EACCES, fs.open(filename.c_str(), &info));
    }
}

TEST_P(IOTest, RenameOpenFile) {
    const std::string oldname("foo");
    const std::string newname("bar");

    const std::string full_oldname("/" + oldname);
    const std::string full_newname("/" + newname);

    int ret;

    // Touch a file.
    scoped_file f(fs, full_oldname, O_CREAT | O_WRONLY);

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[oldname].st_mode));
    }

    // Rename
    {
        ret = fs.rename(full_oldname.c_str(), full_newname.c_str());
        EXPECT_EQ(0, ret);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[newname].st_mode));
    }

    // Stat files via path.
    {
        struct stat buf;
        EXPECT_EQ(-ENOENT, getattr(full_oldname, &buf));

        EXPECT_EQ(0, getattr(full_newname, &buf));
        EXPECT_TRUE(S_ISREG(buf.st_mode));
        EXPECT_EQ(0, buf.st_size);
    }

    // Stat files via descriptor.
    {
        struct stat buf;
        f.stat(&buf);
        EXPECT_TRUE(S_ISREG(buf.st_mode));
        EXPECT_EQ(0, buf.st_size);
    }
}

TEST_P(IOTest, StatInvalidArgument) {
    scoped_file f(fs, "/test", O_CREAT | O_RDWR);
    EXPECT_EQ(-EFAULT, fs.fgetattr(nullptr, nullptr, &f.info));
}

TEST_P(IOTest, StatPathInvalidArgument) {
    EXPECT_EQ(-EFAULT, fs.getattr("/test", nullptr));
}

TEST_P(IOTest, StatInvalidDescriptor) {
    struct fuse_file_info info;
    struct stat buf;
    info.fh = -1;
    EXPECT_EQ(-EBADF, fs.fgetattr(nullptr, &buf, &info));
}

TEST_P(IOTest, StatWhileOpen) {
    // We create a file and stat it by path (rather than descriptor) while
    // keeping the descriptor open.
    const std::string filename("/test");
    const std::string contents("abcdefg");

    // Open a test file in the filesystem, write to it.
    scoped_file f(fs, filename, O_CREAT | O_RDWR);
    f.write(contents);

    EXPECT_EQ(contents.size(), file_size(filename));
}

TEST_P(IOTest, CreateSymlink) {
    const std::string target("/dev/null");
    const std::string link_name("foo");
    const std::string full_link_name("/" + link_name);

    int ret;
    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }

    // symlink
    {
        ret = fs.symlink(target.c_str(), full_link_name.c_str());
        EXPECT_EQ(0, ret);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISLNK(buffer[link_name].st_mode));
    }

    // readlink
    std::string buffer(1 << 8, '\0');
    ret = fs.readlink(full_link_name.c_str(), &buffer[0], buffer.size());
    EXPECT_EQ(target.size(), ret);
    buffer.resize(target.size());
    EXPECT_EQ(target, buffer);
}

bool operator==(const struct timespec& a, const struct timespec& b) {
    return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

bool operator!=(const struct timespec& a, const struct timespec& b) {
    return !(a == b);
}

TEST_P(IOTest, Touch) {
    const std::string filename("/foo");

    int ret;
    {
        scoped_file f(fs, filename, O_CREAT | O_WRONLY);
    }

    struct stat oldstat;
    EXPECT_EQ(0, getattr(filename, &oldstat));

    // Set the time on the file.
    struct timespec times[2] = {{0, 0}, {0, UTIME_OMIT}};
    ret = fs.utimens(filename.c_str(), times);
    EXPECT_EQ(0, ret);

    struct stat newstat;
    EXPECT_EQ(0, getattr(filename, &newstat));

    // Verify access time changed.
    EXPECT_NE(oldstat.st_atim, newstat.st_atim);

    // Verify modified time is unchanged.
    EXPECT_EQ(oldstat.st_mtim, newstat.st_mtim);
}

TEST_P(IOTest, UnlinkFile) {
    const std::string filename("foo");
    const std::string full_filename("/" + filename);

    int ret;

    // Touch a file.
    {
        scoped_file f(fs, full_filename, O_CREAT | O_WRONLY);
    }

    // Read directory
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(3u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
        EXPECT_TRUE(S_ISREG(buffer[filename].st_mode));
    }

    // Unlink
    ret = fs.unlink(full_filename.c_str());
    EXPECT_EQ(0, ret);

    // Verify.
    {
        stat_map buffer;
        ASSERT_EQ(0, readdir("/", &buffer));
        ASSERT_EQ(2u, buffer.size());

        EXPECT_TRUE(S_ISDIR(buffer["."].st_mode));
        EXPECT_TRUE(S_ISDIR(buffer[".."].st_mode));
    }
}

TEST_P(IOTest, UnlinkInvalidFile) {
    EXPECT_EQ(-ENOENT, fs.unlink("/foo"));
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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Assume the second argument is a GPG wrapper binary.
    if (argc == 2) {
        wrapper_path = argv[1];
    } else {
        std::cerr << "Wrapper binary not parsed, skipping some tests!"
                  << std::endl;
    }

    return RUN_ALL_TESTS();
}
