/**
 * asymmetricfs - An asymmetric encryption-aware filesystem
 * (c) 2013 Chris Kennelly <chris@ckennelly.com>
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

/**
 * Workaround per bug in libstdc++ 4.5:
 * http://llvm.org/bugs/show_bug.cgi?id=13364
 */
namespace std { class type_info; }

#include <sys/types.h>
#ifdef HAS_XATTR
#include <attr/xattr.h>
#endif // HAS_XATTR
#include <cassert>
#include <climits>
#include <cstdlib>
#include <dirent.h>
#include "implementation.h"
#include "page_buffer.h"
#include <set>
#include <stdexcept>
#include <string>
#include "subprocess.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <vector>

typedef std::unique_lock<std::mutex> scoped_lock;
typedef std::vector<gpg_recipient> RecipientList;

/**
 * System utilities such as truncate open the file descriptor for writing only.
 * This makes it difficult when we must decrypt the file, truncate, and then
 * reencrypt.
 */
int asymmetricfs::make_rdwr(int flags) const {
    if (!(read_)) {
        return flags;
    } else if (flags & O_RDONLY) {
        return flags;
    } else {
        flags &= ~O_RDONLY;
        flags &= ~O_WRONLY;
        flags |= O_RDWR;
        return flags;
    }
}

class asymmetricfs::internal {
public:
    internal(const std::string& gpg_path, const RecipientList & recipients);
    ~internal();

    const std::string& gpg_path_;
    int fd;
    int flags;
    unsigned references;
    std::string path;

    bool buffer_set;
    bool dirty;
    page_buffer buffer;

    /**
     * Returns 0 on success, otherwise the corresponding standard error code.
     * This should not be called by multiple threads on a single instance.
     */
    int load_buffer();

    int close();
protected:
    internal(const internal &) = delete;
    const internal & operator=(const internal &) = delete;

    bool open_;
    const RecipientList & recipients_;
};

asymmetricfs::internal::internal(
        const std::string& gpg_path, const RecipientList & recipients) :
    gpg_path_(gpg_path), references(0), buffer_set(false), dirty(false),
    open_(true), recipients_(recipients) { }

asymmetricfs::internal::~internal() {
    (void) close();
    assert(references == 0);
}

int asymmetricfs::internal::close() {
    if (!(open_)) {
        return 0;
    }

    int ret = 0;
    if (dirty) {
        std::vector<std::string> argv{"gpg", "-ae", "--no-tty", "--batch"};
        for (const auto& recipient : recipients_) {
            argv.push_back("-r");
            argv.push_back(static_cast<std::string>(recipient));
        }

        /* Start gpg. */
        subprocess s(-1, fd, gpg_path_, argv);

        buffer.splice(s.in(), 0);

        int wait_ret = s.wait();
        if (wait_ret != 0) {
            ret = -EIO;
        }

        dirty = false;
    }

    open_ = false;
    int close_ret = ::close(fd);
    if (ret != 0) {
        return ret;
    } else if (close_ret == 0) {
        return 0;
    } else {
        return errno;
    }
}

int asymmetricfs::internal::load_buffer() {
    if (buffer_set) {
        return 0;
    }

    assert(open_);

    /* Clear the current buffer. */
    dirty = false;
    buffer.clear();

    /* gpg does not react well to seeing multiple encrypted blocks in the same
     * session, so the data needs to be chunked across multiple calls. */
    const std::vector<std::string> argv{"gpg", "-d", "--no-tty", "--batch"};

    struct stat fd_stat;
    int ret = fstat(fd, &fd_stat);
    if (ret != 0) {
        return errno;
    } else if (fd_stat.st_size <= 0) {
        buffer_set = true;
        return 0;
    }

    const size_t fd_size = static_cast<size_t>(fd_stat.st_size);

    const uint8_t * underlying = static_cast<const uint8_t *>(
        mmap(NULL, fd_size, PROT_READ, MAP_SHARED, fd, 0));
    if (underlying == MAP_FAILED) {
        return errno;
    }

    static const char terminator[]    = "-----END PGP MESSAGE-----\n";
    static size_t     terminator_size = sizeof(terminator) - 1;

    buffer_set = true;
    ret = 0;
    for (size_t offset = 0; offset < fd_size; ) {
        /*
         * Find terminator of gpg block.  This can be optimized, but
         * terminator_size is small.
         */
        size_t new_offset;
        for (new_offset = offset; new_offset <= fd_size - terminator_size;
                new_offset++) {
            if (memcmp(terminator, underlying + new_offset,
                    terminator_size) == 0) {
                new_offset += terminator_size;
                break;
            }
        }
        assert(offset <= new_offset);
        assert(new_offset <= fd_size);

        const uint8_t *write_buffer;
        size_t write_size;
        int gpg_stdin;
        if (offset == 0 && new_offset == fd_size) {
            /* Special case:  Single block. */
            gpg_stdin = fd;
            write_buffer = NULL;
            write_size   = 0;
        } else {
            gpg_stdin = -1;
            write_buffer = underlying + offset;
            write_size   = new_offset - offset;

            if (write_size == 0) {
                break;
            }
        }

        /* Start gpg. */
        subprocess s(gpg_stdin, -1, gpg_path_, argv);

        /* Communicate with gpg. */
        const size_t chunk_size = 1 << 20;
        std::string receive_buffer(chunk_size, '\0');
        while (true) {
            size_t this_chunk = receive_buffer.size();

            size_t write_remaining = write_size;
            int cret = s.communicate(&receive_buffer[0], &this_chunk,
                write_buffer, &write_remaining);
            if (cret != 0) {
                ret = -cret;
                break;
            }

            if (chunk_size == this_chunk) {
                break;
            }
            buffer.write(
                chunk_size - this_chunk, buffer.size(), &receive_buffer[0]);

            if (write_buffer) {
                write_buffer += write_size - write_remaining;
                write_size   = write_remaining;
            }
        }

        int wait = s.wait();
        if (wait != 0) {
            buffer_set = false;
            ret = EIO;
            break;
        }

        offset = new_offset;
    }

    munmap(const_cast<uint8_t *>(underlying),
        static_cast<size_t>(fd_stat.st_size));

    return ret;
}

asymmetricfs::asymmetricfs() : read_(false), root_set_(false), gpg_path_("gpg"),
    next_(0) { }

asymmetricfs::~asymmetricfs() {
    if (root_set_) {
        ::close(root_);
    }

    for (open_fd_map_t::iterator it = open_fds_.begin(); it != open_fds_.end();
            ++it) {
        delete it->second;
    }
}

asymmetricfs::fd_t asymmetricfs::next_fd() {
    return next_++;
}

int asymmetricfs::chmod(const char *path_, mode_t mode) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = ::fchmodat(root_, relpath.c_str(), mode, 0);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::chown(const char *path_, uid_t u, gid_t g) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = ::fchownat(root_, relpath.c_str(), u, g, 0);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::create(const char *path_, mode_t mode,
        struct fuse_file_info *info) {
    const std::string path(path_);
    const std::string relpath("." + path);

    info->flags |= O_CLOEXEC;
    info->flags |= O_CREAT;

    assert(info);
    int ret;
    do {
        ret = ::openat(root_, relpath.c_str(), make_rdwr(info->flags), mode);
        if (ret >= 0) {
            break;
        }

        if (read_ && (info->flags & O_WRONLY) && errno == EACCES) {
            ret = ::openat(root_, relpath.c_str(), info->flags, mode);
            if (ret >= 0) {
                break;
            }
        }

        return -errno;
    } while (0);

    /* Update list of open files. */
    scoped_lock l(mx_);
    const fd_t fd = next_fd();
    open_paths_.insert(std::make_pair(path, fd));

    internal * data = new internal(gpg_path_, recipients_);
    data->fd            = ret;
    data->flags         = info->flags;
    data->path          = path;
    data->references    = 1;
    data->buffer_set    = true;
    open_fds_  .insert(std::make_pair(fd, data));

    info->fh = fd;

    return 0;
}

int asymmetricfs::ftruncate(const char *path, off_t offset,
        struct fuse_file_info *info) {
    (void) path;
    assert(info);

    scoped_lock l(mx_);
    return truncatefd(info->fh, offset);
}

int asymmetricfs::truncatefd(fd_t fd, off_t offset) {
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) {
        return -EBADF;
    }

    if (offset < 0) {
        return -EINVAL;
    } else if (offset == 0) {
        int ret = ::ftruncate(it->second->fd, 0);
        if (ret != 0) {
            return -errno;
        } else {
            it->second->buffer.resize(0);
            it->second->dirty = true;
            return 0;
        }
    } else if (read_) {
        /* Decrypt, truncate, (lazily) reencrypt. */
        int ret = it->second->load_buffer();
        if (ret != 0) {
            return -ret;
        } else {
            it->second->buffer.resize(static_cast<size_t>(offset));
            it->second->dirty = true;
            return 0;
        }
    } else {
        return -EACCES;
    }
}

void* asymmetricfs::init(struct fuse_conn_info *conn) {
    (void) conn;

    return NULL;
}

bool asymmetricfs::ready() const {
    return root_set_ && !(recipients_.empty());
}

void asymmetricfs::set_gpg(const std::string& gpg_path) {
    gpg_path_ = gpg_path;
}

void asymmetricfs::set_read(bool r) {
    read_ = r;
}

bool asymmetricfs::set_target(const std::string & target) {
    if (target.empty()) {
        return false;
    }

    if (root_set_) {
        ::close(root_);
        root_set_ = false;
    }

    root_ = ::open(target.c_str(), O_CLOEXEC | O_DIRECTORY);
    return (root_set_ = (root_ >= 0));
}

void asymmetricfs::set_recipients(
        const std::vector<gpg_recipient> & recipients) {
    /*
     * We guarantee the lifetime of the recipient list to
     * asymmetricfs::internal, so reject changes if there are outstanding
     * files.
     */
    if (!(open_fds_.empty())) {
        throw std::runtime_error("Changing recipient list with open files.");
    }

    recipients_ = recipients;
}

int asymmetricfs::fgetattr(const char *path, struct stat *buf,
        struct fuse_file_info *info) {
    (void) path;

    scoped_lock l(mx_);
    return statfd(info->fh, buf);
}

int asymmetricfs::statfd(fd_t fd, struct stat *buf) {
    if (!(buf)) {
        return -EFAULT;
    }

    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) {
        return -EBADF;
    }

    struct stat s;
    const int ret = ::fstat(it->second->fd, &s);
    if (ret != 0) {
        return -errno;
    }

    if (read_) {
        int lret = it->second->load_buffer();
        if (lret != 0) {
            return -lret;
        }
    }

    assert(!(read_) || it->second->buffer_set);
    const size_t size = it->second->buffer.size();
    if (it->second->buffer_set) {
        s.st_size = static_cast<off_t>(size);
    } else if (it->second->flags & O_APPEND) {
        s.st_size += size;
    } /* else: leave st_size as-is. */

    *buf = s;
    return 0;
}

int asymmetricfs::getattr(const char *path_, struct stat *buf) {
    const std::string path(path_);

    /**
     * If !read_, clear the appropriate bits unless the file is open.
     */
    scoped_lock l(mx_);
    auto it = open_paths_.find(path);
    const bool is_open = it != open_paths_.end();

    if (is_open) {
        return statfd(it->second, buf);
    } else {
        if (!(buf)) {
            return -EFAULT;
        }

        const std::string relpath("." + path);
        struct stat s;
        const int ret =
            ::fstatat(root_, relpath.c_str(), &s, AT_SYMLINK_NOFOLLOW);
        if (ret != 0) {
            return -errno;
        }

        if (!(read_) && !(S_ISDIR(s.st_mode))) {
            s.st_mode = s.st_mode &
                static_cast<mode_t>(~(S_IRUSR | S_IRGRP | S_IROTH));
        }

        *buf = s;
        return 0;
    }
}

int asymmetricfs::link(const char *oldpath, const char *newpath) {
    (void) oldpath;
    (void) newpath;

    /* asymmetricfs does not support hard links. */
    return -EPERM;
}

#ifdef HAS_XATTR
int asymmetricfs::listxattr(const char *path_, char *buffer, size_t size) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int fd = ::openat(root_, relpath.c_str(), O_CLOEXEC | O_PATH);
    if (fd < 0) {
        return errno;
    }

    ssize_t ret = ::flistxattr(fd, buffer, size);
    ::close(fd);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}
#endif // HAS_XATTR

int asymmetricfs::mkdir(const char *path_, mode_t mode) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = ::mkdirat(root_, relpath.c_str(), mode);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::open(const char *path_, struct fuse_file_info *info) {
    const std::string path(path_);
    const std::string relpath("." + path);
    assert(info);
    int flags = info->flags;

    /* Determine if the file is already open. */
    scoped_lock l(mx_);

    open_map_t::const_iterator it = open_paths_.find(path);
    if (it != open_paths_.end()) {
        info->fh = it->second;

        auto jit = open_fds_.find(it->second);
        assert(jit != open_fds_.end());
        jit->second->references++;
        return 0;
    }

    const int  access_mode = flags & O_ACCMODE;
    const bool for_reading = (access_mode == O_RDWR) ||
                             (access_mode == O_RDONLY);
    const bool for_writing = (access_mode == O_RDWR) ||
                             (access_mode == O_WRONLY);
    if (!(read_) && for_reading) {
        if (flags & O_CREAT) {
            /* Require that the file be created (i.e., it does not already
             * exist. */
            flags |= O_EXCL;
        }
    }
    flags |= O_CLOEXEC;

    int ret;
    do {
        ret = ::openat(root_, relpath.c_str(), make_rdwr(flags));
        if (ret >= 0) {
            break;
        }

        if (read_ && !(for_writing) && errno == EACCES) {
            ret = ::openat(root_, relpath.c_str(), flags);
            if (ret >= 0) {
                break;
            }
        }

        return -errno;
    } while (0);

    /* Update list of open files. */
    const fd_t fd = next_fd();
    open_paths_.insert(std::make_pair(path, fd));

    internal * data = new internal(gpg_path_, recipients_);
    data->fd            = ret;
    data->flags         = flags;
    data->path          = path;
    data->references    = 1;

    /**
     * If we just created the file, it will be empty.  If so, treat the empty
     * buffer as initialized.  Otherwise, defer decryption until we read the
     * file.
     *
     * This is necessary so we can truncate empty files to non-zero size even
     * in write-only mode.
     */
    struct stat buf;
    int fstat_ret = fstat(ret, &buf);
    if (fstat_ret == 0) {
        data->buffer_set = buf.st_size == 0;
    } else {
        /* An error occured, but treat it as nonfatal. */
        data->buffer_set = false;
    }

    open_fds_  .insert(std::make_pair(fd, data));

    info->fh = fd;

    return 0;
}

int asymmetricfs::opendir(const char *path_, struct fuse_file_info *info) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int dirfd = ::openat(root_, relpath.c_str(), O_CLOEXEC | O_DIRECTORY);
    if (dirfd < 0) {
        return -errno;
    }

    DIR *dir = ::fdopendir(dirfd);
    if (!(dir)) {
        return -errno;
    }

    info->fh = reinterpret_cast<uint64_t>(dir);
    open_dirs_[info->fh] = relpath;
    return 0;
}

int asymmetricfs::read(const char *path, void *buffer, size_t size,
        off_t offset_, struct fuse_file_info *info) {
    (void) path;

    scoped_lock l(mx_);
    open_fd_map_t::const_iterator it = open_fds_.find(info->fh);
    if (it == open_fds_.end()) {
        return -EBADF;
    }

    if (offset_ < 0) {
        return 0;
    }
    const size_t offset = static_cast<size_t>(offset_);

    if (!(read_)) {
        if (!(it->second->buffer_set)) {
            if (it->second->flags & O_APPEND) {
                return -EACCES;
            } else if (!(it->second->flags & O_CREAT)) {
                /*
                 * O_CREAT implies O_EXCL, so if it was not set, the file
                 * already existed and cannot be read.
                 */
                return -EACCES;
            }
        }
    } else {
        /* Read the buffer, as needed. */
        int ret = it->second->load_buffer();
        if (ret != 0) {
            return -ret;
        }
        assert(it->second->buffer_set);
    }

    return static_cast<int>(it->second->buffer.read(size, offset, buffer));
}

int asymmetricfs::readdir(const char *path, void *buffer,
        fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info) {
    (void) path;
    (void) offset;

    DIR *dir = reinterpret_cast<DIR *>(info->fh);

    // Lookup path handle
    auto it = open_dirs_.find(info->fh);
    if (it == open_dirs_.end()) {
        return -EBADF;
    }
    const std::string& relpath = it->second;

    /**
     * readdir is used preferentially over readdir_r here as the API for
     * readdir_r exposes us to the potential problem of failing to allocate
     * enough buffer space for the entry name.
     */
    struct dirent *result;

    /**
     * From the readdir man-page (release 3.44):
     *
     * "On success, readdir() returns a pointer to a dirent structure.  (This
     *  structure may be statically allocated; do not attempt to free(3) it.)
     *  If the end of the directory stream is reached, NULL is returned and
     *  errno is not changed.  If an error occurs, NULL is returned and errno
     *  is set appropriately."
     *
     * errno may be nonzero upon entry into the loop, so it must be cleared as
     * to detect any errors that arise.
     */
    errno = 0;

    /**
     * Per the GNU libc manual:
     *   "Portability Note: On some systems readdir may not return entries for
     *   . and .., even though these are always valid file names in any
     *   directory."
     *
     * Therefore, we track whether we have seen . and .. and inject them
     * accordingly.
     */
    std::set<std::string> fill_in{".", ".."};

    while ((result = ::readdir(dir)) != NULL) {
        struct stat s;
        memset(&s, 0, sizeof(s));
        s.st_ino = result->d_ino;

        bool skip = false;
        unsigned d_type = result->d_type;
        if (result->d_type == DT_UNKNOWN) {
            // Perform stat on entry to get type.
            struct stat t;
            int ret = fstatat(
                root_,
                (relpath + result->d_name).c_str(),
                &t, AT_SYMLINK_NOFOLLOW);
            if (ret < 0) {
                return -errno;
            }
            d_type = IFTODT(t.st_mode);
        }

        switch (d_type) {
            case DT_LNK:
            case DT_REG:
            case DT_DIR:
                s.st_mode = DTTOIF(d_type);
                break;
            case DT_UNKNOWN:
            case DT_BLK:
            case DT_CHR:
            case DT_FIFO:
            case DT_SOCK:
            default:
                skip = true;
                break;
        }

        if (skip) {
            continue;
        }

        fill_in.erase(result->d_name);
        int ret = filler(buffer, result->d_name, &s, 0);
        if (ret) {
            return 0;
        }
    }

    // Fill in . and .., if they were not seen during the main loop.
    for (const std::string& name : fill_in) {
        struct stat s;
        memset(&s, 0, sizeof(s));
        s.st_mode = S_IFDIR;

        int ret = filler(buffer, name.c_str(), &s, 0);
        if (ret) {
            return 0;
        }
    }

    return -errno;
}

int asymmetricfs::readlink(const char *path_, char *buffer, size_t size) {
    const std::string path(path_);
    const std::string relpath("." + path);

    size_t len = size > 0 ? size - 1 : 0;

    ssize_t ret = ::readlinkat(root_, relpath.c_str(), buffer, len);
    if (ret == -1) {
        return -errno;
    } else {
        return int(ret);
    }
}

int asymmetricfs::release(const char *path, struct fuse_file_info *info) {
    (void) path;

    scoped_lock l(mx_);

    auto it = open_fds_.find(info->fh);
    if (it == open_fds_.end()) {
        return 0 /* ignored */;
    }

    const unsigned new_count = --it->second->references;
    if (new_count == 0) {
        /* Close the file. */
        open_paths_.erase(it->second->path);

        delete it->second;
        open_fds_.erase(it);
    }

    return 0 /* ignored */;
}

int asymmetricfs::releasedir(const char *path, struct fuse_file_info *info) {
    (void) path;

    DIR *dir = reinterpret_cast<DIR *>(info->fh);
    int ret = ::closedir(dir);
    if (ret != 0) {
        return -errno;
    }

    open_dirs_.erase(info->fh);
    return 0;
}

#ifdef HAS_XATTR
int asymmetricfs::removexattr(const char *path_, const char *name) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int fd = ::openat(root_, relpath.c_str(), O_CLOEXEC | O_PATH);
    if (fd < 0) {
        return -errno;
    }

    int ret = ::fremovexattr(fd, name);
    ::close(fd);
    if (ret != 0) {
        return -errno;
    }

    return ret;
}
#endif // HAS_XATTR

int asymmetricfs::rename(const char *oldpath_, const char *newpath_) {
    const std::string oldpath(oldpath_);
    const std::string newpath(newpath_);

    const std::string reloldpath("." + oldpath);
    const std::string relnewpath("." + newpath);

    /*
     * Avoid races to rename as our metadata for open files will be manipulated
     * if and only if the underlying rename is successful.
     */
    scoped_lock l(mx_);

    int ret = ::renameat(root_, reloldpath.c_str(), root_, relnewpath.c_str());
    if (ret != 0) {
        return -errno;
    }

    open_map_t::iterator it = open_paths_.find(oldpath);
    if (it != open_paths_.end()) {
        /* Rename existing, open files. */
        const fd_t fd = it->second;

        open_paths_.insert(std::make_pair(newpath, fd));
        open_paths_.erase(it);

        open_fd_map_t::iterator jit = open_fds_.find(fd);
        assert(jit != open_fds_.end());
        if (jit != open_fds_.end()) {
            jit->second->path = newpath;
        }
    }

    return 0;
}

int asymmetricfs::rmdir(const char *path_) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = ::unlinkat(root_, relpath.c_str(), AT_REMOVEDIR);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

#ifdef HAS_XATTR
int asymmetricfs::setxattr(const char *path_, const char *name,
        const void *value, size_t size, int flags) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int fd = ::openat(root_, relpath.c_str(), O_CLOEXEC | O_PATH);
    if (fd < 0) {
        return -errno;
    }

    int ret = ::fsetxattr(fd, name, value, size, flags);
    ::close(fd);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}
#endif // HAS_XATTR

int asymmetricfs::statfs(const char *path, struct statvfs *buf) {
    (void) path;

    int ret = ::fstatvfs(root_, buf);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::symlink(const char *oldpath, const char *newpath_) {
    const std::string newpath(newpath_);
    const std::string relpath("." + newpath);

    int ret = ::symlinkat(oldpath, root_, relpath.c_str());
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::truncate(const char *path_, off_t offset) {
    const std::string path(path_);
    const std::string relpath("." + path);

    if (offset < 0) {
        return -EINVAL;
    }

    /* Determine if the file is already open. */
    scoped_lock l(mx_);

    open_map_t::const_iterator it = open_paths_.find(path);
    const bool is_open = it != open_paths_.end();
    if (is_open) {
        return truncatefd(it->second, offset);
    } else if (offset == 0) {
        int fd = ::openat(root_, relpath.c_str(), O_CLOEXEC | O_WRONLY);
        if (fd < 0) {
            return -errno;
        }

        int ret = ::ftruncate(fd, offset);
        ::close(fd);
        if (ret == 0) {
            return 0;
        } else {
            return -errno;
        }
    } else if (read_) {
        /* Decrypt, truncate, encrypt. */
        const int flags = O_RDWR;
        int fd = ::openat(root_, relpath.c_str(), O_CLOEXEC | flags);
        if (fd < 0) {
            return -errno;
        }

        internal data(gpg_path_, recipients_);
        data.fd         = fd;
        data.flags      = flags;
        data.path       = path;
        /* data is transient and does not escape our scope. */
        data.references = 0;

        int load_ret = data.load_buffer();
        if (load_ret != 0) {
            return -load_ret;
        }

        // Rewind, so when we write out the newly resized buffer, we clobber the
        // old file contents.
        ::lseek(fd, 0, SEEK_SET);

        assert(data.buffer_set);
        data.buffer.resize(static_cast<size_t>(offset));
        data.dirty = true;

        int ret = data.close();
        if (ret == 0) {
            return 0;
        } else {
            return -ret;
        }
    } else {
        return -EACCES;
    }
}

int asymmetricfs::write(const char *path_, const char *buffer, size_t size,
        off_t offset, struct fuse_file_info *info) {
    (void) path_;

    scoped_lock l(mx_);

    assert(info);
    auto it = open_fds_.find(info->fh);
    if (it == open_fds_.end()) {
        return -EBADF;
    }

    if (size == 0) {
        return 0;
    }

    if (offset < 0) {
        return -EINVAL;
    }

    it->second->buffer.write(size, static_cast<size_t>(offset), buffer);
    it->second->dirty = true;

    return static_cast<int>(size);
}

int asymmetricfs::unlink(const char *path_) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = ::unlinkat(root_, relpath.c_str(), 0);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::utimens(const char *path_, const struct timespec tv[2]) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = utimensat(root_, relpath.c_str(), tv, 0);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int asymmetricfs::access(const char *path_, int mode) {
    const std::string path(path_);
    const std::string relpath("." + path);

    int ret = 0;
    if ((mode & R_OK) && !(read_)) {
        // If the file is currently open for reading, grant access normally.
        scoped_lock l(mx_);

        auto it = open_paths_.find(path);
        if (it == open_paths_.end()) {
            // Not open.
            return -EACCES;
        }
        const fd_t fd = it->second;

        auto jit = open_fds_.find(fd);
        if (jit == open_fds_.end()) {
            // open_paths_ and open_fds_ are inconsistent.
            return -EIO;
        }
        const int flags = jit->second->flags;

        if (flags & O_APPEND) {
            // Files open for appending can't be read.
            return -EACCES;
        } else if ((flags & O_CREAT) == 0) {
            // A file opened without O_CREAT implies it existed before, so it
            // cannot be read.
            return -EACCES;
        }

        // Otherwise, fallthrough and check the underlying filesystem.
    }

    int aret = ::faccessat(root_, relpath.c_str(), mode, 0);
    if (aret == 0) {
        return ret;
    } else {
        return -errno;
    }
}
