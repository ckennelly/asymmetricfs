#ifndef __ASYMMETRICFS__IMPLEMENTATION_H__
#define __ASYMMETRICFS__IMPLEMENTATION_H__

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

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 29
#include <fuse.h>
#include "gpg_recipient.h"
#include "memory_lock.h"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class asymmetricfs {
    struct options {
        options();

        std::vector<gpg_recipient> recipients;
        std::string gpg_path;
        memory_lock mlock;
    };
public:
    asymmetricfs();
    ~asymmetricfs();

    /**
     * Configuration.
     *
     * set_target returns true on success.
     * set_recipients cannot be called if files are open.
     */
    bool set_target(const std::string & target);
    void set_read(bool read);
    void set_recipients(const std::vector<gpg_recipient> & recipients);

    /**
     * set_mlock specifies the memory locking behavior to use.  If set_mlock is
     * not called before use, memory_lock_default is used.
     */
    static const memory_lock memory_lock_default;
    void set_mlock(memory_lock mlock);

    /**
     * set_gpg specifies the path to the GPG binary.  If set_gpg is not called
     * before use, "gpg" in the normal search path is used.
     */
    void set_gpg(const std::string& gpg_path);

    bool ready() const;

    /**
     * Filesystem operations.
     */
    void* init(struct fuse_conn_info *conn);

    int access(const char *path, int mode);
    int chmod(const char *path, mode_t mode);
    int chown(const char *path, uid_t u, gid_t g);
    int create(const char *path, mode_t mode, struct fuse_file_info *info);
    int fgetattr(const char *path, struct stat *buf,
        struct fuse_file_info *info);
    int flush(const char *path, struct fuse_file_info *info);
    int fsync(const char *path, struct fuse_file_info *info);
    int ftruncate(const char *path, off_t offset, struct fuse_file_info *info);
    int getattr(const char *path, struct stat *s);
    int link(const char *oldpath, const char *newpath);
    #ifdef HAS_XATTR
    int listxattr(const char *path, char *buffer, size_t size);
    #endif // HAS_XATTR
    int mkdir(const char *path, mode_t mode);
    int open(const char *path, struct fuse_file_info *info);
    int opendir(const char *path, struct fuse_file_info *info);
    int read(const char *path, void *buffer, size_t size, off_t offset,
        struct fuse_file_info *info);
    int readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *info);
    int readlink(const char *path, char *buffer, size_t size);
    int release(const char * path, struct fuse_file_info *info);
    int releasedir(const char *path, struct fuse_file_info *info);
    #ifdef HAS_XATTR
    int removexattr(const char *path, const char *attr);
    #endif // HAS_XATTR
    int rename(const char *, const char *);
    int rmdir(const char *path);
    #ifdef HAS_XATTR
    int setxattr(const char *path, const char *name, const void *value,
        size_t size, int flags);
    #endif // HAS_XATTR
    int statfs(const char *path, struct statvfs *buf);
    int symlink(const char *oldpath, const char *newpath);
    int truncate(const char *path, off_t offset);
    int unlink(const char *path);
    int utimens(const char *path, const struct timespec tv[2]);
    int write(const char *path, const char *buffer, size_t size, off_t offset,
        struct fuse_file_info *info);
private:
    typedef uint64_t fd_t;
    fd_t next_fd();

    bool read_;
    bool root_set_;
    int root_;

    options options_;

    /**
     * This protects all internal data structures.
     */
    std::mutex mx_;

    fd_t next_;
    typedef std::unordered_map<std::string, fd_t> open_map_t;
    open_map_t open_paths_;

    class internal;
    typedef std::unordered_map<fd_t, internal *> open_fd_map_t;
    open_fd_map_t open_fds_;

    /**
     * A mapping from directory handles to their opened paths.
     */
    std::unordered_map<uint64_t, std::string> open_dirs_;

    /**
     * Stats an open internal fd.  The caller should hold a lock.
     */
    int statfd(fd_t fd, struct stat *buf);

    /**
     * Truncates an open internal fd.  The caller should hold a lock.
     */
    int truncatefd(fd_t fd, off_t offset);

    int make_rdwr(int flags) const;

    asymmetricfs(const asymmetricfs &) = delete;
    const asymmetricfs & operator=(const asymmetricfs &) = delete;
};

#endif // __ASYMMETRICFS__IMPLEMENTATION_H__
