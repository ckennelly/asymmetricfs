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

#include <boost/program_options.hpp>
#include <cstring>
#include "implementation.h"
#include <iostream>
#include <stdexcept>
#include <sys/prctl.h>

static asymmetricfs impl;

static int helper_access(const char *path, int mode) {
    return impl.access(path, mode);
}

static int helper_chmod(const char *path, mode_t mode) {
    return impl.chmod(path, mode);
}

static int helper_chown(const char *path, uid_t u, gid_t g) {
    return impl.chown(path, u, g);
}

static int helper_create(const char *path, mode_t mode,
        struct fuse_file_info *info) {
    return impl.create(path, mode, info);
}

static int helper_ftruncate(const char *path, off_t offset,
        struct fuse_file_info *info) {
    return impl.ftruncate(path, offset, info);
}

static int helper_getattr(const char *path, struct stat *s) {
    return impl.getattr(path, s);
}

static void* helper_init(struct fuse_conn_info *conn) {
    return impl.init(conn);
}

static int helper_link(const char *oldpath, const char *newpath) {
    return impl.link(oldpath, newpath);
}

static int helper_mkdir(const char *path, mode_t mode) {
    return impl.mkdir(path, mode);
}

static int helper_open(const char *path, struct fuse_file_info *info) {
    return impl.open(path, info);
}

static int helper_opendir(const char *path, struct fuse_file_info *info) {
    return impl.opendir(path, info);
}

static int helper_read(const char *path, char *buffer, size_t size,
        off_t offset, struct fuse_file_info *info) {
    return impl.read(path, buffer, size, offset, info);
}

static int helper_readdir(const char *path, void * v, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info * info) {
    return impl.readdir(path, v, filler, offset, info);
}

static int helper_readlink(const char *path, char *buffer, size_t size) {
    return impl.readlink(path, buffer, size);
}

static int helper_release(const char *path, struct fuse_file_info *info) {
    return impl.release(path, info);
}

static int helper_releasedir(const char *path, struct fuse_file_info *info) {
    return impl.releasedir(path, info);
}

static int helper_rename(const char *oldpath, const char *newpath) {
    return impl.rename(oldpath, newpath);
}

static int helper_rmdir(const char *path) {
    return impl.rmdir(path);
}

static int helper_statfs(const char *path, struct statvfs *buf) {
    return impl.statfs(path, buf);
}

static int helper_symlink(const char *oldpath, const char *newpath) {
    return impl.symlink(oldpath, newpath);
}

static int helper_truncate(const char *path, off_t offset) {
    return impl.truncate(path, offset);
}

static int helper_unlink(const char *path) {
    return impl.unlink(path);
}

static int helper_utimens(const char *path, const struct timespec tv[2]) {
    return impl.utimens(path, tv);
}

static int helper_write(const char *path, const char *buffer, size_t size,
        off_t offset, struct fuse_file_info *info) {
    return impl.write(path, buffer, size, offset, info);
}

#ifdef HAS_XATTR
static int helper_listxattr(const char *path, char *buffer, size_t size) {
    return impl.listxattr(path, buffer, size);
}

static int helper_removexattr(const char *path, const char *name) {
    return impl.removexattr(path, name);
}

static int helper_setxattr(const char *path, const char *name,
        const char *value, size_t size, int flags) {
    return impl.setxattr(path, name, value, size, flags);
}
#endif // HAS_XATTR

#define STRINGIFY(X) #X
#define STR(X) STRINGIFY(X)

int main(int argc, char **argv) {
    namespace po = boost::program_options;

    typedef std::vector<gpg_recipient> RecipientList;
    RecipientList recipients;
    std::string gpg_path;
    std::string target;
    std::string mount_point;

    po::options_description visible("Options");
    visible.add_options()
        ("help",    "Provides this help message.")
        ("rw",          po::value<bool>()->zero_tokens(), "Read-write mode.")
        ("wo",          po::value<bool>()->zero_tokens(), "Write-only mode.")
        ("gpg-binary",
            po::value<std::string>(&gpg_path)->default_value(STR(GPG_PATH)),
            "Path to GPG binary.")
        ("recipient,r", po::value<RecipientList>(&recipients)->required(), "Key to encrypt to.");

    po::options_description hidden("Hidden Options");
    hidden.add_options()
        ("enable-core-dumps", po::value<bool>()->zero_tokens(),
            "Enable core dumps / debugging")
        ("target",      po::value<std::string>(&target), "Backing directory")
        ("mount-point", po::value<std::string>(&mount_point), "Mount point");

    po::options_description desc;
    desc.add(visible).add(hidden);

    po::positional_options_description p;
    p.add("target", 1).add("mount-point", 1);

    po::variables_map vm;
    std::vector<std::string> unrecognized;
    std::vector<std::string> errors;

    bool usage;
    try {
        po::parsed_options parsed = po::command_line_parser(argc, argv)
            .options(desc).positional(p).allow_unregistered().run();
        po::store(parsed, vm);
        po::notify(vm);

        // Validate recipients now that gpg_path has been parsed.
        for (const auto& r : recipients) {
            r.validate(gpg_path);
        }

        unrecognized =
            collect_unrecognized(parsed.options, po::exclude_positional);
        usage = vm.count("help");
    } catch (std::exception & ex) {
        errors.push_back(ex.what());
    }

    const bool read = vm.count("rw");
    const bool wo   = vm.count("wo");
    if (read && wo) {
        errors.push_back("--rw and --wo are mutually exclusive.");
    } else if (!(read || wo)) {
        errors.push_back("--rw or --wo must be specified.");
    }

    impl.set_gpg(gpg_path);
    impl.set_read(read);
    impl.set_recipients(recipients);
    if (errors.empty()) {
        if (target.empty()) {
            errors.push_back("Target not specified.");
        } else if (!(impl.set_target(target))) {
            errors.push_back("Target is invalid.");
        }

        if (mount_point.empty()) {
            errors.push_back("Mount point not specified.");
        }
    }

    assert(usage || !(errors.empty()) || impl.ready());
    if (!(errors.empty())) {
        const size_t n_errors = errors.size();
        for (size_t i = 0; i < n_errors; i++) {
            std::cerr << errors[i] << std::endl;
        }
        std::cerr << std::endl;

        usage = true;
    }

    if (usage) {
        std::cout << "Usage: " << basename(argv[0]) <<
            " [options] target mount-point" << std::endl << visible <<
            std::endl;
        return 1;
    }

    /* Build argument list to pass into FUSE. */
    std::vector<char *> fuse_argv;
    const size_t n_unrecognized = unrecognized.size();
    const int fuse_argc = static_cast<int>(n_unrecognized) + 2;
    fuse_argv.resize(n_unrecognized + 3);

    fuse_argv[0] = argv[0];

    /*
     * The lifetime of these strings is at least as long as the call to
     * fuse_main.
     */
    for (size_t i = 0; i < n_unrecognized; i++) {
        fuse_argv[i + 1] = const_cast<char *>(unrecognized[i].c_str());
    }
    fuse_argv[n_unrecognized + 1] = const_cast<char *>(mount_point.c_str());
    fuse_argv[n_unrecognized + 2] = NULL;

    struct fuse_operations ops;
    memset(&ops, 0, sizeof(ops));
    ops.access      = helper_access;
    ops.chmod       = helper_chmod;
    ops.chown       = helper_chown;
    ops.create      = helper_create;
    ops.ftruncate   = helper_ftruncate;
    ops.getattr     = helper_getattr;
    ops.init        = helper_init;
    ops.link        = helper_link;
    ops.mkdir       = helper_mkdir;
    ops.open        = helper_open;
    ops.opendir     = helper_opendir;
    ops.read        = helper_read;
    ops.readdir     = helper_readdir;
    ops.readlink    = helper_readlink;
    ops.release     = helper_release;
    ops.releasedir  = helper_releasedir;
    ops.rename      = helper_rename;
    ops.rmdir       = helper_rmdir;
    ops.statfs      = helper_statfs;
    ops.symlink     = helper_symlink;
    ops.truncate    = helper_truncate;
    ops.unlink      = helper_unlink;
    ops.utimens     = helper_utimens;
    ops.write       = helper_write;

    #ifdef HAS_XATTR
    ops.listxattr   = helper_listxattr;
    ops.removexattr = helper_removexattr;
    ops.setxattr    = helper_setxattr;
    #endif // HAS_XATTR

    ops.flag_nullpath_ok = 1;
    #if FUSE_VERSION >= 29
    ops.flag_nopath = 1;
    ops.flag_utime_omit_ok = 1;
    #endif

    // Disable core dumps.
    if (vm.count("enable-core-dumps") == 0) {
        int ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        if (ret == -1) {
            std::cerr << "Unable to disable core dumps." << std::endl
                      << "Run with --enable-core-dumps to continue without "
                         "this measure." << std::endl;
            return 1;
        }
    }

    return fuse_main(fuse_argc, fuse_argv.data(), &ops, NULL);
}
