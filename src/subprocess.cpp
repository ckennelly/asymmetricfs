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

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "subprocess.h"
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

subprocess::subprocess(int fd_in, int fd_out, const std::string& file,
        const std::vector<std::string>& argv) : finished_(false) {
    fflush(stdout);

    int pipes_in[2];
    pipe(pipes_in);

    int pipes_out[2];
    pipe(pipes_out);

    pid_ = fork();
    if (pid_ == -1) {
        std::string error("Unable to fork.");
        throw std::runtime_error(error);
    } else if (pid_ == 0) {
        /* child. */
        if (fd_in >= 0) {
            /* use fd_in argument. */
            dup2(fd_in, STDIN_FILENO);
            if (fd_in != STDIN_FILENO) {
                close(fd_in);
            }
        } else {
            /* use pipe. */
            dup2(pipes_in[0], STDIN_FILENO);
            close(pipes_in[0]);
        }
        close(pipes_in[0]);
        close(pipes_in[1]);

        if (fd_out >= 0) {
            /* use fd_in argument. */
            dup2(fd_out, STDOUT_FILENO);
            if (fd_out != STDOUT_FILENO) {
                close(fd_out);
            }
        } else {
            /* use pipe. */
            dup2(pipes_out[1], STDOUT_FILENO);
        }

        close(pipes_out[0]);
        close(pipes_out[1]);

        std::vector<char *> argptrs;
        for (const auto& v : argv) {
            argptrs.push_back(const_cast<char *>(v.c_str()));
        }
        argptrs.push_back(nullptr);
        execvp(file.c_str(), argptrs.data());
    } else {
        /* parent. */
        if (fd_in >= 0) {
            in_ = fd_in;
            close(pipes_in[1]);
            in_owned_ = false;
        } else {
            in_ = pipes_in[1];
            in_owned_ = true;
        }
        close(pipes_in[0]);

        if (fd_out >= 0) {
            out_ = fd_out;
            close(pipes_out[0]);
            out_owned_ = false;
        } else {
            out_ = pipes_out[0];
            out_owned_ = true;
        }
        close(pipes_out[1]);
    }
}

subprocess::~subprocess() {
    wait();
}

int subprocess::in() {
    return in_;
}

int subprocess::out() {
    return out_;
}

int subprocess::wait() {
    if (finished_) {
        return 0;
    }

    /*
     * Typically, this will be called in the destructor, so throwing an
     * exception when an error occurs may be problematic.
     *
     * If these are owned, they are pipes, so we do not expect to see issues
     * with bad file descriptors or IO errors.
     */
    if (in_owned_) {
        (void) close(in_);
    }

    if (out_owned_) {
        (void) close(out_);
    }

    int status;
    (void) waitpid(pid_, &status, 0);
    finished_ = true;

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
        return -1;
    }
}

int subprocess::communicate(void *read_buffer_, size_t *read_size,
        const void *write_buffer_, size_t *write_size) {
          char *read_buffer  = static_cast<      char *>(read_buffer_);
    const char *write_buffer = static_cast<const char *>(write_buffer_);

    fd_set read_fds, write_fds;

    size_t read_remaining  = read_size  ? *read_size  : 0;
    size_t write_remaining = write_size ? *write_size : 0;
    if (!(in_owned_) && write_remaining > 0) {
        return EINVAL;
    }

    while (read_remaining || write_remaining) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        int nfd = -1;
        if (write_remaining) {
            FD_SET(in_, &write_fds);
            nfd = std::max(nfd, in_);
        }

        if (read_remaining) {
            FD_SET(out_, &read_fds);
            nfd = std::max(nfd, out_);
        }

        int ret = select(nfd + 1, &read_fds, &write_fds, NULL, NULL);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }

            return errno;
        }

        if (write_remaining && FD_ISSET(in_, &write_fds)) {
            ssize_t wret = write(in_, write_buffer, write_remaining);
            if (wret < 0 && errno != EINTR) {
                return errno;
            } else if (wret > 0) {
                /* Advance. */
                size_t uret     = static_cast<size_t>(wret);
                write_buffer    += uret;
                write_remaining -= uret;
                *write_size     = write_remaining;

                if (write_remaining == 0) {
                    in_owned_ = false;
                    close(in_);
                }
            }

            /* If wret == 0, we do not make progress. */
        }

        if (read_remaining && FD_ISSET(out_, &read_fds)) {
            ssize_t rret = read(out_, read_buffer, read_remaining);
            if (rret < 0 && errno != EINTR) {
                return errno;
            } else if (rret == 0) {
                return 0;
            } else if (rret > 0) {
                /* Advance. */
                size_t uret     = static_cast<size_t>(rret);
                read_buffer     += uret;
                read_remaining  -= uret;
                *read_size      = read_remaining;
            }
        }
    }

    return 0;
}
