#ifndef __ASYMMETRICFS__SUBPROCESS_H__
#define __ASYMMETRICFS__SUBPROCESS_H__

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

#include <string>
#include <vector>

class subprocess {
public:
    /**
     * file specifies a command to run (via execvp) and its arguments in argv.
     *
     * A file descriptor for input can be specified in fd_in and for output
     * in fd_out.  If negative, the file descriptor is ignored and a pipe is
     * created.  The pipe is owned by the instance.
     */
    subprocess(int fd_in, int fd_out, const std::string& file,
        const std::vector<std::string>& argv);
    ~subprocess();

    /**
     * The input file descriptor.
     */
    int in();

    /**
     * The output file descriptor.
     */
    int out();

    /**
     * Comparable to Python subprocess' communicate.  Returns the number of
     * bytes read/written remaining the respective size arguments.  The return
     * value is 0 on success, otherwise, errno.
     *
     * It is an error (EINVAL) to specify a write_buffer when subprocess was
     * created with an external (non-pipe) file descriptor.
     */
    int communicate(void *read_buffer, size_t *read_size,
        const void *write_buffer, size_t *write_size);

    /**
     * Wait until the process terminates.  Returns the return exit status code
     * if the program exited normally, otherwise -1.
     */
    int wait();
private:
    pid_t pid_;
    bool finished_;

    bool in_owned_;
    int in_;

    bool out_owned_;
    int out_;

    subprocess(const subprocess &) = delete;
    const subprocess & operator=(const subprocess &) = delete;
};

#endif // __ASYMMETRICFS__SUBPROCESS_H__
