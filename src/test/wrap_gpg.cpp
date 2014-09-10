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
#include "test/file_descriptors.h"
#include <unistd.h>

// This program wraps GPG and ensures that startup occurs with only 3 open file
// descriptors.
int main(int argc, char **argv) {
    (void) argc;

    auto fds = get_file_descriptors(false);
    for (const auto& fd : fds ){
        std::cerr << fd.first << " -> " << fd.second << std::endl;
    }

    if (fds.size() > 3) {
        return 1;
    }

    char gpg[] = "gpg";
    argv[0] = gpg;
    return execvp("gpg", argv);
}
