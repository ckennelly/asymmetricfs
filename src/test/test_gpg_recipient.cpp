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

#include "gpg_recipient.h"
#include <gtest/gtest.h>
#include "test/file_descriptors.h"

TEST(GPGRecipientTest, NoDescriptorsLeaked) {
    // Verify we do not leak descriptors when using gpg_recipient.
    auto starting = get_file_descriptors();

    // TODO:  While implausible, it's possible this is a valid key in someone's
    // public keyring (pgp.mit.edu says there are two, in fact), so we should
    // validate with an empty keyring.
    gpg_recipient g("0x00000000");
    EXPECT_THROW(g.validate("gpg"), invalid_gpg_recipient);

    auto ending = get_file_descriptors();

    // Verify open file descriptors are unchanged.
    EXPECT_EQ(starting, ending);
}
