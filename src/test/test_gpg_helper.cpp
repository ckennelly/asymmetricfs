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

#include "gpg_helper.h"
#include <gtest/gtest.h>
#include <string>

TEST(GPG, GenerateKey) {
    key_specification spec;
    spec.key_size = 1024;
    spec.name = "asymmetricfs";
    spec.email = "testing@example.com";
    spec.comment = "FOR TESTING ONLY";

    gnupg_key key(spec);

    // Try to retrieve the key.  gpg_recipient automatically validates the key.
    setenv("GNUPGHOME", key.home().string().c_str(), 1);
    std::string thumbprint;
    EXPECT_NO_THROW({auto r = key.thumbprint(); thumbprint = r;});
    ASSERT_EQ(8u, thumbprint.size());

    std::string fingerprint = key.fingerprint();
    ASSERT_EQ(40u, fingerprint.size());
    EXPECT_EQ(thumbprint, fingerprint.substr(fingerprint.size() - 8u));
}
