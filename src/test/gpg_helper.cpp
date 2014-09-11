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

#include <boost/algorithm/string/erase.hpp>
#include "gpg_helper.h"
#include <sstream>
#include <string>
#include "subprocess.h"
#include <vector>

key_specification::key_specification() {}

key_specification::key_specification(unsigned key_size_,
    const std::string& name_, const std::string& email_,
    const std::string& comment_) : key_size(key_size_), name(name_),
    email(email_), comment(comment_) {}

gnupg_error::~gnupg_error() {}

gnupg_generation_error::gnupg_generation_error(const std::string& message) :
    what_(message) {}

gnupg_generation_error::~gnupg_generation_error() {}

const std::string& gnupg_generation_error::what() const {
    return what_;
}

gpg_version::gpg_version(int _major, int _minor, int _maintenance) :
    major_(_major), minor_(_minor), maintenance_(_maintenance) {}

gpg_version::gpg_version() {
    std::string buffer(1 << 12, '\0');
    {
        const std::vector<std::string> argv{"gpg", "--version"};

        subprocess p(-1, -1, "gpg", argv);

        size_t buffer_size = buffer.size();

        int ret;
        ret = p.communicate(&buffer[0], &buffer_size, nullptr, nullptr);
        if (ret != 0) {
            throw gnupg_generation_error("Unable to communicate with GPG.");
        }
        // Truncate.  buffer_size now tells us how many bytes are remaining in
        // buffer *after* the actual data.
        buffer.resize(buffer.size() - buffer_size);

        ret = p.wait();
        if (ret != 0) {
            throw gnupg_generation_error("GPG exited with an error.");
        }
    }

    // Expected strings:
    //
    // gpg (GnuPG) 1.4.11
    // gpg (GnuPG) 2.0.25
    int ret = sscanf(buffer.c_str(),
                     "gpg (GnuPG) %d.%d.%d\n", &major_, &minor_, &maintenance_);
    if (ret < 3) {
        throw gnupg_generation_error("Unable to parse version string.");
    }
}

const gpg_version& gpg_version::current() {
    static gpg_version instance;
    return instance;
}

int gpg_version::major() const {
    return major_;
}

int gpg_version::minor() const {
    return minor_;
}

int gpg_version::maintenance() const {
    return maintenance_;
}

bool gpg_version::operator==(const gpg_version& rhs) const {
    return major_ == rhs.major_ && minor_ == rhs.minor_ &&
        maintenance_ == rhs.maintenance_;
}

bool gpg_version::operator<(const gpg_version& rhs) const {
    return major_ < rhs.major_ ||
              (major_ == rhs.major_ &&
                  (minor_ < rhs.minor_ ||
                  (minor_ == rhs.minor_ && maintenance_ < rhs.maintenance_)));
}

gnupg_key::gnupg_key(const key_specification& spec) : spec_(spec),
        public_keyring_(key_directory_.path() / "pubring.gpg"),
        secret_keyring_(key_directory_.path() / "secring.gpg") {
    std::stringstream batch;

    batch << "Key-Type: RSA" << std::endl;
    batch << "Key-Length: " << spec.key_size << std::endl;
    batch << "Subkey-Type: RSA" << std::endl;

    if (!(spec_.name.empty())) {
        batch << "Name-Real: " << spec_.name << std::endl;
    }

    if (!(spec_.email.empty())) {
        batch << "Name-Email: " << spec_.email << std::endl;
    }

    if (!(spec_.comment.empty())) {
        batch << "Name-Comment: " << spec_.comment << std::endl;
    }

    // operator<< quotes the contents of boost::filesystem::path objects,
    // leading GPG to fail.  We convert to a string first, avoiding the
    // automatic quoting.
    batch << "%pubring " << public_keyring_.string() << std::endl;
    batch << "%secring " << secret_keyring_.string() << std::endl;
    batch << "%no-protection" << std::endl;
    batch << "%transient-key" << std::endl;
    batch << "%commit" << std::endl;

    std::string command = batch.str();
    size_t in_size = command.size();

    {
        // Use --quick-random on GPG 1.x and --debug-quick-random on GPG 2.x.
        const std::string quick_random =
            gpg_version::current() < gpg_version(2, 0, 0) ?
            "--quick-random" : "--debug-quick-random";

        const std::vector<std::string> argv{
            "gpg",
            "--gen-key",
            "--batch",
            "--no-tty",
            "--no-default-keyring",
            "--no-permission-warning",
            "--no-options",
            quick_random};
        subprocess p(-1, -1, "gpg", argv);

        int ret;
        ret = p.communicate(nullptr, nullptr, command.c_str(), &in_size);
        if (ret != 0) {
            throw gnupg_generation_error("Unable to communicate with GPG.");
        }

        ret = p.wait();
        if (ret != 0) {
            throw gnupg_generation_error("GPG exited with an error.");
        }
    }

    // Look up key thumbprint.
    std::string buffer(1 << 12, '\0');
    {
        const std::vector<std::string> argv{
            "gpg",
            "--homedir",
            key_directory_.path().string(),
            "--no-permission-warning",
            "--fingerprint"};
        subprocess p(-1, -1, "gpg", argv);

        size_t buffer_size = buffer.size();

        int ret;
        ret = p.communicate(&buffer[0], &buffer_size, nullptr, nullptr);
        if (ret != 0) {
            throw gnupg_generation_error("Unable to communicate with GPG.");
        }
        // Truncate.  buffer_size now tells us how many bytes are remaining in
        // buffer *after* the actual data.
        buffer.resize(buffer.size() - buffer_size);

        ret = p.wait();
        if (ret != 0) {
            throw gnupg_generation_error("GPG exited with an error.");
        }
    }

    const std::string key_size(std::to_string(spec.key_size));
    const std::string key_token = "pub   " + key_size + "R/";
    size_t index = buffer.find(key_token);
    if (index == std::string::npos ||
            index + key_token.size() + 8 > buffer.size()) {
        throw gnupg_generation_error("Unable to locate thumbprint.");
    }

    thumbprint_ = buffer.substr(index + key_token.size(), 8);

    const std::string fingerprint_token("Key fingerprint = ");
    index = buffer.find(fingerprint_token);
    if (index == std::string::npos ||
            index + key_token.size() + 8 > buffer.size()) {
        throw gnupg_generation_error("Unable to locate fingerprint.");
    }
    size_t start = index + fingerprint_token.size();
    size_t eol = buffer.find("\n", start);
    if (eol == std::string::npos) {
        eol = buffer.size();
    }
    // The fingerprint is in groups of 4, separated by spaces.
    fingerprint_ = buffer.substr(start, eol - start);
    boost::algorithm::erase_all(fingerprint_, " ");

    // Configure owner trust for test key.
    {
        const std::string trust(fingerprint_ + ":6:\n");
        const std::vector<std::string> argv{
            "gpg",
            "--homedir",
            key_directory_.path().string(),
            "--no-permission-warning",
            "--import-ownertrust"};
        subprocess p(-1, -1, "gpg", argv);

        size_t buffer_size = trust.size();

        int ret;
        ret = p.communicate(nullptr, nullptr, &trust[0], &buffer_size);
        if (ret != 0) {
            throw gnupg_generation_error("Unable to set owner trust.");
        }

        ret = p.wait();
        if (ret != 0) {
            throw gnupg_generation_error("GPG exited with an error.");
        }
    }
}

gnupg_key::~gnupg_key() {}

boost::filesystem::path gnupg_key::public_keyring() const {
    return public_keyring_;
}

boost::filesystem::path gnupg_key::secret_keyring() const {
    return secret_keyring_;
}

boost::filesystem::path gnupg_key::home() const {
    return key_directory_.path();
}

gpg_recipient gnupg_key::thumbprint() const {
    return gpg_recipient(thumbprint_);
}

const std::string& gnupg_key::fingerprint() const {
    return fingerprint_;
}
