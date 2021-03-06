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

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <gtest/gtest.h>
#include "memory_lock.h"
#include "page_buffer.h"
#include "pthread.h"
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#ifdef HAS_VALGRIND
#include <valgrind/memcheck.h>
#endif

constexpr static size_t page_size = 4096;

std::string make_data(size_t size) {
    std::string ret(size, '\0');
    for (size_t i = 0; i < size; i++) {
        ret[i] = char(i);
    }
    return ret;
}

class Pipe {
public:
    Pipe() : reader_open(true), writer_open(true) {
        int ret = pipe(fds);
        EXPECT_EQ(0, ret);
    }

    ~Pipe() {
        close_reader();
        close_writer();
    }

    int read() { return fds[0]; }
    int write() { return fds[1]; }

    bool eof() {
        char tmp[1];

        return ::read(read(), tmp, sizeof(tmp)) == 0;
    }

    // Helpers to close fds early.
    void close_reader() {
        if (reader_open) {
            close(fds[0]);
            reader_open = false;
        }
    }

    void close_writer() {
        if (writer_open) {
            close(fds[1]);
            writer_open = false;
        }
    }
private:
    int fds[2];
    bool reader_open;
    bool writer_open;
};

class AsynchronousReader {
public:
    AsynchronousReader(std::function<void ()> f) : f_(f){
        int ret = pthread_create(
            &thread_, nullptr, AsynchronousReader::helper, this);
        if (ret != 0) {
            throw std::runtime_error("Unable to create thread.");
        }
    }

    ~AsynchronousReader() {
        (void) pthread_join(thread_, nullptr);
    }
private:
    static void* helper(void* arg) {
        static_cast<AsynchronousReader*>(arg)->f_();
        return nullptr;
    }

    std::function<void ()> f_;
    pthread_t thread_;
};

class PageBufferTest : public ::testing::Test {
public:
    PageBufferTest() : buffer(memory_lock::none) {}

    page_buffer buffer;
};

TEST_F(PageBufferTest, Write) {
    char data[128];
    for (unsigned i = 0; i < sizeof(data); i++) {
        data[i] = static_cast<char>(i);
    }

    buffer.write(sizeof(data), 4096, data);
    EXPECT_EQ(4096 + sizeof(data), buffer.size());

    buffer.write(sizeof(data), 8192, data);
    EXPECT_EQ(8192 + sizeof(data), buffer.size());

    buffer.write(sizeof(data),    0, data);
    EXPECT_EQ(8192 + sizeof(data), buffer.size());
}

TEST_F(PageBufferTest, ReadBlank) {
    const size_t length = 8192 + 1;

    std::string tmp(length, '\1');
    void* ptr = &tmp[0];
    size_t bytes_read = buffer.read(length, 0, ptr);

    EXPECT_EQ(0, bytes_read);
}

TEST_F(PageBufferTest, Overread) {
    const size_t length = 8192 + 1;

    const std::string expected("abcdef");
    buffer.write(expected.size(), 0, &expected[0]);

    std::string tmp(length, '\1');
    #ifdef HAS_VALGRIND
    VALGRIND_MAKE_MEM_UNDEFINED(&tmp[0], length);
    #endif

    void* ptr = &tmp[0];
    size_t bytes_read = buffer.read(length, 0, ptr);

    EXPECT_EQ(expected.size(), bytes_read);
    tmp.resize(expected.size());
    EXPECT_EQ(expected, tmp);
}

TEST_F(PageBufferTest, OverreadNoOverlap) {
    std::string tmp(page_size, 'a');
    buffer.write(tmp.size(), 0, &tmp[0]);
    ASSERT_EQ(tmp.size(), buffer.size());

    size_t ret;
    ret = buffer.read(tmp.size(), buffer.size(), &tmp[0]);
    ASSERT_EQ(0, ret);

    ret = buffer.read(tmp.size(), 2 * buffer.size(), &tmp[0]);
    ASSERT_EQ(0, ret);
}

static char mapping(size_t offset) {
    return static_cast<char>(offset);
}

TEST_F(PageBufferTest, VerifyContents) {
    int steps = 20;
    unsigned seed = 5;
    unsigned max_size = 16;

    std::string expected;

    for (int step = 0; step < steps; step++) {
        const unsigned offset =
            static_cast<unsigned>(rand_r(&seed)) % max_size;
        const unsigned size = std::min(max_size - offset,
            static_cast<unsigned>(rand_r(&seed)));

        /* Generate some data to apply. */
        std::string patch(size, '\0');
        for (unsigned j = 0; j < size; j++) {
            patch[j] = mapping(j);
        }

        /* Apply patch to expected. */
        expected.resize(std::max(expected.size(),
            static_cast<size_t>(offset + size)));
        expected = expected.substr(0, offset) + patch +
            expected.substr(offset + size);

        /* Apply patch to buffer. */
        buffer.write(size, offset, &patch[0]);

        /* Verify results at a random offset. */
        ASSERT_EQ(expected.size(), buffer.size());

        const size_t verify_offset =
            static_cast<unsigned>(rand_r(&seed)) % expected.size();
        const size_t verify_size   = std::min(
            expected.size() - verify_offset,
            static_cast<unsigned>(rand_r(&seed)) % expected.size());

        std::string expect_hunk = expected.substr(verify_offset, verify_size);
        std::string actual_hunk(verify_size, '\0');
        buffer.read(verify_size, verify_offset, &actual_hunk[0]);
        EXPECT_EQ(expect_hunk, actual_hunk);
    }
}

TEST_F(PageBufferTest, ReadMiddleAllocationWholePage) {
    const std::string data = make_data(2 * page_size);

    buffer.write(data.size(), 0, &data[0]);
    EXPECT_EQ(data.size(), buffer.size());

    std::string tmp(page_size, '\0');
    buffer.read(tmp.size(), page_size, &tmp[0]);
    EXPECT_EQ(data.substr(page_size), tmp);
}

TEST_F(PageBufferTest, ReadMiddleAllocationPartialPage) {
    const size_t offset = 1024;
    const std::string data = make_data(page_size + offset);

    buffer.write(data.size(), 0, &data[0]);
    EXPECT_EQ(data.size(), buffer.size());

    std::string tmp(offset, '\0');
    buffer.read(tmp.size(), page_size, &tmp[0]);
    EXPECT_EQ(data.substr(page_size), tmp);
}

TEST_F(PageBufferTest, Resize) {
    std::string data = make_data(256);

    buffer.write(data.size(), 0, &data[0]);
    EXPECT_EQ(data.size(), buffer.size());

    buffer.resize(128);
    data.resize(128);
    EXPECT_EQ(data.size(), buffer.size());

    std::string tmp(128, '\0');
    buffer.read(tmp.size(), 0, &tmp[0]);
    EXPECT_EQ(data, tmp);
}

TEST_F(PageBufferTest, ResizeTriggeringFree) {
    size_t offset = 4096;
    std::string data = make_data(4096);

    buffer.write(data.size(), offset, &data[0]);
    EXPECT_EQ(offset + data.size(), buffer.size());

    std::string tmp(offset + data.size(), '\0');
    size_t ret;

    ret = buffer.read(tmp.size(), 0, &tmp[0]);
    EXPECT_EQ(tmp.size(), ret);
    EXPECT_EQ(std::string(offset, '\0') + data, tmp);

    buffer.resize(offset);

    EXPECT_EQ(offset, buffer.size());
    tmp.assign(offset, '\1');
    ret = buffer.read(tmp.size(), 0, &tmp[0]);
    EXPECT_EQ(std::string(offset, '\0'), tmp);
}

TEST_F(PageBufferTest, Clear) {
    size_t offset = 4096;
    std::string data = make_data(4096);

    buffer.write(data.size(), offset, &data[0]);
    EXPECT_EQ(offset + data.size(), buffer.size());

    buffer.clear();
    EXPECT_EQ(0u, buffer.size());
}

TEST_F(PageBufferTest, LargeGap) {
    Pipe loop;

    const size_t n_pages = 1024;
    std::string data(4096, 'a');
    buffer.write(data.size(), 4096 * (n_pages - 1), &data[0]);

    // The pipe we are writing to will quickly fill up, so we need to read
    // asynchronously.
    bool status = false;
    {
        AsynchronousReader a([&loop, n_pages, &status](){
            std::string tmp(4096, '\0');

            const std::string zero(4096, '\0');
            const std::string final(4096, 'a');

            // Read data of the pipe and verify the contents.
            for (size_t i = 0; i < n_pages; i++) {
                ssize_t read_bytes;
                do {
                    read_bytes = read(loop.read(), &tmp[0], tmp.size());
                } while (read_bytes == 0);
                EXPECT_EQ(tmp.size(), read_bytes);

                status |= tmp != (i < n_pages - 1 ? zero : final);
            }
        });

        ssize_t ret = buffer.splice(loop.write(), 0);
        EXPECT_EQ(n_pages * data.size(), ret);
        loop.close_writer();
    }

    EXPECT_FALSE(status);
}

TEST_F(PageBufferTest, LargeFile) {
    Pipe loop;

    const size_t n_pages = 1024;
    std::string data(4096, '\0');
    for (size_t i = 0; i < n_pages; i++) {
        memcpy(&data[0], &i, sizeof(i));
        memcpy(&data[data.size() - sizeof(i)], &i, sizeof(i));
        buffer.write(data.size(), 4096 * i, &data[0]);
    }

    // The pipe we are writing to will quickly fill up, so we need to read
    // asynchronously.
    bool status = false;
    {
        AsynchronousReader a([&loop, n_pages, &status](){
            std::string tmp(4096, '\0');

            // Read data of the pipe and verify the contents.
            for (size_t i = 0; i < n_pages; i++) {
                ssize_t read_bytes;
                do {
                    read_bytes = read(loop.read(), &tmp[0], tmp.size());
                    if (read_bytes == 0) {
                        sleep(1);
                    }
                } while (read_bytes == 0);
                EXPECT_EQ(tmp.size(), read_bytes);

                size_t start, end;
                memcpy(&start, &tmp[0], sizeof(start));
                memcpy(&end, &tmp[tmp.size() - sizeof(end)], sizeof(end));

                status |= (i != start);
                status |= (i != end);
            }
        });

        ssize_t ret = buffer.splice(loop.write(), 0);
        EXPECT_EQ(n_pages * data.size(), ret);
        loop.close_writer();
    }

    EXPECT_FALSE(status);
}

TEST_F(PageBufferTest, LargeBuffer) {
    const size_t n_pages = 16040;
    const size_t pages_per_chunk = 8;

    std::string tmp(page_size * pages_per_chunk, '\0');
    for (size_t i = 0; i < n_pages; i += pages_per_chunk) {
        for (size_t j = 0; j < pages_per_chunk; j++) {
            size_t v = i + j;
            memcpy(&tmp[page_size * j], &v, sizeof(v));
        }
        EXPECT_EQ(page_size * i, buffer.size());
        buffer.write(tmp.size(), buffer.size(), &tmp[0]);
    }

    tmp.resize(page_size);
    for (size_t i = 0; i < n_pages; i++) {
        size_t ret = buffer.read(tmp.size(), page_size * i, &tmp[0]);
        EXPECT_EQ(tmp.size(), ret);

        size_t v;
        memcpy(&v, &tmp[0], sizeof(v));
        EXPECT_EQ(i, v);
    }
}

// The parameter is the number of set bytes.
class PageBufferSpliceTest : public ::testing::TestWithParam<unsigned>  {
public:
    PageBufferSpliceTest() : buffer(memory_lock::none) {}

    page_buffer buffer;
    Pipe loop;
};

// All data will appear the start of the buffer.
TEST_P(PageBufferSpliceTest, ContiguousStart) {
    const std::string data = make_data(GetParam());

    buffer.write(data.size(), 0, &data[0]);
    EXPECT_EQ(data.size(), buffer.size());

    ssize_t ret = buffer.splice(loop.write(), 0);
    EXPECT_EQ(data.size(), ret);
    loop.close_writer();

    // Read data of the pipe and verify the contents.
    std::string tmp(data.size(), '\0');
    ssize_t read_bytes = read(loop.read(), &tmp[0], tmp.size());
    EXPECT_EQ(data.size(), read_bytes);
    EXPECT_EQ(data, tmp);

    // Check EOF.
    EXPECT_TRUE(loop.eof());
}

TEST_P(PageBufferSpliceTest, SpliceOverMultipleAllocations) {
    const std::string data = make_data(GetParam());
    size_t offset;
    for (offset = 0; offset + page_size <= data.size(); offset += page_size) {
        buffer.write(page_size, offset, &data[offset]);
    }
    // Write tail, if any.
    if (offset < data.size()) {
        buffer.write(data.size() - offset, offset, &data[offset]);
    }

    EXPECT_EQ(data.size(), buffer.size());

    // Splice across several allocations.
    ssize_t ret = buffer.splice(loop.write(), 0);
    EXPECT_EQ(data.size(), ret);
    loop.close_writer();

    // Read data of the pipe and verify the contents.
    std::string tmp(data.size(), '\0');
    ssize_t read_bytes = read(loop.read(), &tmp[0], tmp.size());
    EXPECT_EQ(data.size(), read_bytes);
    EXPECT_EQ(data, tmp);

    // Check EOF.
    EXPECT_TRUE(loop.eof());
}

// Data will be prefixed by an empty page.
TEST_P(PageBufferSpliceTest, EmptyPageStart) {
    size_t offset = 4096;
    size_t length = GetParam();
    if (length == 0) {
        // If we do not write anything, the initial page will not be implicitly
        // initialized via the sparseness of the buffer, so buffer.size() == 0.
        return;
    }

    const std::string data = make_data(length);

    buffer.write(data.size(), offset, &data[0]);
    EXPECT_EQ(offset + data.size(), buffer.size());

    ssize_t ret = buffer.splice(loop.write(), 0);
    EXPECT_EQ(offset + data.size(), ret);
    loop.close_writer();

    // Read data of the pipe and verify the contents.
    std::string tmp(offset + data.size(), '\0');
    ssize_t read_bytes = read(loop.read(), &tmp[0], tmp.size());
    EXPECT_EQ(offset + data.size(), read_bytes);
    EXPECT_EQ(std::string(offset, '\0') + data, tmp);

    // Check EOF.
    EXPECT_TRUE(loop.eof());
}

// Data is written, a two page gap is inserted (ensuring there is at least one
// empty page between writes), and more data is written.
TEST_P(PageBufferSpliceTest, DataGap) {
    size_t gap = 8192;
    size_t length = GetParam();

    const std::string data = make_data(length);

    buffer.write(data.size(), 0, &data[0]);
    buffer.write(data.size(), data.size() + gap, &data[0]);
    if (length == 0) {
        // There will be no data on either side, so the entire buffer will be
        // empty.
        EXPECT_EQ(0, buffer.size());
        return;
    }

    EXPECT_EQ(gap + 2* data.size(), buffer.size());

    ssize_t ret = buffer.splice(loop.write(), 0);
    EXPECT_EQ(gap + 2 * data.size(), ret);
    loop.close_writer();

    // Read data of the pipe and verify the contents.
    std::string tmp(gap + 2 * data.size(), '\0');
    ssize_t read_bytes = read(loop.read(), &tmp[0], tmp.size());
    EXPECT_EQ(gap + 2 * data.size(), read_bytes);
    EXPECT_EQ(data + std::string(gap, '\0') + data, tmp);

    // Check EOF.
    EXPECT_TRUE(loop.eof());
}

INSTANTIATE_TEST_CASE_P(Splicing, PageBufferSpliceTest,
    ::testing::Values(0u, 128u, 4096u, 8192u, 8320u));

// The parameter is the memory locking strategy.
class PageBufferMemoryLockTest :
        public ::testing::TestWithParam<memory_lock>  {
public:
    PageBufferMemoryLockTest() : buffer(GetParam()) {}

    page_buffer buffer;
};

TEST_P(PageBufferMemoryLockTest, ReadWrite) {
    std::string data = make_data(4096);

    buffer.write(data.size(), 0, &data[0]);
    EXPECT_EQ(data.size(), buffer.size());

    std::string tmp(data.size(), '\1');
    #ifdef HAS_VALGRIND
    VALGRIND_MAKE_MEM_UNDEFINED(&tmp[0], data.size());
    #endif
    size_t ret = buffer.read(tmp.size(), 0, &tmp[0]);
    EXPECT_EQ(data.size(), ret);
    EXPECT_EQ(data, tmp);
}

// A helper class for temporary changing resource limits.
class scoped_rlimit {
public:
    scoped_rlimit(int resource, rlim_t value) : resource_(resource) {
        int ret = getrlimit(resource, &old_);
        if (ret != 0) {
            throw std::runtime_error("Unable to retrieve resource limit.");
        }

        struct rlimit r;
        r.rlim_cur = value;
        r.rlim_max = old_.rlim_max;
        ret = setrlimit(resource, &r);
        if (ret != 0) {
            throw std::runtime_error("Unable to set resource limit.");
        }
    }

    ~scoped_rlimit() {
        // We cannot throw in a destructor, so the error is suppressed.
        (void) setrlimit(resource_, &old_);
    }
private:
    int resource_;
    struct rlimit old_;
};

TEST_P(PageBufferMemoryLockTest, NoLockablePages) {
    scoped_rlimit lim(RLIMIT_MEMLOCK, 0);

    std::string data = make_data(4096);

    if (GetParam() != memory_lock::none) {
        EXPECT_THROW(buffer.write(data.size(), 0, &data[0]), std::bad_alloc);
    } else {
        EXPECT_NO_THROW(buffer.write(data.size(), 0, &data[0]));
        EXPECT_EQ(data.size(), buffer.size());

        std::string tmp(data.size(), '\1');
        #ifdef HAS_VALGRIND
        VALGRIND_MAKE_MEM_UNDEFINED(&tmp[0], data.size());
        #endif
        size_t ret = buffer.read(tmp.size(), 0, &tmp[0]);
        EXPECT_EQ(data.size(), ret);
        EXPECT_EQ(data, tmp);
    }
}

INSTANTIATE_TEST_CASE_P(Locking, PageBufferMemoryLockTest,
    ::testing::Values(memory_lock::all,
                      memory_lock::buffers,
                      memory_lock::none));

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
