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
#include <cassert>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include "page_buffer.h"
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef HAS_VALGRIND
#include <valgrind/memcheck.h>
#endif
#include <vector>

namespace {

// flush_iov iteratively calls vmsplice to process all of the data specified in
// the io vector.  It mutates the vector with its progress.
ssize_t flush_iov(int fd, std::vector<iovec>* ios, unsigned int flags) {
    const size_t n_ios = ios->size();
    iovec* v = &(*ios)[0];

    for (size_t index = 0; index < n_ios; ) {
        ssize_t ret = vmsplice(fd, v + index, n_ios - index, flags);
        if (ret == -1) {
            return ret;
        }

        // Advance long the iovec instances for the number of bytes read.
        for (size_t bytes = static_cast<size_t>(ret);
                index < n_ios && bytes > 0; ) {
            size_t len = std::min(v[index].iov_len, bytes);

            v[index].iov_len -= len;
            bytes -= len;
            if (v[index].iov_len == 0) {
                // Move to the next allocation.
                index++;
            } else {
                // Advance within this allocation.
                v[index].iov_base =
                    static_cast<uint8_t*>(v[index].iov_base) + len;
            }
        }
    }

    return 0;
}

/* This splices in zero pages into fd, returning the value from vmsplice. */
ssize_t zero_splice(int fd, size_t size, unsigned int flags) {
    // Clean up flags, as we're going to reuse the same allocation many times.
    flags &= ~unsigned(SPLICE_F_GIFT);

    const size_t max_allocation = 1 << 20 /* 1MB */;
    size_t allocation_size = std::min(size, max_allocation);

    page_allocation tmp(allocation_size, memory_lock::none);
    size_t position;
    for (position = 0; position < size; ) {
        std::vector<iovec> ios;
        while (ios.size() < IOV_MAX && position < size) {
            iovec v;
            v.iov_base = tmp.ptr();
            v.iov_len = std::min(tmp.size(), size - position);
            ios.push_back(v);

            position += v.iov_len;
        }
        assert(position <= size);

        ssize_t ret = flush_iov(fd, &ios, flags);
        if (ret < 0) {
            return ret;
        }
    }

    return static_cast<ssize_t>(position);
}

template<typename T>
static auto find_block(T& m, size_t key) -> decltype(m.find(key)) {
    if (m.empty()) {
        return m.end();
    }

    auto it = m.lower_bound(key);
    if (it != m.end()) {
        if (it->first <= key) {
            return it;
        }

        // As we are going to decrement the pointer, return early if it would
        // not be safe to do so.  Callers will zero-fill blocks between key and
        // it->first.
        if (it == m.begin()) {
            return it;
        }
    }

    // This operation is safe, as m.size() > 0.
    assert(it != m.begin());
    --it;
    assert(it->first <= key);
    return it;
}

}  // namespace

page_allocation::page_allocation(size_t sz, memory_lock m) : size_(sz) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    switch (m) {
        case memory_lock::all:
        case memory_lock::buffers:
            flags |= MAP_LOCKED;
            break;
        case memory_lock::none:
            break;
    }

    ptr_ = mmap(NULL, size_, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (ptr_ == MAP_FAILED) {
        throw std::bad_alloc();
    }
}

page_allocation::~page_allocation() {
    if (ptr_) {
        #ifdef HAS_VALGRIND
        // Annotate ptr_ to be initialized, since this operation is safe even
        // when it has not been, leading Valgrind to raise a false positive.
        VALGRIND_MAKE_MEM_DEFINED(ptr_, size_);
        #endif
        munmap(ptr_, size_);
    }
}

page_allocation::page_allocation(page_allocation&& rhs) {
    ptr_ = rhs.ptr_;
    size_ = rhs.size_;

    rhs.ptr_ = nullptr;
    rhs.size_ = 0;
}

void *page_allocation::ptr() {
    return ptr_;
}

const void *page_allocation::ptr() const {
    return ptr_;
}

size_t page_allocation::size() const {
    return size_;
}

page_buffer::page_buffer(memory_lock m) :
    page_size_(size_t(sysconf(_SC_PAGESIZE))), buffer_size_(0), mlock_(m) { }

page_buffer::~page_buffer() { }

size_t page_buffer::read(size_t n, size_t offset, void *buffer) const {
    size_t base = round_down_to_page(offset);

    // Shrink request to what we can handle.
    n = offset < buffer_size_ ? std::min(n, buffer_size_ - offset) : 0;

    size_t position = 0;
    for (auto it = find_block(page_allocations_, base);
            it != page_allocations_.end() && it->first < n + offset; ++it) {
        if (it->first > position + offset) {
            // Zerofill gap.
            size_t zero_length = it->first - position - offset;
            memset(static_cast<uint8_t*>(buffer) + position, 0, zero_length);
            position += zero_length;
        }
        assert(it->first <= position + offset);

        size_t internal_offset = position + offset - it->first;
        if (internal_offset > it->second.size()) {
            continue;
        }

        size_t internal_length =
            std::min(it->second.size() - internal_offset, n - position);

        memcpy(static_cast<uint8_t*>(buffer) + position,
            static_cast<const uint8_t*>(it->second.ptr()) + internal_offset,
            internal_length);
        position += internal_length;
    }
    assert(position <= n);

    // Zerofill the tail.
    if (position < n) {
        memset(static_cast<uint8_t*>(buffer) + position, 0, n - position);
        position = n;
    }

    return position;
}

void page_buffer::write(size_t n, size_t offset, const void *buffer) {
    for (size_t position = 0; position < n; ) {
        size_t base = round_down_to_page(offset);
        assert(base <= offset);

        auto it = page_allocations_.find(base);
        if (it == page_allocations_.end()) {
            it = page_allocations_.lower_bound(base);
            if (it == page_allocations_.end() ||
                    it->first > base) {
                // Find the beginning of the next allocation, if any.
                const auto end_it = page_allocations_.upper_bound(base);
                size_t end;
                if (end_it == page_allocations_.end()) {
                    end = round_up_to_page(base + n - position);
                } else {
                    end = end_it->first;
                }
                assert(end > base);
                assert(end - base < n - position + page_size_);
                size_t length = end - base;
                assert(is_page_multiple(length));

                // Allocate.
                it = page_allocations_.emplace(base,
                    page_allocation(length, mlock_)).first;
            }
        }

        // Rebase according to the allocation we did find.
        base = it->first;
        assert(offset + position >= base);
        size_t internal_offset = offset + position - base;
        assert(internal_offset < it->second.size());
        size_t internal_length =
            std::min(it->second.size() - internal_offset, n - position);

        // Build pointers.
        const uint8_t* ubuffer = static_cast<const uint8_t*>(buffer);
        uint8_t* destination = static_cast<uint8_t*>(it->second.ptr());

        memcpy(destination + internal_offset, ubuffer + position,
            internal_length);
        position += internal_length;
        buffer_size_ = std::max(buffer_size_, offset + position);
    }
}

ssize_t page_buffer::splice(int fd, unsigned int flags) {
    // The last page is special and is handled accordingly.
    const size_t last_whole_page = round_down_to_page(buffer_size_);

    // Build up contiguous iov's and flush them to fd.
    size_t position = 0;
    page_allocation_map_t::const_iterator it;
    for (it = page_allocations_.begin();
            position < last_whole_page && it != page_allocations_.end(); ) {
        // Fill in gap, if present.
        if (position < it->first) {
            size_t gap_length = it->first - position;
            assert(is_page_multiple(gap_length));

            ssize_t ret = zero_splice(fd, gap_length, flags);
            if (ret == -1) {
                return ret;
            }
            position += gap_length;
        }

        std::vector<iovec> ios;
        while (ios.size() < IOV_MAX && it != page_allocations_.end()) {
            // Verify this is contiguous with position.
            assert(position <= it->first);
            if (position < it->first) {
                // It is not.
                break;
            }

            // If this size would put us past the last_whole_page, we need to
            // stop early.
            size_t internal_size = std::min(it->second.size(),
                last_whole_page - position);
            if (internal_size == 0) {
                break;
            }

            iovec v;
            v.iov_base = const_cast<void*>(it->second.ptr());
            v.iov_len = internal_size;
            ios.push_back(v);

            // Advance
            position += internal_size;
            if (position == last_whole_page) {
                // We need to retain the iterator.
                break;
            }
            ++it;
        }

        ssize_t ret = flush_iov(fd, &ios, flags);
        if (ret < 0) {
            return ret;
        }
    }

    // Zerofill if we stopped early.
    if (position < last_whole_page) {
        size_t gap = last_whole_page - position;
        assert(is_page_multiple(gap));

        ssize_t ret = zero_splice(fd, last_whole_page, flags);
        if (ret < 0) {
            return ret;
        }
        position += static_cast<size_t>(ret);
    }

    // If anything remains, write it normally.
    if (last_whole_page < buffer_size_) {
        assert(it != page_allocations_.end());
        // Advance the iterator if we've exhausted the current allocation chunk.
        if (last_whole_page == it->first + it->second.size()) {
            ++it;
            assert(it != page_allocations_.end());
        }
        assert(it->first <= last_whole_page);

        size_t internal_offset = last_whole_page - it->first;
        assert(internal_offset + buffer_size_ - last_whole_page <
            it->second.size());

        ::write(fd,
            static_cast<const uint8_t*>(it->second.ptr()) + internal_offset,
            buffer_size_ - last_whole_page);
        position += buffer_size_ - last_whole_page;
    }

    return static_cast<ssize_t>(position);
}

size_t page_buffer::size() const {
    return buffer_size_;
}

size_t page_buffer::round_down_to_page(size_t sz) const {
    return sz & ~(page_size_ - 1);
}

size_t page_buffer::round_up_to_page(size_t sz) const {
    return (sz + page_size_ - 1) & ~(page_size_ - 1);
}

bool page_buffer::is_page_multiple(size_t n) const {
    return round_down_to_page(n) == n;
}

void page_buffer::resize(size_t n) {
    if (buffer_size_ > n) {
        // Scan to free pages.
        page_allocation_map_t::iterator it = page_allocations_.lower_bound(n);
        assert(it == page_allocations_.end() || it->first >= n);
        page_allocations_.erase(it, page_allocations_.end());
    }

    buffer_size_ = n;
}

void page_buffer::clear() {
    page_allocations_.clear();
    buffer_size_ = 0;
}
