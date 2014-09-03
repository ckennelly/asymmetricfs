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

/* This splices in zero pages into fd, returning the value from vmsplice. */
ssize_t zero_splice(int fd, size_t size, int flags) {
    // Clean up flags, as we're going to reuse the same allocation many times.
    flags &= ~SPLICE_F_GIFT;

    const size_t max_allocation = 1 << 20 /* 1MB */;
    size_t allocation_size = std::min(size, max_allocation);

    page_allocation tmp(allocation_size);
    size_t position;
    for (position = 0; position < size; ) {
        std::vector<iovec> ios;
        while (ios.size() < IOV_MAX && position < size) {
            iovec v;
            v.iov_base = tmp.ptr();
            v.iov_len = std::min(tmp.size(), position - size);
            ios.push_back(v);

            position += v.iov_len;
        }

        assert(!(ios.empty()));
        ssize_t ret = vmsplice(fd, &ios[0], ios.size(), flags);
        if (ret == -1) {
            return ret;
        }
    }

    return position;
}

}  // namespace

page_allocation::page_allocation(size_t sz) : size_(sz) {
    ptr_ = mmap(NULL, size_, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

page_buffer::page_buffer() : page_size_(sysconf(_SC_PAGESIZE)),
    buffer_size_(0) { }

page_buffer::~page_buffer() { }

size_t page_buffer::read(size_t n, size_t offset, void *buffer) const {
    size_t base = round_down_to_page(offset);

    // Shrink request to what we can handle.
    n = offset < buffer_size_ ? std::min(n, buffer_size_ - offset) : 0;

    size_t position = 0;
    for (auto it = page_allocations_.lower_bound(base);
            it != page_allocations_.end() && it->first < n + offset; ++it) {
        if (it->first > position + offset) {
            // Zerofill gap.
            size_t zero_length = it->first - position - offset;
            memset(static_cast<uint8_t*>(buffer) + position, 0, zero_length);
            position += zero_length;
        }
        assert(it->first <= position + offset);

        size_t internal_offset = position + offset - it->first;
        assert(internal_offset <= it->second.size());

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
                    std::move(page_allocation(length))).first;
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

ssize_t page_buffer::splice(int fd, int flags) {
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

        assert(!(ios.empty()));
        ssize_t ret = vmsplice(fd, &ios[0], ios.size(), flags);
        if (ret == -1) {
            return ret;
        }
    }

    // Zerofill if we stopped early.
    if (position < last_whole_page) {
        size_t gap = last_whole_page - position;
        assert(is_page_multiple(gap));

        ssize_t ret = zero_splice(fd, last_whole_page, flags);
        if (ret == -1) {
            return ret;
        }
        position += ret;
    }

    // If anything remains, write it normally.
    if (last_whole_page < buffer_size_) {
        assert(it != page_allocations_.end());
        assert(it->first <= last_whole_page);

        size_t internal_offset = last_whole_page - it->first;
        assert(internal_offset + buffer_size_ - last_whole_page <
            it->second.size());

        ::write(fd,
            static_cast<const uint8_t*>(it->second.ptr()) + internal_offset,
            buffer_size_ - last_whole_page);
        position += buffer_size_ - last_whole_page;
    }

    return position;
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
