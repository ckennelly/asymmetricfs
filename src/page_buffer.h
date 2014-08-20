#ifndef __ASYMMETRICFS__PAGE_BUFFER_H__
#define __ASYMMETRICFS__PAGE_BUFFER_H__

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

#include <map>

/**
 * page_allocation manages a mmap'd block of memory of a specified size.  It
 * unmaps the memory automatically on destruction.
 */
class page_allocation {
public:
    /**
     * This allocates a buffer of sz bytes.  sz must be a multiple of the page
     * size.
     *
     * std::bad_alloc is thrown on failure.
     */
    explicit page_allocation(size_t sz);
    ~page_allocation();

    /* Move */
    page_allocation(page_allocation&& rhs);

    void *ptr();
    const void *ptr() const;

    size_t size() const;
private:
    /* Noncopyable */
    page_allocation(const page_allocation &) = delete;
    const page_allocation & operator=(const page_allocation &) = delete;

    void* ptr_;
    size_t size_;
};

class page_buffer {
public:
    page_buffer();
    ~page_buffer();

    /**
     * Returns the exact size of the buffer's contents.
     */
    size_t size() const;

    /**
     * Attempts to read n bytes at offset into the specified buffer.
     *
     * This returns the number of bytes successfully read.
     */
    size_t read(size_t n, size_t offset, void *buffer) const;

    /**
     * Writes n bytes at offset from the specified buffer.  Additional pages
     * are acquired as needed.
     */
    void write(size_t n, size_t offset, const void *buffer);

    /**
     * Resizes the buffer to n bytes.
     */
    void resize(size_t n);

    /**
     * Splices the contents of the page_buffer into the specified file
     * descriptor, fd.  It falls back to using write() when processing partial
     * pages.
     *
     * The return value from vmsplice is passed on.
     */
     ssize_t splice(int fd, int flags);
private:
    /* Noncopyable */
    page_buffer(const page_buffer &) = delete;
    const page_buffer & operator=(const page_buffer &) = delete;

    /* Helper functions. */
    size_t round_down_to_page(size_t size) const;
    size_t round_up_to_page(size_t size) const;
    bool is_page_multiple(size_t n) const;

    /**
     * Mapping from offsets to chunks of contiguous page allocations.
     */
    typedef std::map<size_t, page_allocation> page_allocation_map_t;
    page_allocation_map_t page_allocations_;

    const size_t page_size_;
    size_t buffer_size_;
};

#endif // __ASYMMETRICFS__PAGE_BUFFER_H__
