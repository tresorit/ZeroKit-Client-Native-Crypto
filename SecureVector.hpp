/**
 * Copyright (c) 2017, Tresorit Kft.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>
#include <vector>
#include <openssl/crypto.h>

template <typename T>
class SecureAllocator
{
public:
    typedef SecureAllocator<T> allocator_type;
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef void* void_pointer;
    typedef const void* const_void_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef std::true_type propagate_on_container_swap;
    typedef std::true_type propagate_on_container_copy_assignment;
    typedef std::true_type propagate_on_container_move_assignment;
    template <typename U>
    struct rebind
    {
        typedef SecureAllocator<U> other;
    };

    SecureAllocator()
    {
    }

    SecureAllocator(const SecureAllocator<T>&)
    {
    }

    SecureAllocator<T>& operator=(const SecureAllocator<T>&)
    {
        return *this;
    }

    SecureAllocator(SecureAllocator<T>&&)
    {
    }

    SecureAllocator<T>& operator=(SecureAllocator<T>&&)
    {
        return *this;
    }

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&)
    {
    }

    template <typename U>
    SecureAllocator<T>& operator=(const SecureAllocator<U>&)
    {
        return *this;
    }

    template <typename U>
    SecureAllocator(SecureAllocator<U>&&)
    {
    }

    template <typename U>
    SecureAllocator<T>& operator=(SecureAllocator<U>&&)
    {
        return *this;
    }

    SecureAllocator<T> select_on_container_copy_construction() const
    {
        return SecureAllocator<T>();
    }

    ~SecureAllocator()
    {
    }

    bool operator==(const SecureAllocator<T>&) const
    {
        return true;
    }

    bool operator!=(const SecureAllocator<T>&) const
    {
        return false;
    }

    T* address(T& t) const
    {
        return std::addressof(t);
    }

    const T* address(const T& t) const
    {
        return std::addressof(t);
    }

    T* allocate(size_t n)
    {
        return reinterpret_cast<T*>(new char[n * sizeof(T)]);
    }

    T* allocate(size_t n, const void* /*hint*/)
    {
        return reinterpret_cast<T*>(new char[n * sizeof(T)]);
    }

    void deallocate(T* p, size_t n)
    {
        OPENSSL_cleanse(p, n * sizeof(T));
        delete[] reinterpret_cast<char*>(p);
    }

    size_t max_size() const
    {
        return std::numeric_limits<size_t>::max();
    }

    template <class U, class... Args>
    void construct(U* p, Args&&... args)
    {
        new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    template <class U>
    void destroy(U* p)
    {
        p->~U();
        OPENSSL_cleanse(p, sizeof(U));
    }
};

typedef std::vector<uint8_t, SecureAllocator<uint8_t>> SecureVector;
