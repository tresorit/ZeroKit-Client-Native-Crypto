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

#include "Key.hpp"

#include <limits>
#include <openssl/evp.h>

#include "OpenSSLException.hpp"

Key::Key(const uint8_t* key, size_t keyLen)
    : pkey(nullptr)
{
    OPENSSL_THROW_IF(keyLen > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF_NULL(
      this->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, key, static_cast<int>(keyLen)));
}

Key::Key(Key&& other)
    : pkey(other.pkey)
{
    other.pkey = nullptr;
}

Key& Key::operator=(Key&& other)
{
    if (this != &other) {
        if (this->pkey != nullptr) {
            EVP_PKEY_free(this->pkey);
        }
        this->pkey = other.pkey;
        other.pkey = nullptr;
    }

    return *this;
}

Key::~Key()
{
    if (this->pkey != nullptr) {
        EVP_PKEY_free(this->pkey);
    }
}

EVP_PKEY* Key::get()
{
    return this->pkey;
}
