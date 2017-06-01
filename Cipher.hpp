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
#include <vector>
#include <openssl/ossl_typ.h>

#include "SecureVector.hpp"

enum class CipherOperation : int
{
    Decrypt = 0,
    Encrypt = 1
};

enum class CipherType : uint8_t
{
    AES128GCM,
    AES256GCM
};

const EVP_CIPHER* getCipher(CipherType cipherType);

class CipherCtx
{
private:
    EVP_CIPHER_CTX* ctx;

public:
    CipherCtx();
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
    CipherCtx(CipherCtx&& other);
    CipherCtx& operator=(CipherCtx&& other);
    ~CipherCtx();

    EVP_CIPHER_CTX* get();

    void setType(const EVP_CIPHER* cipher, CipherOperation operation);
    void setPadding(bool enable);
    void setKey(const uint8_t* key, size_t len);
    void setIV(const uint8_t* iv, size_t len);
    void updateAAD(const uint8_t* aad, size_t len);
    SecureVector update(const uint8_t* data, size_t len);
    SecureVector finalize();
    SecureVector getTag(size_t len);
    void setTag(const uint8_t* tag, size_t len);
};
