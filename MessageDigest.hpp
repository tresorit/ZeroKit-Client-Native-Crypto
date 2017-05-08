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
#include <openssl/ossl_typ.h>

enum class DigestAlgorithm : uint8_t
{
    SHA256,
    SHA512
};

const EVP_MD* getMessageDigest(DigestAlgorithm mdType);

class MessageDigestCtx
{
private:
    EVP_MD_CTX* ctx;

public:
    MessageDigestCtx();
    MessageDigestCtx(const MessageDigestCtx&) = delete;
    MessageDigestCtx& operator=(const MessageDigestCtx&) = delete;
    MessageDigestCtx(MessageDigestCtx&& other);
    MessageDigestCtx& operator=(MessageDigestCtx&& other);
    ~MessageDigestCtx();

    EVP_MD_CTX* get();

    void hashInit(const EVP_MD* digest);
    void hashUpdate(const uint8_t* data, size_t length);
    void hashFinalize(uint8_t* hash);

    EVP_PKEY_CTX* signInit(const EVP_MD* digest, EVP_PKEY* key);
    void signUpdate(const uint8_t* data, size_t len);
    void signFinalize(uint8_t* signature, size_t signatureLen);

    EVP_PKEY_CTX* verifyInit(const EVP_MD* digest, EVP_PKEY* key);
    void verifyUpdate(const uint8_t* data, size_t len);
    int verifyFinalize(const uint8_t* signature, size_t signatureLen);
};
