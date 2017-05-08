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

#include "MessageDigest.hpp"

#include <openssl/evp.h>

#include "OpenSSLException.hpp"

const EVP_MD* getMessageDigest(DigestAlgorithm mdType)
{
    switch (mdType) {
    case DigestAlgorithm::SHA256:
        return EVP_sha256();
    case DigestAlgorithm::SHA512:
        return EVP_sha512();
    default:
        throw OpenSSLException();
    }
}

MessageDigestCtx::MessageDigestCtx()
    : ctx(nullptr)
{
    OPENSSL_THROW_IF_NULL(this->ctx = EVP_MD_CTX_new());
}

MessageDigestCtx::MessageDigestCtx(MessageDigestCtx&& other)
    : ctx(other.ctx)
{
    other.ctx = nullptr;
}

MessageDigestCtx& MessageDigestCtx::operator=(MessageDigestCtx&& other)
{
    if (this != &other) {
        if (this->ctx != nullptr) {
            EVP_MD_CTX_free(this->ctx);
        }
        this->ctx = other.ctx;
        other.ctx = nullptr;
    }

    return *this;
}

MessageDigestCtx::~MessageDigestCtx()
{
    if (this->ctx != nullptr) {
        EVP_MD_CTX_free(this->ctx);
    }
}

EVP_MD_CTX* MessageDigestCtx::get()
{
    return this->ctx;
}

void MessageDigestCtx::hashInit(const EVP_MD* digest)
{
    OPENSSL_THROW_IF_ERROR(EVP_DigestInit_ex(this->ctx, digest, nullptr));
}

void MessageDigestCtx::hashUpdate(const uint8_t* data, size_t length)
{
    OPENSSL_THROW_IF_ERROR(EVP_DigestUpdate(this->ctx, data, length));
}

void MessageDigestCtx::hashFinalize(uint8_t* hash)
{
    OPENSSL_THROW_IF_ERROR(EVP_DigestFinal_ex(this->ctx, hash, nullptr));
}

EVP_PKEY_CTX* MessageDigestCtx::signInit(const EVP_MD* digest, EVP_PKEY* key)
{
    EVP_PKEY_CTX* pkeyCtx;
    OPENSSL_THROW_IF_ERROR(EVP_DigestSignInit(this->get(), &pkeyCtx, digest, nullptr, key));
    return pkeyCtx;
}

void MessageDigestCtx::signUpdate(const uint8_t* data, size_t len)
{
    OPENSSL_THROW_IF_ERROR(EVP_DigestSignUpdate(this->get(), data, len));
}

void MessageDigestCtx::signFinalize(uint8_t* signature, size_t signatureLen)
{
    size_t len = 0;
    OPENSSL_THROW_IF_ERROR(EVP_DigestSignFinal(this->get(), nullptr, &len));
    OPENSSL_THROW_IF(signatureLen != len);

    OPENSSL_THROW_IF_ERROR(EVP_DigestSignFinal(this->get(), signature, &len));
}

EVP_PKEY_CTX* MessageDigestCtx::verifyInit(const EVP_MD* digest, EVP_PKEY* key)
{
    EVP_PKEY_CTX* pkeyCtx;
    OPENSSL_THROW_IF_ERROR(EVP_DigestVerifyInit(this->get(), &pkeyCtx, digest, nullptr, key));
    return pkeyCtx;
}

void MessageDigestCtx::verifyUpdate(const uint8_t* data, size_t len)
{
    OPENSSL_THROW_IF_ERROR(EVP_DigestVerifyUpdate(this->get(), data, len));
}

int MessageDigestCtx::verifyFinalize(const uint8_t* signature, size_t signatureLen)
{
    auto ret = EVP_DigestVerifyFinal(this->get(), signature, signatureLen);

    // valid return values
    OPENSSL_THROW_IF(ret != 1 && ret != 0);

    return ret;
}
