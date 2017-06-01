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

#include "Cipher.hpp"

#include <limits>
#include <openssl/evp.h>

#include "OpenSSLException.hpp"

const EVP_CIPHER* getCipher(CipherType cipherType)
{
    switch (cipherType) {
    case CipherType::AES128GCM:
        return EVP_aes_128_gcm();
    case CipherType::AES256GCM:
        return EVP_aes_256_gcm();
    default:
        throw OpenSSLException();
    }
}

CipherCtx::CipherCtx()
    : ctx(nullptr)
{
    OPENSSL_THROW_IF_NULL(this->ctx = EVP_CIPHER_CTX_new());
}

CipherCtx::CipherCtx(CipherCtx&& other)
    : ctx(other.ctx)
{
    other.ctx = nullptr;
}

CipherCtx& CipherCtx::operator=(CipherCtx&& other)
{
    if (this != &other) {
        if (this->ctx != nullptr) {
            EVP_CIPHER_CTX_free(this->ctx);
        }
        this->ctx = other.ctx;
        other.ctx = nullptr;
    }

    return *this;
}

CipherCtx::~CipherCtx()
{
    if (this->ctx != nullptr) {
        EVP_CIPHER_CTX_free(this->ctx);
    }
}

EVP_CIPHER_CTX* CipherCtx::get()
{
    return this->ctx;
}

void CipherCtx::setType(const EVP_CIPHER* cipher, CipherOperation operation)
{
    OPENSSL_THROW_IF_ERROR(EVP_CipherInit_ex(
      this->get(), cipher, nullptr, nullptr, nullptr, static_cast<int>(operation)));
}

void CipherCtx::setPadding(bool enable)
{
    OPENSSL_THROW_IF_ERROR(EVP_CIPHER_CTX_set_padding(this->get(), enable));
}

void CipherCtx::setKey(const uint8_t* key, size_t len)
{
    OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())
    int keyLen = EVP_CIPHER_CTX_key_length(this->get());
    OPENSSL_THROW_IF(keyLen < 0);
    OPENSSL_THROW_IF(len != static_cast<size_t>(keyLen));
    OPENSSL_THROW_IF_ERROR(EVP_CipherInit_ex(this->get(), nullptr, nullptr, key, nullptr, -1));
}

void CipherCtx::setIV(const uint8_t* iv, size_t len)
{
    if (EVP_CIPHER_CTX_cipher(this->get()) == getCipher(CipherType::AES128GCM)
      || EVP_CIPHER_CTX_cipher(this->get()) == getCipher(CipherType::AES256GCM)) {
        OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())
        OPENSSL_THROW_IF_ERROR(EVP_CIPHER_CTX_ctrl(
          this->get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(len), nullptr));
    }
    OPENSSL_THROW_IF_ERROR(EVP_CipherInit_ex(this->get(), nullptr, nullptr, nullptr, iv, -1));
}

void CipherCtx::updateAAD(const uint8_t* aad, size_t len)
{
    OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())
    if (aad == nullptr || len == 0) {
        return;
    }

    int outl = 0;
    OPENSSL_THROW_IF_ERROR(
      EVP_CipherUpdate(this->get(), nullptr, &outl, aad, static_cast<int>(len)));
}

SecureVector CipherCtx::update(const uint8_t* data, size_t len)
{
    OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())
    if (data == nullptr || len == 0) {
        return SecureVector();
    }

    int blockSize = EVP_CIPHER_CTX_block_size(this->get());
    OPENSSL_THROW_IF(blockSize < 1);
    SecureVector res(len + static_cast<size_t>(blockSize) - 1);

    int outl = 0;
    OPENSSL_THROW_IF_ERROR(
      EVP_CipherUpdate(this->get(), res.data(), &outl, data, static_cast<int>(len)));
    OPENSSL_THROW_IF(outl < 0);
    res.resize(static_cast<size_t>(outl));
    return res;
}

SecureVector CipherCtx::finalize()
{
    int blockSize = EVP_CIPHER_CTX_block_size(this->get());
    OPENSSL_THROW_IF(blockSize < 1);
    SecureVector res(static_cast<size_t>(blockSize));

    int outl = 0;
    OPENSSL_THROW_IF_ERROR(EVP_CipherFinal_ex(this->get(), res.data(), &outl));
    OPENSSL_THROW_IF(outl < 0);
    res.resize(static_cast<size_t>(outl));
    return res;
}

SecureVector CipherCtx::getTag(size_t len)
{
    OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())

    SecureVector tag(len);
    OPENSSL_THROW_IF_ERROR(
      EVP_CIPHER_CTX_ctrl(this->get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(len), tag.data()));
    return tag;
}

void CipherCtx::setTag(const uint8_t* tag, size_t len)
{
    OPENSSL_THROW_IF(len > std::numeric_limits<int>::max())

    OPENSSL_THROW_IF_ERROR(EVP_CIPHER_CTX_ctrl(this->get(), EVP_CTRL_AEAD_SET_TAG,
      static_cast<int>(len), static_cast<void*>(const_cast<uint8_t*>(tag))));
}
