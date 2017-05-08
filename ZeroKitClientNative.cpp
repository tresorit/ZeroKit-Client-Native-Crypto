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

#include "ZeroKitClientNative.h"

#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "Cipher.hpp"
#include "Hex.hpp"
#include "Key.hpp"
#include "MessageDigest.hpp"
#include "OpenSSLException.hpp"
#include "SecureVector.hpp"
#include "Srp6.hpp"

int cryptoRandomBytes(uint8_t* buf, size_t len)
{
    try {
        OPENSSL_THROW_IF(len > std::numeric_limits<int>::max());
        OPENSSL_THROW_IF_ERROR(RAND_bytes(buf, static_cast<int>(len)));
        return 0;
    } catch (...) {
        return -1;
    }
}

namespace
{
size_t EVP_MD_size_as_size_t(const EVP_MD* digest)
{
    auto size = EVP_MD_size(digest);
    OPENSSL_THROW_IF(size < 0);
    return static_cast<size_t>(size);
}

void calculateSha(const EVP_MD* digest, const char* message, char* hash, size_t hashLen)
{
    const auto len = EVP_MD_size_as_size_t(digest);
    OPENSSL_THROW_IF(hashLen < len * 2 + 1);

    const auto hashVec = hexToByteArray(message);
    SecureVector output(len);

    MessageDigestCtx md;
    md.hashInit(digest);
    md.hashUpdate(hashVec.data(), hashVec.size());
    md.hashFinalize(output.data());

    byteArrayToHex(output, hash);
}
}

int calculateSha256(const char* message, char* hash, size_t hashLen)
{
    try {
        calculateSha(getMessageDigest(DigestAlgorithm::SHA256), message, hash, hashLen);
        return 0;
    } catch (...) {
        return -1;
    }
}

int calculateSha512(const char* message, char* hash, size_t hashLen)
{
    try {
        calculateSha(getMessageDigest(DigestAlgorithm::SHA512), message, hash, hashLen);
        return 0;
    } catch (...) {
        return -1;
    }
}

namespace
{
SecureVector calculateHmacShaInner(
  const EVP_MD* digest, const SecureVector& key, const SecureVector& message)
{
    const auto len = EVP_MD_size_as_size_t(digest);
    SecureVector output(len);

    Key hmacKey(key.data(), key.size());

    MessageDigestCtx md;
    md.signInit(digest, hmacKey.get());
    md.signUpdate(message.data(), message.size());
    md.signFinalize(output.data(), output.size());

    return output;
}

void calculateHmacSha(
  const EVP_MD* digest, const char* key, const char* message, char* hmac, size_t hmacLen)
{
    const auto len = EVP_MD_size_as_size_t(digest);
    OPENSSL_THROW_IF(hmacLen < len * 2 + 1);

    const auto keyVec = hexToByteArray(key);
    const auto messageVec = hexToByteArray(message);
    OPENSSL_THROW_IF(keyVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(messageVec.size() > std::numeric_limits<int>::max());

    byteArrayToHex(calculateHmacShaInner(digest, keyVec, messageVec), hmac);
}

int verifyHmacSha(const EVP_MD* digest, const char* key, const char* message, const char* hmac)
{
    const auto keyVec = hexToByteArray(key);
    const auto messageVec = hexToByteArray(message);
    const auto hmacVec = hexToByteArray(hmac);
    OPENSSL_THROW_IF(keyVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(messageVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(hmacVec.size() > std::numeric_limits<int>::max());

    const auto calculatedHmac = calculateHmacShaInner(digest, keyVec, messageVec);

    if (calculatedHmac.size() != hmacVec.size()) {
        return 0;
    }
    return CRYPTO_memcmp(calculatedHmac.data(), hmacVec.data(), calculatedHmac.size()) == 0;
}
}

int calculateHmacSha256(const char* key, const char* message, char* hmac, size_t hmacLen)
{
    try {
        calculateHmacSha(getMessageDigest(DigestAlgorithm::SHA256), key, message, hmac, hmacLen);
        return 0;
    } catch (...) {
        return -1;
    }
}

int verifyHmacSha256(const char* key, const char* message, const char* hmac)
{
    try {
        return verifyHmacSha(getMessageDigest(DigestAlgorithm::SHA256), key, message, hmac);
    } catch (...) {
        return -1;
    }
}

namespace
{
void derivePbkdf2Hmac(const EVP_MD* digest, const char* password, const char* salt, uint32_t iter,
  char* key, size_t keySize)
{
    const auto passwordVec = hexToByteArray(password);
    const auto saltVec = hexToByteArray(salt);
    OPENSSL_THROW_IF(passwordVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(saltVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(iter > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(keySize > std::numeric_limits<int>::max());

    SecureVector output(keySize);

    OPENSSL_THROW_IF_ERROR(PKCS5_PBKDF2_HMAC(
      password == nullptr ? "" : reinterpret_cast<const char*>(passwordVec.data()),
      static_cast<int>(passwordVec.size()), saltVec.data(), static_cast<int>(saltVec.size()),
      static_cast<int>(iter), digest, static_cast<int>(keySize), output.data()));

    byteArrayToHex(output, key);
}
}

int derivePbkdf2HmacSha256(
  const char* password, const char* salt, uint32_t iter, char* key, size_t keySize)
{
    try {
        derivePbkdf2Hmac(
          getMessageDigest(DigestAlgorithm::SHA256), password, salt, iter, key, keySize);
        return 0;
    } catch (...) {
        return -1;
    }
}

int derivePbkdf2HmacSha512(
  const char* password, const char* salt, uint32_t iter, char* key, size_t keySize)
{
    try {
        derivePbkdf2Hmac(
          getMessageDigest(DigestAlgorithm::SHA512), password, salt, iter, key, keySize);
        return 0;
    } catch (...) {
        return -1;
    }
}

int deriveScrypt(const char* password, const char* salt, uint64_t N, uint64_t r, uint64_t p,
  char* key, size_t keySize)
{
    try {
        const auto passwordVec = hexToByteArray(password);
        const auto saltVec = hexToByteArray(salt);

        SecureVector output(keySize);

        OPENSSL_THROW_IF_ERROR(
          EVP_PBE_scrypt(reinterpret_cast<const char*>(passwordVec.data()), passwordVec.size(),
            saltVec.data(), saltVec.size(), N, r, p, 0 /*maxmem*/, output.data(), output.size()));

        byteArrayToHex(output, key);
        return 0;
    } catch (...) {
        return -1;
    }
}

namespace
{
int encryptAesGcm(CipherType cipherType, const char* key, const char* iv, const char* aad,
  const char* plaintext, char* ciphertext, size_t ciphertextLen, char* tag, size_t tagLen)
{
    const auto keyVec = hexToByteArray(key);
    const auto ivVec = hexToByteArray(iv);
    const auto aadVec = hexToByteArray(aad);
    const auto plaintextVec = hexToByteArray(plaintext);
    OPENSSL_THROW_IF(keyVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(ivVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(aadVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(plaintextVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(tagLen > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(ciphertextLen < strlen(plaintext) + 1);

    CipherCtx ctx;
    ctx.setType(getCipher(cipherType), CipherOperation::Encrypt);
    ctx.setPadding(false);
    ctx.setKey(keyVec.data(), keyVec.size());
    ctx.setIV(ivVec.data(), ivVec.size());
    ctx.updateAAD(aadVec.data(), aadVec.size());
    auto cipher = ctx.update(plaintextVec.data(), plaintextVec.size());
    auto finalCipher = ctx.finalize();
    cipher.insert(cipher.end(), finalCipher.begin(), finalCipher.end());

    byteArrayToHex(cipher, ciphertext);
    byteArrayToHex(ctx.getTag(tagLen), tag);
    return 0;
}

int decryptAesGcm(CipherType cipherType, const char* key, const char* iv, const char* aad,
  const char* ciphertext, const char* tag, char* plaintext, size_t plaintextLen)
{
    const auto keyVec = hexToByteArray(key);
    const auto ivVec = hexToByteArray(iv);
    const auto aadVec = hexToByteArray(aad);
    const auto ciphertextVec = hexToByteArray(ciphertext);
    const auto tagVec = hexToByteArray(tag);
    OPENSSL_THROW_IF(keyVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(ivVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(aadVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(ciphertextVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(tagVec.size() > std::numeric_limits<int>::max());
    OPENSSL_THROW_IF(plaintextLen < strlen(ciphertext) + 1);

    CipherCtx ctx;
    ctx.setType(getCipher(cipherType), CipherOperation::Decrypt);
    ctx.setPadding(false);
    ctx.setKey(keyVec.data(), keyVec.size());
    ctx.setIV(ivVec.data(), ivVec.size());
    ctx.updateAAD(aadVec.data(), aadVec.size());
    auto plain = ctx.update(ciphertextVec.data(), ciphertextVec.size());
    try {
        ctx.setTag(tagVec.data(), tagVec.size());
        auto finalPlain = ctx.finalize();
        plain.insert(plain.end(), finalPlain.begin(), finalPlain.end());
    } catch (...) {
        return 0;
    }

    byteArrayToHex(plain, plaintext);
    return 1;
}
}

int encryptAes128Gcm(const char* key, const char* iv, const char* aad, const char* plaintext,
  char* ciphertext, size_t ciphertextLen, char* tag, size_t tagLen)
{
    try {
        return encryptAesGcm(
          CipherType::AES128GCM, key, iv, aad, plaintext, ciphertext, ciphertextLen, tag, tagLen);
    } catch (...) {
        return -1;
    }
}

int decryptAes128Gcm(const char* key, const char* iv, const char* aad, const char* ciphertext,
  const char* tag, char* plaintext, size_t plaintextLen)
{
    try {
        return decryptAesGcm(
          CipherType::AES128GCM, key, iv, aad, ciphertext, tag, plaintext, plaintextLen);
    } catch (...) {
        return -1;
    }
}

int encryptAes256Gcm(const char* key, const char* iv, const char* aad, const char* plaintext,
  char* ciphertext, size_t ciphertextLen, char* tag, size_t tagLen)
{
    try {
        return encryptAesGcm(
          CipherType::AES256GCM, key, iv, aad, plaintext, ciphertext, ciphertextLen, tag, tagLen);
    } catch (...) {
        return -1;
    }
}

int decryptAes256Gcm(const char* key, const char* iv, const char* aad, const char* ciphertext,
  const char* tag, char* plaintext, size_t plaintextLen)
{
    try {
        return decryptAesGcm(
          CipherType::AES256GCM, key, iv, aad, ciphertext, tag, plaintext, plaintextLen);
    } catch (...) {
        return -1;
    }
}

class Srp6ClientWrapper
{
private:
    Srp6Client client;
    std::vector<char*> strings;

public:
    Srp6ClientWrapper(const char* N, const char* g)
        : client(N, g, DigestAlgorithm::SHA256)
    {
    }

    ~Srp6ClientWrapper()
    {
        for (auto str : this->strings) {
            OPENSSL_clear_free(str, strlen(str));
        }
    }

    BIGNUM* hexToBignum(const char* hex)
    {
        BIGNUM* bn = this->client.getBnCtx().getBigNum();
        if (BN_hex2bn(&bn, hex) <= 0) {
            return nullptr;
        }
        return bn;
    }

    char* bignumToHex(BIGNUM* bn)
    {
        char* hex = BN_bn2hex(bn);
        if (hex != nullptr) {
            this->strings.push_back(hex);
        }
        return hex;
    }

    char* vecToStr(const SecureVector& vec)
    {
        char* str = OPENSSL_strndup(reinterpret_cast<const char*>(vec.data()), vec.size());
        if (str != nullptr) {
            this->strings.push_back(str);
        }
        return str;
    }

    const char* calculateX(const char* salt, const char* identity, const char* password)
    {
        auto saltVec = hexToByteArray(salt);
        auto identityVec = hexToByteArray(identity);
        auto passwordVec = hexToByteArray(password);
        BIGNUM* xBN = this->client.calculateX(saltVec, identityVec, passwordVec);
        char* x = BN_bn2hex(xBN);
        if (x != nullptr) {
            this->strings.push_back(x);
        }
        return x;
    }

    const char* calculateVerifier(const char* x)
    {
        BIGNUM* xBN = this->hexToBignum(x);
        if (xBN == nullptr) {
            return nullptr;
        }
        BIGNUM* vBN = this->client.calculateVerifier(xBN);
        return this->bignumToHex(vBN);
    }

    const char* generateClientCredentials()
    {
        BIGNUM* pubABN = this->client.generateClientCredentials();
        return this->bignumToHex(pubABN);
    }

    const char* calculateSecret(const char* x, const char* serverB)
    {
        BIGNUM* xBN = this->hexToBignum(x);
        if (xBN == nullptr) {
            return nullptr;
        }
        BIGNUM* serverBBN = this->hexToBignum(serverB);
        if (serverBBN == nullptr) {
            return nullptr;
        }
        BIGNUM* secretBN = client.calculateSecret(xBN, serverBBN);
        if (secretBN == nullptr) {
            return nullptr;
        }
        return this->bignumToHex(secretBN);
    }

    const char* calculateClientEvidenceMessage()
    {
        const auto M1Vec = this->client.calculateClientEvidenceMessage();
        const auto M1Hex = byteArrayToHex(M1Vec);
        return this->vecToStr(M1Hex);
    }

    int verifyServerEvidenceMessage(const char* serverM2)
    {
        const auto serverM2Vec = hexToByteArray(serverM2);
        return client.verifyServerEvidenceMessage(serverM2Vec);
    }

    const char* calculateSessionKey()
    {
        const auto KeyVec = this->client.calculateSessionKey();
        const auto KeyHex = byteArrayToHex(KeyVec);
        return this->vecToStr(KeyHex);
    }
};

TresoritSrp6Client* srp6ClientNew(const char* N, const char* g)
{
    try {
        return reinterpret_cast<TresoritSrp6Client*>(new Srp6ClientWrapper(N, g));
    } catch (...) {
        return nullptr;
    }
}

const char* srp6ClientCalculateX(
  TresoritSrp6Client* client, const char* salt, const char* identity, const char* password)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->calculateX(salt, identity, password);
    } catch (...) {
        return nullptr;
    }
}

const char* srp6ClientCalculateVerifier(TresoritSrp6Client* client, const char* x)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->calculateVerifier(x);
    } catch (...) {
        return nullptr;
    }
}

const char* srp6ClientGenerateClientCredentials(TresoritSrp6Client* client)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->generateClientCredentials();
    } catch (...) {
        return nullptr;
    }
}

const char* srp6ClientCalculateSecret(
  TresoritSrp6Client* client, const char* x, const char* serverB)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->calculateSecret(x, serverB);
    } catch (...) {
        return nullptr;
    }
}

const char* srp6ClientCalculateClientEvidenceMessage(TresoritSrp6Client* client)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->calculateClientEvidenceMessage();
    } catch (...) {
        return nullptr;
    }
}

int srp6ClientVerifyServerEvidenceMessage(TresoritSrp6Client* client, const char* serverM2)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->verifyServerEvidenceMessage(serverM2);
    } catch (...) {
        return -1;
    }
}

const char* srp6ClientCalculateSessionKey(TresoritSrp6Client* client)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        return wrapper->calculateSessionKey();
    } catch (...) {
        return nullptr;
    }
}

void srp6ClientFree(TresoritSrp6Client* client)
{
    try {
        Srp6ClientWrapper* wrapper = reinterpret_cast<Srp6ClientWrapper*>(client);
        delete wrapper;
    } catch (...) {
    }
}
