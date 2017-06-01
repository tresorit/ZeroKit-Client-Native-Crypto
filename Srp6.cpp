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

#include "Srp6.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <openssl/evp.h>

#include "OpenSSLException.hpp"

namespace
{
size_t BN_num_bytes_as_size_t(const BIGNUM* bn)
{
    auto size = BN_num_bytes(bn);
    OPENSSL_THROW_IF(size < 0);
    return static_cast<size_t>(size);
}

size_t EVP_MD_size_as_size_t(const EVP_MD* digest)
{
    auto size = EVP_MD_size(digest);
    OPENSSL_THROW_IF(size < 0);
    return static_cast<size_t>(size);
}
}

BIGNUM* Srp6Utilities::calculateK(
  BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* g)
{
    return hashPaddedPair(ctx, digest, N, N, g);
}

BIGNUM* Srp6Utilities::calculateU(
  BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B)
{
    BIGNUM* u = hashPaddedPair(ctx, digest, N, A, B);
    OPENSSL_THROW_IF(BN_is_zero(u) != 0);
    return u;
}

BIGNUM* Srp6Utilities::calculateX(BigNumCtx& ctx, const EVP_MD* digest, SecureVector salt,
  SecureVector identity, SecureVector password)
{
    BIGNUM* x = ctx.getBigNum();

    size_t len = EVP_MD_size_as_size_t(digest);
    SecureVector output(len);

    MessageDigestCtx md;
    md.hashInit(digest);
    md.hashUpdate(identity.data(), identity.size());
    md.hashUpdate(reinterpret_cast<const uint8_t*>(":"), 1);
    md.hashUpdate(password.data(), password.size());
    md.hashFinalize(output.data());

    MessageDigestCtx md2;
    md2.hashInit(digest);
    md2.hashUpdate(salt.data(), salt.size());
    md2.hashUpdate(output.data(), output.size());
    md2.hashFinalize(output.data());

    OPENSSL_THROW_IF_NULL(BN_bin2bn(output.data(), static_cast<int>(output.size()), x));

    return x;
}

BIGNUM* Srp6Utilities::generatePrivateValue(BigNumCtx& ctx, const BIGNUM* N)
{
    BIGNUM* priv = ctx.getBigNum();
    {
        auto guard = ctx.getGuard();
        BIGNUM* min = ctx.getBigNum();
        BIGNUM* range = ctx.getBigNum();

        int minBits = std::min(256, BN_num_bits(N) / 2);

        OPENSSL_THROW_IF_ERROR(BN_one(min));
        OPENSSL_THROW_IF_ERROR(BN_lshift(min, min, minBits - 1));

        OPENSSL_THROW_IF_NULL(BN_copy(range, N));
        OPENSSL_THROW_IF_ERROR(BN_sub(range, range, min));

        OPENSSL_THROW_IF_ERROR(BN_rand_range(priv, range));
        OPENSSL_THROW_IF_ERROR(BN_add(priv, priv, min));
    }
    return priv;
}

bool Srp6Utilities::validatePublicValue(
  BIGNUM* pub, BigNumCtx& ctx, const BIGNUM* N, const BIGNUM* val)
{
    OPENSSL_THROW_IF_ERROR(BN_mod(pub, val, N, ctx.get()));
    if (BN_is_zero(pub)) {
        return false;
    }
    return true;
}

SecureVector Srp6Utilities::calculateM1(
  const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B, const BIGNUM* S)
{
    return hashPaddedTriplet(digest, N, A, B, S);
}

SecureVector Srp6Utilities::calculateM2(
  const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* M1, const BIGNUM* S)
{
    return hashPaddedTriplet(digest, N, A, M1, S);
}

SecureVector Srp6Utilities::calculateKey(
  BigNumCtx& /*ctx*/, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* S)
{
    size_t padLength = BN_num_bytes_as_size_t(N);

    auto P = getPadded(S, padLength);

    size_t len = EVP_MD_size_as_size_t(digest);
    SecureVector Key(len, 0);

    MessageDigestCtx md;
    md.hashInit(digest);
    md.hashUpdate(P.data(), P.size());
    md.hashFinalize(Key.data());

    return Key;
}

SecureVector Srp6Utilities::hashPaddedTriplet(
  const EVP_MD* digest, const BIGNUM* N, const BIGNUM* n1, const BIGNUM* n2, const BIGNUM* n3)
{
    size_t padLength = BN_num_bytes_as_size_t(N);

    auto n1_bytes = getPadded(n1, padLength);
    auto n2_bytes = getPadded(n2, padLength);
    auto n3_bytes = getPadded(n3, padLength);

    size_t len = EVP_MD_size_as_size_t(digest);
    SecureVector output(len);

    MessageDigestCtx md;
    md.hashInit(digest);
    md.hashUpdate(n1_bytes.data(), n1_bytes.size());
    md.hashUpdate(n2_bytes.data(), n2_bytes.size());
    md.hashUpdate(n3_bytes.data(), n3_bytes.size());
    md.hashFinalize(output.data());

    return output;
}

BIGNUM* Srp6Utilities::hashPaddedPair(
  BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* n1, const BIGNUM* n2)
{
    BIGNUM* hash = ctx.getBigNum();

    size_t padLength = BN_num_bytes_as_size_t(N);

    auto n1_bytes = getPadded(n1, padLength);
    auto n2_bytes = getPadded(n2, padLength);

    size_t len = EVP_MD_size_as_size_t(digest);
    SecureVector output(len);

    MessageDigestCtx md;
    md.hashInit(digest);
    md.hashUpdate(n1_bytes.data(), n1_bytes.size());
    md.hashUpdate(n2_bytes.data(), n2_bytes.size());
    md.hashFinalize(output.data());

    OPENSSL_THROW_IF_NULL(BN_bin2bn(output.data(), static_cast<int>(output.size()), hash));

    return hash;
}

SecureVector Srp6Utilities::getPadded(const BIGNUM* n, size_t length)
{
    SecureVector bs(length, 0);
    size_t offset = 0;
    size_t size = BN_num_bytes_as_size_t(n);
    OPENSSL_THROW_IF(size > length);
    offset = length - size;
    BN_bn2bin(n, bs.data() + offset);

    return bs;
}

Srp6Client::Srp6Client(const char* N, const char* g, DigestAlgorithm mdType)
    : bnCtx(BigNumCtx())
    , N(this->bnCtx.getBigNum())
    , g(this->bnCtx.getBigNum())
    , digest(getMessageDigest(mdType))
    , privA(nullptr)
    , pubA(nullptr)
    , B(nullptr)
    , u(nullptr)
    , S(nullptr)
{
    OPENSSL_THROW_IF(BN_hex2bn(&this->N, N) <= 0);
    OPENSSL_THROW_IF(BN_hex2bn(&this->g, g) <= 0);
}

Srp6Client::~Srp6Client()
{
}

BIGNUM* Srp6Client::calculateX(
  const SecureVector& salt, const SecureVector& identity, const SecureVector& password)
{
    return Srp6Utilities::calculateX(this->bnCtx, this->digest, salt, identity, password);
}

BIGNUM* Srp6Client::calculateVerifier(BIGNUM* x)
{
    BIGNUM* v = this->bnCtx.getBigNum();
    {
        auto guard = this->bnCtx.getGuard();
        OPENSSL_THROW_IF_ERROR(BN_mod_exp(v, this->g, x, this->N, this->bnCtx.get()));
    }

    return v;
}

BIGNUM* Srp6Client::generateClientCredentials()
{
    this->privA = Srp6Utilities::generatePrivateValue(this->bnCtx, this->N);

    this->pubA = this->bnCtx.getBigNum();

    OPENSSL_THROW_IF_ERROR(
      BN_mod_exp(this->pubA, this->g, this->privA, this->N, this->bnCtx.get()));

    return this->pubA;
}

BIGNUM* Srp6Client::calculateSecret(BIGNUM* x, BIGNUM* serverB)
{
    this->B = this->bnCtx.getBigNum();
    if (!Srp6Utilities::validatePublicValue(this->B, this->bnCtx, this->N, serverB)) {
        return nullptr;
    }

    this->u = Srp6Utilities::calculateU(this->bnCtx, this->digest, this->N, this->pubA, this->B);

    this->S = this->bnCtx.getBigNum();
    {
        auto guard = this->bnCtx.getGuard();
        BIGNUM* k = Srp6Utilities::calculateK(this->bnCtx, this->digest, this->N, this->g);

        BIGNUM* exp = this->bnCtx.getBigNum();
        OPENSSL_THROW_IF_ERROR(BN_mul(exp, this->u, x, this->bnCtx.get()));
        OPENSSL_THROW_IF_ERROR(BN_add(exp, exp, this->privA));

        BIGNUM* tmp = this->bnCtx.getBigNum();
        OPENSSL_THROW_IF_ERROR(BN_mod_exp(tmp, this->g, x, this->N, this->bnCtx.get()));
        OPENSSL_THROW_IF_ERROR(BN_mod_mul(tmp, tmp, k, this->N, this->bnCtx.get()));

        OPENSSL_THROW_IF_ERROR(BN_mod_sub(this->S, this->B, tmp, this->N, this->bnCtx.get()));
        OPENSSL_THROW_IF_ERROR(BN_mod_exp(this->S, this->S, exp, this->N, this->bnCtx.get()));
    }

    return this->S;
}

const SecureVector& Srp6Client::calculateClientEvidenceMessage()
{
    if (this->pubA == nullptr || this->B == nullptr || this->S == nullptr) {
        throw OpenSSLException();
    }
    this->M1 = Srp6Utilities::calculateM1(this->digest, this->N, this->pubA, this->B, this->S);
    return this->M1;
}

bool Srp6Client::verifyServerEvidenceMessage(const SecureVector& serverM2)
{
    if (this->pubA == nullptr || this->M1.empty() || this->S == nullptr) {
        throw OpenSSLException();
    }
    BIGNUM* M1BN = this->bnCtx.getBigNum();
    OPENSSL_THROW_IF_NULL(BN_bin2bn(this->M1.data(), static_cast<int>(this->M1.size()), M1BN));
    auto computedM2 = Srp6Utilities::calculateM2(this->digest, this->N, this->pubA, M1BN, this->S);
    if (computedM2 == serverM2) {
        this->M2 = std::move(computedM2);
        return true;
    }
    return false;
}

const SecureVector& Srp6Client::calculateSessionKey()
{
    if (this->S == nullptr || this->M1.empty() || this->M2.empty()) {
        throw OpenSSLException();
    }
    this->Key = Srp6Utilities::calculateKey(this->bnCtx, this->digest, this->N, this->S);
    return this->Key;
}

BigNumCtx& Srp6Client::getBnCtx()
{
    return this->bnCtx;
}
