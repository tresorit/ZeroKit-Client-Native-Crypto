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

#include <vector>

#include "BigNum.hpp"
#include "MessageDigest.hpp"
#include "SecureVector.hpp"

struct Srp6Utilities
{
    static BIGNUM* calculateK(
      BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* g);
    static BIGNUM* calculateU(
      BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B);
    static BIGNUM* calculateX(BigNumCtx& ctx, const EVP_MD* digest, SecureVector salt,
      SecureVector identity, SecureVector password);

    static BIGNUM* generatePrivateValue(BigNumCtx& ctx, const BIGNUM* N);
    static bool validatePublicValue(
      BIGNUM* pub, BigNumCtx& ctx, const BIGNUM* N, const BIGNUM* val);

    static SecureVector calculateM1(
      const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B, const BIGNUM* S);
    static SecureVector calculateM2(
      const EVP_MD* digest, const BIGNUM* N, const BIGNUM* A, const BIGNUM* M1, const BIGNUM* S);
    static SecureVector calculateKey(
      BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* S);

    static SecureVector hashPaddedTriplet(
      const EVP_MD* digest, const BIGNUM* N, const BIGNUM* n1, const BIGNUM* n2, const BIGNUM* n3);
    static BIGNUM* hashPaddedPair(
      BigNumCtx& ctx, const EVP_MD* digest, const BIGNUM* N, const BIGNUM* n1, const BIGNUM* n2);

    static SecureVector getPadded(const BIGNUM* n, size_t length);
};

class Srp6Client
{
private:
    BigNumCtx bnCtx;

    BIGNUM* N;
    BIGNUM* g;

    const EVP_MD* digest;

    BIGNUM* privA;
    BIGNUM* pubA;

    BIGNUM* B;

    BIGNUM* u;
    BIGNUM* S;

    SecureVector M1;
    SecureVector M2;

    SecureVector Key;

public:
    Srp6Client(const char* N, const char* g, DigestAlgorithm mdType);

    ~Srp6Client();

    BIGNUM* calculateX(
      const SecureVector& salt, const SecureVector& identity, const SecureVector& password);

    BIGNUM* calculateVerifier(BIGNUM* x);

    BIGNUM* generateClientCredentials();

    BIGNUM* calculateSecret(BIGNUM* x, BIGNUM* serverB);

    const SecureVector& calculateClientEvidenceMessage();

    bool verifyServerEvidenceMessage(const SecureVector& serverM2);

    const SecureVector& calculateSessionKey();

    BigNumCtx& getBnCtx();
};
