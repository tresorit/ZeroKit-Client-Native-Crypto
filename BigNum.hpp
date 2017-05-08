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

#include <openssl/bn.h>

class BigNumCtx
{
private:
    BN_CTX* ctx;

public:
    BigNumCtx();
    BigNumCtx(const BigNumCtx&) = delete;
    BigNumCtx& operator=(const BigNumCtx&) = delete;
    BigNumCtx(BigNumCtx&& other);
    BigNumCtx& operator=(BigNumCtx&& other);
    ~BigNumCtx();

    BN_CTX* get();

    BIGNUM* getBigNum();
    BIGNUM* getBigNum(BN_ULONG w);

    class BigNumCtxGuard
    {
    private:
        BigNumCtx* ctx;

    public:
        BigNumCtxGuard(const BigNumCtxGuard&) = delete;
        BigNumCtxGuard& operator=(const BigNumCtxGuard&) = delete;
        BigNumCtxGuard(BigNumCtxGuard&& other);
        BigNumCtxGuard& operator=(BigNumCtxGuard&& other);
        BigNumCtxGuard(BigNumCtx* ctx);
        ~BigNumCtxGuard();
    };

    BigNumCtxGuard getGuard();
};
