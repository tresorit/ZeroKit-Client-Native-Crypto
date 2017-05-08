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

#include "BigNum.hpp"
#include "OpenSSLException.hpp"

BigNumCtx::BigNumCtx()
    : ctx(nullptr)
{
    OPENSSL_THROW_IF_NULL(this->ctx = BN_CTX_new());
    BN_CTX_start(this->ctx);
}

BigNumCtx::BigNumCtx(BigNumCtx&& other)
    : ctx(other.ctx)
{
    other.ctx = nullptr;
}

BigNumCtx& BigNumCtx::operator=(BigNumCtx&& other)
{
    if (this != &other) {
        if (this->ctx != nullptr) {
            BN_CTX_end(this->ctx);
            BN_CTX_free(this->ctx);
        }
        this->ctx = other.ctx;
        other.ctx = nullptr;
    }

    return *this;
}

BigNumCtx::~BigNumCtx()
{
    if (this->ctx != nullptr) {
        BN_CTX_end(this->ctx);
        BN_CTX_free(this->ctx);
    }
}

BN_CTX* BigNumCtx::get()
{
    return this->ctx;
}

BIGNUM* BigNumCtx::getBigNum()
{
    OPENSSL_THROW_IF_NULL(this->ctx);

    BIGNUM* bn = nullptr;
    OPENSSL_THROW_IF_NULL(bn = BN_CTX_get(this->ctx));

    return bn;
}

BIGNUM* BigNumCtx::getBigNum(BN_ULONG w)
{
    BIGNUM* bn = this->getBigNum();
    switch (w) {
    case 0:
        BN_zero(bn);
        break;
    case 1:
        OPENSSL_THROW_IF_ERROR(BN_one(bn));
        break;
    default:
        OPENSSL_THROW_IF_ERROR(BN_set_word(bn, w));
        break;
    }

    return bn;
}

BigNumCtx::BigNumCtxGuard::BigNumCtxGuard(BigNumCtx* ctx)
    : ctx(ctx)
{
    if (this->ctx != nullptr) {
        BN_CTX_start(this->ctx->get());
    }
}

BigNumCtx::BigNumCtxGuard::~BigNumCtxGuard()
{
    if (this->ctx != nullptr) {
        BN_CTX_end(this->ctx->get());
    }
}

BigNumCtx::BigNumCtxGuard::BigNumCtxGuard(BigNumCtxGuard&& other)
    : ctx(other.ctx)
{
    other.ctx = nullptr;
}

BigNumCtx::BigNumCtxGuard& BigNumCtx::BigNumCtxGuard::operator=(BigNumCtxGuard&& other)
{
    if (this != &other) {
        if (this->ctx != nullptr) {
            BN_CTX_end(this->ctx->get());
        }

        this->ctx = other.ctx;
        other.ctx = nullptr;
    }

    return *this;
}

BigNumCtx::BigNumCtxGuard BigNumCtx::getGuard()
{
    OPENSSL_THROW_IF_NULL(this->ctx);

    return BigNumCtxGuard(this);
}
