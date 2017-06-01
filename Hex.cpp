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

#include "Hex.hpp"
#include "OpenSSLException.hpp"

#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace
{
uint8_t fromHexDigit(char c)
{
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    throw std::range_error("Bad hexencoded string");
}
}

SecureVector hexToByteArray(const char* hex)
{
    const size_t len = strlen(hex);
    if (len % 2 != 0) {
        throw std::range_error("Bad hexencoded string");
    }
    SecureVector bytes(len / 2, 0);
    for (size_t i = 0; i < len / 2; i++) {
        bytes[i] =
          static_cast<uint8_t>((fromHexDigit(hex[2 * i + 0]) << 4) | fromHexDigit(hex[2 * i + 1]));
    }
    return bytes;
}

void byteArrayToHex(const SecureVector& bytes, char* hex)
{
    OPENSSL_THROW_IF(bytes.size() > (std::numeric_limits<size_t>::max() / 2 - 1));
    for (size_t i = 0; i < bytes.size(); i++) {
        auto h = bytes[i] >> 4;
        hex[2 * i + 0] = static_cast<char>(h < 10 ? ('0' + h) : ('a' + (h - 10)));
        auto l = bytes[i] & 0xf;
        hex[2 * i + 1] = static_cast<char>(l < 10 ? ('0' + l) : ('a' + (l - 10)));
    }
    hex[bytes.size() * 2] = '\0';
}

SecureVector byteArrayToHex(const SecureVector& bytes)
{
    OPENSSL_THROW_IF(bytes.size() > (std::numeric_limits<size_t>::max() / 2 - 1));
    SecureVector hex(bytes.size() * 2 + 1, '\0');

    byteArrayToHex(bytes, reinterpret_cast<char*>(hex.data()));

    return hex;
}
