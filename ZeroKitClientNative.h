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

#ifndef ZEROKITCLIENTNATIVE_H
#define ZEROKITCLIENTNATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifndef ZEROKITCLIENTNATIVE_PUBLIC
#ifdef _WIN32
#ifdef ZEROKITCLIENTNATIVE_CREATEDLL
#define ZEROKITCLIENTNATIVE_PUBLIC __declspec(dllexport)
#else
#define ZEROKITCLIENTNATIVE_PUBLIC __declspec(dllimport)
#endif
#else
#define ZEROKITCLIENTNATIVE_PUBLIC __attribute__((visibility("default")))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Provides cryptographically strong pseudo-random bytes.
 * @param buf the buffer which to write the bytes.
 * @param len the length of the buffer.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int cryptoRandomBytes(uint8_t* buf, size_t len);

/**
 * Calculates the SHA256 hash of the message.
 * @param message the hexencoded message.
 * @param hash the buffer to store the hexencoded hash. Must be at least 65 bytes long.
 * @param hashLen the length of the hash buffer.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int calculateSha256(const char* message, char* hash, size_t hashLen);

/**
 * Calculates the SHA512 hash of the message.
 * @param message the hexencoded message.
 * @param hash the buffer to store the hexencoded hash. Must be at least 129 bytes long.
 * @param hashLen the length of the hash buffer.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int calculateSha512(const char* message, char* hash, size_t hashLen);

/**
 * Calculates the HMAC-SHA256 of the message.
 * @param key the hexencoded key.
 * @param message the hexencoded message.
 * @param hmac the buffer to store the hexencoded HMAC. Must be at least 65 bytes long.
 * @param hmacLen the length of the HMAC buffer.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int calculateHmacSha256(
  const char* key, const char* message, char* hmac, size_t hmacLen);

/**
 * Verifies the HMAC-SHA256 of the message.
 * @param key the hexencoded key.
 * @param message the hexencoded message.
 * @param hmac the hexencoded HMAC.
 * @return negative on error, 0 if the verification failed, 1 if the verification succeeded
 */
ZEROKITCLIENTNATIVE_PUBLIC int verifyHmacSha256(
  const char* key, const char* message, const char* hmac);

/**
 * Derives a key with PBKDF2-HMAC-SHA256 from the password.
 * @param password the hexencoded password.
 * @param salt the hexencoded salt.
 * @param iter the number of iterations.
 * @param key the buffer to store the hexencoded key. Must be at least (keySize * 2 + 1) bytes long.
 * @param keySize the desired length of the key.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int derivePbkdf2HmacSha256(
  const char* password, const char* salt, uint32_t iter, char* key, size_t keySize);

/**
 * Derives a key with PBKDF2-HMAC-SHA512 from the password.
 * @param password the hexencoded password.
 * @param salt the hexencoded salt.
 * @param iter the number of iterations.
 * @param key the buffer to store the hexencoded key. Must be at least (keySize * 2 + 1) bytes long.
 * @param keySize the desired length of the key in bytes.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int derivePbkdf2HmacSha512(
  const char* password, const char* salt, uint32_t iter, char* key, size_t keySize);

/**
 * Derives a key with Scrypt from the password.
 * @param password the hexencoded password.
 * @param salt the hexencoded salt.
 * @param N iteration count.
 * @param r underlying blocksize.
 * @param p paralellization factor.
 * @param key the buffer to store the hexencoded key. Must be at least (keySize * 2 + 1) bytes long.
 * @param keySize the desired length of the key in bytes.
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int deriveScrypt(const char* password, const char* salt, uint64_t N,
  uint64_t r, uint64_t p, char* key, size_t keySize);

/**
 * Encrypts the plaintext with AES128-GCM.
 * @param key the hexencoded key. Must be (128 / 8) * 2 + 1 = 33 bytes long.
 * @param iv the hexencoded IV. Must be a cryptographically secure random and must be different for
 * every encryption.
 * @param aad the hexencoded AAD.
 * @param plaintext the hexencoded plaintext.
 * @param ciphertext the buffer to store the hexencoded ciphertext. Must be at least as long as the
 * hexencoded plaintext (including the terminating NULL character).
 * @param ciphertextLen the length of the ciphertext buffer.
 * @param tag the buffer to store the hexencoded tag. Must be at least (tagLen * 2 + 1) bytes long.
 * @param tagLen the desired length of the tag in bytes. Must be at least 12 (16 is most commonly used).
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int encryptAes128Gcm(const char* key, const char* iv, const char* aad,
  const char* plaintext, char* ciphertext, size_t ciphertextLen, char* tag, size_t tagLen);

/**
 * Decrypts the ciphertext with AES128-GCM.
 * @param key the hexencoded key. Must be (128 / 8) * 2 + 1 = 33 bytes long.
 * @param iv the hexencoded IV.
 * @param aad the hexencoded AAD.
 * @param ciphertext the hexencoded ciphertext.
 * @param tag the hexencoded tag. The (non-hexencoded) tag must be at least 12 bytes long.
 * @param plaintext the buffer to store the hexencoded plaintext. Must be at least as long as the
 * hexencoded ciphertext (including the terminating NULL character).
 * @param plaintextLen the length of the plaintext buffer.
 * @return negative on error, 0 if the verification failed, 1 if the verification succeeded. The
 * plaintext MUST NOT be used unless the return value is 1.
 */
ZEROKITCLIENTNATIVE_PUBLIC int decryptAes128Gcm(const char* key, const char* iv, const char* aad,
  const char* ciphertext, const char* tag, char* plaintext, size_t plaintextLen);

/**
 * Encrypts the plaintext with AES256-GCM.
 * @param key the hexencoded key. Must be (256 / 8) * 2 + 1 = 65 bytes long.
 * @param iv the hexencoded IV. Must be a cryptographically secure random and must be different for
 * every encryption.
 * @param aad the hexencoded AAD.
 * @param plaintext the hexencoded plaintext.
 * @param ciphertext the buffer to store the hexencoded ciphertext. Must be at least as long as the
 * hexencoded plaintext (including the terminating NULL character).
 * @param ciphertextLen the length of the ciphertext buffer.
 * @param tag the buffer to store the hexencoded tag. Must be at least (tagLen * 2 + 1) bytes long.
 * @param tagLen the desired length of the tag in bytes. Must be at least 12 (16 is most commonly used).
 * @return 0 on success, negative on error
 */
ZEROKITCLIENTNATIVE_PUBLIC int encryptAes256Gcm(const char* key, const char* iv, const char* aad,
  const char* plaintext, char* ciphertext, size_t ciphertextLen, char* tag, size_t tagLen);

/**
 * Decrypts the ciphertext with AES256-GCM.
 * @param key the hexencoded key. Must be (256 / 8) * 2 + 1 = 65 bytes long.
 * @param iv the hexencoded IV.
 * @param aad the hexencoded AAD.
 * @param ciphertext the hexencoded ciphertext.
 * @param tag the hexencoded tag. The (non-hexencoded) tag must be at least 12 bytes long.
 * @param plaintext the buffer to store the hexencoded plaintext. Must be at least as long as the
 * hexencoded ciphertext (including the terminating NULL character).
 * @param plaintextLen the length of the plaintext buffer.
 * @return negative on error, 0 if the verification failed, 1 if the verification succeeded. The
 * plaintext MUST NOT be used unless the return value is 1.
 */
ZEROKITCLIENTNATIVE_PUBLIC int decryptAes256Gcm(const char* key, const char* iv, const char* aad,
  const char* ciphertext, const char* tag, char* plaintext, size_t plaintextLen);

/**
 * Handle for the client side of an SRP-6 transaction. Must not be reused.
 */
typedef void TresoritSrp6Client;

/**
 * Creates a new SRP-6 client handle.
 * @param N the hexencoded modulus.
 * @param g the hexencoded generator.
 * @return NULL on error, the handle on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC TresoritSrp6Client* srp6ClientNew(const char* N, const char* g);

/**
 * Calculates x according to RFC2945 with SHA256.
 * @param client the SRP-6 client handle.
 * @param salt the hexencoded salt.
 * @param identity the hexencoded identity.
 * @param password the hexencoded password.
 * @return NULL on error, the hexencoded x on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientCalculateX(
  TresoritSrp6Client* client, const char* salt, const char* identity, const char* password);

/**
 * Generates the verifier.
 * @param client the SRP-6 client handle.
 * @param x the hexencoded x derived from the salt, identity and password by hash or password
 * derivation functions.
 * @return NULL on error, the hexencoded verifier (v) on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientCalculateVerifier(
  TresoritSrp6Client* client, const char* x);

/**
 * Generates the client credentials (privA + pubA).
 * @param client the SRP-6 client handle.

 * @return NULL on error, the hexencoded public client credentials (pubA) on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientGenerateClientCredentials(
  TresoritSrp6Client* client);

/**
 * Calculates the secret (S).
 * @param client the SRP-6 client handle.
 * @param x the hexencoded x derived from the salt, identity and password by hash or password
 * derivation functions.
 * @param serverB the hexencoded public server credentials (pubB).
 * @return NULL on error, the hexencoded secret on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientCalculateSecret(
  TresoritSrp6Client* client, const char* x, const char* serverB);

/**
 * Calculates the client evidence message (M1).
 * @param client the SRP-6 client handle.
 * @return NULL on error, the hexencoded client evidence message on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientCalculateClientEvidenceMessage(
  TresoritSrp6Client* client);

/**
 * Verifies the server evidence message.
 * @param client the SRP-6 client handle.
 * @param serverM2 the hexencoded server evidence message (M2).
 * @return negative on error, 0 if the verification failed, 1 if the verification succeeded
 */
ZEROKITCLIENTNATIVE_PUBLIC int srp6ClientVerifyServerEvidenceMessage(
  TresoritSrp6Client* client, const char* serverM2);

/**
 * Calculates the session key (K).
 * @param client the SRP-6 client handle.
 * @return NULL on error, the hexencoded session key on success.
 */
ZEROKITCLIENTNATIVE_PUBLIC const char* srp6ClientCalculateSessionKey(TresoritSrp6Client* client);

/**
 * Frees the SRP-6 client handle and associated strings. Invalidates every result obtained from the
 * handle.
 * @param client the SRP-6 client handle.
 */
ZEROKITCLIENTNATIVE_PUBLIC void srp6ClientFree(TresoritSrp6Client* client);

#ifdef __cplusplus
}
#endif

#endif
