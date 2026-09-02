/*
 * Copyright 2002-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_AES_H
#define OPENSSL_AES_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_AES_H
#endif

#include <openssl/opensslconf.h>

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16

#ifndef OPENSSL_NO_DEPRECATED_3_0

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

#define AES_MAXNR 14

/* This should be a hidden type, but EVP requires that the size be known */
/**
 * @brief Expanded AES key schedule for the low-level AES_* APIs (deprecated; prefer EVP).
 */
struct aes_key_st {
#ifdef AES_LONG
    /** Round-key words for encryption or decryption (AES_LONG element width). */
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
#else
    /** Round-key words for encryption or decryption. */
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
#endif
    /** Number of AES rounds for this key length (10, 12, or 14). */
    int rounds;
};
/**
 * @brief Expanded AES key schedule for the low-level AES_* APIs (deprecated; prefer EVP).
 */
typedef struct aes_key_st AES_KEY;

#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return a short string describing compiled AES implementation options (deprecated).
 * @return Static NUL-terminated options string.
 */
OSSL_DEPRECATEDIN_3_0 const char *AES_options(void);
/**
 * @brief Expand a user key into an AES encryption key schedule (deprecated; prefer EVP).
 * @param userKey Raw AES key bytes (16, 24, or 32 bytes for 128/192/256-bit).
 * @param bits Key length in bits (128, 192, or 256).
 * @param key Destination expanded key schedule for AES_encrypt() and encrypting modes.
 * @return 0 on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
/**
 * @brief Expand a user key into an AES decryption key schedule (deprecated; prefer EVP).
 * @param userKey Raw AES key bytes (16, 24, or 32 bytes for 128/192/256-bit).
 * @param bits Key length in bits (128, 192, or 256).
 * @param key Destination expanded key schedule for AES_decrypt() and decrypting modes.
 * @return 0 on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
/**
 * @brief Encrypt one 16-byte AES block with a key schedule (deprecated; prefer EVP).
 * @param in 16-byte plaintext block.
 * @param out 16-byte ciphertext buffer (may equal @p in).
 * @param key Expanded AES encrypt key from AES_set_encrypt_key().
 */
OSSL_DEPRECATEDIN_3_0
void AES_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);
/**
 * @brief Decrypt one 16-byte AES block with a key schedule (deprecated; prefer EVP).
 * @param in 16-byte ciphertext block.
 * @param out 16-byte plaintext buffer (may equal @p in).
 * @param key Expanded AES decrypt key from AES_set_decrypt_key().
 */
OSSL_DEPRECATEDIN_3_0
void AES_decrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);
/**
 * @brief Encrypt or decrypt one 16-byte AES block in ECB mode (deprecated; prefer EVP).
 * @param in 16-byte input block.
 * @param out 16-byte output buffer (may equal @p in).
 * @param key Expanded AES key from AES_set_encrypt_key() or AES_set_decrypt_key().
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key, const int enc);
/**
 * @brief Encrypt or decrypt data with AES in CBC mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process (should be a multiple of AES_BLOCK_SIZE).
 * @param key Expanded AES key schedule matching @p enc.
 * @param ivec 16-byte IV updated in place to the last ciphertext block.
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, const int enc);
/**
 * @brief Encrypt or decrypt data with AES in 128-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded AES key schedule.
 * @param ivec 16-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, int *num, const int enc);
/**
 * @brief Encrypt or decrypt data with AES in 1-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded AES key schedule.
 * @param ivec 16-byte IV updated in place.
 * @param num Feedback bit offset into the IV (updated; typically starts at 0).
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, int *num, const int enc);
/**
 * @brief Encrypt or decrypt data with AES in 8-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded AES key schedule.
 * @param ivec 16-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, int *num, const int enc);
/**
 * @brief Encrypt or decrypt data with AES in 128-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded AES key schedule.
 * @param ivec 16-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, int *num);

/* NB: the IV is _two_ blocks long */
/**
 * @brief Encrypt or decrypt with AES in infinite garble extension (IGE) mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length (multiple of AES_BLOCK_SIZE).
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded AES key schedule matching @p enc.
 * @param ivec 32-byte (two-block) IV updated in place.
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
/**
 * @brief Encrypt or decrypt with AES in bidirectional IGE mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length (multiple of AES_BLOCK_SIZE).
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key First expanded AES key schedule.
 * @param key2 Second expanded AES key schedule used in the bidirectional step.
 * @param ivec 64-byte (four-block) IV; not updated by this call.
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key, const AES_KEY *key2,
    const unsigned char *ivec, const int enc);
/**
 * @brief Wrap (encrypt) a key with AES Key Wrap per RFC 3394 (deprecated; prefer EVP).
 * @param key Expanded AES key used as the Key Encryption Key.
 * @param iv Optional 8-byte integrity check value, or NULL for the default IV.
 * @param out Buffer for the wrapped key (at least @p inlen + 8 bytes).
 * @param in Key material to wrap; length must be a multiple of 8.
 * @param inlen Length of @p in in bytes.
 * @return Length of wrapped data written to @p out, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
    unsigned char *out, const unsigned char *in,
    unsigned int inlen);
/**
 * @brief Unwrap (decrypt) a key with AES Key Wrap per RFC 3394 (deprecated; prefer EVP).
 * @param key Expanded AES key used as the Key Encryption Key.
 * @param iv Optional 8-byte integrity check value, or NULL for the default IV.
 * @param out Buffer for the unwrapped key (at least @p inlen - 8 bytes).
 * @param in Wrapped key material; length must be a multiple of 8 and at least 16.
 * @param inlen Length of @p in in bytes.
 * @return Length of unwrapped data written to @p out, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
    unsigned char *out, const unsigned char *in,
    unsigned int inlen);
#endif

#ifdef __cplusplus
}
#endif

#endif
