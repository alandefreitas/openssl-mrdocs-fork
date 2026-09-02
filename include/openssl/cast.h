/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CAST_H
#define OPENSSL_CAST_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_CAST_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CAST
#ifdef __cplusplus
extern "C" {
#endif

#define CAST_BLOCK 8
#define CAST_KEY_LENGTH 16

#ifndef OPENSSL_NO_DEPRECATED_3_0

#define CAST_ENCRYPT 1
#define CAST_DECRYPT 0

#define CAST_LONG unsigned int

/**
 * @brief Legacy CAST-128 expanded key schedule (deprecated low-level type; prefer EVP).
 */
typedef struct cast_key_st {
    /** Expanded CAST round subkeys. */
    CAST_LONG data[32];
    /** Nonzero when a short key uses the reduced-round CAST schedule. */
    int short_key; /* Use reduced rounds for short key */
} CAST_KEY;

#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Expand a CAST user key into a CAST_KEY schedule (deprecated; prefer EVP).
 * @param key Destination expanded CAST key schedule.
 * @param len Length of @p data in bytes (typically up to CAST_KEY_LENGTH).
 * @param data Raw CAST key bytes.
 */
OSSL_DEPRECATEDIN_3_0
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
/**
 * @brief Encrypt or decrypt one 8-byte CAST block in ECB mode (deprecated; prefer EVP).
 * @param in 8-byte input block.
 * @param out 8-byte output buffer (may equal @p in).
 * @param key Expanded CAST key from CAST_set_key().
 * @param enc CAST_ENCRYPT to encrypt, or CAST_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out,
    const CAST_KEY *key, int enc);
/**
 * @brief Encrypt one CAST block in place as two CAST_LONG words (deprecated low-level).
 * @param data Two CAST_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded CAST key from CAST_set_key().
 */
OSSL_DEPRECATEDIN_3_0
void CAST_encrypt(CAST_LONG *data, const CAST_KEY *key);
/**
 * @brief Decrypt one CAST block in place as two CAST_LONG words (deprecated low-level).
 * @param data Two CAST_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded CAST key from CAST_set_key().
 */
OSSL_DEPRECATEDIN_3_0
void CAST_decrypt(CAST_LONG *data, const CAST_KEY *key);
/**
 * @brief Encrypt or decrypt data with CAST in CBC mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded CAST key from CAST_set_key().
 * @param iv 8-byte IV updated in place to the last ciphertext block.
 * @param enc CAST_ENCRYPT to encrypt, or CAST_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out,
    long length, const CAST_KEY *ks, unsigned char *iv,
    int enc);
/**
 * @brief Encrypt or decrypt data with CAST in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded CAST key from CAST_set_key().
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc CAST_ENCRYPT to encrypt, or CAST_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, const CAST_KEY *schedule,
    unsigned char *ivec, int *num, int enc);
/**
 * @brief Encrypt or decrypt data with CAST in 64-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded CAST key from CAST_set_key().
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, const CAST_KEY *schedule,
    unsigned char *ivec, int *num);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
