/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_RC2_H
#define OPENSSL_RC2_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_RC2_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_RC2
#ifdef __cplusplus
extern "C" {
#endif

#define RC2_BLOCK 8
#define RC2_KEY_LENGTH 16

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Unsigned integer word type used in the deprecated low-level RC2 key schedule.
 */
typedef unsigned int RC2_INT;

#define RC2_ENCRYPT 1
#define RC2_DECRYPT 0

/**
 * @brief Expanded RC2 key schedule used by the deprecated low-level RC2_* encryptors.
 */
typedef struct rc2_key_st {
    /** 64-word expanded key table produced by RC2_set_key(). */
    RC2_INT data[64];
} RC2_KEY;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Expand a raw RC2 key into an RC2_KEY schedule (deprecated).
 * @param key Destination schedule.
 * @param len Number of key bytes at @p data.
 * @param data Raw key octets.
 * @param bits Effective key bits for RC2 (typically 8..1024; 0 selects a default of 1024).
 */
OSSL_DEPRECATEDIN_3_0 void RC2_set_key(RC2_KEY *key, int len,
    const unsigned char *data, int bits);
/**
 * @brief Encrypt or decrypt one RC2 block in ECB mode (deprecated).
 * @param in 8-byte input block.
 * @param out 8-byte output block (may equal @p in).
 * @param key Expanded key from RC2_set_key().
 * @param enc RC2_ENCRYPT to encrypt, or RC2_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_ecb_encrypt(const unsigned char *in,
    unsigned char *out, RC2_KEY *key,
    int enc);
/**
 * @brief Encrypt one RC2 block held as two host-endian longs (deprecated).
 * @param data Two-element array holding the 64-bit block.
 * @param key Expanded key from RC2_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void RC2_encrypt(unsigned long *data, RC2_KEY *key);
/**
 * @brief Decrypt one RC2 block held as two host-endian longs (deprecated).
 * @param data Two-element array holding the 64-bit block.
 * @param key Expanded key from RC2_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void RC2_decrypt(unsigned long *data, RC2_KEY *key);
/**
 * @brief Encrypt or decrypt with RC2 in CBC mode (deprecated).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process (should be a multiple of RC2_BLOCK).
 * @param ks Expanded key from RC2_set_key().
 * @param iv 8-byte IV; updated to the last ciphertext block.
 * @param enc RC2_ENCRYPT or RC2_DECRYPT.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *ks, unsigned char *iv,
    int enc);
/**
 * @brief Encrypt or decrypt with RC2 in 64-bit CFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from RC2_set_key().
 * @param ivec 8-byte IV, updated in place.
 * @param num Offset into the CFB stream (0..7), updated in place.
 * @param enc RC2_ENCRYPT or RC2_DECRYPT.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num, int enc);
/**
 * @brief Encrypt or decrypt with RC2 in 64-bit OFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from RC2_set_key().
 * @param ivec 8-byte IV, updated in place.
 * @param num Offset into the OFB keystream (0..7), updated in place.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
