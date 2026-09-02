/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_BLOWFISH_H
#define OPENSSL_BLOWFISH_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_BLOWFISH_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_BF
#include <openssl/e_os2.h>
#ifdef __cplusplus
extern "C" {
#endif

#define BF_BLOCK 8

#ifndef OPENSSL_NO_DEPRECATED_3_0

#define BF_ENCRYPT 1
#define BF_DECRYPT 0

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! BF_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define BF_LONG unsigned int

#define BF_ROUNDS 16

/**
 * @brief Legacy Blowfish expanded key schedule (P-array and S-boxes).
 */
typedef struct bf_key_st {
    /** Blowfish P-array including the two extra subkeys. */
    BF_LONG P[BF_ROUNDS + 2];
    /** Blowfish S-boxes (four boxes of 256 entries). */
    BF_LONG S[4 * 256];
} BF_KEY;

#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Expand a raw Blowfish key into a BF_KEY schedule (deprecated).
 * @param key Destination key schedule.
 * @param len Number of key bytes at @p data (1..56 typical; longer keys are truncated per Blowfish).
 * @param data Raw key octets.
 */
OSSL_DEPRECATEDIN_3_0 void BF_set_key(BF_KEY *key, int len,
    const unsigned char *data);
/**
 * @brief Encrypt one Blowfish block in place (deprecated low-level primitive).
 * @param data Two BF_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded Blowfish key schedule from BF_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void BF_encrypt(BF_LONG *data, const BF_KEY *key);
/**
 * @brief Decrypt one Blowfish block in place (deprecated low-level primitive).
 * @param data Two BF_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded Blowfish key schedule from BF_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void BF_decrypt(BF_LONG *data, const BF_KEY *key);
/**
 * @brief Encrypt or decrypt one 8-byte Blowfish block in ECB mode (deprecated).
 * @param in 8-byte input block.
 * @param out 8-byte output buffer (may equal @p in).
 * @param key Expanded Blowfish key schedule from BF_set_key().
 * @param enc BF_ENCRYPT to encrypt, or BF_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void BF_ecb_encrypt(const unsigned char *in,
    unsigned char *out, const BF_KEY *key,
    int enc);
/**
 * @brief Encrypt or decrypt data with Blowfish in CBC mode (deprecated).
 * @param in Input bytes of length @p length (need not be block-aligned; CFB-style trailing handled).
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded Blowfish key from BF_set_key().
 * @param ivec 8-byte IV; updated to the last ciphertext block on return.
 * @param enc BF_ENCRYPT to encrypt, or BF_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void BF_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    const BF_KEY *schedule,
    unsigned char *ivec, int enc);
/**
 * @brief Encrypt or decrypt with Blowfish in 64-bit CFB mode (deprecated; prefer EVP_EncryptInit_ex and related EVP APIs).
 * @param in Input bytes of length @p length (need not be a multiple of 8).
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded Blowfish key from BF_set_key().
 * @param ivec 8-byte IV; updated with running feedback state on return.
 * @param num Offset into the CFB feedback block (0..7), updated in place; initialize to 0 with @p ivec.
 * @param enc BF_ENCRYPT to encrypt, or BF_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void BF_cfb64_encrypt(const unsigned char *in,
    unsigned char *out,
    long length, const BF_KEY *schedule,
    unsigned char *ivec, int *num,
    int enc);
/**
 * @brief Encrypt or decrypt with Blowfish in 64-bit OFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from BF_set_key().
 * @param ivec 8-byte initialization vector, updated in place.
 * @param num Offset into the OFB keystream (0..7), updated in place.
 */
OSSL_DEPRECATEDIN_3_0 void BF_ofb64_encrypt(const unsigned char *in,
    unsigned char *out,
    long length, const BF_KEY *schedule,
    unsigned char *ivec, int *num);
/**
 * @brief Return a short string describing the compiled Blowfish implementation (deprecated).
 * @return Static implementation tag such as "blowfish(ptr)"; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const char *BF_options(void);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
