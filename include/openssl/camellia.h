/*
 * Copyright 2006-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CAMELLIA_H
#define OPENSSL_CAMELLIA_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_CAMELLIA_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CAMELLIA
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define CAMELLIA_BLOCK_SIZE 16

#ifndef OPENSSL_NO_DEPRECATED_3_0

#define CAMELLIA_ENCRYPT 1
#define CAMELLIA_DECRYPT 0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */

/* This should be a hidden type, but EVP requires that the size be known */

#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

/**
 * @brief Expanded Camellia round-key table stored as CAMELLIA_TABLE_WORD_LEN unsigned ints.
 */
typedef unsigned int KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN]; /* to match
                                                               * with WORD */

/**
 * @brief Legacy Camellia expanded key schedule (deprecated low-level type; prefer EVP_CIPHER APIs).
 */
struct camellia_key_st {
    /**
     * @brief Storage for the round-key table with forced 64-bit alignment.
     */
    union {
        /** Dummy member ensuring the union (and thus @c rd_key) is 64-bit aligned. */
        double d; /* ensures 64-bit align */
        /** Expanded Camellia round keys produced by Camellia_set_key(). */
        KEY_TABLE_TYPE rd_key;
    } u;
    /** Number of Camellia grand rounds for this key length (for example 3 or 4). */
    int grand_rounds;
};
/**
 * @brief Typedef alias for struct camellia_key_st used by the deprecated Camellia_* primitives.
 */
typedef struct camellia_key_st CAMELLIA_KEY;

#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Expand a raw Camellia key into a CAMELLIA_KEY schedule (deprecated; prefer EVP).
 * @param userKey Raw key octets (16, 24, or 32 bytes for 128/192/256-bit keys).
 * @param bits Key length in bits (128, 192, or 256).
 * @param key Destination expanded key schedule.
 * @return 0 on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int Camellia_set_key(const unsigned char *userKey,
    const int bits,
    CAMELLIA_KEY *key);
/**
 * @brief Encrypt one 16-byte Camellia block (deprecated; prefer EVP_EncryptInit_ex and related EVP APIs).
 * @param in 16-byte plaintext block.
 * @param out 16-byte ciphertext buffer (may equal @p in).
 * @param key Expanded Camellia key from Camellia_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_encrypt(const unsigned char *in,
    unsigned char *out,
    const CAMELLIA_KEY *key);
/**
 * @brief Decrypt one 16-byte Camellia block (deprecated; prefer EVP_DecryptInit_ex and related EVP APIs).
 * @param in 16-byte ciphertext block.
 * @param out 16-byte plaintext buffer (may equal @p in).
 * @param key Expanded Camellia key from Camellia_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_decrypt(const unsigned char *in,
    unsigned char *out,
    const CAMELLIA_KEY *key);
/**
 * @brief Encrypt or decrypt one 16-byte Camellia block in ECB mode (deprecated).
 * @param in 16-byte input block.
 * @param out 16-byte output buffer (may equal @p in).
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param enc Non-zero (CAMELLIA_ENCRYPT) to encrypt, zero (CAMELLIA_DECRYPT) to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_ecb_encrypt(const unsigned char *in,
    unsigned char *out,
    const CAMELLIA_KEY *key,
    const int enc);
/**
 * @brief Encrypt or decrypt data with Camellia in CBC mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process (need not be block-aligned).
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated to the last ciphertext block on return.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cbc_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    const int enc);
/**
 * @brief Encrypt or decrypt data with Camellia in 128-bit CFB mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process (need not be block-aligned).
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated with running feedback state on return.
 * @param num Byte offset into the feedback buffer (0–15); updated on return; initialize to 0 with @p ivec.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cfb128_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num,
    const int enc);
/**
 * @brief Encrypt or decrypt data with Camellia in 1-bit CFB mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated with running feedback state on return.
 * @param num Bit offset into the feedback buffer (0–7); updated on return.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cfb1_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num,
    const int enc);
/**
 * @brief Encrypt or decrypt data with Camellia in 8-bit CFB mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated with running feedback state on return.
 * @param num Byte offset into the feedback buffer; updated on return; initialize to 0 with @p ivec.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cfb8_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num,
    const int enc);
/**
 * @brief Encrypt or decrypt data with Camellia in 128-bit OFB mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated with running feedback state on return.
 * @param num Byte offset into the feedback buffer; updated on return; initialize to 0 with @p ivec.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_ofb128_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num);
/**
 * @brief Encrypt or decrypt data with Camellia in 128-bit CTR mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte counter block; low bytes are incremented on return.
 * @param ecount_buf Encrypted counter block cache updated by the routine.
 * @param num Byte offset into @p ecount_buf for the next keystream byte; updated on return.
 */
OSSL_DEPRECATEDIN_3_0
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const CAMELLIA_KEY *key,
    unsigned char ivec[CAMELLIA_BLOCK_SIZE],
    unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE],
    unsigned int *num);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
