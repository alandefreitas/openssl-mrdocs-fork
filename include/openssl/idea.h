/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_IDEA_H
#define OPENSSL_IDEA_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_IDEA_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_IDEA
#ifdef __cplusplus
extern "C" {
#endif

#define IDEA_BLOCK 8
#define IDEA_KEY_LENGTH 16

#ifndef OPENSSL_NO_DEPRECATED_3_0

/**
 * @brief Unsigned word type used in the IDEA key schedule tables.
 */
typedef unsigned int IDEA_INT;

#define IDEA_ENCRYPT 1
#define IDEA_DECRYPT 0

/**
 * @brief Expanded IDEA key schedule for the low-level IDEA_* APIs (deprecated; prefer EVP).
 */
typedef struct idea_key_st {
    /** Round subkeys arranged as 9 rounds of 6 IDEA_INT words each. */
    IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return a short string describing the IDEA implementation (deprecated).
 * @return Static option description string (for example "idea(int)").
 */
OSSL_DEPRECATEDIN_3_0 const char *IDEA_options(void);
/**
 * @brief Encrypt one 8-byte IDEA block in ECB mode (deprecated; prefer EVP).
 * @param in 8-byte plaintext block.
 * @param out 8-byte ciphertext buffer (may equal @p in).
 * @param ks Expanded encrypt schedule from IDEA_set_encrypt_key().
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_ecb_encrypt(const unsigned char *in,
    unsigned char *out,
    IDEA_KEY_SCHEDULE *ks);
/**
 * @brief Expand a 16-byte IDEA key into an encryption key schedule (deprecated; prefer EVP).
 * @param key 16-byte IDEA key.
 * @param ks Destination encryption schedule.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_set_encrypt_key(const unsigned char *key,
    IDEA_KEY_SCHEDULE *ks);
/**
 * @brief Derive an IDEA decryption schedule from an encryption schedule (deprecated).
 * @param ek Encryption schedule from IDEA_set_encrypt_key().
 * @param dk Destination decryption schedule.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek,
    IDEA_KEY_SCHEDULE *dk);
/**
 * @brief Encrypt or decrypt data with IDEA in CBC mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA key schedule matching @p enc.
 * @param iv 8-byte IV updated in place.
 * @param enc IDEA_ENCRYPT to encrypt, or IDEA_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int enc);
/**
 * @brief Encrypt or decrypt data with IDEA in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA encryption schedule.
 * @param iv 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc IDEA_ENCRYPT to encrypt, or IDEA_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num,
    int enc);
/**
 * @brief Encrypt or decrypt data with IDEA in 64-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA encryption schedule.
 * @param iv 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num);
/**
 * @brief Encrypt one IDEA block in place using an expanded key schedule (deprecated; prefer EVP).
 * @param in Two @c unsigned long words holding the 64-bit block (updated with ciphertext).
 * @param ks Expanded IDEA encryption or decryption schedule.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_encrypt(unsigned long *in,
    IDEA_KEY_SCHEDULE *ks);
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define idea_options IDEA_options
#define idea_ecb_encrypt IDEA_ecb_encrypt
#define idea_set_encrypt_key IDEA_set_encrypt_key
#define idea_set_decrypt_key IDEA_set_decrypt_key
#define idea_cbc_encrypt IDEA_cbc_encrypt
#define idea_cfb64_encrypt IDEA_cfb64_encrypt
#define idea_ofb64_encrypt IDEA_ofb64_encrypt
#define idea_encrypt IDEA_encrypt
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
