/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_RIPEMD_H
#define OPENSSL_RIPEMD_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_RIPEMD_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_RMD160
#include <openssl/e_os2.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_LENGTH 20

#ifdef __cplusplus
extern "C" {
#endif
#if !defined(OPENSSL_NO_DEPRECATED_3_0)

#define RIPEMD160_LONG unsigned int

#define RIPEMD160_CBLOCK 64
#define RIPEMD160_LBLOCK (RIPEMD160_CBLOCK / 4)

/**
 * @brief Legacy RIPEMD-160 hashing context (deprecated; prefer EVP_MD APIs).
 */
typedef struct RIPEMD160state_st {
    /** Chaining variables A..E of the RIPEMD-160 compression function. */
    RIPEMD160_LONG A, B, C, D, E;
    /** Low 32 bits of the bit-length counter. */
    RIPEMD160_LONG Nl;
    /** High 32 bits of the bit-length counter. */
    RIPEMD160_LONG Nh;
    /** Current message block buffer (RIPEMD160_LBLOCK words). */
    RIPEMD160_LONG data[RIPEMD160_LBLOCK];
    /** Number of bytes currently buffered in @c data toward a full block. */
    unsigned int num;
} RIPEMD160_CTX;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Initialize a RIPEMD-160 hashing context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RIPEMD160_Init(RIPEMD160_CTX *c);
/**
 * @brief Absorb @p len bytes into a RIPEMD-160 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context initialised by RIPEMD160_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data,
    size_t len);
/**
 * @brief Finalise a RIPEMD-160 digest into a 20-byte buffer (deprecated; prefer EVP_DigestFinal_ex).
 * @param md Destination buffer of at least RIPEMD160_DIGEST_LENGTH bytes.
 * @param c Context to finalise (left in an undefined state afterward).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c);
/**
 * @brief Compute the RIPEMD-160 digest of @p n bytes at @p d in one shot (deprecated; prefer EVP_Digest).
 * @param d Input message bytes.
 * @param n Length of @p d in bytes.
 * @param md Output buffer for the 20-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *RIPEMD160(const unsigned char *d, size_t n,
    unsigned char *md);
/**
 * @brief Process one 64-byte RIPEMD-160 block into the context chaining state (deprecated).
 * @param c Context whose A..E state is updated.
 * @param b 64-byte message block in the RIPEMD-160 input layout.
 */
OSSL_DEPRECATEDIN_3_0 void RIPEMD160_Transform(RIPEMD160_CTX *c,
    const unsigned char *b);
#endif

#ifdef __cplusplus
}
#endif
#endif
#endif
