/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MD5_H
#define OPENSSL_MD5_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_MD5_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MD5
#include <openssl/e_os2.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_LENGTH 16

#if !defined(OPENSSL_NO_DEPRECATED_3_0)
/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! MD5_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define MD5_LONG unsigned int

#define MD5_CBLOCK 64
#define MD5_LBLOCK (MD5_CBLOCK / 4)

/**
 * @brief Incremental MD5 digest state (also typedef'd as MD5_CTX); deprecated low-level API.
 */
typedef struct MD5state_st {
    /** Chaining variables A..D of the MD5 compression function. */
    MD5_LONG A, B, C, D;
    /** Low 32 bits of the bit-length counter. */
    MD5_LONG Nl;
    /** High 32 bits of the bit-length counter. */
    MD5_LONG Nh;
    /** Current message block buffer (MD5_LBLOCK words). */
    MD5_LONG data[MD5_LBLOCK];
    /** Number of bytes currently buffered in @c data toward a full block. */
    unsigned int num;
} MD5_CTX;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Initialize a low-level MD5 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MD5_Init(MD5_CTX *c);
/**
 * @brief Absorb more message bytes into an MD5 digest context (deprecated).
 * @param c MD5 context initialized with MD5_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MD5_Update(MD5_CTX *c, const void *data, size_t len);
/**
 * @brief Finish an MD5 message digest and write the 16-byte result (deprecated).
 * @param md Output buffer for the digest (must hold at least 16 bytes).
 * @param c MD5 context initialized with MD5_Init() and updated with MD5_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MD5_Final(unsigned char *md, MD5_CTX *c);
/**
 * @brief Compute the MD5 digest of @p n bytes at @p d in one shot (deprecated; prefer EVP_Digest).
 * @param d Input message bytes.
 * @param n Length of @p d in bytes.
 * @param md Output buffer for the 16-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *MD5(const unsigned char *d, size_t n,
    unsigned char *md);
/**
 * @brief Apply the MD5 compression function to one 64-byte block (deprecated).
 * @param c MD5 context whose chaining variables are updated in place.
 * @param b Input block of MD5_CBLOCK (64) bytes.
 */
OSSL_DEPRECATEDIN_3_0 void MD5_Transform(MD5_CTX *c, const unsigned char *b);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
