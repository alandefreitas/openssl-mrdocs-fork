/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MDC2_H
#define OPENSSL_MDC2_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_MDC2_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MDC2
#include <stdlib.h>
#include <openssl/des.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MDC2_DIGEST_LENGTH 16

#if !defined(OPENSSL_NO_DEPRECATED_3_0)

#define MDC2_BLOCK 8

/**
 * @brief Incremental MDC-2 digest state (also typedef'd as MDC2_CTX); deprecated low-level API.
 */
typedef struct mdc2_ctx_st {
    /** Number of valid bytes currently buffered in @c data (0 .. MDC2_BLOCK-1). */
    unsigned int num;
    /** Current partial message block being accumulated (MDC2_BLOCK bytes). */
    unsigned char data[MDC2_BLOCK];
    /** Running MDC-2 chaining values (two DES blocks). */
    DES_cblock h, hh;
    /** Padding rule: 1 or 2 (default 1). */
    unsigned int pad_type; /* either 1 or 2, default 1 */
} MDC2_CTX;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Initialise an MDC-2 digest context (deprecated).
 * @param c Context storage to initialise for a new MDC-2 hash.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MDC2_Init(MDC2_CTX *c);
/**
 * @brief Absorb more message bytes into an MDC-2 digest context (deprecated).
 * @param c MDC-2 context initialized with MDC2_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MDC2_Update(MDC2_CTX *c, const unsigned char *data,
    size_t len);
/**
 * @brief Finalise an MDC-2 digest and write the 16-byte result (deprecated).
 * @param md Destination buffer for the MDC2_DIGEST_LENGTH-byte digest.
 * @param c MDC-2 context to finalise (must have been initialised).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MDC2_Final(unsigned char *md, MDC2_CTX *c);
/**
 * @brief Compute the MDC-2 digest of @p n bytes at @p d in one shot (deprecated; prefer EVP_Digest).
 * @param d Input message bytes.
 * @param n Length of @p d in bytes.
 * @param md Output buffer for the 16-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *MDC2(const unsigned char *d, size_t n,
    unsigned char *md);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
