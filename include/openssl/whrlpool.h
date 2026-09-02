/*
 * Copyright 2005-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_WHRLPOOL_H
#define OPENSSL_WHRLPOOL_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_WHRLPOOL_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_WHIRLPOOL
#include <openssl/e_os2.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define WHIRLPOOL_DIGEST_LENGTH (512 / 8)

#if !defined(OPENSSL_NO_DEPRECATED_3_0)

#define WHIRLPOOL_BBLOCK 512
#define WHIRLPOOL_COUNTER (256 / 8)

/**
 * @brief Incremental WHIRLPOOL digest state (deprecated; prefer EVP_MD APIs).
 */
typedef struct {
    /** Hash state H stored as bytes or doubles for alignment. */
    union {
        /** Digest bytes (WHIRLPOOL_DIGEST_LENGTH). */
        unsigned char c[WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        /** Alignment padding view forcing 64-bit alignment of H. */
        double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    /** Partial message block buffer (WHIRLPOOL_BBLOCK/8 bytes). */
    unsigned char data[WHIRLPOOL_BBLOCK / 8];
    /** Bit offset within the current incomplete byte of @c data (0..7). */
    unsigned int bitoff;
    /** Bit-length counter of absorbed message bits (WHIRLPOOL_COUNTER octets). */
    size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
} WHIRLPOOL_CTX;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Initialize a low-level WHIRLPOOL digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
/**
 * @brief Absorb more message bytes into a WHIRLPOOL digest context (deprecated).
 * @param c Context initialized with WHIRLPOOL_Init().
 * @param inp Message bytes to hash.
 * @param bytes Number of bytes at @p inp.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Update(WHIRLPOOL_CTX *c,
    const void *inp, size_t bytes);
/**
 * @brief Absorb @p bits bits of message data into a WHIRLPOOL context (deprecated).
 * @param c Context initialized with WHIRLPOOL_Init().
 * @param inp Bit-oriented message data (consumed MSB-first within each byte).
 * @param bits Number of bits to absorb from @p inp.
 */
OSSL_DEPRECATEDIN_3_0 void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c,
    const void *inp, size_t bits);
/**
 * @brief Finalise a WHIRLPOOL digest into a 64-byte buffer (deprecated; prefer EVP_DigestFinal_ex).
 * @param md Destination buffer of at least WHIRLPOOL_DIGEST_LENGTH bytes.
 * @param c Context to finalise (left in an undefined state afterward).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Final(unsigned char *md, WHIRLPOOL_CTX *c);
/**
 * @brief Compute the WHIRLPOOL digest of @p bytes at @p inp in one shot (deprecated; prefer EVP_Digest).
 * @param inp Input message bytes.
 * @param bytes Length of @p inp in bytes.
 * @param md Output buffer for the 64-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *WHIRLPOOL(const void *inp, size_t bytes,
    unsigned char *md);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
