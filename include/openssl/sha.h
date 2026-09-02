/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_SHA_H
#define OPENSSL_SHA_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_SHA_H
#endif

#include <openssl/e_os2.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_DIGEST_LENGTH 20

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define SHA_LONG unsigned int

#define SHA_LBLOCK 16
#define SHA_CBLOCK (SHA_LBLOCK * 4) /* SHA treats input data as a      \
                                     * contiguous array of 32 bit wide \
                                     * big-endian values. */
#define SHA_LAST_BLOCK (SHA_CBLOCK - 8)

/**
 * @brief Incremental SHA-1 digest state (also typedef'd as SHA_CTX); deprecated low-level API.
 */
typedef struct SHAstate_st {
    /** Chaining variables H0..H4 of the SHA-1 compression function. */
    SHA_LONG h0, h1, h2, h3, h4;
    /** Low 32 bits of the bit-length counter. */
    SHA_LONG Nl;
    /** High 32 bits of the bit-length counter. */
    SHA_LONG Nh;
    /** Current message block buffer (16 SHA_LONG words). */
    SHA_LONG data[SHA_LBLOCK];
    /** Number of bytes currently buffered in @c data toward a full block. */
    unsigned int num;
} SHA_CTX;

/**
 * @brief Initialize a low-level SHA-1 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Init(SHA_CTX *c);
/**
 * @brief Absorb @p len bytes at @p data into a SHA-1 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA1_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
/**
 * @brief Finalize a SHA-1 digest into @p md and clear @p c (deprecated; prefer EVP_DigestFinal_ex).
 * @param md Output buffer of at least SHA_DIGEST_LENGTH (20) bytes.
 * @param c Context previously updated with SHA1_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Final(unsigned char *md, SHA_CTX *c);
/**
 * @brief Process one SHA-1 compression round on a full 64-byte block (deprecated).
 * @param c SHA-1 context whose chaining variables are updated.
 * @param data Pointer to SHA_CBLOCK input bytes.
 */
OSSL_DEPRECATEDIN_3_0 void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
#endif

/**
 * @brief Compute the SHA-1 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA_DIGEST_LENGTH bytes, or NULL to use a static buffer (not thread-safe).
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL), or NULL on error.
 */
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define SHA256_CBLOCK (SHA_LBLOCK * 4) /* SHA-256 treats input data as a  \
                                        * contiguous array of 32 bit wide \
                                        * big-endian values. */

/**
 * @brief Incremental SHA-224 / SHA-256 digest state (also typedef'd as SHA256_CTX); deprecated low-level API.
 */
typedef struct SHA256state_st {
    /** Working hash state H0..H7 (eight 32-bit words). */
    SHA_LONG h[8];
    /** Low and high 32-bit halves of the bit-length counter. */
    SHA_LONG Nl, Nh;
    /** Partial input block being accumulated (SHA_LBLOCK words). */
    SHA_LONG data[SHA_LBLOCK];
    /** Bytes buffered in @c data, and configured digest length (SHA-224 vs SHA-256). */
    unsigned int num, md_len;
} SHA256_CTX;

/**
 * @brief Initialize a SHA-224 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize (uses the SHA256_CTX layout).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Init(SHA256_CTX *c);
/**
 * @brief Absorb message bytes into a SHA-224 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA224_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Update(SHA256_CTX *c,
    const void *data, size_t len);
/**
 * @brief Place the SHA-224 digest into @p md and clear @p c (deprecated).
 * @param md Buffer of at least SHA224_DIGEST_LENGTH bytes receiving the digest.
 * @param c SHA-224/256 context previously updated with SHA224_Update.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Final(unsigned char *md, SHA256_CTX *c);
/**
 * @brief Initialise a SHA-256 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialise.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA256_Init(SHA256_CTX *c);
/**
 * @brief Absorb message bytes into a SHA-256 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA256_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA256_Update(SHA256_CTX *c,
    const void *data, size_t len);
/**
 * @brief Finalise a SHA-256 digest and write the 32-byte hash.
 * @param md Output buffer of at least SHA256_DIGEST_LENGTH bytes.
 * @param c Context previously updated with SHA256_Update(); not reused afterward without re-init.
 * @return 1 on success, or 0 on error.
 *
 * Deprecated; prefer EVP_DigestFinal_ex() / EVP_Q_digest().
 */
OSSL_DEPRECATEDIN_3_0 int SHA256_Final(unsigned char *md, SHA256_CTX *c);
/**
 * @brief Process one 64-byte SHA-256 block into digest state @p c (deprecated).
 * @param c SHA-256 context whose state words are updated.
 * @param data Pointer to a single 64-byte message block.
 */
OSSL_DEPRECATEDIN_3_0 void SHA256_Transform(SHA256_CTX *c,
    const unsigned char *data);
#endif

/**
 * @brief Compute the SHA-224 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA224_DIGEST_LENGTH bytes, or NULL for a static buffer.
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
/**
 * @brief Compute the SHA-256 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA256_DIGEST_LENGTH bytes, or NULL for a static buffer (not thread-safe).
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);

#define SHA256_192_DIGEST_LENGTH 24
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
#define SHA512_CBLOCK (SHA_LBLOCK * 8)
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SHA_LONG64 unsigned __int64
#elif defined(__arch64__)
#define SHA_LONG64 unsigned long
#else
#define SHA_LONG64 unsigned long long
#endif

/**
 * @brief Incremental SHA-384 / SHA-512 digest state (also typedef'd as SHA512_CTX).
 */
typedef struct SHA512state_st {
    /** Working hash state H0..H7 (eight 64-bit words). */
    SHA_LONG64 h[8];
    SHA_LONG64 Nl; /**< Low 64 bits of the bit-length counter. */
    SHA_LONG64 Nh; /**< High 64 bits of the bit-length counter. */
    /**
     * @brief Current message block viewed as 64-bit words (@c d) or bytes (@c p).
     */
    union {
        /** Current message block as 64-bit words for the compression function. */
        SHA_LONG64 d[SHA_LBLOCK];
        /** Current message block as bytes for partial-block buffering. */
        unsigned char p[SHA512_CBLOCK];
    } u;
    /** Number of bytes currently buffered in u.p toward a full block. */
    unsigned int num;
    /** Digest output length in bytes (SHA384_DIGEST_LENGTH or SHA512_DIGEST_LENGTH). */
    unsigned int md_len;
} SHA512_CTX;

/**
 * @brief Initialize a SHA-384 digest context (deprecated; prefer EVP_DigestInit).
 * @param c Context to initialize; uses the SHA-512 state layout with a 384-bit digest length.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA384_Init(SHA512_CTX *c);
/**
 * @brief Absorb message bytes into a SHA-384 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA384_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA384_Update(SHA512_CTX *c,
    const void *data, size_t len);
/**
 * @brief Finalise a SHA-384 digest and write the 48-byte hash (deprecated).
 * @param md Output buffer of at least SHA384_DIGEST_LENGTH bytes.
 * @param c Context previously updated with SHA384_Update().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int SHA384_Final(unsigned char *md, SHA512_CTX *c);
/**
 * @brief Initialize a SHA-512 digest context (deprecated; prefer EVP_DigestInit).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Init(SHA512_CTX *c);
/**
 * @brief Absorb message bytes into a SHA-512 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA512_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Update(SHA512_CTX *c,
    const void *data, size_t len);
/**
 * @brief Finalize a SHA-512 digest and write SHA512_DIGEST_LENGTH bytes to @p md (deprecated).
 * @param md Destination buffer for the digest.
 * @param c Context previously updated with SHA512_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Final(unsigned char *md, SHA512_CTX *c);
/**
 * @brief Process one SHA-512 block into @p c (deprecated low-level primitive).
 * @param c SHA-512 context whose state is updated.
 * @param data Exactly SHA512_CBLOCK bytes of input.
 */
OSSL_DEPRECATEDIN_3_0 void SHA512_Transform(SHA512_CTX *c,
    const unsigned char *data);
#endif

/**
 * @brief Compute the SHA-384 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA384_DIGEST_LENGTH bytes, or NULL for a static buffer.
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
/**
 * @brief Compute the SHA-512 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA512_DIGEST_LENGTH bytes, or NULL for a static buffer (not thread-safe).
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);

#ifdef __cplusplus
}
#endif

#endif
