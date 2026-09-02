/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_COMP_H
#define OPENSSL_COMP_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_COMP_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_COMP
#include <openssl/crypto.h>
#include <openssl/comperr.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a compression context for the given method.
 * @param meth Compression method to use.
 * @return New context, or NULL on error.
 */
COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
/**
 * @brief Return the compression method associated with a context.
 * @param ctx Compression context to query.
 * @return The COMP_METHOD used to create @p ctx.
 */
const COMP_METHOD *COMP_CTX_get_method(const COMP_CTX *ctx);
/**
 * @brief Get the numeric type identifier of a compression context's method.
 * @param comp Compression context to query.
 * @return Method type NID, or NID_undef if unavailable.
 */
int COMP_CTX_get_type(const COMP_CTX *comp);
/**
 * @brief Get the numeric type identifier of a compression method.
 * @param meth Compression method to query.
 * @return Method type NID, or NID_undef if unavailable.
 */
int COMP_get_type(const COMP_METHOD *meth);
/**
 * @brief Return the human-readable name of a compression method.
 * @param meth Compression method to query.
 * @return Static name string that must not be freed, or NULL on failure.
 */
const char *COMP_get_name(const COMP_METHOD *meth);
/**
 * @brief Free a compression context.
 * @param ctx Context to free, or NULL.
 */
void COMP_CTX_free(COMP_CTX *ctx);

/**
 * @brief Compress a block of data.
 * @param ctx Compression context.
 * @param out Output buffer for compressed data.
 * @param olen Capacity of @p out in bytes.
 * @param in Input data to compress.
 * @param ilen Length of @p in in bytes.
 * @return Number of bytes written to @p out, or -1 on error.
 */
int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
    unsigned char *in, int ilen);
/**
 * @brief Decompress @p ilen bytes from @p in into @p out using a COMP_CTX.
 * @param ctx Compression context (for example zlib) that performs expansion.
 * @param out Destination buffer for expanded data.
 * @param olen Capacity of @p out in bytes.
 * @param in Compressed input bytes.
 * @param ilen Number of compressed bytes at @p in.
 * @return Number of bytes written to @p out, or a negative value on error.
 */
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
    unsigned char *in, int ilen);

/**
 * @brief Return the zlib compression method.
 * @return zlib COMP_METHOD, or a no-op method if zlib is unavailable.
 */
COMP_METHOD *COMP_zlib(void);
/**
 * @brief Return the one-shot zlib compression method.
 * @return zlib oneshot COMP_METHOD, or a no-op method if zlib is unavailable.
 */
COMP_METHOD *COMP_zlib_oneshot(void);
/**
 * @brief Return the stream-based brotli compression method.
 * @return brotli COMP_METHOD on success, or NULL on failure (or if brotli is unavailable).
 */
COMP_METHOD *COMP_brotli(void);
/**
 * @brief Return the one-shot brotli compression method.
 * @return brotli oneshot COMP_METHOD, or a no-op method if brotli is unavailable.
 */
COMP_METHOD *COMP_brotli_oneshot(void);
/**
 * @brief Return the Zstandard compression method.
 * @return zstd COMP_METHOD, or a no-op method if zstd is unavailable.
 */
COMP_METHOD *COMP_zstd(void);
/**
 * @brief Return the one-shot Zstandard COMP_METHOD (compresses each BIO_write as a complete frame).
 * @return Pointer to the static oneshot ZSTD method, or NULL if ZSTD support is unavailable.
 */
COMP_METHOD *COMP_zstd_oneshot(void);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define COMP_zlib_cleanup() \
    while (0)               \
    continue
#endif

#ifdef OPENSSL_BIO_H
const BIO_METHOD *BIO_f_zlib(void);
const BIO_METHOD *BIO_f_brotli(void);
const BIO_METHOD *BIO_f_zstd(void);
#endif

#ifdef __cplusplus
}
#endif
#endif
#endif
