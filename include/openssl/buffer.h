/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_BUFFER_H
#define OPENSSL_BUFFER_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_BUFFER_H
#endif

#include <openssl/types.h>
#ifndef OPENSSL_CRYPTO_H
#include <openssl/crypto.h>
#endif
#include <openssl/buffererr.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/types.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define BUF_strdup(s) OPENSSL_strdup(s)
#define BUF_strndup(s, size) OPENSSL_strndup(s, size)
#define BUF_memdup(data, size) OPENSSL_memdup(data, size)
#define BUF_strlcpy(dst, src, size) OPENSSL_strlcpy(dst, src, size)
#define BUF_strlcat(dst, src, size) OPENSSL_strlcat(dst, src, size)
#define BUF_strnlen(str, maxlen) OPENSSL_strnlen(str, maxlen)
#endif

struct buf_mem_st {
    /** Current number of valid content bytes stored in @c data. */
    size_t length;
    /** Dynamically allocated buffer holding @c length bytes of content (capacity @c max). */
    char *data;
    /** Allocated capacity of @c data in bytes. */
    size_t max;
    /** Allocation flags such as BUF_MEM_FLAG_SECURE for secure-heap storage. */
    unsigned long flags;
};

#define BUF_MEM_FLAG_SECURE 0x01

/**
 * @brief Allocate an empty BUF_MEM with default (non-secure) allocation flags.
 * @return New zero-length BUF_MEM, or NULL on allocation failure.
 */
BUF_MEM *BUF_MEM_new(void);
/**
 * @brief Allocate a new BUF_MEM with the given allocation flags.
 * @param flags Allocation flags such as BUF_MEM_FLAG_SECURE for secure-heap @c data.
 * @return New zero-length BUF_MEM, or NULL on allocation failure.
 */
BUF_MEM *BUF_MEM_new_ex(unsigned long flags);
/**
 * @brief Free a BUF_MEM and its data buffer.
 * @param a Buffer to free, or NULL.
 *
 * Clears @c data before release when the buffer was allocated with secure flags.
 */
void BUF_MEM_free(BUF_MEM *a);
/**
 * @brief Grow or shrink a BUF_MEM so its valid length is @p len.
 * @param str Buffer to resize.
 * @param len Desired length in bytes; expands capacity when needed.
 * @return New length on success, or 0 on allocation failure.
 *
 * Newly allocated capacity beyond the previous length is left uninitialized;
 * use BUF_MEM_grow_clean() when cleared growth is required.
 */
size_t BUF_MEM_grow(BUF_MEM *str, size_t len);
/**
 * @brief Grow or shrink a BUF_MEM buffer, zeroing any released or newly unused bytes.
 * @param str Buffer to resize.
 * @param len Desired length in bytes.
 * @return New length on success, or 0 on allocation failure.
 *
 * Like BUF_MEM_grow(), but clears freed trailing data and newly allocated unused space.
 */
size_t BUF_MEM_grow_clean(BUF_MEM *str, size_t len);
/**
 * @brief Reverse @p siz bytes from @p in into @p out (or in place if @p in is NULL).
 * @param out Destination buffer; may equal @p in when reversing in place with @p in non-NULL, or the sole buffer when @p in is NULL.
 * @param in Source bytes to reverse, or NULL to reverse @p out in place.
 * @param siz Number of bytes to reverse.
 */
void BUF_reverse(unsigned char *out, const unsigned char *in, size_t siz);

#ifdef __cplusplus
}
#endif
#endif
