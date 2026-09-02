/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PARAM_BUILD_H
#define OPENSSL_PARAM_BUILD_H
#pragma once

#include <openssl/params.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate an empty OSSL_PARAM builder.
 * @return New builder, or NULL on allocation failure; free with OSSL_PARAM_BLD_free().
 */
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
/**
 * @brief Convert a built-up parameter builder into a newly allocated OSSL_PARAM array.
 * @param bld Builder populated with OSSL_PARAM_BLD_push_*() calls.
 * @return Allocated OSSL_PARAM array (free with OSSL_PARAM_free()), or NULL on error.
 */
OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld);
/**
 * @brief Free an OSSL_PARAM builder allocated by OSSL_PARAM_BLD_new().
 * @param bld Builder to free, or NULL.
 */
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld);

/**
 * @brief Append a signed int parameter to a builder (stored by value).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_int(OSSL_PARAM_BLD *bld, const char *key, int val);
/**
 * @brief Append an unsigned int parameter to a builder (stored by value).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_uint(OSSL_PARAM_BLD *bld, const char *key,
    unsigned int val);
/**
 * @brief Append a signed long parameter to a builder (stored by value).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_long(OSSL_PARAM_BLD *bld, const char *key,
    long int val);
/**
 * @brief Append an unsigned long parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_ulong(OSSL_PARAM_BLD *bld, const char *key,
    unsigned long int val);
/**
 * @brief Append a signed 32-bit integer parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_int32(OSSL_PARAM_BLD *bld, const char *key,
    int32_t val);
/**
 * @brief Append an unsigned 32-bit integer parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_uint32(OSSL_PARAM_BLD *bld, const char *key,
    uint32_t val);
/**
 * @brief Append a signed 64-bit integer parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_int64(OSSL_PARAM_BLD *bld, const char *key,
    int64_t val);
/**
 * @brief Append an unsigned 64-bit integer parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_uint64(OSSL_PARAM_BLD *bld, const char *key,
    uint64_t val);
/**
 * @brief Append a size_t parameter to a builder (stored by value).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_size_t(OSSL_PARAM_BLD *bld, const char *key,
    size_t val);
/**
 * @brief Append a time_t parameter to a builder (stored by value).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_time_t(OSSL_PARAM_BLD *bld, const char *key,
    time_t val);
/**
 * @brief Append a double-precision floating-point parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_double(OSSL_PARAM_BLD *bld, const char *key,
    double val);
/**
 * @brief Append a BIGNUM parameter by reference (must remain valid until OSSL_PARAM_BLD_to_param()).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param bn Non-negative BIGNUM to store; secure BIGNUMs yield secure OSSL_PARAM storage.
 * @return 1 on success, or 0 on error (including negative @p bn).
 */
int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key,
    const BIGNUM *bn);
/**
 * @brief Append a BIGNUM parameter padded to exactly @p sz bytes (by reference until to_param).
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param bn Non-negative BIGNUM to store.
 * @param sz Exact encoded size in bytes; fails if @p bn does not fit.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_BN_pad(OSSL_PARAM_BLD *bld, const char *key,
    const BIGNUM *bn, size_t sz);
/**
 * @brief Append a UTF-8 string parameter by reference until OSSL_PARAM_BLD_to_param().
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param buf UTF-8 string (NUL not counted in @p bsize); must remain in scope until to_param.
 * @param bsize Length of @p buf excluding NUL, or 0 to compute via strlen().
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key,
    const char *buf, size_t bsize);
/**
 * @brief Append a UTF-8 string pointer parameter that remains referenced until OSSL_PARAM_free().
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param buf UTF-8 string; must remain valid until the resulting OSSL_PARAM array is freed.
 * @param bsize Length of @p buf excluding NUL, or 0 to compute via strlen().
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_utf8_ptr(OSSL_PARAM_BLD *bld, const char *key,
    char *buf, size_t bsize);
/**
 * @brief Append an octet-string parameter by reference until OSSL_PARAM_BLD_to_param().
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param buf Octet buffer that must remain in scope until to_param.
 * @param bsize Length of @p buf in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *bld, const char *key,
    const void *buf, size_t bsize);
/**
 * @brief Append an octet-string pointer parameter that remains referenced until OSSL_PARAM_free().
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param buf Octet buffer that must remain valid until the resulting OSSL_PARAM array is freed.
 * @param bsize Length of @p buf in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_octet_ptr(OSSL_PARAM_BLD *bld, const char *key,
    void *buf, size_t bsize);

#ifdef __cplusplus
}
#endif
#endif /* OPENSSL_PARAM_BUILD_H */
