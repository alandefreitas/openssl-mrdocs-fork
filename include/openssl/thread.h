/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_THREAD_H
#define OPENSSL_THREAD_H

#define OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL (1U << 0)
#define OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN (1U << 1)

#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return bitmask of thread features supported by this OpenSSL build.
 * @return OSSL_THREAD_SUPPORT_FLAG_* bits indicating thread-pool and default-spawn support.
 */
uint32_t OSSL_get_thread_support_flags(void);
/**
 * @brief Set the maximum number of threads the OpenSSL thread pool may use for @p ctx.
 * @param ctx Library context whose pool limit is updated, or NULL for the default.
 * @param max_threads Maximum pool size; 0 disables the pool and tears down existing pool threads.
 * @return 1 on success, or 0 if thread pooling is unsupported or the call fails.
 */
int OSSL_set_max_threads(OSSL_LIB_CTX *ctx, uint64_t max_threads);
/**
 * @brief Return the current maximum thread-pool size configured for a library context.
 * @param ctx Library context to query, or NULL for the default.
 * @return Configured maximum threads, or 0 if pooling is disabled or unavailable.
 */
uint64_t OSSL_get_max_threads(OSSL_LIB_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_THREAD_H */
