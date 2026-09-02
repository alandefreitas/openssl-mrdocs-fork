/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PROVIDER_H
#define OPENSSL_PROVIDER_H
#pragma once

#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set and Get a library context search path */
/**
 * @brief Set the default filesystem search path used when loading providers.
 * @param libctx Library context whose provider search path is updated, or NULL for the default.
 * @param path Directory path searched for provider modules.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *libctx, const char *path);
/**
 * @brief Return the default filesystem search path for loading providers (borrowed).
 * @param libctx Library context to query, or NULL for the default.
 * @return Internal NUL-terminated path string, or NULL if unset; do not free.
 */
const char *OSSL_PROVIDER_get0_default_search_path(OSSL_LIB_CTX *libctx);

/* Load and unload a provider */
/**
 * @brief Load a provider by name into a library context.
 * @param ctx Library context that will own the provider, or NULL for the default.
 * @param name Provider name (for example "default" or "legacy").
 * @return Provider handle on success, or NULL on failure; unload with OSSL_PROVIDER_unload().
 */
OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *ctx, const char *name);
/**
 * @brief Load a provider by name with an optional parameter array.
 * @param ctx Library context that will own the provider, or NULL for the default.
 * @param name Provider name (for example "default" or "legacy").
 * @param params Optional OSSL_PARAM array configuring the provider, or NULL.
 * @return Provider handle on success, or NULL on failure; unload with OSSL_PROVIDER_unload().
 */
OSSL_PROVIDER *OSSL_PROVIDER_load_ex(OSSL_LIB_CTX *ctx, const char *name,
    OSSL_PARAM *params);
/**
 * @brief Try to load a provider by name, optionally keeping fallback providers.
 * @param libctx Library context that will own the provider, or NULL for the default.
 * @param name Provider name (for example "default" or "legacy").
 * @param retain_fallbacks Non-zero to leave fallback providers active after a successful load.
 * @return Provider handle on success, or NULL on failure; unload with OSSL_PROVIDER_unload().
 */
OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *libctx, const char *name,
    int retain_fallbacks);
/**
 * @brief Try to load a provider with parameters, optionally keeping fallback providers.
 * @param ctx Library context that will own the provider, or NULL for the default.
 * @param name Provider name (for example "default" or "legacy").
 * @param params Optional OSSL_PARAM array configuring the provider, or NULL.
 * @param retain_fallbacks Non-zero to leave fallback providers active after a successful load.
 * @return Provider handle on success, or NULL on failure; unload with OSSL_PROVIDER_unload().
 */
OSSL_PROVIDER *OSSL_PROVIDER_try_load_ex(OSSL_LIB_CTX *ctx, const char *name,
    OSSL_PARAM *params,
    int retain_fallbacks);
/**
 * @brief Unload a provider, running its teardown and releasing its resources.
 * @param prov Provider previously returned by OSSL_PROVIDER_load() or a related loader.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
/**
 * @brief Report whether a named provider is available in a library context.
 * @param ctx Library context to query, or NULL for the default.
 * @param name Provider name to look up.
 * @return 1 if the provider is available (loaded or loadable as configured), or 0 otherwise.
 */
int OSSL_PROVIDER_available(OSSL_LIB_CTX *ctx, const char *name);
/**
 * @brief Invoke a callback for every provider available in a library context.
 * @param ctx Library context to enumerate, or NULL for the default.
 * @param cb Callback receiving each provider and @p cbdata; return 0 to stop early.
 * @param cbdata Opaque argument passed to @p cb.
 * @return 1 if all callbacks succeeded, or 0 if a callback returned 0 or an error occurred.
 */
int OSSL_PROVIDER_do_all(OSSL_LIB_CTX *ctx,
    int (*cb)(OSSL_PROVIDER *provider, void *cbdata),
    void *cbdata);

/**
 * @brief Return the gettable parameter descriptors for a provider (borrowed).
 * @param prov Provider to query.
 * @return NULL-terminated OSSL_PARAM array describing gettable params, or NULL on error.
 */
const OSSL_PARAM *OSSL_PROVIDER_gettable_params(const OSSL_PROVIDER *prov);
/**
 * @brief Fetch provider parameters into a caller-supplied OSSL_PARAM array.
 * @param prov Provider to query.
 * @param params Array of OSSL_PARAM entries to fill (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PROVIDER_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[]);
/**
 * @brief Run the provider's self-test routine, if implemented.
 * @param prov Provider to test.
 * @return 1 if self-tests passed or are unsupported, or 0 on failure.
 */
int OSSL_PROVIDER_self_test(const OSSL_PROVIDER *prov);
/**
 * @brief Query a named provider capability via a callback.
 * @param prov Provider to query.
 * @param capability Capability name (for example "TLS-GROUP").
 * @param cb Callback invoked for each capability description.
 * @param arg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PROVIDER_get_capabilities(const OSSL_PROVIDER *prov,
    const char *capability,
    OSSL_CALLBACK *cb,
    void *arg);

/**
 * @brief Query algorithms a provider implements for an operation.
 * @param prov Provider to query.
 * @param operation_id Operation identifier (OSSL_OP_*).
 * @param no_cache Optional output set nonzero when results must not be cached; may be NULL.
 * @return Algorithm array owned by the provider until OSSL_PROVIDER_unquery_operation(), or NULL.
 */
const OSSL_ALGORITHM *OSSL_PROVIDER_query_operation(const OSSL_PROVIDER *prov,
    int operation_id,
    int *no_cache);
/**
 * @brief Release algorithm results previously returned by OSSL_PROVIDER_query_operation().
 * @param prov Provider that produced @p algs.
 * @param operation_id Operation identifier previously queried (OSSL_OP_*).
 * @param algs Algorithm array returned by the matching query_operation call.
 */
void OSSL_PROVIDER_unquery_operation(const OSSL_PROVIDER *prov,
    int operation_id, const OSSL_ALGORITHM *algs);
/**
 * @brief Return the provider's opaque provider-context pointer (borrowed).
 * @param prov Provider to query.
 * @return Provider-specific context pointer passed to its algorithms, or NULL.
 */
void *OSSL_PROVIDER_get0_provider_ctx(const OSSL_PROVIDER *prov);
/**
 * @brief Return the provider's dispatch table of core functions (borrowed).
 * @param prov Provider to query.
 * @return Internal OSSL_DISPATCH array, or NULL if unavailable; do not free.
 */
const OSSL_DISPATCH *OSSL_PROVIDER_get0_dispatch(const OSSL_PROVIDER *prov);

/* Add a built in providers */
/**
 * @brief Register a built-in provider init function under @p name in a library context.
 * @param ctx Library context receiving the registration, or NULL for the default.
 * @param name Name under which the provider can later be loaded.
 * @param init_fn Provider entry point of type OSSL_provider_init_fn.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX *ctx, const char *name,
    OSSL_provider_init_fn *init_fn);

/* Information */
/**
 * @brief Return the registered name of a provider (borrowed).
 * @param prov Provider to query.
 * @return Internal NUL-terminated provider name, or NULL; do not free.
 */
const char *OSSL_PROVIDER_get0_name(const OSSL_PROVIDER *prov);

#ifdef __cplusplus
}
#endif

#endif
