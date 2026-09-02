/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_KDF_H
#define OPENSSL_KDF_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_KDF_H
#endif

#include <stdarg.h>
#include <stddef.h>
#include <openssl/types.h>
#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Increment the reference count on a fetched EVP_KDF method.
 * @param kdf KDF method returned by EVP_KDF_fetch().
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_up_ref(EVP_KDF *kdf);
/**
 * @brief Release a reference to a fetched EVP_KDF method.
 * @param kdf Method from EVP_KDF_fetch(), or NULL.
 */
void EVP_KDF_free(EVP_KDF *kdf);
/**
 * @brief Fetch a key-derivation algorithm implementation from providers.
 * @param libctx Library context, or NULL for the default.
 * @param algorithm KDF name such as "HKDF" or "PBKDF2".
 * @param properties Optional provider property query, or NULL.
 * @return Fetched EVP_KDF with refcount 1, or NULL on error; free with EVP_KDF_free().
 */
EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);

/**
 * @brief Allocate a key-derivation context for a fetched EVP_KDF.
 * @param kdf Algorithm from EVP_KDF_fetch() (not consumed; may be freed after).
 * @return New context, or NULL on failure; free with EVP_KDF_CTX_free().
 */
EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf);
/**
 * @brief Free a KDF context and its associated state.
 * @param ctx Context to free, or NULL.
 */
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);
/**
 * @brief Duplicate a KDF context, copying algorithm state where supported.
 * @param src Source context to copy.
 * @return New EVP_KDF_CTX, or NULL on failure.
 */
EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src);
/**
 * @brief Return a human-readable description of a KDF algorithm.
 * @param kdf KDF method to query.
 * @return Internal description string, or NULL; do not free.
 */
const char *EVP_KDF_get0_description(const EVP_KDF *kdf);
/**
 * @brief Test whether an EVP_KDF implementation is known by @p name.
 * @param kdf Fetched KDF method.
 * @param name Algorithm name or synonym to match.
 * @return 1 if @p name identifies @p kdf, or 0 otherwise.
 */
int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name);
/**
 * @brief Return the algorithm name of a KDF method.
 * @param kdf KDF method to query.
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KDF_get0_name(const EVP_KDF *kdf);
/**
 * @brief Return the provider that implemented a fetched EVP_KDF.
 * @param kdf KDF method to query.
 * @return Provider handle, or NULL; do not free.
 */
const OSSL_PROVIDER *EVP_KDF_get0_provider(const EVP_KDF *kdf);
/**
 * @brief Return the EVP_KDF method associated with a derivation context.
 * @param ctx KDF context from EVP_KDF_CTX_new().
 * @return Borrowed EVP_KDF pointer; do not free.
 */
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx);

/**
 * @brief Reset a KDF context so it can be reconfigured and reused.
 * @param ctx KDF context to clear, or NULL.
 */
void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx);
/**
 * @brief Return the output size produced by @p ctx, or SIZE_MAX if variable-length.
 * @param ctx KDF context to query.
 * @return Fixed output length in bytes, 0 on error, or SIZE_MAX when unbounded.
 */
size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *ctx);
/**
 * @brief Derive keying material into @p key using the parameters bound to @p ctx.
 * @param ctx Initialized KDF context.
 * @param key Output buffer for the derived key.
 * @param keylen Number of bytes to write to @p key.
 * @param params Optional additional OSSL_PARAM array, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);
/**
 * @brief Retrieve algorithm-level OSSL_PARAM values from a fetched EVP_KDF.
 * @param kdf Fetched KDF algorithm.
 * @param params NULL-terminated parameter array to fill.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[]);
/**
 * @brief Retrieve gettable parameters from an EVP_KDF_CTX.
 * @param ctx KDF context to query.
 * @param params Parameter array describing the values to fetch.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Apply OSSL_PARAM values (salt, key, info, digest, …) to a KDF context.
 * @param ctx KDF context.
 * @param params NULL-terminated parameter array.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Describe the parameters that can be read from an EVP_KDF via EVP_KDF_get_params().
 * @param kdf KDF method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf);
/**
 * @brief Return OSSL_PARAM descriptors that can be retrieved from an EVP_KDF_CTX.
 * @param kdf Fetched KDF algorithm whose context gettable params are queried.
 * @return Array of OSSL_PARAM descriptors terminated by an end sentinel, or NULL.
 */
const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf);
/**
 * @brief Describe context parameters that can be set before deriving with @p kdf.
 * @param kdf KDF method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf);
/**
 * @brief Return the OSSL_PARAM descriptors that can be retrieved from a KDF context.
 * @param ctx KDF context whose gettable parameters are queried.
 * @return Array of OSSL_PARAM descriptors terminated by an end sentinel, or NULL.
 */
const OSSL_PARAM *EVP_KDF_CTX_gettable_params(EVP_KDF_CTX *ctx);
/**
 * @brief Describe parameters currently settable on an EVP_KDF_CTX instance.
 * @param ctx KDF context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_CTX_settable_params(EVP_KDF_CTX *ctx);

/**
 * @brief Invoke @p fn for every KDF algorithm available from @p libctx providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each fetched EVP_KDF and @p arg.
 * @param arg Opaque pointer passed through to @p fn.
 */
void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KDF *kdf, void *arg),
    void *arg);
/**
 * @brief Invoke @p fn for every name/alias of KDF algorithm @p kdf.
 * @param kdf Fetched KDF algorithm.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_names_do_all(const EVP_KDF *kdf,
    void (*fn)(const char *name, void *data),
    void *data);

#define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND 0
#define EVP_KDF_HKDF_MODE_EXTRACT_ONLY 1
#define EVP_KDF_HKDF_MODE_EXPAND_ONLY 2

#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV 65
#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI 66
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV 67
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI 68
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV 69
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI 70

/* The legacy PKEY-based KDF API follows. */

/** EVP_PKEY ctrl: select the digest used by the TLS PRF KDF. */
#define EVP_PKEY_CTRL_TLS_MD (EVP_PKEY_ALG_CTRL)
#define EVP_PKEY_CTRL_TLS_SECRET (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_TLS_SEED (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_HKDF_MD (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_HKDF_SALT (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_HKDF_KEY (EVP_PKEY_ALG_CTRL + 5)
#define EVP_PKEY_CTRL_HKDF_INFO (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_HKDF_MODE (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_PASS (EVP_PKEY_ALG_CTRL + 8)
#define EVP_PKEY_CTRL_SCRYPT_SALT (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_SCRYPT_N (EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTRL_SCRYPT_R (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_SCRYPT_P (EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND \
    EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
#define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY \
    EVP_KDF_HKDF_MODE_EXTRACT_ONLY
#define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY \
    EVP_KDF_HKDF_MODE_EXPAND_ONLY

/**
 * @brief Select the digest used by a TLS1-PRF EVP_PKEY_CTX.
 * @param ctx Context for EVP_PKEY_TLS1_PRF key derivation.
 * @param md Message digest (for example EVP_sha256()) used by the PRF.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * @brief Set the TLS1-PRF secret on a key context (copies @p sec).
 * @param pctx Context configured for TLS1-PRF.
 * @param sec Secret octets to copy.
 * @param seclen Length of @p sec in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set1_tls1_prf_secret(EVP_PKEY_CTX *pctx,
    const unsigned char *sec, int seclen);

/**
 * @brief Append seed bytes to the TLS1-PRF seed on a key context.
 * @param pctx Context configured for TLS1-PRF.
 * @param seed Additional seed octets to append (copied).
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_add1_tls1_prf_seed(EVP_PKEY_CTX *pctx,
    const unsigned char *seed, int seedlen);

/**
 * @brief Set the message digest used by the HKDF extract/expand stages.
 * @param ctx Context configured for the HKDF KDF.
 * @param md Digest algorithm (for example EVP_sha256()).
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * @brief Set the HKDF salt, replacing any previously set salt.
 * @param ctx Context configured for the HKDF KDF.
 * @param salt Salt octets (copied), or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *ctx,
    const unsigned char *salt, int saltlen);

/**
 * @brief Set the HKDF input keying material (IKM) on a PKEY KDF context.
 * @param ctx Context configured for the HKDF KDF.
 * @param key Input keying material bytes (copied).
 * @param keylen Length of @p key in bytes.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *ctx,
    const unsigned char *key, int keylen);

/**
 * @brief Append octets to the HKDF info/context parameter on a PKEY HKDF context.
 * @param ctx Key derivation context configured for HKDF.
 * @param info Additional info bytes to append (copied).
 * @param infolen Length of @p info in bytes.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *ctx,
    const unsigned char *info, int infolen);

/**
 * @brief Select HKDF extract/expand mode on a key-derivation EVP_PKEY_CTX.
 * @param ctx HKDF derivation context.
 * @param mode EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND, EXTRACT_ONLY, or EXPAND_ONLY.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode);
#define EVP_PKEY_CTX_hkdf_mode EVP_PKEY_CTX_set_hkdf_mode

/**
 * @brief Set the password for a PBE-based EVP_PKEY_CTX derivation (PKCS#5 style).
 * @param ctx Key-derivation context.
 * @param pass Password bytes (may contain embedded NULs).
 * @param passlen Length of @p pass in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX *ctx, const char *pass,
    int passlen);

/**
 * @brief Set the scrypt salt on a KDF key context (copies @p salt).
 * @param ctx Context configured for the scrypt algorithm.
 * @param salt Salt octets to copy.
 * @param saltlen Length of @p salt in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set1_scrypt_salt(EVP_PKEY_CTX *ctx,
    const unsigned char *salt, int saltlen);

/**
 * @brief Set the scrypt CPU/memory cost parameter N on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param n Cost parameter N (power of two).
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *ctx, uint64_t n);

/**
 * @brief Set the scrypt block-size parameter r on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param r Block-size parameter (must be > 0).
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *ctx, uint64_t r);

/**
 * @brief Set the scrypt parallelization parameter p on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param p Parallelization parameter.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *ctx, uint64_t p);

/**
 * @brief Cap the memory scrypt may use during key derivation.
 * @param ctx Context configured for the scrypt KDF.
 * @param maxmem_bytes Maximum bytes of RAM the derivation may consume.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_maxmem_bytes(EVP_PKEY_CTX *ctx,
    uint64_t maxmem_bytes);

#ifdef __cplusplus
}
#endif
#endif
