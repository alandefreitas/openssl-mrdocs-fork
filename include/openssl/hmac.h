/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HMAC_H
#define OPENSSL_HMAC_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_HMAC_H
#endif

#include <openssl/opensslconf.h>

#include <openssl/evp.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HMAC_MAX_MD_CBLOCK 200 /* Deprecated */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the output length in bytes of the digest used by an HMAC context (deprecated).
 * @param e HMAC context whose underlying hash size is queried.
 * @return Digest output size in bytes, or 0 if @p e has no digest set.
 */
OSSL_DEPRECATEDIN_3_0 size_t HMAC_size(const HMAC_CTX *e);
/**
 * @brief Allocate a new HMAC context (deprecated; prefer EVP_MAC).
 * @return New HMAC_CTX, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 HMAC_CTX *HMAC_CTX_new(void);
/**
 * @brief Reset an HMAC context to a reusable empty state (deprecated; prefer EVP_MAC).
 * @param ctx Context to clear and reinitialize for a new HMAC_Init_ex sequence.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_CTX_reset(HMAC_CTX *ctx);
/**
 * @brief Free an HMAC context.
 * @param ctx Context to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void HMAC_CTX_free(HMAC_CTX *ctx);
#endif
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/**
 * @brief Initialize an HMAC context with a key and digest (legacy).
 * @param ctx HMAC context to initialize.
 * @param key HMAC key material.
 * @param len Length of @p key in bytes.
 * @param md Message digest to use, or NULL to keep the current digest.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_1_1_0 __owur int HMAC_Init(HMAC_CTX *ctx,
    const void *key, int len,
    const EVP_MD *md);
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief (Re)initialize an HMAC_CTX with key and digest (deprecated; prefer EVP_MAC).
 * @param ctx HMAC context to initialize.
 * @param key HMAC key bytes, or NULL to reuse the previous key when only @p md changes.
 * @param len Length of @p key in bytes (ignored when @p key is NULL).
 * @param md Message digest used as the HMAC hash, or NULL to keep the previous digest.
 * @param impl Optional ENGINE implementing @p md, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
/**
 * @brief Absorb more message bytes into an HMAC context (deprecated; prefer EVP_MAC_update).
 * @param ctx HMAC context initialized with HMAC_Init_ex().
 * @param data Next chunk of message bytes.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data,
    size_t len);
/**
 * @brief Finalize an HMAC computation and write the MAC.
 * @param ctx HMAC context to finalize.
 * @param md Output buffer for the MAC.
 * @param len Receives the MAC length in bytes; may be NULL.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_Final(HMAC_CTX *ctx, unsigned char *md,
    unsigned int *len);
/**
 * @brief Copy the HMAC state from @p sctx into @p dctx (deprecated).
 * @param dctx Destination context; must already be allocated with HMAC_CTX_new().
 * @param sctx Source context whose digest, key, and intermediate state are copied.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 __owur int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);
/**
 * @brief Set flags on an HMAC context, forwarded to the underlying digest.
 * @param ctx HMAC context to update.
 * @param flags Flag bits to set.
 */
OSSL_DEPRECATEDIN_3_0 void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
/**
 * @brief Get the message digest associated with an HMAC context.
 * @param ctx HMAC context to query.
 * @return Digest method, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const EVP_MD *HMAC_CTX_get_md(const HMAC_CTX *ctx);
#endif

/**
 * @brief Compute an HMAC over @p data using digest @p evp_md and key @p key.
 * @param evp_md Message digest (e.g. EVP_sha256()); variable-length digests such as SHAKE are not supported.
 * @param key HMAC key material, or NULL when @p key_len is 0.
 * @param key_len Length of @p key in bytes.
 * @param data Message bytes to authenticate.
 * @param data_len Number of bytes at @p data.
 * @param md Output buffer of at least EVP_MAX_MD_SIZE bytes, or NULL to use a static buffer (not thread-safe).
 * @param md_len Receives the MAC length in bytes; may be NULL.
 * @return Pointer to the MAC bytes (@p md or the static buffer), or NULL on error.
 *
 * Uses the default OSSL_LIB_CTX; prefer EVP_Q_mac() when a library context is required.
 */
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
    const unsigned char *data, size_t data_len,
    unsigned char *md, unsigned int *md_len);

#ifdef __cplusplus
}
#endif

#endif
