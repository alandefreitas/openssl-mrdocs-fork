/*
 * Copyright 2010-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMAC_H
#define OPENSSL_CMAC_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_CMAC_H
#endif

#ifndef OPENSSL_NO_CMAC

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* Opaque */
/**
 * @brief Opaque CMAC (Cipher-based MAC) context (deprecated; prefer EVP_MAC).
 */
typedef struct CMAC_CTX_st CMAC_CTX;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate a new CMAC context (deprecated; prefer EVP_MAC).
 * @return New CMAC_CTX, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 CMAC_CTX *CMAC_CTX_new(void);
/**
 * @brief Clear sensitive CMAC state while keeping the context allocated (deprecated).
 * @param ctx Context to clean, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_cleanup(CMAC_CTX *ctx);
/**
 * @brief Free a CMAC context and its resources.
 * @param ctx Context to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_free(CMAC_CTX *ctx);
/**
 * @brief Return the internal EVP_CIPHER_CTX used by a CMAC context (deprecated).
 * @param ctx CMAC context.
 * @return Borrowed cipher context pointer owned by @p ctx.
 */
OSSL_DEPRECATEDIN_3_0 EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
/**
 * @brief Copy CMAC state from @p in into @p out (deprecated).
 * @param out Destination CMAC context (already allocated).
 * @param in Source CMAC context to duplicate.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);
/**
 * @brief Initialize a CMAC context with a key and block cipher (deprecated; prefer EVP_MAC).
 * @param ctx CMAC context to initialize.
 * @param key CMAC key material.
 * @param keylen Length of @p key in bytes.
 * @param cipher Block cipher implementing CMAC (for example AES-128-CBC).
 * @param impl Optional ENGINE implementing @p cipher, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Init(CMAC_CTX *ctx,
    const void *key, size_t keylen,
    const EVP_CIPHER *cipher, ENGINE *impl);
/**
 * @brief Absorb more message bytes into a CMAC computation (deprecated).
 * @param ctx CMAC context initialized with CMAC_Init().
 * @param data Message bytes to authenticate.
 * @param dlen Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Update(CMAC_CTX *ctx,
    const void *data, size_t dlen);
/**
 * @brief Finish a CMAC and write the authentication tag (deprecated).
 * @param ctx CMAC context updated with CMAC_Update().
 * @param out Buffer for the MAC (cipher block size), or NULL to query length only.
 * @param poutlen On entry, capacity of @p out; on success, bytes written (or required).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Final(CMAC_CTX *ctx,
    unsigned char *out, size_t *poutlen);
/**
 * @brief Reinitialize a CMAC context after CMAC_Final() so more data can be absorbed (deprecated).
 * @param ctx CMAC context previously finished with CMAC_Final(); must still hold key material.
 * @return 1 on success, or 0 if @p ctx was not initialized or Final was not called.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_resume(CMAC_CTX *ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif
#endif
