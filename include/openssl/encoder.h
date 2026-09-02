/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ENCODER_H
#define OPENSSL_ENCODER_H
#pragma once

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <openssl/encodererr.h>
#include <openssl/types.h>
#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch an encoder implementation from providers by algorithm name.
 * @param libctx Library context, or NULL for the default.
 * @param name Encoder algorithm name (for example "RSA" or "DER").
 * @param properties Optional property query string, or NULL.
 * @return Fetched OSSL_ENCODER, or NULL on error; release with OSSL_ENCODER_free().
 */
OSSL_ENCODER *OSSL_ENCODER_fetch(OSSL_LIB_CTX *libctx, const char *name,
    const char *properties);
/**
 * @brief Increment the reference count of a fetched encoder.
 * @param encoder Encoder whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder);
/**
 * @brief Decrement the reference count of a fetched encoder and free it at zero.
 * @param encoder Encoder to release, or NULL (no-op).
 */
void OSSL_ENCODER_free(OSSL_ENCODER *encoder);

/**
 * @brief Return the provider that supplies a fetched encoder.
 * @param encoder Encoder to query.
 * @return Provider object, or NULL on error.
 */
const OSSL_PROVIDER *OSSL_ENCODER_get0_provider(const OSSL_ENCODER *encoder);
/**
 * @brief Return the property definition string of a fetched encoder.
 * @param encoder Encoder to query.
 * @return Property definition string, or NULL if unavailable.
 */
const char *OSSL_ENCODER_get0_properties(const OSSL_ENCODER *encoder);
/**
 * @brief Return the primary algorithm name used to fetch an encoder.
 * @param kdf Encoder to query.
 * @return Algorithm name owned by @p kdf (do not free), or NULL if unavailable.
 */
const char *OSSL_ENCODER_get0_name(const OSSL_ENCODER *kdf);
/**
 * @brief Return a human-readable description of an encoder implementation.
 * @param kdf Encoder method whose description is queried.
 * @return Description string for display, or NULL if none is available.
 */
const char *OSSL_ENCODER_get0_description(const OSSL_ENCODER *kdf);
/**
 * @brief Test whether an encoder implements the algorithm identified by @p name.
 * @param encoder Encoder to query.
 * @param name Algorithm name or synonym to match.
 * @return 1 if @p encoder is identifiable as @p name, otherwise 0.
 */
int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name);

/**
 * @brief Invoke a callback for every encoder provided by activated providers.
 * @param libctx Library context, or NULL for the default.
 * @param fn Callback invoked once per encoder.
 * @param arg Opaque argument passed to @p fn.
 */
void OSSL_ENCODER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(OSSL_ENCODER *encoder, void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every name/synonym associated with an encoder.
 * @param encoder Encoder whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque argument passed to @p fn.
 * @return 1 if the callback was invoked for all names, or 0 if none were called.
 */
int OSSL_ENCODER_names_do_all(const OSSL_ENCODER *encoder,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return descriptors for parameters that can be retrieved from an encoder.
 * @param encoder Encoder to query.
 * @return OSSL_PARAM array of gettable parameter descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *OSSL_ENCODER_gettable_params(OSSL_ENCODER *encoder);
/**
 * @brief Retrieve parameters from an encoder into an OSSL_PARAM array.
 * @param encoder Encoder to query.
 * @param params Array of OSSL_PARAM requests; unrecognized keys are ignored.
 * @return 1 on success, or 0 on error.
 */
int OSSL_ENCODER_get_params(OSSL_ENCODER *encoder, OSSL_PARAM params[]);

/**
 * @brief Return the OSSL_PARAM descriptors that may be set on an encoder context.
 * @param encoder Encoder implementation to query.
 * @return Array of settable parameter descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *OSSL_ENCODER_settable_ctx_params(OSSL_ENCODER *encoder);
/**
 * @brief Create an empty encoder context for chaining and running encoders.
 * @return New OSSL_ENCODER_CTX, or NULL on allocation failure; free with OSSL_ENCODER_CTX_free().
 */
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new(void);
/**
 * @brief Apply an OSSL_PARAM array to an encoder context.
 * @param ctx Encoder context to configure.
 * @param params Parameters recognised by the encoder's settable_ctx_params; may be empty.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_params(OSSL_ENCODER_CTX *ctx,
    const OSSL_PARAM params[]);
/**
 * @brief Free an encoder context and invoke any registered cleanup callback.
 * @param ctx Encoder context to free, or NULL (no-op).
 */
void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx);

/* Utilities that help set specific parameters */
/**
 * @brief Set a passphrase used when the encoder encrypts private-key output.
 * @param ctx Encoder context to configure.
 * @param kstr Passphrase bytes (not necessarily NUL-terminated).
 * @param klen Length of @p kstr in bytes.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_passphrase(OSSL_ENCODER_CTX *ctx,
    const unsigned char *kstr, size_t klen);
/**
 * @brief Set a legacy PEM password callback used to prompt for a passphrase.
 * @param ctx Encoder context to configure.
 * @param cb PEM-style password callback, or NULL to clear.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_pem_password_cb(OSSL_ENCODER_CTX *ctx,
    pem_password_cb *cb, void *cbarg);
/**
 * @brief Set an OSSL_PASSPHRASE_CALLBACK used to prompt for a passphrase.
 * @param ctx Encoder context to configure.
 * @param cb Passphrase callback invoked when encryption needs a secret.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
    OSSL_PASSPHRASE_CALLBACK *cb,
    void *cbarg);
/**
 * @brief Set a UI method for passphrase prompting on an encoder context.
 * @param ctx Encoder context to configure.
 * @param ui_method UI_METHOD used to read passphrases, or NULL for the default.
 * @param ui_data Application data passed to the UI method.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);
/**
 * @brief Select the cipher used to encrypt encoded private-key material.
 * @param ctx Encoder context to configure.
 * @param cipher_name Cipher algorithm name (for example "AES-256-CBC"), or NULL to clear.
 * @param propquery Property query for fetching the cipher, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_cipher(OSSL_ENCODER_CTX *ctx,
    const char *cipher_name,
    const char *propquery);
/**
 * @brief Set the key/component selection mask for encoding (OSSL_KEYMGMT_SELECT_*).
 * @param ctx Encoder context to configure.
 * @param selection Non-zero bit mask of components to encode.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection);
/**
 * @brief Set the ending output type that a complete encoder chain must produce.
 * @param ctx Encoder context to configure.
 * @param output_type Output type name (for example "DER" or "PEM").
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_output_type(OSSL_ENCODER_CTX *ctx,
    const char *output_type);
/**
 * @brief Set the desired output structure name for the encoder chain (for example "pkcs8").
 * @param ctx Encoder context to configure.
 * @param output_structure Structure name understood by the encoder implementations, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_output_structure(OSSL_ENCODER_CTX *ctx,
    const char *output_structure);

/* Utilities to add encoders */
/**
 * @brief Add an encoder implementation to an encoder context's chain.
 * @param ctx Encoder context to populate.
 * @param encoder Fetched encoder to append for encoding the input object.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder);
/**
 * @brief Add encoder implementations that continue an already-attached encoder chain.
 * @param ctx Encoder context to extend.
 * @param libctx Library context used when fetching extra encoders, or NULL for the default.
 * @param propq Optional property query for fetching, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_add_extra(OSSL_ENCODER_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Return how many encoder implementations are currently attached to @p ctx.
 * @param ctx Encoder context to query, or NULL.
 * @return Number of attached encoders, or 0 if @p ctx is NULL.
 */
int OSSL_ENCODER_CTX_get_num_encoders(OSSL_ENCODER_CTX *ctx);

/**
 * @brief Opaque pairing of an OSSL_ENCODER with its per-instance encoder context during an encode run.
 */
typedef struct ossl_encoder_instance_st OSSL_ENCODER_INSTANCE;
/**
 * @brief Return the OSSL_ENCODER implementation bound to an encoder instance.
 * @param encoder_inst Encoder instance from a construct callback.
 * @return Encoder method for this instance, or NULL if unset.
 */
OSSL_ENCODER *
OSSL_ENCODER_INSTANCE_get_encoder(OSSL_ENCODER_INSTANCE *encoder_inst);
/**
 * @brief Return the provider encoder context for an encoder instance.
 * @param encoder_inst Encoder instance from a construct callback.
 * @return Provider-side encoder context pointer, or NULL if unset.
 */
void *
OSSL_ENCODER_INSTANCE_get_encoder_ctx(OSSL_ENCODER_INSTANCE *encoder_inst);
/**
 * @brief Return the output type name for an encoder instance (for example "DER" or "PEM").
 * @param encoder_inst Encoder instance to query.
 * @return Internal NUL-terminated type string, or NULL if unset.
 */
const char *
OSSL_ENCODER_INSTANCE_get_output_type(OSSL_ENCODER_INSTANCE *encoder_inst);
/**
 * @brief Return the output-structure name for an encoder instance (for example "pkcs8").
 * @param encoder_inst Encoder instance to query.
 * @return Internal NUL-terminated structure string, or NULL if unset.
 */
const char *
OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst);

/**
 * @brief Callback that builds the provider-native object passed to an encoder instance.
 * @param encoder_inst Encoder instance for the current encode step.
 * @param construct_data Opaque pointer from OSSL_ENCODER_CTX_set_construct_data().
 * @return Provider-native object reference for encoding, or NULL on failure.
 */
typedef const void *OSSL_ENCODER_CONSTRUCT(OSSL_ENCODER_INSTANCE *encoder_inst,
    void *construct_data);
/**
 * @brief Cleanup callback that releases construct_data after encoding finishes.
 * @param construct_data Opaque pointer previously set via OSSL_ENCODER_CTX_set_construct_data().
 */
typedef void OSSL_ENCODER_CLEANUP(void *construct_data);

/**
 * @brief Register the constructor that builds the provider-side object to encode.
 * @param ctx Encoder context to configure.
 * @param construct Callback returning a provider-native object, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_construct(OSSL_ENCODER_CTX *ctx,
    OSSL_ENCODER_CONSTRUCT *construct);
/**
 * @brief Associate opaque construct data passed to the encoder construct callback.
 * @param ctx Encoder context to configure.
 * @param construct_data Caller-owned pointer delivered to OSSL_ENCODER_CONSTRUCT / CLEANUP.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_construct_data(OSSL_ENCODER_CTX *ctx,
    void *construct_data);
/**
 * @brief Register a cleanup callback invoked from OSSL_ENCODER_CTX_free().
 * @param ctx Encoder context to configure.
 * @param cleanup Callback that frees construct data, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_cleanup(OSSL_ENCODER_CTX *ctx,
    OSSL_ENCODER_CLEANUP *cleanup);

/* Utilities to output the object to encode */
/**
 * @brief Run encoding for a context and write the result to a BIO.
 * @param ctx Configured encoder context.
 * @param out Destination BIO (text or binary mode as appropriate for the output type).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Run encoding for a context and write the result to a FILE stream.
 * @param ctx Configured encoder context.
 * @param fp Destination FILE (text or binary mode as appropriate for the output type).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
#endif
/**
 * @brief Run encoding for a context and write the result into a memory buffer.
 * @param ctx Configured encoder context.
 * @param pdata Address of an output buffer pointer; if *@p pdata is NULL, a buffer is allocated with OPENSSL_malloc() and ownership transfers to the caller. If non-NULL, *@p pdata must point to a buffer of size *@p pdata_len.
 * @param pdata_len On input, capacity of *@p pdata when non-NULL; on success, length of encoded data. Required (must not be NULL).
 * @return 1 on success, or 0 on failure (including when a caller-supplied buffer is too small).
 */
int OSSL_ENCODER_to_data(OSSL_ENCODER_CTX *ctx, unsigned char **pdata,
    size_t *pdata_len);

/**
 * @brief Create an encoder context preconfigured to encode an EVP_PKEY.
 *
 * Performs an implicit encoder fetch suitable for @p pkey, which is more useful
 * than calling OSSL_ENCODER_CTX_new() alone. The returned context may have zero
 * encoders if none matched; check with OSSL_ENCODER_CTX_get_num_encoders().
 *
 * @param pkey Assigned public or private key to encode.
 * @param selection OSSL_KEYMGMT_SELECT_* mask for components to encode.
 * @param output_type Desired ending output type (for example "DER" or "PEM").
 * @param output_struct Desired output structure name (for example "pkcs8"), or NULL.
 * @param propquery Optional property query for encoder fetching, or NULL.
 * @return New encoder context, or NULL on error; free with OSSL_ENCODER_CTX_free().
 */
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_for_pkey(const EVP_PKEY *pkey,
    int selection,
    const char *output_type,
    const char *output_struct,
    const char *propquery);

#ifdef __cplusplus
}
#endif
#endif
