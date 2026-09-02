/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DECODER_H
#define OPENSSL_DECODER_H
#pragma once

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <openssl/decodererr.h>
#include <openssl/types.h>
#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch a decoder implementation from providers by algorithm name.
 * @param libctx Library context, or NULL for the default.
 * @param name Decoder algorithm name (for example "DER").
 * @param properties Optional property query string, or NULL.
 * @return Fetched OSSL_DECODER, or NULL on error; release with OSSL_DECODER_free().
 */
OSSL_DECODER *OSSL_DECODER_fetch(OSSL_LIB_CTX *libctx, const char *name,
    const char *properties);
/**
 * @brief Increment the reference count of a fetched decoder.
 * @param encoder Decoder whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_up_ref(OSSL_DECODER *encoder);
/**
 * @brief Decrement the reference count of a fetched decoder and free it at zero.
 * @param encoder Decoder to release, or NULL (no-op).
 */
void OSSL_DECODER_free(OSSL_DECODER *encoder);

/**
 * @brief Return the provider that supplies a fetched decoder.
 * @param encoder Decoder to query.
 * @return Provider object, or NULL on error.
 */
const OSSL_PROVIDER *OSSL_DECODER_get0_provider(const OSSL_DECODER *encoder);
/**
 * @brief Return the property definition string of a fetched decoder.
 * @param encoder Decoder to query.
 * @return Property definition string, or NULL if unavailable.
 */
const char *OSSL_DECODER_get0_properties(const OSSL_DECODER *encoder);
/**
 * @brief Return the primary algorithm name used to fetch a decoder.
 * @param decoder Decoder to query.
 * @return Algorithm name owned by @p decoder (do not free), or NULL if unavailable.
 */
const char *OSSL_DECODER_get0_name(const OSSL_DECODER *decoder);
/**
 * @brief Return a human-readable description of a fetched decoder.
 * @param decoder Decoder to query.
 * @return Description string, or NULL if unavailable.
 */
const char *OSSL_DECODER_get0_description(const OSSL_DECODER *decoder);
/**
 * @brief Test whether a decoder implements the algorithm identified by @p name.
 * @param encoder Decoder to query.
 * @param name Algorithm name or synonym to match.
 * @return 1 if @p encoder is identifiable as @p name, otherwise 0.
 */
int OSSL_DECODER_is_a(const OSSL_DECODER *encoder, const char *name);

/**
 * @brief Invoke a callback for every decoder provided by activated providers.
 * @param libctx Library context, or NULL for the default.
 * @param fn Callback invoked once per decoder.
 * @param arg Opaque argument passed to @p fn.
 */
void OSSL_DECODER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(OSSL_DECODER *encoder, void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every name/synonym associated with a decoder.
 * @param encoder Decoder whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque argument passed to @p fn.
 * @return 1 if the callback was invoked for all names, or 0 if none were called.
 */
int OSSL_DECODER_names_do_all(const OSSL_DECODER *encoder,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return descriptors for parameters that can be retrieved from a decoder.
 * @param decoder Decoder to query.
 * @return OSSL_PARAM array of gettable parameter descriptors, or NULL if none.
 */
const OSSL_PARAM *OSSL_DECODER_gettable_params(OSSL_DECODER *decoder);
/**
 * @brief Retrieve parameters from a decoder into an OSSL_PARAM array.
 * @param decoder Decoder to query.
 * @param params Array of OSSL_PARAM requests; unrecognized keys are ignored.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_get_params(OSSL_DECODER *decoder, OSSL_PARAM params[]);

/**
 * @brief Return descriptors for parameters that can be set on a decoder context.
 * @param encoder Decoder whose settable context parameters are listed.
 * @return OSSL_PARAM array of settable parameter descriptors, or NULL if none.
 */
const OSSL_PARAM *OSSL_DECODER_settable_ctx_params(OSSL_DECODER *encoder);
/**
 * @brief Create an empty decoder context for chaining and running decoders.
 * @return New OSSL_DECODER_CTX, or NULL on allocation failure; free with OSSL_DECODER_CTX_free().
 */
OSSL_DECODER_CTX *OSSL_DECODER_CTX_new(void);
/**
 * @brief Apply an OSSL_PARAM array to all decoders currently attached to @p ctx.
 * @param ctx Decoder context whose decoders receive @p params.
 * @param params Parameters to set; unrecognized keys are ignored by implementations.
 * @return 1 if recognized parameters were valid, or 0 on failure.
 */
int OSSL_DECODER_CTX_set_params(OSSL_DECODER_CTX *ctx,
    const OSSL_PARAM params[]);
/**
 * @brief Free a decoder context and invoke any registered cleanup callback.
 * @param ctx Decoder context to free, or NULL (no-op).
 */
void OSSL_DECODER_CTX_free(OSSL_DECODER_CTX *ctx);

/* Utilities that help set specific parameters */
/**
 * @brief Supply a passphrase for decrypting encoded private-key input.
 * @param ctx Decoder context to configure.
 * @param kstr Passphrase bytes.
 * @param klen Length of @p kstr in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_passphrase(OSSL_DECODER_CTX *ctx,
    const unsigned char *kstr, size_t klen);
/**
 * @brief Set a legacy PEM password callback used to prompt for a passphrase.
 * @param ctx Decoder context to configure.
 * @param cb PEM-style password callback, or NULL to clear.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_pem_password_cb(OSSL_DECODER_CTX *ctx,
    pem_password_cb *cb, void *cbarg);
/**
 * @brief Set an OSSL_PASSPHRASE_CALLBACK used to prompt for a passphrase.
 * @param ctx Decoder context to configure.
 * @param cb Passphrase callback invoked when decryption needs a secret.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_passphrase_cb(OSSL_DECODER_CTX *ctx,
    OSSL_PASSPHRASE_CALLBACK *cb,
    void *cbarg);
/**
 * @brief Set a UI method for passphrase prompting on a decoder context.
 * @param ctx Decoder context to configure.
 * @param ui_method UI_METHOD used to read passphrases, or NULL for the default.
 * @param ui_data Application data passed to the UI method.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_passphrase_ui(OSSL_DECODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);

/*
 * Utilities to read the object to decode, with the result sent to cb.
 * These will discover all provided methods
 */

/**
 * @brief Set the key/component selection mask for decoding (OSSL_KEYMGMT_SELECT_*).
 * @param ctx Decoder context to configure.
 * @param selection Bit mask of components to decode.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection);
/**
 * @brief Set the starting input type that limits which decoder chains are considered.
 * @param ctx Decoder context to configure.
 * @param input_type Encoding type name (for example "DER" or "PEM"), or NULL for any.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_input_type(OSSL_DECODER_CTX *ctx,
    const char *input_type);
/**
 * @brief Set the expected ASN.1 structure name for the encoded input.
 * @param ctx Decoder context to configure.
 * @param input_structure Structure name (for example "EncryptedPrivateKeyInfo"), or NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_input_structure(OSSL_DECODER_CTX *ctx,
    const char *input_structure);
/**
 * @brief Attach a fetched decoder implementation to a decoder context.
 * @param ctx Decoder context to extend.
 * @param decoder Decoder from OSSL_DECODER_fetch() (reference is up-reffed).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder);
/**
 * @brief Add decoder implementations that feed already-attached decoders (build chains).
 * @param ctx Decoder context to extend.
 * @param libctx Library context used when fetching extra decoders, or NULL for the default.
 * @param propq Optional property query for fetching, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_CTX_add_extra(OSSL_DECODER_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Return how many decoder implementations are currently attached to @p ctx.
 * @param ctx Decoder context to query, or NULL.
 * @return Number of attached decoders, or 0 if @p ctx is NULL.
 */
int OSSL_DECODER_CTX_get_num_decoders(OSSL_DECODER_CTX *ctx);

/**
 * @brief Opaque pairing of an OSSL_DECODER with its per-instance decoder context during a decode run.
 */
typedef struct ossl_decoder_instance_st OSSL_DECODER_INSTANCE;
/**
 * @brief Return the decoder implementation associated with a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @return OSSL_DECODER used for this instance, or NULL on failure.
 */
OSSL_DECODER *
OSSL_DECODER_INSTANCE_get_decoder(OSSL_DECODER_INSTANCE *decoder_inst);
/**
 * @brief Return the provider decoder context for a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @return Opaque provider decoder context, or NULL if unavailable.
 */
void *
OSSL_DECODER_INSTANCE_get_decoder_ctx(OSSL_DECODER_INSTANCE *decoder_inst);
/**
 * @brief Return the input-type name configured for a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @return Input-type string (for example "DER"), or NULL if unavailable.
 */
const char *
OSSL_DECODER_INSTANCE_get_input_type(OSSL_DECODER_INSTANCE *decoder_inst);
/**
 * @brief Return the input-structure name configured for a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @param was_set Optional output set to 1 if an input structure was explicitly configured.
 * @return Input-structure name string, or NULL if unset.
 */
const char *
OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
    int *was_set);

/**
 * @brief Callback that builds an application object from a decoder's provider-native result.
 * @param decoder_inst Decoder instance that produced the object.
 * @param params Provider-native object parameters describing the decoded result.
 * @param construct_data Pointer previously set via OSSL_DECODER_CTX_set_construct_data().
 * @return 1 if the object was constructed, or 0 if it could not be handled.
 */
typedef int OSSL_DECODER_CONSTRUCT(OSSL_DECODER_INSTANCE *decoder_inst,
    const OSSL_PARAM *params,
    void *construct_data);
/**
 * @brief Callback that frees construct data when an OSSL_DECODER_CTX is freed.
 * @param construct_data Pointer previously set via OSSL_DECODER_CTX_set_construct_data().
 */
typedef void OSSL_DECODER_CLEANUP(void *construct_data);

/**
 * @brief Register a callback invoked when a decoded object is constructed.
 * @param ctx Decoder context to configure.
 * @param construct Callback receiving params for each constructed object, or NULL to clear.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_construct(OSSL_DECODER_CTX *ctx,
    OSSL_DECODER_CONSTRUCT *construct);
/**
 * @brief Attach opaque application data passed to the construct and cleanup callbacks.
 * @param ctx Decoder context to configure.
 * @param construct_data Pointer passed as construct_data to OSSL_DECODER_CONSTRUCT / CLEANUP.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_construct_data(OSSL_DECODER_CTX *ctx,
    void *construct_data);
/**
 * @brief Register a cleanup callback invoked from OSSL_DECODER_CTX_free().
 * @param ctx Decoder context to configure.
 * @param cleanup Callback that frees construct data, or NULL to clear.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_cleanup(OSSL_DECODER_CTX *ctx,
    OSSL_DECODER_CLEANUP *cleanup);
/**
 * @brief Return the construct callback currently set on a decoder context.
 * @param ctx Decoder context to query.
 * @return Construct callback pointer, or NULL if unset.
 */
OSSL_DECODER_CONSTRUCT *OSSL_DECODER_CTX_get_construct(OSSL_DECODER_CTX *ctx);
/**
 * @brief Return the construct-data pointer currently set on a decoder context.
 * @param ctx Decoder context to query.
 * @return Opaque construct data, or NULL if unset.
 */
void *OSSL_DECODER_CTX_get_construct_data(OSSL_DECODER_CTX *ctx);
/**
 * @brief Return the cleanup callback currently set on a decoder context.
 * @param ctx Decoder context to query.
 * @return Cleanup callback pointer, or NULL if unset.
 */
OSSL_DECODER_CLEANUP *OSSL_DECODER_CTX_get_cleanup(OSSL_DECODER_CTX *ctx);

/**
 * @brief Export a reference from a decoder instance via a provider export callback.
 * @param decoder_inst Decoder instance that produced @p reference.
 * @param reference Reference bytes to export.
 * @param reference_sz Size of @p reference in bytes.
 * @param export_cb Provider export callback.
 * @param export_cbarg Opaque argument passed to @p export_cb.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst,
    void *reference, size_t reference_sz,
    OSSL_CALLBACK *export_cb, void *export_cbarg);

/**
 * @brief Run decoding from a BIO into objects handled by the context's construct callback.
 * @param ctx Configured decoder context.
 * @param in Input BIO (preferably binary mode).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Run decoding from a FILE stream (same as OSSL_DECODER_from_bio() with a file BIO).
 * @param ctx Configured decoder context.
 * @param in Input FILE stream.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_from_fp(OSSL_DECODER_CTX *ctx, FILE *in);
#endif
/**
 * @brief Run decoding from a memory buffer, advancing *@p pdata past consumed bytes.
 * @param ctx Configured decoder context.
 * @param pdata Address of a pointer to the input bytes; updated past what was decoded.
 * @param pdata_len Address of the remaining length; updated with bytes left undecoded.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_from_data(OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
    size_t *pdata_len);

/*
 * Create the OSSL_DECODER_CTX with an associated type.  This will perform
 * an implicit OSSL_DECODER_fetch(), suitable for the object of that type.
 */
/**
 * @brief Create a decoder context preconfigured to decode an EVP_PKEY.
 * @param pkey Address of a pointer set to the decoded key on success.
 * @param input_type Expected encoding type (for example "DER"), or NULL.
 * @param input_struct Expected ASN.1 structure name, or NULL.
 * @param keytype Target key type name (for example "RSA"), or NULL.
 * @param selection OSSL_KEYMGMT_SELECT_* mask for components to decode.
 * @param libctx Library context, or NULL for the default.
 * @param propquery Optional property query for decoder fetching, or NULL.
 * @return New decoder context, or NULL on error; free with OSSL_DECODER_CTX_free().
 */
OSSL_DECODER_CTX *
OSSL_DECODER_CTX_new_for_pkey(EVP_PKEY **pkey,
    const char *input_type,
    const char *input_struct,
    const char *keytype, int selection,
    OSSL_LIB_CTX *libctx, const char *propquery);

#ifdef __cplusplus
}
#endif
#endif
