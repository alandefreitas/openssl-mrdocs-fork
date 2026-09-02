/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_STORE_H
#define OPENSSL_STORE_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_OSSL_STORE_H
#endif

#include <stdarg.h>
#include <openssl/types.h>
#include <openssl/pem.h>
#include <openssl/storeerr.h>

#ifdef __cplusplus
extern "C" {
#endif

/*-
 *  The main OSSL_STORE functions.
 *  ------------------------------
 *
 *  These allow applications to open a channel to a resource with supported
 *  data (keys, certs, crls, ...), read the data a piece at a time and decide
 *  what to do with it, and finally close.
 */

/**
 * @brief Opaque context for an open OSSL_STORE channel to a URI or BIO.
 */
typedef struct ossl_store_ctx_st OSSL_STORE_CTX;

/**
 * @brief Callback that may rewrite or drop each OSSL_STORE_INFO after it is loaded.
 * @param info Loaded store object; the callback may free it and return a replacement.
 * @param post_process_data Application pointer passed to OSSL_STORE_open() / attach().
 * @return Replacement OSSL_STORE_INFO to keep, or NULL to drop this object.
 */
typedef OSSL_STORE_INFO *(*OSSL_STORE_post_process_info_fn)(OSSL_STORE_INFO *info,
    void *post_process_data);

/**
 * @brief Open an OSSL_STORE channel for the given URI.
 * @param uri URI identifying the store resource (scheme selects the loader).
 * @param ui_method UI method for passwords or other interactive input, or NULL.
 * @param ui_data Application data passed to @p ui_method whenever it is used.
 * @param post_process Optional post-process callback for each loaded object, or NULL.
 * @param post_process_data Application pointer passed to @p post_process.
 * @return New store context, or NULL on error; free with OSSL_STORE_close().
 */
OSSL_STORE_CTX *
OSSL_STORE_open(const char *uri, const UI_METHOD *ui_method, void *ui_data,
    OSSL_STORE_post_process_info_fn post_process,
    void *post_process_data);
/**
 * @brief Open an OSSL_STORE channel with an explicit library context and parameters.
 * @param uri URI identifying the store resource (scheme selects the loader).
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query for fetching the loader, or NULL.
 * @param ui_method UI method for passwords or other interactive input, or NULL.
 * @param ui_data Application data passed to @p ui_method whenever it is used.
 * @param params Optional OSSL_PARAM array passed to the loader, or NULL.
 * @param post_process Optional post-process callback for each loaded object, or NULL.
 * @param post_process_data Application pointer passed to @p post_process.
 * @return New store context, or NULL on error; free with OSSL_STORE_close().
 */
OSSL_STORE_CTX *
OSSL_STORE_open_ex(const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
    const UI_METHOD *ui_method, void *ui_data,
    const OSSL_PARAM params[],
    OSSL_STORE_post_process_info_fn post_process,
    void *post_process_data);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Send a loader-specific or common control command to an open store (deprecated).
 * @param ctx Open store context.
 * @param cmd Control command (for example OSSL_STORE_C_USE_SECMEM).
 * @return 1 on success, or 0 on error.
 *
 * Additional command-specific arguments follow @p cmd (variadic).
 */
OSSL_DEPRECATEDIN_3_0 int OSSL_STORE_ctrl(OSSL_STORE_CTX *ctx, int cmd,
    ... /* args */);
/**
 * @brief va_list form of OSSL_STORE_ctrl() (deprecated).
 * @param ctx Open store context.
 * @param cmd Control command (for example OSSL_STORE_C_USE_SECMEM).
 * @param args Command-specific arguments.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int OSSL_STORE_vctrl(OSSL_STORE_CTX *ctx, int cmd,
    va_list args);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0

/*
 * Common ctrl commands that different loaders may choose to support.
 */
/* int on = 0 or 1; STORE_ctrl(ctx, STORE_C_USE_SECMEM, &on); */
#define OSSL_STORE_C_USE_SECMEM 1
/* Where custom commands start */
#define OSSL_STORE_C_CUSTOM_START 100

#endif

/**
 * @brief Load the next object from an open OSSL_STORE channel.
 * @param ctx Open store context.
 * @return New OSSL_STORE_INFO, or NULL on error or when no object is available; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *ctx);

/*
 * Deletes the object in the store by URI.
 * Returns 1 on success, 0 otherwise.
 */
/**
 * @brief Delete the object identified by @p uri from its store backend.
 * @param uri URI of the object to delete.
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query for fetching the loader, or NULL.
 * @param ui_method UI method for passwords or other interactive input, or NULL.
 * @param ui_data Application data passed to @p ui_method whenever it is used.
 * @param params Optional OSSL_PARAM array passed to the loader, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_STORE_delete(const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
    const UI_METHOD *ui_method, void *ui_data,
    const OSSL_PARAM params[]);

/**
 * @brief Test whether an open store has no more objects to load.
 * @param ctx Open store context.
 * @return 1 if end of data has been reached, or 0 otherwise.
 */
int OSSL_STORE_eof(OSSL_STORE_CTX *ctx);

/**
 * @brief Test whether the last store operation recorded an error on @p ctx.
 * @param ctx Open store context.
 * @return 1 if an error occurred, or 0 otherwise.
 */
int OSSL_STORE_error(OSSL_STORE_CTX *ctx);

/**
 * @brief Close an OSSL_STORE channel and free its context.
 * @param ctx Store context to close, or NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_STORE_close(OSSL_STORE_CTX *ctx);

/**
 * @brief Open an OSSL_STORE channel that reads from a BIO using a named scheme.
 * @param bio BIO supplying store data (contents determine safety of this call).
 * @param scheme URI scheme selecting the loader (for example "file").
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query for fetching the loader, or NULL.
 * @param ui_method UI method for passwords or other interactive input, or NULL.
 * @param ui_data Application data passed to @p ui_method whenever it is used.
 * @param params Optional OSSL_PARAM array passed to the loader, or NULL.
 * @param post_process Optional post-process callback for each loaded object, or NULL.
 * @param post_process_data Application pointer passed to @p post_process.
 * @return New store context, or NULL on error; free with OSSL_STORE_close().
 */
OSSL_STORE_CTX *OSSL_STORE_attach(BIO *bio, const char *scheme,
    OSSL_LIB_CTX *libctx, const char *propq,
    const UI_METHOD *ui_method, void *ui_data,
    const OSSL_PARAM params[],
    OSSL_STORE_post_process_info_fn post_process,
    void *post_process_data);

/*-
 *  Extracting OpenSSL types from and creating new OSSL_STORE_INFOs
 *  ---------------------------------------------------------------
 */

/*
 * Types of data that can be ossl_stored in a OSSL_STORE_INFO.
 * OSSL_STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
#define OSSL_STORE_INFO_NAME 1 /* char * */
#define OSSL_STORE_INFO_PARAMS 2 /* EVP_PKEY * */
#define OSSL_STORE_INFO_PUBKEY 3 /* EVP_PKEY * */
#define OSSL_STORE_INFO_PKEY 4 /* EVP_PKEY * */
#define OSSL_STORE_INFO_CERT 5 /* X509 * */
#define OSSL_STORE_INFO_CRL 6 /* X509_CRL * */

/*
 * Functions to generate OSSL_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the OSSL_STORE_INFO
 * and will therefore be freed when the OSSL_STORE_INFO is freed.
 */
/**
 * @brief Create an OSSL_STORE_INFO that takes ownership of @p data for @p type.
 * @param type OSSL_STORE_INFO_* type code matching @p data.
 * @param data Object pointer transferred to the new info (freed with the info).
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new(int type, void *data);
/**
 * @brief Create an OSSL_STORE_INFO_NAME holding @p name (takes ownership of @p name).
 * @param name URI or pathname string; ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_NAME(char *name);
/**
 * @brief Attach an optional description string to an OSSL_STORE_INFO_NAME.
 * @param info Store object of type OSSL_STORE_INFO_NAME.
 * @param desc Description string; ownership transfers on success.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_STORE_INFO_set0_NAME_description(OSSL_STORE_INFO *info, char *desc);
/**
 * @brief Create an OSSL_STORE_INFO holding key parameters (takes ownership of @p params).
 * @param params EVP_PKEY containing parameters only; ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_PARAMS(EVP_PKEY *params);
/**
 * @brief Create an OSSL_STORE_INFO holding a public key (takes ownership of @p pubkey).
 * @param pubkey Public EVP_PKEY; ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_PUBKEY(EVP_PKEY *pubkey);
/**
 * @brief Create an OSSL_STORE_INFO holding a key (takes ownership of @p pkey).
 * @param pkey EVP_PKEY (typically a private key); ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_PKEY(EVP_PKEY *pkey);
/**
 * @brief Create an OSSL_STORE_INFO holding an X.509 certificate (takes ownership of @p x509).
 * @param x509 Certificate; ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_CERT(X509 *x509);
/**
 * @brief Create an OSSL_STORE_INFO holding a CRL (takes ownership of @p crl).
 * @param crl Certificate revocation list; ownership transfers on success.
 * @return New OSSL_STORE_INFO, or NULL on error; free with OSSL_STORE_INFO_free().
 */
OSSL_STORE_INFO *OSSL_STORE_INFO_new_CRL(X509_CRL *crl);

/*
 * Functions to try to extract data from a OSSL_STORE_INFO.
 */
/**
 * @brief Return the OSSL_STORE_INFO_* type code of a store object.
 * @param info Store object to query.
 * @return Type code such as OSSL_STORE_INFO_CERT, or 0 if @p info is NULL.
 */
int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO *info);
/**
 * @brief Return the typed object pointer from a store info when @p type matches (borrowed).
 * @param type Expected OSSL_STORE_INFO_* type code.
 * @param info Store object to query.
 * @return Internal data pointer if @p info has @p type, or NULL otherwise; do not free.
 */
void *OSSL_STORE_INFO_get0_data(int type, const OSSL_STORE_INFO *info);
/**
 * @brief Return the name string from an OSSL_STORE_INFO_NAME object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_NAME.
 * @return Internal name pointer, or NULL if absent or wrong type; do not free.
 */
const char *OSSL_STORE_INFO_get0_NAME(const OSSL_STORE_INFO *info);
/**
 * @brief Return a copy of the name string from an OSSL_STORE_INFO_NAME object.
 * @param info Store object of type OSSL_STORE_INFO_NAME.
 * @return Newly allocated name, or NULL on error; free with OPENSSL_free().
 */
char *OSSL_STORE_INFO_get1_NAME(const OSSL_STORE_INFO *info);
/**
 * @brief Return the optional description for an OSSL_STORE_INFO_NAME (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_NAME.
 * @return Internal description pointer, or NULL if absent; do not free.
 */
const char *OSSL_STORE_INFO_get0_NAME_description(const OSSL_STORE_INFO *info);
/**
 * @brief Return a copy of the optional description for an OSSL_STORE_INFO_NAME.
 * @param info Store object of type OSSL_STORE_INFO_NAME.
 * @return Newly allocated description, or NULL on error; free with OPENSSL_free().
 */
char *OSSL_STORE_INFO_get1_NAME_description(const OSSL_STORE_INFO *info);
/**
 * @brief Return the key-parameter EVP_PKEY from a store object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_PARAMS.
 * @return Internal EVP_PKEY pointer, or NULL if absent or wrong type; do not free.
 */
EVP_PKEY *OSSL_STORE_INFO_get0_PARAMS(const OSSL_STORE_INFO *info);
/**
 * @brief Return a new reference to the key-parameter EVP_PKEY from a store object.
 * @param info Store object of type OSSL_STORE_INFO_PARAMS.
 * @return Up-reffed EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *OSSL_STORE_INFO_get1_PARAMS(const OSSL_STORE_INFO *info);
/**
 * @brief Return the public-key EVP_PKEY from a store object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_PUBKEY.
 * @return Internal EVP_PKEY pointer, or NULL if absent or wrong type; do not free.
 */
EVP_PKEY *OSSL_STORE_INFO_get0_PUBKEY(const OSSL_STORE_INFO *info);
/**
 * @brief Return a new reference to the public-key EVP_PKEY from a store object.
 * @param info Store object of type OSSL_STORE_INFO_PUBKEY.
 * @return Up-reffed EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *OSSL_STORE_INFO_get1_PUBKEY(const OSSL_STORE_INFO *info);
/**
 * @brief Return the key EVP_PKEY from a store object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_PKEY.
 * @return Internal EVP_PKEY pointer, or NULL if absent or wrong type; do not free.
 */
EVP_PKEY *OSSL_STORE_INFO_get0_PKEY(const OSSL_STORE_INFO *info);
/**
 * @brief Return a new reference to the key EVP_PKEY from a store object.
 * @param info Store object of type OSSL_STORE_INFO_PKEY.
 * @return Up-reffed EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *OSSL_STORE_INFO_get1_PKEY(const OSSL_STORE_INFO *info);
/**
 * @brief Return the X.509 certificate from a store object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_CERT.
 * @return Internal X509 pointer, or NULL if absent or wrong type; do not free.
 */
X509 *OSSL_STORE_INFO_get0_CERT(const OSSL_STORE_INFO *info);
/**
 * @brief Return a new reference to the X.509 certificate from a store object.
 * @param info Store object of type OSSL_STORE_INFO_CERT.
 * @return Up-reffed X509, or NULL on error; free with X509_free().
 */
X509 *OSSL_STORE_INFO_get1_CERT(const OSSL_STORE_INFO *info);
/**
 * @brief Return the CRL from a store object (borrowed).
 * @param info Store object of type OSSL_STORE_INFO_CRL.
 * @return Internal X509_CRL pointer, or NULL if absent or wrong type; do not free.
 */
X509_CRL *OSSL_STORE_INFO_get0_CRL(const OSSL_STORE_INFO *info);
/**
 * @brief Return a new reference to the CRL from a store object.
 * @param info Store object of type OSSL_STORE_INFO_CRL.
 * @return Up-reffed X509_CRL, or NULL on error; free with X509_CRL_free().
 */
X509_CRL *OSSL_STORE_INFO_get1_CRL(const OSSL_STORE_INFO *info);

/**
 * @brief Return a static string name for an OSSL_STORE_INFO_* type code.
 * @param type Type code such as OSSL_STORE_INFO_CERT.
 * @return NUL-terminated type name, or NULL if @p type is unknown.
 */
const char *OSSL_STORE_INFO_type_string(int type);

/**
 * @brief Free an OSSL_STORE_INFO and the object it owns.
 * @param info Store object to free, or NULL.
 */
void OSSL_STORE_INFO_free(OSSL_STORE_INFO *info);

/*-
 *  Functions to construct a search URI from a base URI and search criteria
 *  -----------------------------------------------------------------------
 */

/* OSSL_STORE search types */
#define OSSL_STORE_SEARCH_BY_NAME 1 /* subject in certs, issuer in CRLs */
#define OSSL_STORE_SEARCH_BY_ISSUER_SERIAL 2
#define OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT 3
#define OSSL_STORE_SEARCH_BY_ALIAS 4

/* To check what search types the scheme handler supports */
/**
 * @brief Test whether the loader for an open store supports a search type.
 * @param ctx Open store context.
 * @param search_type OSSL_STORE_SEARCH_BY_* criterion type.
 * @return 1 if supported, or 0 otherwise.
 */
int OSSL_STORE_supports_search(OSSL_STORE_CTX *ctx, int search_type);

/* Search term constructors */
/*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
 */
/**
 * @brief Build a search criterion matching a subject (certs) or issuer (CRLs) name.
 * @param name X509_NAME owned by the caller; must remain valid for the search lifetime.
 * @return New OSSL_STORE_SEARCH, or NULL on error; free with OSSL_STORE_SEARCH_free().
 */
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_name(X509_NAME *name);
/**
 * @brief Build a search criterion matching an issuer name and serial number.
 * @param name Issuer X509_NAME owned by the caller; must remain valid for the search lifetime.
 * @param serial Serial number owned by the caller; must remain valid for the search lifetime.
 * @return New OSSL_STORE_SEARCH, or NULL on error; free with OSSL_STORE_SEARCH_free().
 */
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_issuer_serial(X509_NAME *name,
    const ASN1_INTEGER
        *serial);
/**
 * @brief Build a search criterion matching a key fingerprint.
 * @param digest Digest algorithm used for the fingerprint, or NULL for the loader default.
 * @param bytes Fingerprint octets owned by the caller; must remain valid for the search lifetime.
 * @param len Length of @p bytes in octets.
 * @return New OSSL_STORE_SEARCH, or NULL on error; free with OSSL_STORE_SEARCH_free().
 */
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_key_fingerprint(const EVP_MD *digest,
    const unsigned char
        *bytes,
    size_t len);
/**
 * @brief Build a search criterion matching an alias string.
 * @param alias Alias text owned by the caller; must remain valid for the search lifetime.
 * @return New OSSL_STORE_SEARCH, or NULL on error; free with OSSL_STORE_SEARCH_free().
 */
OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_alias(const char *alias);

/* Search term destructor */
/**
 * @brief Free an OSSL_STORE_SEARCH criterion (does not free caller-owned inputs).
 * @param search Search criterion to free, or NULL.
 */
void OSSL_STORE_SEARCH_free(OSSL_STORE_SEARCH *search);

/* Search term accessors */
/**
 * @brief Return the OSSL_STORE_SEARCH_BY_* type of a search criterion.
 * @param criterion Search criterion to query.
 * @return Search type code.
 */
int OSSL_STORE_SEARCH_get_type(const OSSL_STORE_SEARCH *criterion);
/**
 * @brief Return the X509_NAME from a by-name or issuer-serial search criterion (borrowed).
 * @param criterion Search criterion holding a name.
 * @return Internal X509_NAME pointer, or NULL if not applicable; do not free.
 */
X509_NAME *OSSL_STORE_SEARCH_get0_name(const OSSL_STORE_SEARCH *criterion);
/**
 * @brief Return the serial number from an issuer-serial search criterion (borrowed).
 * @param criterion Search criterion of type OSSL_STORE_SEARCH_BY_ISSUER_SERIAL.
 * @return Internal ASN1_INTEGER pointer, or NULL if not applicable; do not free.
 */
const ASN1_INTEGER *OSSL_STORE_SEARCH_get0_serial(const OSSL_STORE_SEARCH
        *criterion);
/**
 * @brief Return the fingerprint or alias byte string from a search criterion (borrowed).
 * @param criterion Search criterion holding raw bytes.
 * @param length Receives the byte count on success.
 * @return Internal byte pointer, or NULL if not applicable; do not free.
 */
const unsigned char *OSSL_STORE_SEARCH_get0_bytes(const OSSL_STORE_SEARCH
                                                      *criterion,
    size_t *length);
/**
 * @brief Return the alias string from a search criterion (borrowed).
 * @param criterion Search criterion of type OSSL_STORE_SEARCH_BY_ALIAS.
 * @return Internal NUL-terminated string, or NULL if not applicable; do not free.
 */
const char *OSSL_STORE_SEARCH_get0_string(const OSSL_STORE_SEARCH *criterion);
/**
 * @brief Return the digest method from a key-fingerprint search criterion (borrowed).
 * @param criterion Search criterion of type OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT.
 * @return Internal EVP_MD pointer, or NULL if unset; do not free.
 */
const EVP_MD *OSSL_STORE_SEARCH_get0_digest(const OSSL_STORE_SEARCH *criterion);

/**
 * @brief Restrict an open store to a single expected OSSL_STORE_INFO_* type.
 * @param ctx Open store context; must be called before the first OSSL_STORE_load().
 * @param expected_type Desired type code, or 0 for unspecified.
 * @return 1 on success, or 0 on error.
 */
int OSSL_STORE_expect(OSSL_STORE_CTX *ctx, int expected_type);
/**
 * @brief Attach a search criterion to an open store before loading.
 * @param ctx Open store context; must be called before the first OSSL_STORE_load().
 * @param search Search criterion from OSSL_STORE_SEARCH_by_*().
 * @return 1 on success, or 0 on error.
 */
int OSSL_STORE_find(OSSL_STORE_CTX *ctx, const OSSL_STORE_SEARCH *search);

/*-
 *  Function to fetch a loader and extract data from it
 *  ---------------------------------------------------
 */

/**
 * @brief Opaque OSSL_STORE loader implementation for a URI scheme.
 */
typedef struct ossl_store_loader_st OSSL_STORE_LOADER;

/**
 * @brief Fetch a provider-based OSSL_STORE loader for a URI scheme.
 * @param libctx Library context, or NULL for the default.
 * @param scheme URI scheme name (for example "file").
 * @param properties Optional property query string, or NULL.
 * @return Fetched loader, or NULL on error; release with OSSL_STORE_LOADER_free().
 */
OSSL_STORE_LOADER *OSSL_STORE_LOADER_fetch(OSSL_LIB_CTX *libctx,
    const char *scheme,
    const char *properties);
/**
 * @brief Increment the reference count on a fetched store loader.
 * @param loader Loader to retain.
 * @return 1 on success, or 0 on error.
 */
int OSSL_STORE_LOADER_up_ref(OSSL_STORE_LOADER *loader);
/**
 * @brief Release a reference to a store loader.
 * @param loader Loader to free, or NULL.
 */
void OSSL_STORE_LOADER_free(OSSL_STORE_LOADER *loader);
/**
 * @brief Return the provider that implements a fetched store loader (borrowed).
 * @param loader Loader to query.
 * @return Internal OSSL_PROVIDER pointer, or NULL if unavailable; do not free.
 */
const OSSL_PROVIDER *OSSL_STORE_LOADER_get0_provider(const OSSL_STORE_LOADER *
        loader);
/**
 * @brief Return the property definition string of a fetched store loader (borrowed).
 * @param loader Loader to query.
 * @return Internal property string, or NULL if unavailable; do not free.
 */
const char *OSSL_STORE_LOADER_get0_properties(const OSSL_STORE_LOADER *loader);
/**
 * @brief Return a human-readable description of a fetched store loader (borrowed).
 * @param loader Loader to query.
 * @return Internal description string, or NULL if unavailable; do not free.
 */
const char *OSSL_STORE_LOADER_get0_description(const OSSL_STORE_LOADER *loader);
/**
 * @brief Test whether a store loader implements the given URI scheme name.
 * @param loader Loader to query.
 * @param scheme Scheme name to match.
 * @return 1 if @p loader is an implementation of @p scheme, or 0 otherwise.
 */
int OSSL_STORE_LOADER_is_a(const OSSL_STORE_LOADER *loader,
    const char *scheme);
/**
 * @brief Invoke a callback for every store loader provided in a library context.
 * @param libctx Library context to enumerate, or NULL for the default.
 * @param fn Callback receiving each loader and @p arg.
 * @param arg Opaque argument passed to @p fn.
 */
void OSSL_STORE_LOADER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(OSSL_STORE_LOADER *loader,
        void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every scheme name of a store loader.
 * @param loader Loader whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque argument passed to @p fn.
 * @return 1 on success, or 0 on error.
 */
int OSSL_STORE_LOADER_names_do_all(const OSSL_STORE_LOADER *loader,
    void (*fn)(const char *name, void *data),
    void *data);

/*-
 *  Function to register a loader for the given URI scheme.
 *  -------------------------------------------------------
 *
 *  The loader receives all the main components of an URI except for the
 *  scheme.
 */

#ifndef OPENSSL_NO_DEPRECATED_3_0

/* struct ossl_store_loader_ctx_st is defined differently by each loader */
/**
 * @brief Opaque per-open context used by a deprecated ENGINE-based store loader.
 */
typedef struct ossl_store_loader_ctx_st OSSL_STORE_LOADER_CTX;
/**
 * @brief Deprecated loader callback that opens a URI and returns a loader context.
 * @param loader Loader being invoked.
 * @param uri URI without the scheme prefix handled by the registration.
 * @param ui_method UI method for interactive input, or NULL.
 * @param ui_data Application data for @p ui_method.
 * @return New OSSL_STORE_LOADER_CTX, or NULL on error.
 */
typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_fn)(const OSSL_STORE_LOADER *loader, const char *uri,
    const UI_METHOD *ui_method, void *ui_data);
/**
 * @brief Deprecated loader callback that opens a URI with library context and property query.
 * @param loader Loader being invoked.
 * @param uri URI without the scheme prefix handled by the registration.
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query, or NULL.
 * @param ui_method UI method for interactive input, or NULL.
 * @param ui_data Application data for @p ui_method.
 * @return New OSSL_STORE_LOADER_CTX, or NULL on error.
 */
typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_ex_fn)(const OSSL_STORE_LOADER *loader,
    const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
    const UI_METHOD *ui_method, void *ui_data);

/**
 * @brief Deprecated loader callback that attaches to a BIO.
 * @param loader Loader being invoked.
 * @param bio BIO supplying store data.
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query, or NULL.
 * @param ui_method UI method for interactive input, or NULL.
 * @param ui_data Application data for @p ui_method.
 * @return New OSSL_STORE_LOADER_CTX, or NULL on error.
 */
typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_attach_fn)(const OSSL_STORE_LOADER *loader, BIO *bio,
    OSSL_LIB_CTX *libctx, const char *propq,
    const UI_METHOD *ui_method, void *ui_data);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_ctrl() / vctrl().
 * @param ctx Loader-specific open context.
 * @param cmd Control command.
 * @param args Command arguments.
 * @return 1 on success, or 0 on error.
 */
typedef int (*OSSL_STORE_ctrl_fn)(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_expect().
 * @param ctx Loader-specific open context.
 * @param expected Expected OSSL_STORE_INFO_* type, or 0.
 * @return 1 on success, or 0 on error.
 */
typedef int (*OSSL_STORE_expect_fn)(OSSL_STORE_LOADER_CTX *ctx, int expected);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_find().
 * @param ctx Loader-specific open context.
 * @param criteria Search criterion from OSSL_STORE_SEARCH_by_*().
 * @return 1 on success, or 0 on error.
 */
typedef int (*OSSL_STORE_find_fn)(OSSL_STORE_LOADER_CTX *ctx, const OSSL_STORE_SEARCH *criteria);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_load().
 * @param ctx Loader-specific open context.
 * @param ui_method UI method for interactive input, or NULL.
 * @param ui_data Application data for @p ui_method.
 * @return New OSSL_STORE_INFO, or NULL on error / end of data.
 */
typedef OSSL_STORE_INFO *(*OSSL_STORE_load_fn)(OSSL_STORE_LOADER_CTX *ctx, const UI_METHOD *ui_method, void *ui_data);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_eof().
 * @param ctx Loader-specific open context.
 * @return 1 at end of data, or 0 otherwise.
 */
typedef int (*OSSL_STORE_eof_fn)(OSSL_STORE_LOADER_CTX *ctx);
/**
 * @brief Deprecated loader callback implementing OSSL_STORE_error().
 * @param ctx Loader-specific open context.
 * @return 1 if an error occurred, or 0 otherwise.
 */
typedef int (*OSSL_STORE_error_fn)(OSSL_STORE_LOADER_CTX *ctx);
/**
 * @brief Deprecated loader callback that closes and frees a loader context.
 * @param ctx Loader-specific open context.
 * @return 1 on success, or 0 on error.
 */
typedef int (*OSSL_STORE_close_fn)(OSSL_STORE_LOADER_CTX *ctx);

#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate a deprecated ENGINE-based store loader for @p scheme; prefer OSSL_STORE_LOADER_fetch().
 * @param e ENGINE implementing the loader, or NULL.
 * @param scheme URI scheme this loader handles.
 * @return New OSSL_STORE_LOADER, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
OSSL_STORE_LOADER *OSSL_STORE_LOADER_new(ENGINE *e, const char *scheme);
/**
 * @brief Set the open callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param open_function Callback invoked by OSSL_STORE_open().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_open(OSSL_STORE_LOADER *loader,
    OSSL_STORE_open_fn open_function);
/**
 * @brief Set the open_ex callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param open_ex_function Callback invoked by OSSL_STORE_open_ex().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_open_ex(OSSL_STORE_LOADER *loader,
    OSSL_STORE_open_ex_fn open_ex_function);
/**
 * @brief Set the attach callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param attach_function Callback invoked by OSSL_STORE_attach().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_attach(OSSL_STORE_LOADER *loader,
    OSSL_STORE_attach_fn attach_function);
/**
 * @brief Set the ctrl callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param ctrl_function Callback invoked by OSSL_STORE_ctrl() / vctrl().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_ctrl(OSSL_STORE_LOADER *loader,
    OSSL_STORE_ctrl_fn ctrl_function);
/**
 * @brief Set the expect callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param expect_function Callback invoked by OSSL_STORE_expect().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_expect(OSSL_STORE_LOADER *loader,
    OSSL_STORE_expect_fn expect_function);
/**
 * @brief Set the find callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param find_function Callback invoked by OSSL_STORE_find().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_find(OSSL_STORE_LOADER *loader,
    OSSL_STORE_find_fn find_function);
/**
 * @brief Set the load callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param load_function Callback invoked by OSSL_STORE_load().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_load(OSSL_STORE_LOADER *loader,
    OSSL_STORE_load_fn load_function);
/**
 * @brief Set the eof callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param eof_function Callback invoked by OSSL_STORE_eof().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_eof(OSSL_STORE_LOADER *loader,
    OSSL_STORE_eof_fn eof_function);
/**
 * @brief Set the error callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param error_function Callback invoked by OSSL_STORE_error().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_error(OSSL_STORE_LOADER *loader,
    OSSL_STORE_error_fn error_function);
/**
 * @brief Set the close callback on a deprecated ENGINE-based store loader.
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @param close_function Callback invoked by OSSL_STORE_close().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_LOADER_set_close(OSSL_STORE_LOADER *loader,
    OSSL_STORE_close_fn close_function);
/**
 * @brief Return the ENGINE associated with a deprecated store loader (borrowed).
 * @param loader Loader from OSSL_STORE_LOADER_new().
 * @return Internal ENGINE pointer, or NULL; prefer provider-based OSSL_STORE_LOADER_fetch().
 */
OSSL_DEPRECATEDIN_3_0
const ENGINE *OSSL_STORE_LOADER_get0_engine(const OSSL_STORE_LOADER *loader);
/**
 * @brief Return the URI scheme registered for a deprecated store loader (borrowed).
 * @param loader Loader to query.
 * @return Internal scheme string, or NULL; do not free.
 */
OSSL_DEPRECATEDIN_3_0
const char *OSSL_STORE_LOADER_get0_scheme(const OSSL_STORE_LOADER *loader);
/**
 * @brief Register a deprecated ENGINE-based store loader; prefer OSSL_STORE_LOADER_fetch().
 * @param loader Loader configured with OSSL_STORE_LOADER_set_*().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_register_loader(OSSL_STORE_LOADER *loader);
/**
 * @brief Unregister a deprecated ENGINE-based store loader by URI scheme.
 * @param scheme URI scheme previously registered with OSSL_STORE_register_loader().
 * @return The deregistered loader, or NULL if @p scheme was not registered.
 */
OSSL_DEPRECATEDIN_3_0
OSSL_STORE_LOADER *OSSL_STORE_unregister_loader(const char *scheme);
#endif

/*-
 *  Functions to list STORE loaders
 *  -------------------------------
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Invoke a callback for every registered store loader (deprecated).
 * @param do_function Callback receiving each loader and @p do_arg.
 * @param do_arg Opaque argument passed to @p do_function.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int OSSL_STORE_do_all_loaders(void (*do_function)(const OSSL_STORE_LOADER *loader,
                                  void *do_arg),
    void *do_arg);
#endif

#ifdef __cplusplus
}
#endif
#endif
