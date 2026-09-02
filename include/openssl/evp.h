/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EVP_H
#define OPENSSL_EVP_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_ENVELOPE_H
#endif

#include <stdarg.h>

#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif

#include <openssl/opensslconf.h>
#include <openssl/types.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/symhacks.h>
#include <openssl/bio.h>
#include <openssl/evperr.h>
#include <openssl/params.h>

#define EVP_MAX_MD_SIZE 64 /* longest known is SHA512 */
#define EVP_MAX_KEY_LENGTH 64
#define EVP_MAX_IV_LENGTH 16
#define EVP_MAX_BLOCK_LENGTH 32
#define EVP_MAX_AEAD_TAG_LENGTH 16

#define PKCS5_SALT_LEN 8
/* Default PKCS#5 iteration count */
#define PKCS5_DEFAULT_ITER 2048

#include <openssl/objects.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define EVP_PK_RSA 0x0001
#define EVP_PK_DSA 0x0002
#define EVP_PK_DH 0x0004
#define EVP_PK_EC 0x0008
#define EVP_PKT_SIGN 0x0010
#define EVP_PKT_ENC 0x0020
#define EVP_PKT_EXCH 0x0040
#define EVP_PKS_RSA 0x0100
#define EVP_PKS_DSA 0x0200
#define EVP_PKS_EC 0x0400
#endif

#define EVP_PKEY_NONE NID_undef
#define EVP_PKEY_RSA NID_rsaEncryption
#define EVP_PKEY_RSA2 NID_rsa
#define EVP_PKEY_RSA_PSS NID_rsassaPss
#define EVP_PKEY_DSA NID_dsa
#define EVP_PKEY_DSA1 NID_dsa_2
#define EVP_PKEY_DSA2 NID_dsaWithSHA
#define EVP_PKEY_DSA3 NID_dsaWithSHA1
#define EVP_PKEY_DSA4 NID_dsaWithSHA1_2
#define EVP_PKEY_DH NID_dhKeyAgreement
#define EVP_PKEY_DHX NID_dhpublicnumber
#define EVP_PKEY_EC NID_X9_62_id_ecPublicKey
#define EVP_PKEY_SM2 NID_sm2
#define EVP_PKEY_HMAC NID_hmac
#define EVP_PKEY_CMAC NID_cmac
#define EVP_PKEY_SCRYPT NID_id_scrypt
#define EVP_PKEY_TLS1_PRF NID_tls1_prf
#define EVP_PKEY_HKDF NID_hkdf
#define EVP_PKEY_POLY1305 NID_poly1305
#define EVP_PKEY_SIPHASH NID_siphash
#define EVP_PKEY_X25519 NID_X25519
#define EVP_PKEY_ED25519 NID_ED25519
#define EVP_PKEY_X448 NID_X448
#define EVP_PKEY_ED448 NID_ED448
/* Special indicator that the object is uniquely provider side */
#define EVP_PKEY_KEYMGMT -1

/* Easy to use macros for EVP_PKEY related selections */
#define EVP_PKEY_KEY_PARAMETERS \
    (OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
#define EVP_PKEY_PRIVATE_KEY \
    (EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
#define EVP_PKEY_PUBLIC_KEY \
    (EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
#define EVP_PKEY_KEYPAIR \
    (EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set the default property query string used for algorithm fetches in @p libctx.
 * @param libctx Library context to update, or NULL for the default context.
 * @param propq Property query string (for example "fips=yes"), or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Query whether the library context's default property query requires FIPS algorithms.
 * @param libctx Library context to query, or NULL for the default context.
 * @return 1 if the default properties imply FIPS-only fetches, or 0 otherwise.
 */
int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx);
/**
 * @brief Enable or disable the FIPS constraint in a library context's default properties.
 * @param libctx Library context to update, or NULL for the default context.
 * @param enable Non-zero to require FIPS algorithms in default fetches, or 0 to clear that constraint.
 * @return 1 on success, or 0 on failure.
 */
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable);

#define EVP_PKEY_MO_SIGN 0x0001
#define EVP_PKEY_MO_VERIFY 0x0002
#define EVP_PKEY_MO_ENCRYPT 0x0004
#define EVP_PKEY_MO_DECRYPT 0x0008

#ifndef EVP_MD
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate a mutable EVP_MD method object for custom digests (deprecated).
 * @param md_type NID identifying the digest algorithm.
 * @param pkey_type Legacy NID associating the digest with a public-key type, or NID_undef.
 * @return New EVP_MD, or NULL on allocation failure.
 *
 * Deprecated; prefer provider-based digests instead of building EVP_MD methods by hand.
 */
OSSL_DEPRECATEDIN_3_0 EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
/**
 * @brief Duplicate a custom EVP_MD method (deprecated).
 * @param md Digest method to copy.
 * @return New EVP_MD copy, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EVP_MD *EVP_MD_meth_dup(const EVP_MD *md);
/**
 * @brief Free a custom EVP_MD method created with EVP_MD_meth_new (deprecated).
 * @param md Digest method to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_MD_meth_free(EVP_MD *md);
/**
 * @brief Set the input block size advertised by a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param blocksize Block size in bytes (for example 64 for SHA-1).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
/**
 * @brief Set the digest output size on a custom EVP_MD method (deprecated).
 * @param md Digest method under construction.
 * @param resultsize Digest length in bytes (for example 32 for SHA-256).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
/**
 * @brief Set the private context data size for a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param datasize Number of bytes of application data to allocate with each EVP_MD_CTX.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
/**
 * @brief Set behaviour flags on a custom EVP_MD method (deprecated).
 * @param md Digest method to update.
 * @param flags EVP_MD_FLAG_* bits controlling copying and oneshot behaviour.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);
/**
 * @brief Set the init callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param init Callback invoked to start a digest operation on a context.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
/**
 * @brief Set the update callback on a custom EVP_MD method (deprecated).
 * @param md Digest method object to update.
 * @param update Callback that absorbs more message bytes into @p ctx, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count));
/**
 * @brief Set the final callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed with EVP_MD_meth_new().
 * @param final Callback that writes the digest and finalises @p ctx.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx, unsigned char *md));
/**
 * @brief Set the context-copy callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed with EVP_MD_meth_new().
 * @param copy Callback that duplicates digest state from @p from into @p to.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to, const EVP_MD_CTX *from));
/**
 * @brief Set the cleanup callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param cleanup Callback invoked to release context-specific resources before the context is cleared.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
/**
 * @brief Set the ctrl callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param ctrl Callback handling EVP_MD_CTRL_* commands for digest contexts.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2));
/**
 * @brief Return the input block size previously set on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Input block size in bytes, or 0 if unset.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_input_blocksize(const EVP_MD *md);
/**
 * @brief Return the digest output size previously set on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Result size in bytes, or 0 if unset.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_result_size(const EVP_MD *md);
/**
 * @brief Return the application-data size reserved by a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Size in bytes previously set with EVP_MD_meth_set_app_datasize().
 */
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_app_datasize(const EVP_MD *md);
/**
 * @brief Return the flag bits configured on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Flag mask such as EVP_MD_FLAG_ONESHOT / EVP_MD_FLAG_XOF.
 */
OSSL_DEPRECATEDIN_3_0 unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);
/**
 * @brief Return the init callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);
/**
 * @brief Return the update callback previously set on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the update function, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
    const void *data, size_t count);
/**
 * @brief Return the final callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the finalization callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
    unsigned char *md);
/**
 * @brief Return the context-copy callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the copy callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
    const EVP_MD_CTX *from);
/**
 * @brief Return the cleanup callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the cleanup callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);
/**
 * @brief Return the ctrl callback installed on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Function pointer for EVP_MD_CTX ctrl commands, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
    int p1, void *p2);
#endif
/* digest can only handle a single block */
#define EVP_MD_FLAG_ONESHOT 0x0001

/* digest is extensible-output function, XOF */
#define EVP_MD_FLAG_XOF 0x0002

/* DigestAlgorithmIdentifier flags... */

#define EVP_MD_FLAG_DIGALGID_MASK 0x0018

/* NULL or absent parameter accepted. Use NULL */

#define EVP_MD_FLAG_DIGALGID_NULL 0x0000

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

#define EVP_MD_FLAG_DIGALGID_ABSENT 0x0008

/* Custom handling via ctrl */

#define EVP_MD_FLAG_DIGALGID_CUSTOM 0x0018

/* Note if suitable for use in FIPS mode */
#define EVP_MD_FLAG_FIPS 0x0400

/* Digest ctrls */

#define EVP_MD_CTRL_DIGALGID 0x1
#define EVP_MD_CTRL_MICALG 0x2
#define EVP_MD_CTRL_XOF_LEN 0x3
#define EVP_MD_CTRL_TLSTREE 0x4

/* Minimum Algorithm specific ctrl value */

#define EVP_MD_CTRL_ALG_CTRL 0x1000

#endif /* !EVP_MD */

/* values for EVP_MD_CTX flags */

#define EVP_MD_CTX_FLAG_ONESHOT 0x0001 /* digest update will be \
                                        * called once only */
#define EVP_MD_CTX_FLAG_CLEANED 0x0002 /* context has already been \
                                        * cleaned */
#define EVP_MD_CTX_FLAG_REUSE 0x0004 /* Don't free up ctx->md_data \
                                      * in EVP_MD_CTX_reset */
/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here so we
 * don't accidentally reuse the values for other purposes.
 */

/* This flag has no effect from openssl-3.0 onwards */
#define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW 0x0008

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */
#define EVP_MD_CTX_FLAG_PAD_MASK 0xF0 /* RSA mode to use */
#define EVP_MD_CTX_FLAG_PAD_PKCS1 0x00 /* PKCS#1 v1.5 mode */
#define EVP_MD_CTX_FLAG_PAD_X931 0x10 /* X9.31 mode */
#define EVP_MD_CTX_FLAG_PAD_PSS 0x20 /* PSS mode */

#define EVP_MD_CTX_FLAG_NO_INIT 0x0100 /* Don't initialize md_data */
/*
 * Some functions such as EVP_DigestSign only finalise copies of internal
 * contexts so additional data can be included after the finalisation call.
 * This is inefficient if this functionality is not required: it is disabled
 * if the following flag is set.
 */
#define EVP_MD_CTX_FLAG_FINALISE 0x0200
/* NOTE: 0x0400 and 0x0800 are reserved for internal usage */

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate a custom EVP_CIPHER method object (deprecated).
 * @param cipher_type NID identifying the cipher algorithm.
 * @param block_size Block size in bytes (1 for stream ciphers).
 * @param key_len Default key length in bytes.
 * @return New mutable EVP_CIPHER, or NULL on failure; free with EVP_CIPHER_meth_free().
 */
OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
/**
 * @brief Duplicate a custom EVP_CIPHER method object (deprecated).
 * @param cipher Method to copy.
 * @return Newly allocated EVP_CIPHER copy, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);
/**
 * @brief Free a custom EVP_CIPHER created with EVP_CIPHER_meth_new() (deprecated).
 * @param cipher Cipher method to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);
/**
 * @brief Set the IV length advertised by a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method under construction.
 * @param iv_len IV length in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
/**
 * @brief Set EVP_CIPH_* capability flags on a custom EVP_CIPHER (deprecated).
 * @param cipher Cipher method being constructed.
 * @param flags Combination of EVP_CIPH_* flags (mode, variable length, AEAD, …).
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
/**
 * @brief Set how many bytes of cipher-specific context storage to allocate (deprecated).
 * @param cipher Custom cipher method to update.
 * @param ctx_size Size in bytes of the implementation context allocated with each EVP_CIPHER_CTX.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
/**
 * @brief Set the key/IV initialization callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param init Callback that prepares @p ctx for encrypt or decrypt, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
    int (*init)(EVP_CIPHER_CTX *ctx,
        const unsigned char *key,
        const unsigned char *iv,
        int enc));
/**
 * @brief Set the encrypt/decrypt update callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param do_cipher Callback that transforms @p inl bytes from @p in to @p out, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
    int (*do_cipher)(EVP_CIPHER_CTX *ctx,
        unsigned char *out,
        const unsigned char *in,
        size_t inl));
/**
 * @brief Set the context-cleanup callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param cleanup Callback invoked when an EVP_CIPHER_CTX using this method is reset or freed.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
    int (*cleanup)(EVP_CIPHER_CTX *));
/**
 * @brief Set the ASN.1 parameter-encoding callback on a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method under construction.
 * @param set_asn1_parameters Callback that writes algorithm parameters from @p ctx into an ASN1_TYPE.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
    int (*set_asn1_parameters)(EVP_CIPHER_CTX *,
        ASN1_TYPE *));
/**
 * @brief Set the callback that exports cipher parameters into an ASN.1 type (deprecated).
 * @param cipher Custom cipher method to update.
 * @param get_asn1_parameters Callback that fills an ASN1_TYPE from the cipher context, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *,
        ASN1_TYPE *));
/**
 * @brief Set the ctrl callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param ctrl Callback handling EVP_CIPHER_CTX_ctrl commands, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
    int (*ctrl)(EVP_CIPHER_CTX *, int type,
        int arg, void *ptr));
/**
 * @brief Return the init callback previously set on a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Pointer to the init function, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_init(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
    const unsigned char *key,
    const unsigned char *iv,
    int enc);
/**
 * @brief Return the do_cipher callback from a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Pointer to the encrypt/decrypt update callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t inl);
/**
 * @brief Return the cleanup callback previously set on a custom EVP_CIPHER method.
 * @param cipher Cipher method to query.
 * @return Pointer to the cleanup function, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *);
/**
 * @brief Return the set_asn1_params callback previously set on a custom EVP_CIPHER method.
 * @param cipher Cipher method to query.
 * @return Function that writes AlgorithmIdentifier parameters from @c EVP_CIPHER_CTX into an ASN1_TYPE, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
    ASN1_TYPE *);
/**
 * @brief Return the get_asn1_params callback previously set on a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Function that reads AlgorithmIdentifier parameters from an ASN1_TYPE into @c EVP_CIPHER_CTX, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
    ASN1_TYPE *);
/**
 * @brief Return the ctrl callback previously set on a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Pointer to the ctrl function, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *, int type,
    int arg, void *ptr);
#endif

/* Values for cipher flags */

/* Modes for ciphers */

#define EVP_CIPH_STREAM_CIPHER 0x0
#define EVP_CIPH_ECB_MODE 0x1
#define EVP_CIPH_CBC_MODE 0x2
#define EVP_CIPH_CFB_MODE 0x3
#define EVP_CIPH_OFB_MODE 0x4
#define EVP_CIPH_CTR_MODE 0x5
#define EVP_CIPH_GCM_MODE 0x6
#define EVP_CIPH_CCM_MODE 0x7
#define EVP_CIPH_XTS_MODE 0x10001
#define EVP_CIPH_WRAP_MODE 0x10002
#define EVP_CIPH_OCB_MODE 0x10003
#define EVP_CIPH_SIV_MODE 0x10004
#define EVP_CIPH_GCM_SIV_MODE 0x10005
#define EVP_CIPH_MODE 0xF0007
/* Set if variable length cipher */
#define EVP_CIPH_VARIABLE_LENGTH 0x8
/* Set if the iv handling should be done by the cipher itself */
#define EVP_CIPH_CUSTOM_IV 0x10
/* Set if the cipher's init() function should be called if key is NULL */
#define EVP_CIPH_ALWAYS_CALL_INIT 0x20
/* Call ctrl() to init cipher parameters */
#define EVP_CIPH_CTRL_INIT 0x40
/* Don't use standard key length function */
#define EVP_CIPH_CUSTOM_KEY_LENGTH 0x80
/* Don't use standard block padding */
#define EVP_CIPH_NO_PADDING 0x100
/* cipher handles random key generation */
#define EVP_CIPH_RAND_KEY 0x200
/* cipher has its own additional copying logic */
#define EVP_CIPH_CUSTOM_COPY 0x400
/* Don't use standard iv length function */
#define EVP_CIPH_CUSTOM_IV_LENGTH 0x800
/* Legacy and no longer relevant: Allow use default ASN1 get/set iv */
#define EVP_CIPH_FLAG_DEFAULT_ASN1 0
/* Free:                                         0x1000 */
/* Buffer length in bits not bytes: CFB1 mode only */
#define EVP_CIPH_FLAG_LENGTH_BITS 0x2000
/* Deprecated FIPS flag: was 0x4000 */
#define EVP_CIPH_FLAG_FIPS 0
/* Deprecated FIPS flag: was 0x8000 */
#define EVP_CIPH_FLAG_NON_FIPS_ALLOW 0

/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
#define EVP_CIPH_FLAG_CTS 0x4000
#define EVP_CIPH_FLAG_CUSTOM_CIPHER 0x100000
#define EVP_CIPH_FLAG_AEAD_CIPHER 0x200000
#define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
/* Cipher can handle pipeline operations */
#define EVP_CIPH_FLAG_PIPELINE 0X800000
/* For provider implementations that handle  ASN1 get/set param themselves */
#define EVP_CIPH_FLAG_CUSTOM_ASN1 0x1000000
/* For ciphers generating unprotected CMS attributes */
#define EVP_CIPH_FLAG_CIPHER_WITH_MAC 0x2000000
/* For supplementary wrap cipher support */
#define EVP_CIPH_FLAG_GET_WRAP_CIPHER 0x4000000
#define EVP_CIPH_FLAG_INVERSE_CIPHER 0x8000000

/*
 * Cipher context flag to indicate we can handle wrap mode: if allowed in
 * older applications it could overflow buffers.
 */

#define EVP_CIPHER_CTX_FLAG_WRAP_ALLOW 0x1

/* ctrl() values */

#define EVP_CTRL_INIT 0x0
#define EVP_CTRL_SET_KEY_LENGTH 0x1
#define EVP_CTRL_GET_RC2_KEY_BITS 0x2
#define EVP_CTRL_SET_RC2_KEY_BITS 0x3
#define EVP_CTRL_GET_RC5_ROUNDS 0x4
#define EVP_CTRL_SET_RC5_ROUNDS 0x5
#define EVP_CTRL_RAND_KEY 0x6
#define EVP_CTRL_PBE_PRF_NID 0x7
#define EVP_CTRL_COPY 0x8
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 0x10
#define EVP_CTRL_AEAD_SET_TAG 0x11
#define EVP_CTRL_AEAD_SET_IV_FIXED 0x12
#define EVP_CTRL_GCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_GCM_GET_TAG EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_GCM_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_GCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED
#define EVP_CTRL_GCM_IV_GEN 0x13
#define EVP_CTRL_CCM_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_CCM_GET_TAG EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_CCM_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_CCM_SET_IV_FIXED EVP_CTRL_AEAD_SET_IV_FIXED
#define EVP_CTRL_CCM_SET_L 0x14
#define EVP_CTRL_CCM_SET_MSGLEN 0x15
/*
 * AEAD cipher deduces payload length and returns number of bytes required to
 * store MAC and eventual padding. Subsequent call to EVP_Cipher even
 * appends/verifies MAC.
 */
#define EVP_CTRL_AEAD_TLS1_AAD 0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
#define EVP_CTRL_AEAD_SET_MAC_KEY 0x17
/* Set the GCM invocation field, decrypt only */
#define EVP_CTRL_GCM_SET_IV_INV 0x18

#define EVP_CTRL_TLS1_1_MULTIBLOCK_AAD 0x19
#define EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT 0x1a
#define EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT 0x1b
#define EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE 0x1c

#define EVP_CTRL_SSL3_MASTER_SECRET 0x1d

/* EVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
#define EVP_CTRL_SET_SBOX 0x1e
/*
 * EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
#define EVP_CTRL_SBOX_USED 0x1f
/* EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
#define EVP_CTRL_KEY_MESH 0x20
/* EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
#define EVP_CTRL_BLOCK_PADDING_MODE 0x21

/* Set the output buffers to use for a pipelined operation */
#define EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS 0x22
/* Set the input buffers to use for a pipelined operation */
#define EVP_CTRL_SET_PIPELINE_INPUT_BUFS 0x23
/* Set the input buffer lengths to use for a pipelined operation */
#define EVP_CTRL_SET_PIPELINE_INPUT_LENS 0x24
/* Get the IV length used by the cipher */
#define EVP_CTRL_GET_IVLEN 0x25
/* 0x26 is unused */
/* Tell the cipher it's doing a speed test (SIV disallows multiple ops) */
#define EVP_CTRL_SET_SPEED 0x27
/* Get the unprotectedAttrs from cipher ctx */
#define EVP_CTRL_PROCESS_UNPROTECTED 0x28
/* Get the supplementary wrap cipher */
#define EVP_CTRL_GET_WRAP_CIPHER 0x29
/* TLSTREE key diversification */
#define EVP_CTRL_TLSTREE 0x2A

/* Padding modes */
#define EVP_PADDING_PKCS7 1
#define EVP_PADDING_ISO7816_4 2
#define EVP_PADDING_ANSI923 3
#define EVP_PADDING_ISO10126 4
#define EVP_PADDING_ZERO 5

/* RFC 5246 defines additional data to be 13 bytes in length */
#define EVP_AEAD_TLS1_AAD_LEN 13

/**
 * @brief Parameters for TLS 1.1 AES multiblock EVP_CIPHER_CTX_ctrl operations.
 */
typedef struct {
    /** Destination buffer for TLS 1.1 multiblock ciphertext or plaintext output. */
    unsigned char *out;
    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;
    /** Length in bytes of the buffer at @c inp / @c out for the multiblock operation. */
    size_t len;
    /** Interleave factor selecting how many records are processed together. */
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
#define EVP_GCM_TLS_FIXED_IV_LEN 4
/* Length of explicit part of IV part of TLS records */
#define EVP_GCM_TLS_EXPLICIT_IV_LEN 8
/* Length of tag for TLS */
#define EVP_GCM_TLS_TAG_LEN 16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
#define EVP_CCM_TLS_FIXED_IV_LEN 4
/* Length of explicit part of IV part of TLS records */
#define EVP_CCM_TLS_EXPLICIT_IV_LEN 8
/* Total length of CCM IV length for TLS */
#define EVP_CCM_TLS_IV_LEN 12
/* Length of tag for TLS */
#define EVP_CCM_TLS_TAG_LEN 16
/* Length of CCM8 tag for TLS */
#define EVP_CCM8_TLS_TAG_LEN 8

/* Length of tag for TLS */
#define EVP_CHACHAPOLY_TLS_TAG_LEN 16

/**
 * @brief Cipher algorithm pointer paired with an initialization vector buffer.
 */
typedef struct evp_cipher_info_st {
    /** Cipher implementation used with @c iv. */
    const EVP_CIPHER *cipher;
    /** Initialization vector octets for @c cipher (up to EVP_MAX_IV_LENGTH bytes). */
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;

/* Password based encryption function */
/**
 * @brief Callback type that derives a key/IV from a password and initializes a cipher context for PBE.
 * @param ctx Cipher context to initialize for encryption or decryption.
 * @param pass Password bytes (not necessarily NUL-terminated).
 * @param passlen Length of @p pass in bytes, or -1 if @p pass is NUL-terminated.
 * @param param Algorithm-specific ASN.1 parameters (for example a salt and iteration count).
 * @param cipher Cipher algorithm to use.
 * @param md Digest used in the PBE key-derivation function.
 * @param en_de 1 to encrypt, 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 */
typedef int(EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);

/**
 * @brief Extended password-based encryption key-setup callback with library context support.
 * @param ctx Cipher context that receives the derived key and IV.
 * @param pass Password bytes (may contain embedded NULs when @p passlen is set).
 * @param passlen Length of @p pass in bytes, or -1 if @p pass is a NUL-terminated string.
 * @param param Algorithm-specific PBE parameters (for example PBKDF2PARAM).
 * @param cipher Cipher to initialize.
 * @param md Digest used by the PBE scheme when applicable.
 * @param en_de 1 to encrypt, 0 to decrypt.
 * @param libctx Library context used when fetching algorithms, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
typedef int(EVP_PBE_KEYGEN_EX)(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de, OSSL_LIB_CTX *libctx, const char *propq);

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define EVP_PKEY_assign_RSA(pkey, rsa) EVP_PKEY_assign((pkey), EVP_PKEY_RSA, \
    (rsa))
#endif

#ifndef OPENSSL_NO_DSA
#define EVP_PKEY_assign_DSA(pkey, dsa) EVP_PKEY_assign((pkey), EVP_PKEY_DSA, \
    (dsa))
#endif

#if !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#define EVP_PKEY_assign_DH(pkey, dh) EVP_PKEY_assign((pkey), EVP_PKEY_DH, (dh))
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
#ifndef OPENSSL_NO_EC
#define EVP_PKEY_assign_EC_KEY(pkey, eckey) \
    EVP_PKEY_assign((pkey), EVP_PKEY_EC, (eckey))
#endif
#endif
#ifndef OPENSSL_NO_SIPHASH
#define EVP_PKEY_assign_SIPHASH(pkey, shkey) EVP_PKEY_assign((pkey), \
    EVP_PKEY_SIPHASH, (shkey))
#endif

#ifndef OPENSSL_NO_POLY1305
#define EVP_PKEY_assign_POLY1305(pkey, polykey) EVP_PKEY_assign((pkey), \
    EVP_PKEY_POLY1305, (polykey))
#endif

/* Add some extra combinations */
#define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
#define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))
#define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
#define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

/**
 * @brief Return the NID identifying a message-digest algorithm.
 * @param md Digest method to query.
 * @return Algorithm NID such as NID_sha256, or NID_undef on error.
 */
int EVP_MD_get_type(const EVP_MD *md);
#define EVP_MD_type EVP_MD_get_type
#define EVP_MD_nid EVP_MD_get_type
/**
 * @brief Return the primary algorithm name of a message digest.
 * @param md Digest method to query.
 * @return Internal NUL-terminated name string (do not free), or NULL on error.
 */
const char *EVP_MD_get0_name(const EVP_MD *md);
#define EVP_MD_name EVP_MD_get0_name
/**
 * @brief Return a human-readable description of a digest algorithm.
 * @param md Digest method to query.
 * @return Description string for display, or NULL if unavailable.
 */
const char *EVP_MD_get0_description(const EVP_MD *md);
/**
 * @brief Test whether a digest implementation is known by @p name (including aliases).
 * @param md Digest method to query.
 * @param name Algorithm name such as "SHA256".
 * @return 1 if @p md matches @p name, or 0 otherwise.
 */
int EVP_MD_is_a(const EVP_MD *md, const char *name);
/**
 * @brief Invoke a callback for every known name alias of a message digest.
 * @param md Digest method whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_names_do_all(const EVP_MD *md,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return the provider that implements a message-digest algorithm.
 * @param md Digest method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL on error.
 */
const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md);
/**
 * @brief Return the legacy public-key NID associated with a digest method.
 * @param md Digest method to query.
 * @return NID of the traditional combined pkey+digest type, or NID_undef.
 */
int EVP_MD_get_pkey_type(const EVP_MD *md);
#define EVP_MD_pkey_type EVP_MD_get_pkey_type
/**
 * @brief Return the output size of a message digest in bytes.
 * @param md Digest method to query.
 * @return Digest length in bytes, or a negative value if unavailable / for unbounded XOFs.
 */
int EVP_MD_get_size(const EVP_MD *md);
#define EVP_MD_size EVP_MD_get_size
/**
 * @brief Return the internal block size of a message digest in bytes.
 * @param md Digest method to query.
 * @return Block size in bytes used by the compression function.
 */
int EVP_MD_get_block_size(const EVP_MD *md);
#define EVP_MD_block_size EVP_MD_get_block_size
/**
 * @brief Return the flag bits associated with a digest method.
 * @param md Digest method to query.
 * @return Bitmask of EVP_MD_FLAG_* values.
 */
unsigned long EVP_MD_get_flags(const EVP_MD *md);
#define EVP_MD_flags EVP_MD_get_flags

/**
 * @brief Return the digest method currently associated with a digest context.
 * @param ctx Digest context to query.
 * @return Internal EVP_MD pointer (do not free), or NULL if unset.
 */
const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx);
/**
 * @brief Return the digest method associated with @p ctx, transferring a reference to the caller.
 * @param ctx Digest context to query.
 * @return EVP_MD with an incremented reference count (free with EVP_MD_free), or NULL if unset.
 */
EVP_MD *EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the EVP_MD currently associated with a digest context (deprecated).
 * @param ctx Digest context to query.
 * @return Digest method pointer, or NULL if unset; prefer EVP_MD_CTX_get0_md().
 */
OSSL_DEPRECATEDIN_3_0
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
/**
 * @brief Return the digest update function currently used by a digest context (deprecated).
 * @param ctx Digest context to query.
 * @return Update callback invoked by EVP_DigestUpdate(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
    const void *data, size_t count);
/**
 * @brief Override the update function used by a digest context (deprecated).
 * @param ctx Digest context whose update implementation is replaced.
 * @param update Replacement update callback, or NULL to restore the method default.
 */
OSSL_DEPRECATEDIN_3_0
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
    int (*update)(EVP_MD_CTX *ctx,
        const void *data, size_t count));
#endif
#define EVP_MD_CTX_get0_name(e) EVP_MD_get0_name(EVP_MD_CTX_get0_md(e))
#define EVP_MD_CTX_get_size(e) EVP_MD_get_size(EVP_MD_CTX_get0_md(e))
#define EVP_MD_CTX_size EVP_MD_CTX_get_size
#define EVP_MD_CTX_get_block_size(e) EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e))
#define EVP_MD_CTX_block_size EVP_MD_CTX_get_block_size
#define EVP_MD_CTX_get_type(e) EVP_MD_get_type(EVP_MD_CTX_get0_md(e))
#define EVP_MD_CTX_type EVP_MD_CTX_get_type
/**
 * @brief Return the EVP_PKEY_CTX currently attached to a digest context.
 * @param ctx Digest context to query.
 * @return Associated key context, or NULL if none; do not free the result.
 */
EVP_PKEY_CTX *EVP_MD_CTX_get_pkey_ctx(const EVP_MD_CTX *ctx);
#define EVP_MD_CTX_pkey_ctx EVP_MD_CTX_get_pkey_ctx
/**
 * @brief Attach or clear the EVP_PKEY_CTX owned by a digest context (for DigestSign/DigestVerify).
 * @param ctx Digest context that will hold @p pctx.
 * @param pctx Key context to assign; ownership is transferred to @p ctx. Pass NULL to clear.
 */
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
/**
 * @brief Return the digest method's private data pointer for a context.
 * @param ctx Digest context to query.
 * @return Implementation-specific data pointer (do not free), or NULL if unavailable.
 */
void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx);
#define EVP_MD_CTX_md_data EVP_MD_CTX_get0_md_data

/**
 * @brief Return the NID associated with a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Cipher NID, or NID_undef if unknown or uninitialized.
 */
int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher);
#define EVP_CIPHER_nid EVP_CIPHER_get_nid
/**
 * @brief Return the primary name of a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Internal name string; do not free.
 */
const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher);
#define EVP_CIPHER_name EVP_CIPHER_get0_name
/**
 * @brief Return a human-readable description of a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Description string for display, or NULL if unavailable.
 */
const char *EVP_CIPHER_get0_description(const EVP_CIPHER *cipher);
/**
 * @brief Test whether @p cipher is known under algorithm name @p name.
 * @param cipher Cipher implementation to query.
 * @param name Algorithm name or alias (for example "AES-128-CBC").
 * @return 1 if @p name identifies @p cipher, or 0 otherwise.
 */
int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name);
/**
 * @brief Invoke a callback for every name synonym associated with a cipher.
 * @param cipher Cipher algorithm to enumerate names for.
 * @param fn Callback receiving each name and @p data.
 * @param data User pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return the provider that implements a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL for legacy methods.
 */
const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher);
/**
 * @brief Return the block size of a cipher in bytes.
 * @param cipher Cipher method to query.
 * @return Block size in bytes (1 for stream ciphers).
 */
int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);
#define EVP_CIPHER_block_size EVP_CIPHER_get_block_size
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the size of the cipher's legacy implementation context (deprecated).
 * @param cipher Cipher method to query.
 * @return Context size in bytes expected by the method's init/do_cipher callbacks.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);
#endif
/**
 * @brief Return the default key length of a cipher in bytes.
 * @param cipher Cipher method to query.
 * @return Default key length in bytes.
 */
int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);
#define EVP_CIPHER_key_length EVP_CIPHER_get_key_length
/**
 * @brief Return the IV length in bytes required by a cipher.
 * @param cipher Cipher method to query.
 * @return IV length, or 0 if the cipher does not use an IV.
 */
int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);
#define EVP_CIPHER_iv_length EVP_CIPHER_get_iv_length
/**
 * @brief Return the capability and behavior flags of a cipher.
 * @param cipher Cipher method to query.
 * @return Bitmask of EVP_CIPH_* flags for @p cipher.
 */
unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER *cipher);
#define EVP_CIPHER_flags EVP_CIPHER_get_flags
/**
 * @brief Return the cipher mode constant for a cipher method.
 * @param cipher Cipher method to query.
 * @return An EVP_CIPH_*_MODE value (for example EVP_CIPH_CBC_MODE).
 */
int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher);
#define EVP_CIPHER_mode EVP_CIPHER_get_mode
/**
 * @brief Return the OBJECT IDENTIFIER NID of a cipher (ignoring parameters).
 * @param cipher Cipher method to query.
 * @return Cipher OID NID, or NID_undef if the cipher has no ASN.1 support.
 */
int EVP_CIPHER_get_type(const EVP_CIPHER *cipher);
#define EVP_CIPHER_type EVP_CIPHER_get_type
/**
 * @brief Fetch a cipher implementation from providers in a library context.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Cipher algorithm name.
 * @param properties Optional property query string, or NULL.
 * @return Fetched EVP_CIPHER (free with EVP_CIPHER_free()), or NULL on failure.
 */
EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Increment the reference count on a fetched EVP_CIPHER.
 * @param cipher Cipher object from EVP_CIPHER_fetch() / similar.
 * @return 1 on success, or 0 on error.
 */
int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
/**
 * @brief Free a fetched or duplicated EVP_CIPHER method.
 * @param cipher Cipher to free, or NULL.
 */
void EVP_CIPHER_free(EVP_CIPHER *cipher);

/**
 * @brief Return the cipher method currently associated with a cipher context.
 * @param ctx Cipher context to query.
 * @return Internal EVP_CIPHER pointer (do not free), or NULL if unset.
 */
const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Return a new reference to the EVP_CIPHER used by a cipher context.
 * @param ctx Cipher context to query.
 * @return Cipher with an incremented reference count, or NULL if unset; free with EVP_CIPHER_free.
 */
EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx);
/**
 * @brief Test whether a cipher context is currently configured for encryption.
 * @param ctx Cipher context to query.
 * @return 1 if encrypting, or 0 if decrypting.
 */
int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_encrypting EVP_CIPHER_CTX_is_encrypting
/**
 * @brief Return the NID of the cipher currently bound to a cipher context.
 * @param ctx Cipher context to query.
 * @return Algorithm NID, or NID_undef if no cipher is set.
 */
int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_nid EVP_CIPHER_CTX_get_nid
/**
 * @brief Return the block size of the cipher bound to a cipher context.
 * @param ctx Cipher context to query.
 * @return Block size in bytes, or 0 if no cipher is set.
 */
int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_block_size EVP_CIPHER_CTX_get_block_size
/**
 * @brief Return the key length currently configured on a cipher context.
 * @param ctx Cipher context to query.
 * @return Key length in bytes (may differ from the cipher default after set_key_length).
 */
int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_get_key_length
/**
 * @brief Return the IV length in bytes for the cipher currently set on @p ctx.
 * @param ctx Initialised cipher context.
 * @return IV length in bytes, or 0 if the cipher uses no IV / on error.
 */
int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_iv_length EVP_CIPHER_CTX_get_iv_length
/**
 * @brief Return the authentication tag length for an AEAD cipher context.
 * @param ctx Cipher context initialized for an AEAD algorithm.
 * @return Tag length in bytes, or 0 if the context is not AEAD or the length is unset.
 */
int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_tag_length EVP_CIPHER_CTX_get_tag_length
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the EVP_CIPHER associated with a cipher context.
 * @param ctx Cipher context to query.
 * @return Cipher method pointer, or NULL if unset.
 */
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Return a pointer to the IV stored in a cipher context (deprecated).
 * @param ctx Cipher context to query.
 * @return Internal IV buffer (do not free), or NULL if unavailable.
 *
 * Prefer EVP_CIPHER_CTX_get_updated_iv() / OSSL_PARAM queries for new code.
 */
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Return the IV originally supplied when the cipher context was initialized (deprecated).
 * @param ctx Cipher context to query.
 * @return Pointer to the original IV bytes, or NULL if unavailable.
 */
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Return a mutable pointer to the current IV in a cipher context (deprecated).
 * @param ctx Cipher context whose IV buffer is accessed.
 * @return Pointer to the IV bytes, or NULL if unavailable.
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
#endif
/**
 * @brief Copy the current IV state from a cipher context into a buffer.
 * @param ctx Cipher context whose updated IV is read.
 * @param buf Destination buffer that receives the IV bytes.
 * @param len Size of @p buf in bytes; must be at least EVP_CIPHER_CTX_get_iv_length(@p ctx).
 * @return 1 on success, or 0 on failure (including if @p buf is too small).
 */
int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
/**
 * @brief Copy the original IV from a cipher context into @p buf.
 * @param ctx Cipher context previously initialized with an IV.
 * @param buf Destination buffer for the IV bytes.
 * @param len Capacity of @p buf in bytes (must be at least the IV length).
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the internal partial-block buffer of a cipher context (deprecated).
 * @param ctx Cipher context whose @c buf field is exposed.
 * @return Pointer to the context's internal buffer used for leftover partial blocks.
 */
OSSL_DEPRECATEDIN_3_0
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
#endif
/**
 * @brief Return the cipher-specific "num" field of a cipher context.
 * @param ctx Cipher context to query.
 * @return Current num value (often how much of the current block has been used).
 */
int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_num EVP_CIPHER_CTX_get_num
/**
 * @brief Set the partial-block offset counter stored in a cipher context.
 * @param ctx Cipher context to update.
 * @param num New offset value used by some cipher modes for leftover bytes.
 * @return 1 on success.
 */
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
/**
 * @brief Duplicate a cipher context, including its algorithm state.
 * @param in Context to copy.
 * @return Newly allocated copy, or NULL on error; free with EVP_CIPHER_CTX_free.
 */
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);
/**
 * @brief Copy the cipher state from one context into another.
 * @param out Destination context; must already be allocated and is reset as needed.
 * @param in Source context whose algorithm state is duplicated.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
/**
 * @brief Return the application-specific pointer previously stored on a cipher context.
 * @param ctx Cipher context to query.
 * @return Opaque pointer from EVP_CIPHER_CTX_set_app_data(), or NULL if unset.
 */
void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Store an application pointer on a cipher context.
 * @param ctx Cipher context.
 * @param data Opaque pointer retained until overwritten or the context is freed.
 */
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
/**
 * @brief Return the cipher-implementation private data pointer for @p ctx.
 * @param ctx Cipher context.
 * @return Implementation-specific data pointer, or NULL if unset.
 */
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
/**
 * @brief Replace the cipher-implementation private data pointer on @p ctx.
 * @param ctx Cipher context.
 * @param cipher_data New implementation data pointer (ownership remains with the caller/impl).
 * @return The previous cipher-data pointer.
 */
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
#define EVP_CIPHER_CTX_get0_name(c) EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c))
#define EVP_CIPHER_CTX_get_type(c) EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))
#define EVP_CIPHER_CTX_type EVP_CIPHER_CTX_get_type
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define EVP_CIPHER_CTX_flags(c) EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c))
#endif
#define EVP_CIPHER_CTX_get_mode(c) EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))
#define EVP_CIPHER_CTX_mode EVP_CIPHER_CTX_get_mode

#define EVP_ENCODE_LENGTH(l) ((((l) + 2) / 3 * 4) + ((l) / 48 + 1) * 2 + 80)
#define EVP_DECODE_LENGTH(l) (((l) + 3) / 4 * 3 + 80)

#define EVP_SignInit_ex(a, b, c) EVP_DigestInit_ex(a, b, c)
#define EVP_SignInit(a, b) EVP_DigestInit(a, b)
#define EVP_SignUpdate(a, b, c) EVP_DigestUpdate(a, b, c)
#define EVP_VerifyInit_ex(a, b, c) EVP_DigestInit_ex(a, b, c)
#define EVP_VerifyInit(a, b) EVP_DigestInit(a, b)
#define EVP_VerifyUpdate(a, b, c) EVP_DigestUpdate(a, b, c)
#define EVP_OpenUpdate(a, b, c, d, e) EVP_DecryptUpdate(a, b, c, d, e)
#define EVP_SealUpdate(a, b, c, d, e) EVP_EncryptUpdate(a, b, c, d, e)

#ifdef CONST_STRICT
void BIO_set_md(BIO *, const EVP_MD *md);
#else
#define BIO_set_md(b, md) BIO_ctrl(b, BIO_C_SET_MD, 0, (void *)(md))
#endif
#define BIO_get_md(b, mdp) BIO_ctrl(b, BIO_C_GET_MD, 0, (mdp))
#define BIO_get_md_ctx(b, mdcp) BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, (mdcp))
#define BIO_set_md_ctx(b, mdcp) BIO_ctrl(b, BIO_C_SET_MD_CTX, 0, (mdcp))
#define BIO_get_cipher_status(b) BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, NULL)
#define BIO_get_cipher_ctx(b, c_pp) BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, (c_pp))

/**
 * @brief Encrypt or decrypt up to @p inl bytes from @p in into @p out (legacy one-shot).
 * @param c Cipher context already initialized for encrypt or decrypt.
 * @param out Output buffer for the transformed bytes.
 * @param in Input bytes to process.
 * @param inl Number of input bytes; for legacy ciphers without EVP_CIPH_FLAG_CUSTOM_CIPHER must be a multiple of the block size.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_CipherUpdate() and EVP_CipherFinal_ex() for new code.
 */
__owur int EVP_Cipher(EVP_CIPHER_CTX *c,
    unsigned char *out,
    const unsigned char *in, unsigned int inl);

#define EVP_add_cipher_alias(n, alias) \
    OBJ_NAME_add((alias), OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS, (n))
#define EVP_add_digest_alias(n, alias) \
    OBJ_NAME_add((alias), OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, (n))
#define EVP_delete_cipher_alias(alias) \
    OBJ_NAME_remove(alias, OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS);
#define EVP_delete_digest_alias(alias) \
    OBJ_NAME_remove(alias, OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS);

/**
 * @brief Fetch gettable algorithm parameters from a message-digest method.
 * @param digest Digest method to query.
 * @param params Array of OSSL_PARAM descriptors to fill; terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[]);
/**
 * @brief Set algorithm parameters on a digest context via an OSSL_PARAM array.
 * @param ctx Digest context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Retrieve algorithm parameters from a digest context into @p params.
 * @param ctx Digest context to query.
 * @param params OSSL_PARAM array describing the values to fetch (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Describe the parameters that can be read from a message-digest method.
 * @param digest Digest method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL on error.
 */
const OSSL_PARAM *EVP_MD_gettable_params(const EVP_MD *digest);
/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on an MD context.
 * @param md Digest method whose settable context parameters are listed.
 * @return NULL-terminated OSSL_PARAM array, or NULL if none are available.
 */
const OSSL_PARAM *EVP_MD_settable_ctx_params(const EVP_MD *md);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_MD context.
 * @param md Digest algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MD_gettable_ctx_params(const EVP_MD *md);
/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on a digest context.
 * @param ctx Digest context whose provider implementation is queried.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx);
/**
 * @brief Describe OSSL_PARAM keys that can be retrieved from digest context @p ctx.
 * @param ctx Digest context whose gettable parameters are queried.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx);
/**
 * @brief Send a legacy control request to a digest context.
 * @param ctx Digest context to control.
 * @param cmd Control command (algorithm-specific).
 * @param p1 Integer control argument.
 * @param p2 Pointer control argument, or NULL.
 * @return 1 on success, or a command-specific status / 0 on failure.
 */
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
/**
 * @brief Allocate a new digest context.
 * @return New EVP_MD_CTX, or NULL on allocation failure; free with EVP_MD_CTX_free().
 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
/**
 * @brief Reset @p ctx so it can be reused with EVP_DigestInit_ex() without freeing it.
 * @param ctx Digest context to clear.
 * @return 1 on success, or 0 on error.
 */
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
/**
 * @brief Free a digest context and release its resources.
 * @param ctx Context to free, or NULL.
 */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
#define EVP_MD_CTX_create() EVP_MD_CTX_new()
#define EVP_MD_CTX_init(ctx) EVP_MD_CTX_reset((ctx))
#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
/**
 * @brief Duplicate a digest context, including algorithm state and any associated key material.
 * @param in Source context to copy.
 * @return Newly allocated copy, or NULL on failure.
 */
__owur EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in);
/**
 * @brief Copy digest context state from @p in into an already allocated @p out.
 * @param out Destination context (must be initialised); previous state is replaced.
 * @param in Source context to copy, including algorithm state and associated key material.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
/**
 * @brief Set flag bits on a digest context without clearing existing flags.
 * @param ctx Digest context to update.
 * @param flags Bitmask of EVP_MD_CTX_* flags to set.
 */
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
/**
 * @brief Clear flag bits on a digest context.
 * @param ctx Digest context to update.
 * @param flags Bitmask of EVP_MD_CTX_* flags to clear.
 */
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
/**
 * @brief Test whether the given flag bits are set on a digest context.
 * @param ctx Digest context to query.
 * @param flags EVP_MD_CTX_* flag mask to test.
 * @return Bitwise AND of the context flags with @p flags.
 */
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);
/**
 * @brief Initialize a digest context with @p type and optional algorithm parameters.
 * @param ctx Digest context to (re)initialize; must have been created with EVP_MD_CTX_new().
 * @param type Digest algorithm, or NULL to reuse the algorithm already associated with @p ctx.
 * @param params Optional OSSL_PARAM array applied to the digest (terminated by OSSL_PARAM_END), or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type,
    const OSSL_PARAM params[]);
/**
 * @brief Initialise digest context @p ctx for algorithm @p type.
 * @param ctx Digest context to initialise (from EVP_MD_CTX_new()).
 * @param type Digest algorithm (for example from EVP_sha256()), or NULL to reuse the previous type.
 * @param impl Legacy ENGINE implementing @p type, or NULL for the default implementation.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
    ENGINE *impl);
/**
 * @brief Hash more input bytes into an initialized message-digest context.
 * @param ctx Digest context previously set up with EVP_DigestInit_ex() or similar.
 * @param d Bytes to absorb.
 * @param cnt Number of bytes at @p d.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
    size_t cnt);
/**
 * @brief Finalize a digest computation and write the message digest to @p md without resetting ownership of @p ctx.
 * @param ctx Digest context that has absorbed input via EVP_DigestUpdate().
 * @param md Buffer that receives the digest; must be large enough for EVP_MD_CTX_get_size(@p ctx) bytes.
 * @param s Optional destination for the digest length in bytes, or NULL.
 * @return 1 on success, or 0 on failure.
 *
 * Unlike EVP_DigestFinal(), the context may be reused after EVP_MD_CTX_reset() without freeing it.
 */
__owur int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
    unsigned int *s);
/**
 * @brief Hash @p count bytes at @p data in one shot and write the digest to @p md.
 * @param data Input bytes to hash.
 * @param count Number of bytes at @p data.
 * @param md Output buffer for the digest; at most EVP_MAX_MD_SIZE bytes are written.
 * @param size Optional destination for the digest length in bytes, or NULL.
 * @param type Digest algorithm to use.
 * @param impl Optional ENGINE providing @p type, or NULL for the default implementation.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_Digest(const void *data, size_t count,
    unsigned char *md, unsigned int *size,
    const EVP_MD *type, ENGINE *impl);
/**
 * @brief One-shot digest of @p data using a fetched algorithm name.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param name Digest algorithm name (for example "SHA256").
 * @param propq Property query for the fetch, or NULL.
 * @param data Bytes to hash.
 * @param datalen Number of bytes at @p data.
 * @param md Output buffer for the digest (at least the algorithm size).
 * @param mdlen Optional in/out length of @p md; updated to the digest size.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name,
    const char *propq, const void *data, size_t datalen,
    unsigned char *md, size_t *mdlen);

/**
 * @brief Copy a digest context into a freshly allocated destination (legacy helper).
 * @param out Destination context; must not already hold digest state (prefer EVP_MD_CTX_copy_ex).
 * @param in Source context to duplicate.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
/**
 * @brief Initialize a digest context for hashing with @p type (legacy ENGINE-aware form).
 * @param ctx Digest context to initialize.
 * @param type Digest method to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_DigestInit_ex2() for new code.
 */
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
/**
 * @brief Finalize a digest computation and write the message digest.
 * @param ctx Digest context that has been updated with message data.
 * @param md Output buffer of at least EVP_MD_size bytes receiving the digest.
 * @param s Optional pointer receiving the digest length in bytes, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
    unsigned int *s);
/**
 * @brief Finalize an XOF digest and write @p outlen bytes of output.
 * @param ctx Digest context after EVP_DigestUpdate() (for example SHAKE).
 * @param out Buffer that receives @p outlen bytes of XOF output.
 * @param outlen Number of output bytes to produce.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);
/**
 * @brief Squeeze additional output from an XOF digest context (for example SHAKE).
 * @param ctx Digest context after EVP_DigestFinalXOF() / absorb phase as required by the algorithm.
 * @param out Buffer that receives @p outlen bytes of XOF output.
 * @param outlen Number of bytes to squeeze.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);

/**
 * @brief Fetch a digest implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Digest algorithm name (for example "SHA256").
 * @param properties Optional property query string, or NULL.
 * @return Fetched EVP_MD (free with EVP_MD_free()), or NULL on failure.
 */
__owur EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);

/**
 * @brief Increment the reference count on a fetched EVP_MD.
 * @param md Digest method whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_up_ref(EVP_MD *md);
/**
 * @brief Free a fetched EVP_MD (decrement its reference count).
 * @param md Digest method from EVP_MD_fetch(), or NULL.
 */
void EVP_MD_free(EVP_MD *md);

/**
 * @brief Prompt on the terminal for a password into @p buf.
 * @param buf Destination buffer receiving the password (NUL-terminated).
 * @param length Capacity of @p buf in bytes including the NUL terminator.
 * @param prompt Prompt string shown to the user, or NULL for the default.
 * @param verify Nonzero to ask twice and require matching input.
 * @return 0 on success, a negative value on mismatch/cancel, or a positive UI error code.
 */
int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
/**
 * @brief Prompt for a password with a minimum and maximum length.
 * @param buf Output buffer receiving the password (NUL-terminated).
 * @param minlen Minimum acceptable password length in characters.
 * @param maxlen Maximum length including space for the trailing NUL.
 * @param prompt Prompt string shown to the user.
 * @param verify When non-zero, prompt twice and require matching input.
 * @return 0 on success, or a non-zero value on failure / mismatch.
 */
int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
    const char *prompt, int verify);
/**
 * @brief Set the default password prompt string used by EVP password helpers.
 * @param prompt NUL-terminated prompt text copied into an internal buffer, or NULL to clear.
 */
void EVP_set_pw_prompt(const char *prompt);
/**
 * @brief Return the process-wide default password prompt string.
 * @return Pointer to the current prompt (do not free), never NULL after library init.
 */
char *EVP_get_pw_prompt(void);

/**
 * @brief Derive a cipher key and IV from a password using the legacy EVP_BytesToKey KDF.
 * @param type Cipher whose key and IV lengths determine the output sizes.
 * @param md Digest used in the iterative key derivation (commonly EVP_md5()).
 * @param salt Optional 8-byte salt, or NULL.
 * @param data Password / passphrase bytes.
 * @param datal Length of @p data in bytes.
 * @param count Iteration count (higher slows brute-force attacks).
 * @param key Output buffer for the derived key, or NULL to skip.
 * @param iv Output buffer for the derived IV, or NULL to skip.
 * @return Length of the derived key in bytes, or 0 on error.
 */
__owur int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
    const unsigned char *salt,
    const unsigned char *data, int datal, int count,
    unsigned char *key, unsigned char *iv);

/**
 * @brief Set flag bits on a cipher context without clearing existing flags.
 * @param ctx Cipher context to update.
 * @param flags Bitmask of EVP_CIPH_* context flags to set.
 */
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
/**
 * @brief Clear selected flag bits on a cipher context.
 * @param ctx Cipher context to update.
 * @param flags Bitmask of EVP_CIPHER_CTX flag bits to clear (for example EVP_CIPH_NO_PADDING).
 */
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
/**
 * @brief Test whether selected flag bits are set on a cipher context.
 * @param ctx Cipher context to query.
 * @param flags Bitmask of EVP_CIPHER_CTX flag bits to test (for example EVP_CIPH_NO_PADDING).
 * @return Bitwise AND of @p flags with the context's flags (non-zero if any tested bit is set).
 */
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags);

/**
 * @brief Initialize @p ctx for encryption with @p cipher, @p key, and @p iv.
 * @param ctx Cipher context to initialize (must already be allocated).
 * @param cipher Cipher algorithm, or NULL to reuse the previous cipher while setting a new key/IV.
 * @param key Encryption key bytes, or NULL to set the cipher without a key yet.
 * @param iv Initialization vector, or NULL when the cipher does not use an IV or the IV is set later.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv);
/**
 * @brief Initialize @p ctx for encryption with an optional ENGINE implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param impl Optional ENGINE providing the implementation, or NULL.
 * @param key Encryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);
/**
 * @brief Initialize a cipher context for encryption with optional OSSL_PARAM settings.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the previous cipher.
 * @param key Encryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when the cipher does not need one yet.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key,
    const unsigned char *iv,
    const OSSL_PARAM params[]);
/**
 * @brief Encrypt @p inl bytes from @p in and write ciphertext to @p out.
 * @param ctx Cipher context previously set up for encryption.
 * @param out Output buffer for encrypted bytes (may equal @p in for in-place encryption when block-aligned).
 * @param outl Receives the number of bytes written to @p out.
 * @param in Plaintext input bytes.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);
/**
 * @brief Finalize encryption and write any remaining ciphertext (including padding).
 * @param ctx Cipher context previously used with EVP_EncryptUpdate().
 * @param out Buffer receiving final ciphertext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);
/**
 * @brief Finish encryption and write any remaining padded ciphertext bytes.
 * @param ctx Cipher context previously used with EVP_EncryptUpdate().
 * @param out Buffer receiving the final ciphertext block(s).
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);

/**
 * @brief Initialize a cipher context for decryption (legacy ENGINE-aware form).
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm to use.
 * @param key Decryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not yet required.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_DecryptInit_ex2() for new code.
 */
__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv);
/**
 * @brief Initialize @p ctx for decryption with an optional ENGINE implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param impl Optional ENGINE providing the implementation, or NULL.
 * @param key Decryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);
/**
 * @brief Initialize @p ctx for decryption with @p cipher, @p key, @p iv, and optional parameters.
 * @param ctx Cipher context to (re)initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the algorithm already associated with @p ctx.
 * @param key Decryption key bytes, or NULL to set the cipher without a key yet.
 * @param iv Initialization vector, or NULL when unused or set later.
 * @param params Optional OSSL_PARAM array applied after initialization, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DecryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key,
    const unsigned char *iv,
    const OSSL_PARAM params[]);
/**
 * @brief Decrypt a chunk of ciphertext into @p out, updating the cipher context.
 * @param ctx Cipher context initialized for decryption.
 * @param out Output buffer for plaintext (may be NULL to pass AAD for AEAD ciphers).
 * @param outl Receives the number of plaintext bytes written.
 * @param in Ciphertext (or AAD) bytes to process.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);
/**
 * @brief Finish decryption and write any remaining plaintext (legacy wrapper).
 * @param ctx Decryption context previously updated with EVP_DecryptUpdate.
 * @param outm Buffer receiving the final plaintext block(s).
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, 0 on padding/authentication failure, or a negative value on error.
 */
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);
/**
 * @brief Finalize decryption and write any remaining plaintext (including padding removal).
 * @param ctx Cipher context previously used with EVP_DecryptUpdate().
 * @param outm Buffer receiving final plaintext bytes (may need a full block of space).
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure (for example padding errors).
 */
__owur int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);

/**
 * @brief Initialize @p ctx for encryption or decryption using the default implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param key Key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc);
/**
 * @brief Initialise @p ctx for encryption or decryption with @p cipher.
 * @param ctx Cipher context to initialise.
 * @param cipher Cipher algorithm, or NULL to keep the current cipher and change key/IV/dir.
 * @param impl Legacy ENGINE, or NULL for the default implementation.
 * @param key Raw key bytes, or NULL to set later.
 * @param iv IV/nonce bytes, or NULL when not required / set later.
 * @param enc 1 to encrypt, 0 to decrypt, or -1 to leave the direction unchanged.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv, int enc);
/**
 * @brief Initialise a cipher context with optional OSSL_PARAM settings.
 * @param ctx Cipher context to initialise.
 * @param cipher Cipher algorithm, or NULL to reuse the one already in @p ctx.
 * @param key Key bytes, or NULL to set later.
 * @param iv IV/nonce bytes, or NULL when not yet available / not required.
 * @param enc 1 to encrypt, 0 to decrypt, or -1 to leave the prior direction.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc, const OSSL_PARAM params[]);
/**
 * @brief Encrypt or decrypt a chunk of data using a cipher context already set for either direction.
 * @param ctx Cipher context initialized for encryption or decryption.
 * @param out Output buffer for ciphertext or plaintext.
 * @param outl Receives the number of bytes written to @p out.
 * @param in Input bytes to process.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);
/**
 * @brief Finalize a cipher operation and write any remaining output bytes.
 * @param ctx Cipher context previously used with EVP_CipherUpdate().
 * @param outm Buffer receiving final output bytes.
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);
/**
 * @brief Finalize a cipher operation (extended form) and write any remaining output.
 * @param ctx Cipher context previously used with EVP_CipherUpdate().
 * @param outm Buffer receiving final output bytes.
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);

/**
 * @brief Finish a legacy Sign operation and write the signature using @p pkey.
 * @param ctx Digest/sign context that has absorbed the message via EVP_DigestUpdate().
 * @param md Output buffer for the signature.
 * @param s Receives the signature length in bytes.
 * @param pkey Private key used to produce the signature.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey);
/**
 * @brief Finish a legacy Sign operation with an explicit library context and property query.
 * @param ctx Digest/sign context that has absorbed the message via EVP_DigestUpdate().
 * @param md Output buffer for the signature.
 * @param s Receives the signature length in bytes.
 * @param pkey Private key used to produce the signature.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *propq);

/**
 * @brief Sign @p tbs in one call using a prepared DigestSign context.
 * @param ctx Context initialized with EVP_DigestSignInit().
 * @param sigret Output buffer for the signature, or NULL to query the required length.
 * @param siglen On input, size of @p sigret; on output, signature length.
 * @param tbs Message bytes to sign ("to be signed").
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen, const unsigned char *tbs,
    size_t tbslen);

/**
 * @brief Finish a verify operation by checking @p sigbuf against the digested data.
 * @param ctx Digest/verify context that has absorbed the message via EVP_DigestUpdate().
 * @param sigbuf Signature bytes to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param pkey Public key used for verification.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
    unsigned int siglen, EVP_PKEY *pkey);
/**
 * @brief Verify a signature against the digest accumulated in @p ctx using @p pkey.
 * @param ctx Digest/verify context that has absorbed message data.
 * @param sigbuf Signature bytes to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param pkey Public key used for verification.
 * @param libctx Library context used when creating a context for @p pkey, or NULL for the default.
 * @param propq Property query string for provider selection, or NULL.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
__owur int EVP_VerifyFinal_ex(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
    unsigned int siglen, EVP_PKEY *pkey,
    OSSL_LIB_CTX *libctx, const char *propq);

/**
 * @brief Verify @p sigret over @p tbs in one call using a prepared DigestVerify context.
 * @param ctx Context initialized with EVP_DigestVerifyInit().
 * @param sigret Signature bytes to verify.
 * @param siglen Length of @p sigret in bytes.
 * @param tbs Message bytes that were signed ("to be signed").
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
    size_t siglen, const unsigned char *tbs,
    size_t tbslen);

/**
 * @brief Initialise a digest-sign operation using a digest name and library context.
 * @param ctx Message-digest context that will accumulate data to sign.
 * @param pctx Optional address receiving the EVP_PKEY_CTX used for signing, or NULL.
 * @param mdname Digest algorithm name (for example "SHA256"), or NULL for the key default.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param props Property query for algorithm fetches, or NULL.
 * @param pkey Private key used to create the signature.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);
/**
 * @brief Initialise @p ctx for a one-shot or streaming DigestSign with key @p pkey.
 * @param ctx Digest/sign context to initialise.
 * @param pctx Optional out-parameter receiving the internal EVP_PKEY_CTX, or NULL.
 * @param type Digest to use, or NULL for algorithms that do not take a separate MD.
 * @param e Legacy ENGINE, or NULL.
 * @param pkey Private key used for signing.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
/**
 * @brief Hash more message bytes into an initialized DigestSign context.
 * @param ctx Signing context from EVP_DigestSignInit() or EVP_DigestSignInit_ex().
 * @param data Bytes to absorb into the signature hash.
 * @param dsize Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t dsize);
/**
 * @brief Finalize a DigestSign operation and write the signature.
 * @param ctx Context initialized with EVP_DigestSignInit and updated with EVP_DigestSignUpdate.
 * @param sigret Buffer receiving the signature, or NULL to only query the required length.
 * @param siglen On entry, size of @p sigret; on exit, signature length (or required size).
 * @return 1 on success, or 0 / a negative value on error.
 */
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen);

/**
 * @brief Initialize a digest-verify operation with an explicit digest name and library context.
 * @param ctx Digest context to initialize for verification.
 * @param pctx Optional receiver for the internal EVP_PKEY_CTX, or NULL.
 * @param mdname Digest algorithm name (for example "SHA256"), or NULL to use the key default.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param props Property query string for fetches, or NULL.
 * @param pkey Public key used to verify the signature.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);
/**
 * @brief Initialise @p ctx for a DigestVerify operation with public key @p pkey.
 * @param ctx Digest/verify context to initialise.
 * @param pctx Optional out-parameter receiving the internal EVP_PKEY_CTX, or NULL.
 * @param type Digest to use, or NULL for algorithms that do not take a separate MD.
 * @param e Legacy ENGINE, or NULL.
 * @param pkey Public key used for verification.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
/**
 * @brief Hash more message bytes into an initialized DigestVerify context.
 * @param ctx Verification context from EVP_DigestVerifyInit() or EVP_DigestVerifyInit_ex().
 * @param data Bytes to absorb into the verification hash.
 * @param dsize Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t dsize);
/**
 * @brief Finish a DigestVerify operation by checking @p sig against the digested data.
 * @param ctx Context initialized with EVP_DigestVerifyInit() and updated with the message.
 * @param sig Signature bytes to verify.
 * @param siglen Length of @p sig in bytes.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
    size_t siglen);

/**
 * @brief Initialize envelope decryption: unwrap @p ek with @p priv and set up @p type.
 * @param ctx Cipher context to initialize for decryption.
 * @param type Content-encryption cipher, or NULL to defer until a later call.
 * @param ek Encrypted content-encryption key.
 * @param ekl Length of @p ek in bytes.
 * @param iv IV for @p type, or NULL if not required yet.
 * @param priv Recipient private key used to decrypt @p ek.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    const unsigned char *ek, int ekl,
    const unsigned char *iv, EVP_PKEY *priv);
/**
 * @brief Finalize an open (envelope decrypt) operation and write any remaining plaintext.
 * @param ctx Cipher context initialized with EVP_OpenInit().
 * @param out Buffer receiving final plaintext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

/**
 * @brief Initialize a seal (envelope encrypt) operation for @p npubk recipients.
 * @param ctx Cipher context that will encrypt the content with a generated session key.
 * @param type Symmetric cipher used for the content.
 * @param ek Array of buffers receiving per-recipient encrypted session keys.
 * @param ekl Array receiving the encrypted-key lengths written to @p ek.
 * @param iv Buffer receiving the generated IV (sized for @p type), or NULL if unused.
 * @param pubk Array of recipient public keys used to wrap the session key.
 * @param npubk Number of entries in @p pubk / @p ek / @p ekl.
 * @return Number of recipients successfully processed, or 0 on failure.
 */
__owur int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    unsigned char **ek, int *ekl, unsigned char *iv,
    EVP_PKEY **pubk, int npubk);
/**
 * @brief Finalize a seal (envelope encrypt) operation and write any remaining ciphertext.
 * @param ctx Cipher context initialized with EVP_SealInit().
 * @param out Buffer receiving final ciphertext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

/**
 * @brief Allocate a new Base64 encode/decode context.
 * @return New EVP_ENCODE_CTX, or NULL on allocation failure.
 */
EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void);
/**
 * @brief Free a Base64 encode/decode context.
 * @param ctx Context to free, or NULL.
 */
void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);
/**
 * @brief Copy a Base64 encode/decode context.
 * @param dctx Destination context (must already be allocated).
 * @param sctx Source context to copy from.
 * @return 1 on success, or 0 on failure.
 */
int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx);
/**
 * @brief Return the number of pending (unflushed) bytes in an encode/decode context.
 * @param ctx Encode/decode context to query.
 * @return Number of buffered input bytes awaiting encoding or decoding.
 */
int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);
/**
 * @brief Initialise a Base64 encode context for EVP_EncodeUpdate/Final.
 * @param ctx Encode context (typically from EVP_ENCODE_CTX_new()).
 */
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
/**
 * @brief Base64-encode a chunk of input, writing complete output lines to @p out.
 * @param ctx Encode context initialized with EVP_EncodeInit().
 * @param out Buffer receiving encoded output (may be empty if data was only buffered).
 * @param outl Receives the number of bytes written to @p out.
 * @param in Input octets to encode.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
/**
 * @brief Flush remaining Base64-encoded output from an encode context.
 * @param ctx Encode context previously used with EVP_EncodeUpdate().
 * @param out Buffer receiving the final encoded bytes (and trailing newline when applicable).
 * @param outl Receives the number of bytes written to @p out.
 */
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
/**
 * @brief Base64-encode @p n bytes from @p f into @p t as a single block (with NUL terminator).
 * @param t Destination buffer (at least ((n+2)/3)*4 + 1 bytes).
 * @param f Input octets to encode.
 * @param n Number of input bytes.
 * @return Number of Base64 characters written, not counting the trailing NUL.
 */
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

/**
 * @brief Initialize a context for incremental Base64 decoding.
 * @param ctx Encode/decode context previously allocated with EVP_ENCODE_CTX_new().
 */
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
/**
 * @brief Decode a chunk of Base64 input into @p out, updating the decode context.
 * @param ctx Decode context previously initialized with EVP_DecodeInit().
 * @param out Buffer receiving decoded octets for this chunk.
 * @param outl Receives the number of bytes written to @p out.
 * @param in Base64 input characters for this update.
 * @param inl Number of bytes in @p in.
 * @return 1 if more data may follow, 0 if an EOF marker was seen, or -1 on error.
 */
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
/**
 * @brief Finish a Base64 decode, flushing any remaining decoded bytes.
 * @param ctx Decode context previously used with EVP_DecodeUpdate().
 * @param out Buffer receiving final decoded bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or a negative value on decode error.
 */
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
/**
 * @brief Base64-decode @p n characters from @p f into @p t as a single block.
 * @param t Destination buffer for decoded octets.
 * @param f Base64 input characters (whitespace should already be removed for legacy behaviour).
 * @param n Number of input characters; should be a multiple of four.
 * @return Number of decoded bytes written, or -1 on error.
 */
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define EVP_CIPHER_CTX_init(c) EVP_CIPHER_CTX_reset(c)
#define EVP_CIPHER_CTX_cleanup(c) EVP_CIPHER_CTX_reset(c)
#endif
/**
 * @brief Allocate an empty cipher context.
 * @return New EVP_CIPHER_CTX, or NULL on allocation failure.
 */
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
/**
 * @brief Reset a cipher context to a reusable empty state without freeing it.
 * @param c Context to clear; may be reused with EVP_EncryptInit_ex / EVP_DecryptInit_ex afterward.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
/**
 * @brief Free a cipher context and any associated resources.
 * @param c Context to free; NULL is ignored.
 */
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
/**
 * @brief Set a variable-length cipher's key length on a cipher context.
 * @param x Cipher context whose cipher supports variable key lengths.
 * @param keylen Desired key length in bytes.
 * @return 1 on success, or 0 if the length is unsupported.
 */
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
/**
 * @brief Enable or disable standard block-cipher padding on a cipher context.
 * @param c Cipher context to update.
 * @param pad Nonzero to enable PKCS-style padding; zero to disable.
 * @return 1 on success.
 */
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
/**
 * @brief Send a cipher-specific control request to an EVP_CIPHER_CTX.
 * @param ctx Cipher context to control.
 * @param type EVP_CTRL_* command code.
 * @param arg Integer argument for @p type.
 * @param ptr Pointer argument for @p type, or NULL.
 * @return 1 on success, <=0 on failure (command-specific).
 */
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
/**
 * @brief Generate a random key suitable for the cipher currently set on @p ctx.
 * @param ctx Cipher context whose algorithm determines the key length.
 * @param key Buffer receiving the generated key (at least EVP_CIPHER_CTX_get_key_length() bytes).
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
/**
 * @brief Retrieve algorithm-level parameters from a cipher implementation.
 * @param cipher Cipher method to query.
 * @param params OSSL_PARAM array describing the values to fetch.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[]);
/**
 * @brief Set provider parameters on an initialised cipher context.
 * @param ctx Cipher context.
 * @param params NULL-terminated OSSL_PARAM array of values to apply.
 * @return 1 on success, or 0 on error.
 */
int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Retrieve algorithm parameters from a cipher context into @p params.
 * @param ctx Cipher context to query.
 * @param params NULL-terminated OSSL_PARAM array of parameters to fill.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_CIPHER algorithm.
 * @param cipher Cipher algorithm whose gettable parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher);
/**
 * @brief Describe OSSL_PARAM keys that may be set on contexts of @p cipher.
 * @param cipher Cipher implementation to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher);
/**
 * @brief Describe OSSL_PARAM keys that may be retrieved from contexts of @p cipher.
 * @param cipher Cipher implementation to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher);
/**
 * @brief Return the OSSL_PARAM descriptors that may be set on an initialized cipher context.
 * @param ctx Cipher context to query.
 * @return Array of settable parameter descriptors terminated by OSSL_PARAM_construct_end(), or NULL.
 */
const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *ctx);
/**
 * @brief Describe OSSL_PARAM keys gettable from the cipher currently bound to @p ctx.
 * @param ctx Cipher context.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx);

/**
 * @brief Return the message-digest filter BIO method.
 * @return BIO_METHOD that digests data passed through it via EVP_Digest* routines.
 */
const BIO_METHOD *BIO_f_md(void);
/**
 * @brief Return the BIO filter method that Base64-encodes or decodes data.
 * @return Pointer to the Base64 BIO_METHOD for use with BIO_new().
 */
const BIO_METHOD *BIO_f_base64(void);
/**
 * @brief Return the filter BIO_METHOD that encrypts or decrypts data with an EVP_CIPHER.
 * @return Pointer to the cipher filter BIO method.
 */
const BIO_METHOD *BIO_f_cipher(void);
/**
 * @brief Return the BIO filter method that adds a digest-protected reliable stream.
 * @return Pointer to the BIO_f_reliable method.
 *
 * Writes are checksummed so a reader can detect truncation or corruption.
 */
const BIO_METHOD *BIO_f_reliable(void);
/**
 * @brief Configure a cipher filter BIO with algorithm, key, IV, and encrypt/decrypt mode.
 * @param b BIO created with BIO_f_cipher().
 * @param c Cipher algorithm to use.
 * @param k Key bytes whose length matches the cipher's key length.
 * @param i IV bytes whose length matches the cipher's IV length (may be NULL for ECB).
 * @param enc 1 to encrypt, or 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 */
__owur int BIO_set_cipher(BIO *b, const EVP_CIPHER *c, const unsigned char *k,
    const unsigned char *i, int enc);

/**
 * @brief Return the null digest method (zero-length digest, for testing/legacy use).
 * @return Pointer to the static null EVP_MD.
 */
const EVP_MD *EVP_md_null(void);
#ifndef OPENSSL_NO_MD2
const EVP_MD *EVP_md2(void);
#endif
#ifndef OPENSSL_NO_MD4
/**
 * @brief Return the MD4 digest method (128-bit output; legacy provider).
 * @return EVP_MD for MD4, or NULL if unavailable.
 */
const EVP_MD *EVP_md4(void);
#endif
#ifndef OPENSSL_NO_MD5
/**
 * @brief Return the MD5 digest method (128-bit output).
 * @return Pointer to the static MD5 EVP_MD.
 */
const EVP_MD *EVP_md5(void);
/**
 * @brief Return the EVP_MD for the combined MD5-SHA-1 digest used by TLS 1.0/1.1.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_md5_sha1(void);
#endif
#ifndef OPENSSL_NO_BLAKE2
/**
 * @brief Return the EVP_MD for BLAKE2b-512.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_blake2b512(void);
/**
 * @brief Return the EVP_MD for BLAKE2s-256.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_blake2s256(void);
#endif
/**
 * @brief Return the SHA-1 digest method (160-bit output).
 * @return Pointer to the static SHA-1 EVP_MD.
 */
const EVP_MD *EVP_sha1(void);
/**
 * @brief Return the SHA-224 digest method (224-bit output).
 * @return EVP_MD for SHA-224, or NULL if unavailable.
 */
const EVP_MD *EVP_sha224(void);
/**
 * @brief Return the SHA-256 digest method (256-bit output).
 * @return EVP_MD for SHA-256, or NULL if unavailable.
 */
const EVP_MD *EVP_sha256(void);
/**
 * @brief Return the EVP_MD for SHA-384.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_sha384(void);
/**
 * @brief Return the SHA-512 digest method (512-bit output).
 * @return EVP_MD for SHA-512, or NULL if unavailable.
 */
const EVP_MD *EVP_sha512(void);
/**
 * @brief Return the EVP_MD for SHA-512/224 (truncated SHA-512).
 * @return Built-in message digest method (do not free).
 */
const EVP_MD *EVP_sha512_224(void);
/**
 * @brief Return the EVP_MD for SHA-512/256.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_sha512_256(void);
/**
 * @brief Return the EVP_MD for SHA3-224.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_sha3_224(void);
/**
 * @brief Return the built-in SHA3-256 message-digest method.
 * @return Pointer to the SHA3-256 EVP_MD (do not free).
 */
const EVP_MD *EVP_sha3_256(void);
/**
 * @brief Return the EVP_MD for SHA3-384.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_sha3_384(void);
/**
 * @brief Return the SHA3-512 digest method (512-bit output).
 * @return EVP_MD for SHA3-512, or NULL if unavailable.
 */
const EVP_MD *EVP_sha3_512(void);
/**
 * @brief Return the EVP_MD for SHAKE128 (XOF).
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_shake128(void);
/**
 * @brief Return the SHAKE256 XOF digest method.
 * @return EVP_MD for shake256, or NULL if unavailable.
 */
const EVP_MD *EVP_shake256(void);

#ifndef OPENSSL_NO_MDC2
/**
 * @brief Return the EVP_MD for MDC2.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_mdc2(void);
#endif
#ifndef OPENSSL_NO_RMD160
/**
 * @brief Return the EVP_MD for RIPEMD-160.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_ripemd160(void);
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
/**
 * @brief Return the WHIRLPOOL digest method (512-bit output; legacy provider).
 * @return EVP_MD for WHIRLPOOL, or NULL if unavailable.
 */
const EVP_MD *EVP_whirlpool(void);
#endif
#ifndef OPENSSL_NO_SM3
/**
 * @brief Return the EVP_MD for SM3.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *EVP_sm3(void);
#endif
/**
 * @brief Return the EVP_CIPHER for the null (pass-through) cipher.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_enc_null(void); /* does nothing :-) */
#ifndef OPENSSL_NO_DES
/**
 * @brief Return the EVP_CIPHER for DES in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ecb(void);
/**
 * @brief Return the EVP_CIPHER for two-key triple-DES in CBC mode (alias of EVP_des_ede_cbc).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede(void);
/**
 * @brief Return the EVP_CIPHER for triple-DES EDE with three keys in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3(void);
/**
 * @brief Return the EVP_CIPHER for two-key triple-DES in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede_ecb(void);
/**
 * @brief Return the EVP_CIPHER for three-key triple-DES in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3_ecb(void);
/**
 * @brief Return the EVP_CIPHER for DES in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_cfb64(void);
#define EVP_des_cfb EVP_des_cfb64
/**
 * @brief Return the EVP_CIPHER for DES in 1-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_cfb1(void);
/**
 * @brief Return the single-DES cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for des-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_cfb8(void);
/**
 * @brief Return the two-key triple-DES cipher in 64-bit CFB mode.
 * @return EVP_CIPHER for des-ede-cfb64, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_ede_cfb64(void);
#define EVP_des_ede_cfb EVP_des_ede_cfb64
/**
 * @brief Return the EVP_CIPHER for triple-DES EDE in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
#define EVP_des_ede3_cfb EVP_des_ede3_cfb64
/**
 * @brief Return the EVP_CIPHER for three-key triple-DES in 1-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
/**
 * @brief Return the EVP_CIPHER for three-key triple-DES in 8-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
/**
 * @brief Return the single-DES cipher in OFB mode.
 * @return EVP_CIPHER for des-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_ofb(void);
/**
 * @brief Return the two-key triple-DES cipher in OFB mode.
 * @return EVP_CIPHER for des-ede-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_ede_ofb(void);
/**
 * @brief Return the EVP_CIPHER for three-key triple-DES in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede3_ofb(void);
/**
 * @brief Return the EVP_CIPHER for DES in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_cbc(void);
/**
 * @brief Return the EVP_CIPHER for two-key triple-DES in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede_cbc(void);
/**
 * @brief Return the built-in Triple-DES (EDE3) CBC cipher method.
 * @return Pointer to the DES-EDE3-CBC EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_des_ede3_cbc(void);
/**
 * @brief Return the DES-X cipher in CBC mode.
 * @return EVP_CIPHER for desx-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_desx_cbc(void);
/**
 * @brief Return the Triple-DES key-wrap cipher (RFC 3217).
 * @return EVP_CIPHER for DES-EDE3-WRAP, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_ede3_wrap(void);
/*
 * This should now be supported through the dev_crypto ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
#endif
#ifndef OPENSSL_NO_RC4
/**
 * @brief Return the RC4 stream cipher.
 * @return EVP_CIPHER for rc4, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_rc4(void);
/**
 * @brief Return the EVP_CIPHER for RC4 with a 40-bit effective key (legacy).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_rc4_40(void);
#ifndef OPENSSL_NO_MD5
/**
 * @brief Return the EVP_CIPHER for the RC4-HMAC-MD5 AEAD suite (TLS legacy).
 * @return Built-in cipher method (do not free), or NULL if the algorithm is unavailable.
 */
const EVP_CIPHER *EVP_rc4_hmac_md5(void);
#endif
#endif
#ifndef OPENSSL_NO_IDEA
/**
 * @brief Return the EVP_CIPHER for IDEA in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_idea_ecb(void);
/**
 * @brief Return the EVP_CIPHER for IDEA in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_idea_cfb64(void);
#define EVP_idea_cfb EVP_idea_cfb64
/**
 * @brief Return the EVP_CIPHER for IDEA in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_idea_ofb(void);
/**
 * @brief Return the EVP_CIPHER for IDEA in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_idea_cbc(void);
#endif
#ifndef OPENSSL_NO_RC2
/**
 * @brief Return the EVP_CIPHER for RC2 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_rc2_ecb(void);
/**
 * @brief Return the RC2 cipher in CBC mode.
 * @return EVP_CIPHER for rc2-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_rc2_cbc(void);
/**
 * @brief Return the RC2 cipher in CBC mode with a 40-bit effective key.
 * @return EVP_CIPHER for rc2-40-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_rc2_40_cbc(void);
/**
 * @brief Return the EVP_CIPHER for RC2-64 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_rc2_64_cbc(void);
/**
 * @brief Return the RC2 cipher in 64-bit CFB mode.
 * @return EVP_CIPHER for rc2-cfb64, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_rc2_cfb64(void);
#define EVP_rc2_cfb EVP_rc2_cfb64
/**
 * @brief Return the EVP_CIPHER for RC2 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_rc2_ofb(void);
#endif
#ifndef OPENSSL_NO_BF
/**
 * @brief Return the Blowfish cipher in ECB mode.
 * @return EVP_CIPHER for bf-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_bf_ecb(void);
/**
 * @brief Return the Blowfish cipher in CBC mode.
 * @return EVP_CIPHER for bf-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_bf_cbc(void);
/**
 * @brief Return the EVP_CIPHER for Blowfish in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_bf_cfb64(void);
#define EVP_bf_cfb EVP_bf_cfb64
/**
 * @brief Return the Blowfish cipher in OFB mode.
 * @return EVP_CIPHER for bf-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_bf_ofb(void);
#endif
#ifndef OPENSSL_NO_CAST
/**
 * @brief Return the EVP_CIPHER for CAST5 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_cast5_ecb(void);
/**
 * @brief Return the CAST5 cipher in CBC mode.
 * @return EVP_CIPHER for cast5-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_cast5_cbc(void);
/**
 * @brief Return the EVP_CIPHER for CAST5 in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_cast5_cfb64(void);
#define EVP_cast5_cfb EVP_cast5_cfb64
/**
 * @brief Return the CAST5 cipher in OFB mode.
 * @return EVP_CIPHER for cast5-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_cast5_ofb(void);
#endif
#ifndef OPENSSL_NO_RC5
const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void);
#define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
#endif
/**
 * @brief Return the AES-128 cipher in ECB mode.
 * @return EVP_CIPHER for aes-128-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_128_ecb(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cbc(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in 1-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cfb1(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in 8-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cfb8(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cfb128(void);
#define EVP_aes_128_cfb EVP_aes_128_cfb128
/**
 * @brief Return the EVP_CIPHER for AES-128 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_ofb(void);
/**
 * @brief Return the AES-128 cipher in CTR mode.
 * @return EVP_CIPHER for aes-128-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_128_ctr(void);
/**
 * @brief Return the AES-128 cipher in CCM mode.
 * @return EVP_CIPHER for aes-128-ccm, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_128_ccm(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in GCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_gcm(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 in XTS mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_xts(void);
/**
 * @brief Return the EVP_CIPHER for AES-128 key wrap (RFC 3394).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_wrap(void);
/**
 * @brief Return the AES-128 cipher in key-wrap-with-padding mode (RFC 5649).
 * @return EVP_CIPHER for aes-128-wrap-pad, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_128_wrap_pad(void);
#ifndef OPENSSL_NO_OCB
/**
 * @brief Return the AES-128 cipher in OCB mode.
 * @return EVP_CIPHER for aes-128-ocb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_128_ocb(void);
#endif
/**
 * @brief Return the EVP_CIPHER for AES-192 in ECB mode.
 * @return EVP_CIPHER for AES-192-ECB, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_ecb(void);
/**
 * @brief Return the AES-192 cipher in CBC mode.
 * @return EVP_CIPHER for aes-192-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_cbc(void);
/**
 * @brief Return the AES-192 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aes-192-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_cfb1(void);
/**
 * @brief Return the AES-192 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for aes-192-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_cfb8(void);
/**
 * @brief Return the EVP_CIPHER for AES-192 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_192_cfb128(void);
#define EVP_aes_192_cfb EVP_aes_192_cfb128
/**
 * @brief Return the EVP_CIPHER for AES-192 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_192_ofb(void);
/**
 * @brief Return the AES-192 cipher in CTR mode.
 * @return EVP_CIPHER for aes-192-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_ctr(void);
/**
 * @brief Return the EVP_CIPHER for AES-192 in CCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_192_ccm(void);
/**
 * @brief Return the AES-192 cipher in GCM mode.
 * @return EVP_CIPHER for aes-192-gcm, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_gcm(void);
/**
 * @brief Return the AES-192 cipher in key-wrap mode (RFC 3394).
 * @return EVP_CIPHER for aes-192-wrap, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_wrap(void);
/**
 * @brief Return the AES-192 cipher in key-wrap-with-padding mode (RFC 5649).
 * @return EVP_CIPHER for aes-192-wrap-pad, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_wrap_pad(void);
#ifndef OPENSSL_NO_OCB
/**
 * @brief Return the built-in AES-192 OCB authenticated-encryption cipher method.
 * @return Pointer to the AES-192-OCB EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_aes_192_ocb(void);
#endif
/**
 * @brief Return the EVP_CIPHER for AES-256 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_ecb(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_cbc(void);
/**
 * @brief Return the AES-256 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aes-256-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_256_cfb1(void);
/**
 * @brief Return the AES-256 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for aes-256-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_256_cfb8(void);
/**
 * @brief Return the AES-256 cipher in 128-bit CFB mode.
 * @return EVP_CIPHER for aes-256-cfb128, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_256_cfb128(void);
#define EVP_aes_256_cfb EVP_aes_256_cfb128
/**
 * @brief Return the EVP_CIPHER for AES-256 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_ofb(void);
/**
 * @brief Return the AES-256 cipher in CTR mode.
 * @return EVP_CIPHER for aes-256-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_256_ctr(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 in CCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_ccm(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 in GCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_gcm(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 in XTS mode (IEEE 1619 / NIST SP 800-38E).
 * @return Pointer to the cipher method (expects a 512-bit key), or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_xts(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 key wrap (RFC 3394).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_wrap(void);
/**
 * @brief Return the EVP_CIPHER for AES-256 key wrap with padding (RFC 5649).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_wrap_pad(void);
#ifndef OPENSSL_NO_OCB
/**
 * @brief Return the EVP_CIPHER for AES-256 in OCB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_ocb(void);
#endif
/**
 * @brief Return the EVP_CIPHER for AES-128-CBC with HMAC-SHA1 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
/**
 * @brief Return the EVP_CIPHER for AES-256-CBC with HMAC-SHA1 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
/**
 * @brief Return the EVP_CIPHER for AES-128-CBC with HMAC-SHA256 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void);
/**
 * @brief Return the EVP_CIPHER for AES-256-CBC with HMAC-SHA256 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void);
#ifndef OPENSSL_NO_ARIA
/**
 * @brief Return the ARIA-128 cipher in ECB mode.
 * @return EVP_CIPHER for aria-128-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_ecb(void);
/**
 * @brief Return the built-in ARIA-128 CBC cipher method.
 * @return Pointer to the ARIA-128-CBC EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_aria_128_cbc(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-128 in 1-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_128_cfb1(void);
/**
 * @brief Return the ARIA-128 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for aria-128-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_cfb8(void);
/**
 * @brief Return the ARIA-128 cipher in 128-bit CFB mode.
 * @return EVP_CIPHER for aria-128-cfb128, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_cfb128(void);
#define EVP_aria_128_cfb EVP_aria_128_cfb128
/**
 * @brief Return the EVP_CIPHER for ARIA-128 in CTR mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_128_ctr(void);
/**
 * @brief Return the ARIA-128 cipher in OFB mode.
 * @return EVP_CIPHER for aria-128-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_ofb(void);
/**
 * @brief Return the ARIA-128 cipher in GCM mode.
 * @return EVP_CIPHER for aria-128-gcm, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_gcm(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-128 in CCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_128_ccm(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-192 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_ecb(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-192 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_cbc(void);
/**
 * @brief Return the ARIA-192 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aria-192-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_192_cfb1(void);
/**
 * @brief Return the ARIA-192 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for aria-192-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_192_cfb8(void);
/**
 * @brief Return the ARIA-192 cipher in 128-bit CFB mode.
 * @return EVP_CIPHER for aria-192-cfb128, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_192_cfb128(void);
#define EVP_aria_192_cfb EVP_aria_192_cfb128
/**
 * @brief Return the ARIA-192 cipher in CTR mode.
 * @return EVP_CIPHER for aria-192-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_192_ctr(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-192 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_ofb(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-192 in GCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_gcm(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-192 in CCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_ccm(void);
/**
 * @brief Return the ARIA-256 cipher in ECB mode.
 * @return EVP_CIPHER for aria-256-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_ecb(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-256 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_256_cbc(void);
/**
 * @brief Return the ARIA-256 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aria-256-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_cfb1(void);
/**
 * @brief Return the ARIA-256 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for aria-256-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_cfb8(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-256 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_256_cfb128(void);
#define EVP_aria_256_cfb EVP_aria_256_cfb128
/**
 * @brief Return the ARIA-256 cipher in CTR mode.
 * @return EVP_CIPHER for aria-256-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_ctr(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-256 in OFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_256_ofb(void);
/**
 * @brief Return the EVP_CIPHER for ARIA-256 in GCM mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_256_gcm(void);
/**
 * @brief Return the ARIA-256 cipher in CCM mode.
 * @return EVP_CIPHER for aria-256-ccm, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_ccm(void);
#endif
#ifndef OPENSSL_NO_CAMELLIA
/**
 * @brief Return the EVP_CIPHER for Camellia-128 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_128_ecb(void);
/**
 * @brief Return the Camellia-128 cipher in CBC mode.
 * @return EVP_CIPHER for camellia-128-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_128_cbc(void);
/**
 * @brief Return the Camellia-128 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for camellia-128-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_128_cfb1(void);
/**
 * @brief Return the Camellia-128 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for camellia-128-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_128_cfb8(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-128 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_128_cfb128(void);
#define EVP_camellia_128_cfb EVP_camellia_128_cfb128
/**
 * @brief Return the Camellia-128 cipher in OFB mode.
 * @return EVP_CIPHER for camellia-128-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_128_ofb(void);
/**
 * @brief Return the Camellia-128 cipher in CTR mode.
 * @return EVP_CIPHER for camellia-128-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_128_ctr(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-192 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_192_ecb(void);
/**
 * @brief Return the Camellia-192 cipher in CBC mode.
 * @return EVP_CIPHER for camellia-192-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_192_cbc(void);
/**
 * @brief Return the Camellia-192 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for camellia-192-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_192_cfb1(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-192 in 8-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_192_cfb8(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-192 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_192_cfb128(void);
#define EVP_camellia_192_cfb EVP_camellia_192_cfb128
/**
 * @brief Return the Camellia-192 cipher in OFB mode.
 * @return EVP_CIPHER for camellia-192-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_192_ofb(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-192 in CTR mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_192_ctr(void);
/**
 * @brief Return the Camellia-256 cipher in ECB mode.
 * @return EVP_CIPHER for camellia-256-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_ecb(void);
/**
 * @brief Return the Camellia-256 cipher in CBC mode.
 * @return EVP_CIPHER for camellia-256-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_cbc(void);
/**
 * @brief Return the Camellia-256 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for camellia-256-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_cfb1(void);
/**
 * @brief Return the Camellia-256 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for camellia-256-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
/**
 * @brief Return the Camellia-256 cipher in 128-bit CFB mode.
 * @return EVP_CIPHER for camellia-256-cfb128, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_cfb128(void);
#define EVP_camellia_256_cfb EVP_camellia_256_cfb128
/**
 * @brief Return the Camellia-256 cipher in OFB mode.
 * @return EVP_CIPHER for camellia-256-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_ofb(void);
/**
 * @brief Return the EVP_CIPHER for Camellia-256 in CTR mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_camellia_256_ctr(void);
#endif
#ifndef OPENSSL_NO_CHACHA
/**
 * @brief Return the ChaCha20 stream cipher.
 * @return EVP_CIPHER for chacha20, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_chacha20(void);
#ifndef OPENSSL_NO_POLY1305
/**
 * @brief Return the EVP_CIPHER for ChaCha20-Poly1305 AEAD.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_chacha20_poly1305(void);
#endif
#endif

#ifndef OPENSSL_NO_SEED
/**
 * @brief Return the SEED cipher in ECB mode.
 * @return EVP_CIPHER for seed-ecb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_seed_ecb(void);
/**
 * @brief Return the SEED cipher in CBC mode.
 * @return EVP_CIPHER for seed-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_seed_cbc(void);
/**
 * @brief Return the EVP_CIPHER for SEED in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_seed_cfb128(void);
#define EVP_seed_cfb EVP_seed_cfb128
/**
 * @brief Return the SEED cipher in OFB mode.
 * @return EVP_CIPHER for seed-ofb, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_seed_ofb(void);
#endif

#ifndef OPENSSL_NO_SM4
/**
 * @brief Return the EVP_CIPHER for SM4 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_sm4_ecb(void);
/**
 * @brief Return the EVP_CIPHER for SM4 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_sm4_cbc(void);
/**
 * @brief Return the EVP_CIPHER for SM4 in 128-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_sm4_cfb128(void);
#define EVP_sm4_cfb EVP_sm4_cfb128
/**
 * @brief Return the EVP_CIPHER for SM4 in OFB mode.
 * @return EVP_CIPHER for SM4-OFB, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_sm4_ofb(void);
/**
 * @brief Return the EVP_CIPHER for SM4 in CTR mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_sm4_ctr(void);
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define OPENSSL_add_all_algorithms_conf()            \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
            | OPENSSL_INIT_ADD_ALL_DIGESTS           \
            | OPENSSL_INIT_LOAD_CONFIG,              \
        NULL)
#define OPENSSL_add_all_algorithms_noconf()          \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
            | OPENSSL_INIT_ADD_ALL_DIGESTS,          \
        NULL)

#ifdef OPENSSL_LOAD_CONF
#define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_conf()
#else
#define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_noconf()
#endif

#define OpenSSL_add_all_ciphers() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#define OpenSSL_add_all_digests() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#define EVP_cleanup() \
    while (0)         \
    continue
#endif

/**
 * @brief Register @p cipher in the legacy EVP cipher name table.
 * @param cipher Cipher method to add (must remain valid for the process lifetime).
 * @return 1 on success, or 0 on failure.
 */
int EVP_add_cipher(const EVP_CIPHER *cipher);
/**
 * @brief Register @p digest in the legacy EVP digest name table.
 * @param digest Digest method to add (must remain valid for the process lifetime).
 * @return 1 on success, or 0 on failure.
 */
int EVP_add_digest(const EVP_MD *digest);

/**
 * @brief Look up a cipher algorithm by name (for example "AES-256-GCM").
 * @param name Cipher name or alias known to OpenSSL.
 * @return Matching EVP_CIPHER, or NULL if @p name is unknown.
 */
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
/**
 * @brief Look up a message digest algorithm by name (e.g. "SHA256").
 * @param name Digest name or alias known to OpenSSL.
 * @return Matching EVP_MD, or NULL if @p name is unknown.
 */
const EVP_MD *EVP_get_digestbyname(const char *name);

/**
 * @brief Invoke @p fn for every cipher name mapping in the legacy EVP cipher table.
 * @param fn Callback receiving the cipher method, from-name, to-name, and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph,
                           const char *from, const char *to, void *x),
    void *arg);
/**
 * @brief Invoke @p fn for every cipher name mapping, in sorted name order.
 * @param fn Callback receiving the cipher method, from-name, to-name, and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph, const char *from,
                                  const char *to, void *x),
    void *arg);
/**
 * @brief Invoke a callback for every cipher implementation available from providers.
 * @param libctx Library context whose providers are queried, or NULL for the default context.
 * @param fn Callback invoked once per EVP_CIPHER; must not free @p cipher.
 * @param arg Opaque pointer passed through to @p fn.
 */
void EVP_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_CIPHER *cipher, void *arg),
    void *arg);

/**
 * @brief Invoke a callback for every digest name in the legacy algorithm table.
 * @param fn Callback receiving the EVP_MD (may be NULL for aliases), the registered name, any alias target, and @p arg.
 * @param arg User pointer passed through to @p fn.
 */
void EVP_MD_do_all(void (*fn)(const EVP_MD *ciph,
                       const char *from, const char *to, void *x),
    void *arg);
/**
 * @brief Call @p fn for each built-in digest name, in sorted name order (legacy).
 * @param fn Callback receiving the digest method, canonical name, alias, and @p arg.
 * @param arg Opaque pointer forwarded to every @p fn invocation.
 */
void EVP_MD_do_all_sorted(void (*fn)(const EVP_MD *ciph, const char *from,
                              const char *to, void *x),
    void *arg);
/**
 * @brief Invoke a callback for every message digest provided in a library context.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each available EVP_MD and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_MD *md, void *arg),
    void *arg);

/* MAC stuff */

/**
 * @brief Fetch a MAC algorithm implementation from providers.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param algorithm MAC algorithm name (for example "HMAC" or "CMAC").
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_MAC (refcount 1), or NULL on error; free with EVP_MAC_free().
 */
EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);
/**
 * @brief Increment the reference count on a fetched EVP_MAC.
 * @param mac MAC algorithm from EVP_MAC_fetch().
 * @return 1 on success, or 0 on error.
 */
int EVP_MAC_up_ref(EVP_MAC *mac);
/**
 * @brief Release a reference to a fetched EVP_MAC.
 * @param mac MAC algorithm to free; NULL is ignored.
 */
void EVP_MAC_free(EVP_MAC *mac);
/**
 * @brief Return one algorithm name for a fetched MAC implementation.
 * @param mac MAC method to query.
 * @return Name string owned by OpenSSL; for multi-named MACs prefer EVP_MAC_names_do_all().
 */
const char *EVP_MAC_get0_name(const EVP_MAC *mac);
/**
 * @brief Return a human-readable description of a MAC algorithm.
 * @param mac MAC algorithm to query.
 * @return Internal description string (do not free), or NULL if none is provided.
 */
const char *EVP_MAC_get0_description(const EVP_MAC *mac);
/**
 * @brief Test whether a MAC implementation matches an algorithm name.
 * @param mac MAC method to query.
 * @param name Algorithm name (for example "HMAC" or "CMAC").
 * @return 1 if @p mac is known as @p name, or 0 otherwise.
 */
int EVP_MAC_is_a(const EVP_MAC *mac, const char *name);
/**
 * @brief Return the provider that implements a MAC algorithm.
 * @param mac MAC method obtained from EVP_MAC_fetch().
 * @return Provider pointer, or NULL if unavailable.
 */
const OSSL_PROVIDER *EVP_MAC_get0_provider(const EVP_MAC *mac);
/**
 * @brief Retrieve algorithm parameters from a fetched MAC implementation.
 * @param mac MAC algorithm obtained from EVP_MAC_fetch().
 * @param params NULL-terminated OSSL_PARAM array of parameters to fill.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[]);

/**
 * @brief Allocate a new MAC operation context for @p mac.
 * @param mac MAC method obtained from EVP_MAC_fetch() (reference is up-reffed).
 * @return New EVP_MAC_CTX, or NULL on failure; free with EVP_MAC_CTX_free().
 */
EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac);
/**
 * @brief Free a MAC context and its associated resources.
 * @param ctx Context to free; NULL is ignored.
 */
void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);
/**
 * @brief Duplicate a MAC context, including its current state.
 * @param src Source context to copy.
 * @return Newly allocated copy, or NULL on failure.
 */
EVP_MAC_CTX *EVP_MAC_CTX_dup(const EVP_MAC_CTX *src);
/**
 * @brief Return the EVP_MAC associated with a MAC context.
 * @param ctx MAC context to query.
 * @return Internal EVP_MAC pointer (do not free), or NULL if unset.
 */
EVP_MAC *EVP_MAC_CTX_get0_mac(EVP_MAC_CTX *ctx);
/**
 * @brief Get parameters from a MAC context.
 * @param ctx MAC context to query.
 * @param params Array of OSSL_PARAM request/response descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Apply an OSSL_PARAM array of parameters to a MAC context.
 * @param ctx MAC context to update.
 * @param params Parameter array terminated by OSSL_PARAM_construct_end().
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);

/**
 * @brief Return the MAC output size for the algorithm bound to @p ctx.
 * @param ctx Initialized MAC context.
 * @return Tag/MAC length in bytes, or 0 if unavailable.
 */
size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx);
/**
 * @brief Return the MAC block size for the algorithm bound to @p ctx.
 * @param ctx Initialized MAC context.
 * @return Block size in bytes, or 0 if unavailable.
 */
size_t EVP_MAC_CTX_get_block_size(EVP_MAC_CTX *ctx);
/**
 * @brief One-shot MAC computation: fetch the algorithm, process @p data, and write the tag.
 * @param libctx Library context used to fetch the MAC, or NULL for the default.
 * @param name MAC algorithm name (for example "HMAC" or "CMAC").
 * @param propq Property query for the MAC fetch, or NULL.
 * @param subalg Optional sub-algorithm name (for example the HMAC digest), or NULL.
 * @param params Optional OSSL_PARAM array for algorithm setup, or NULL.
 * @param key MAC key octets.
 * @param keylen Length of @p key in bytes.
 * @param data Message bytes to authenticate.
 * @param datalen Length of @p data in bytes.
 * @param out Buffer that receives the MAC, or NULL to query the required size via @p outlen.
 * @param outsize Size of @p out in bytes when @p out is non-NULL.
 * @param outlen On success, receives the number of MAC bytes written (or required if @p out is NULL).
 * @return Pointer to @p out on success, or NULL on failure.
 */
unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
    const char *subalg, const OSSL_PARAM *params,
    const void *key, size_t keylen,
    const unsigned char *data, size_t datalen,
    unsigned char *out, size_t outsize, size_t *outlen);
/**
 * @brief Initialize a MAC context with a key and optional algorithm parameters.
 * @param ctx MAC context created with EVP_MAC_CTX_new().
 * @param key MAC key octets.
 * @param keylen Length of @p key in bytes.
 * @param params Optional OSSL_PARAM array (for example digest selection), or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);
/**
 * @brief Feed more message bytes into a MAC computation.
 * @param ctx MAC context previously initialised with EVP_MAC_init().
 * @param data Message bytes to absorb.
 * @param datalen Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
/**
 * @brief Finish a MAC computation and write the authentication tag to a buffer.
 * @param ctx MAC context previously updated with EVP_MAC_update().
 * @param out Buffer that receives the MAC, or NULL to query the required size via @p outl.
 * @param outl On success, receives the number of bytes written (or required if @p out is NULL).
 * @param outsize Size of @p out in bytes when @p out is non-NULL.
 * @return 1 on success, or 0 on error.
 */
int EVP_MAC_final(EVP_MAC_CTX *ctx,
    unsigned char *out, size_t *outl, size_t outsize);
/**
 * @brief Finalize an XOF-style MAC and write @p outsize bytes of output.
 * @param ctx MAC context that has absorbed input via EVP_MAC_update().
 * @param out Buffer receiving the MAC output.
 * @param outsize Number of output bytes requested.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a fetched EVP_MAC algorithm.
 * @param mac MAC algorithm whose gettable algorithm parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_MAC context.
 * @param mac MAC algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);
/**
 * @brief Describe OSSL_PARAM keys that may be set on MAC contexts for @p mac.
 * @param mac MAC algorithm to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a live MAC context.
 * @param ctx MAC context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_CTX_gettable_params(EVP_MAC_CTX *ctx);
/**
 * @brief Return the OSSL_PARAM descriptors settable on a live MAC context.
 * @param ctx MAC context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_CTX_settable_params(EVP_MAC_CTX *ctx);

/**
 * @brief Invoke a callback for every MAC implementation available from activated providers.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each EVP_MAC and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_MAC_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_MAC *mac, void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every name (including aliases) associated with a MAC implementation.
 * @param mac MAC algorithm whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_names_do_all(const EVP_MAC *mac,
    void (*fn)(const char *name, void *data),
    void *data);

/* RAND stuff */
/**
 * @brief Fetch a random-number generator implementation from providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "CTR-DRBG" or "HASH-DRBG".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_RAND, or NULL on error; free with EVP_RAND_free.
 */
EVP_RAND *EVP_RAND_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);
/**
 * @brief Increment the reference count on a fetched EVP_RAND.
 * @param rand RAND method whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_up_ref(EVP_RAND *rand);
/**
 * @brief Release a reference to an EVP_RAND obtained from EVP_RAND_fetch.
 * @param rand RNG method to free, or NULL.
 */
void EVP_RAND_free(EVP_RAND *rand);
/**
 * @brief Return the primary algorithm name of a fetched EVP_RAND.
 * @param rand RAND algorithm object.
 * @return NUL-terminated name, or NULL on error.
 */
const char *EVP_RAND_get0_name(const EVP_RAND *rand);
/**
 * @brief Return a human-readable description of a random-number algorithm.
 * @param md RAND algorithm implementation to query.
 * @return Internal description string (do not free), or NULL if none is available.
 */
const char *EVP_RAND_get0_description(const EVP_RAND *md);
/**
 * @brief Test whether a RAND implementation is known under the given name.
 * @param rand RAND method to query.
 * @param name Algorithm name to match (for example "CTR-DRBG").
 * @return 1 if @p name is an alias for @p rand, or 0 otherwise.
 */
int EVP_RAND_is_a(const EVP_RAND *rand, const char *name);
/**
 * @brief Return the provider that supplied a RAND implementation.
 * @param rand RAND method to query.
 * @return Provider pointer, or NULL if unavailable.
 */
const OSSL_PROVIDER *EVP_RAND_get0_provider(const EVP_RAND *rand);
/**
 * @brief Retrieve algorithm-level parameters from a RAND implementation.
 * @param rand RAND method whose parameters are queried.
 * @param params Array of OSSL_PARAM request descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[]);

/**
 * @brief Create a RAND context for @p rand, optionally chaining from a parent DRBG.
 * @param rand Fetched EVP_RAND implementation (reference count is incremented).
 * @param parent Optional parent EVP_RAND_CTX used as entropy source, or NULL.
 * @return New EVP_RAND_CTX, or NULL on failure; free with EVP_RAND_CTX_free().
 */
EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent);
/**
 * @brief Increment the reference count on an EVP_RAND_CTX.
 * @param ctx RAND context whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx);
/**
 * @brief Free an EVP_RAND_CTX and release associated resources.
 * @param ctx RAND context to free, or NULL.
 */
void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx);
/**
 * @brief Return the EVP_RAND algorithm associated with RAND context @p ctx.
 * @param ctx RAND context.
 * @return Borrowed EVP_RAND pointer (do not free), or NULL if unset.
 */
EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
/**
 * @brief Retrieve algorithm parameters from a RAND context into @p params.
 * @param ctx RAND context to query.
 * @param params OSSL_PARAM array describing the values to fetch (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Set parameters on a RAND context via an OSSL_PARAM array.
 * @param ctx RAND context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Return the OSSL_PARAM descriptors that can be retrieved from an EVP_RAND algorithm.
 * @param rand RAND algorithm object.
 * @return Array of gettable parameter descriptors terminated by OSSL_PARAM_construct_end(), or NULL.
 */
const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand);
/**
 * @brief Return the OSSL_PARAM descriptors for parameters gettable on a RAND context.
 * @param rand RAND method whose gettable context parameters are listed.
 * @return Constant OSSL_PARAM array for use with EVP_RAND_CTX_get_params(), or NULL if none.
 */
const OSSL_PARAM *EVP_RAND_gettable_ctx_params(const EVP_RAND *rand);
/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on a RAND context.
 * @param rand RAND method whose settable context parameters are listed.
 * @return Constant OSSL_PARAM array for use with EVP_RAND_CTX_set_params(), or NULL if none.
 */
const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a live RAND context.
 * @param ctx RAND context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_RAND_CTX_gettable_params(EVP_RAND_CTX *ctx);
/**
 * @brief Return the parameters that may be set on a RAND context.
 * @param ctx RAND context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_RAND_CTX_settable_params(EVP_RAND_CTX *ctx);

/**
 * @brief Invoke a callback for every RAND implementation available from activated providers.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each EVP_RAND and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_RAND_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_RAND *rand, void *arg),
    void *arg);
/**
 * @brief Call @p fn for each synonymous name of a random-number algorithm implementation.
 * @param rand RAND method whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_names_do_all(const EVP_RAND *rand,
    void (*fn)(const char *name, void *data),
    void *data);

/**
 * @brief Instantiate (seed) an EVP_RAND_CTX so it can generate random bytes.
 * @param ctx RNG context to instantiate.
 * @param strength Requested security strength in bits.
 * @param prediction_resistance Non-zero to force a reseed from live entropy.
 * @param pstr Optional personalization string, or NULL.
 * @param pstr_len Length of @p pstr in bytes.
 * @param params Optional OSSL_PARAM array of additional parameters, or NULL.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr, size_t pstr_len,
    const OSSL_PARAM params[]);
/**
 * @brief Clear the instantiated state of a RAND context, returning it to uninitialised.
 * @param ctx RAND context previously passed to EVP_RAND_instantiate().
 * @return 1 on success, or 0 on error.
 */
int EVP_RAND_uninstantiate(EVP_RAND_CTX *ctx);
/**
 * @brief Generate random bytes from a RAND context.
 * @param ctx RAND context to draw from.
 * @param out Buffer receiving random octets.
 * @param outlen Number of bytes to generate.
 * @param strength Requested security strength in bits (0 selects the context default).
 * @param prediction_resistance Non-zero to request prediction resistance / reseed before output.
 * @param addin Optional additional input mixed into the generation, or NULL.
 * @param addin_len Length of @p addin in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out,
    size_t outlen, unsigned int strength,
    int prediction_resistance,
    const unsigned char *addin, size_t addin_len);
/**
 * @brief Reseed a DRBG/RAND context with optional entropy and additional input.
 * @param ctx RAND context to reseed.
 * @param prediction_resistance Nonzero to request prediction resistance when supported.
 * @param ent Optional entropy bytes, or NULL to let the implementation gather entropy.
 * @param ent_len Length of @p ent.
 * @param addin Optional additional input bytes, or NULL.
 * @param addin_len Length of @p addin.
 * @return 1 on success, or 0 on error.
 */
int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
    const unsigned char *ent, size_t ent_len,
    const unsigned char *addin, size_t addin_len);
/**
 * @brief Generate a nonce of @p outlen bytes from RAND context @p ctx.
 * @param ctx Instantiated RAND context.
 * @param out Buffer receiving the nonce.
 * @param outlen Number of nonce bytes to produce.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen);
/**
 * @brief Enable thread-safe locking on a RAND context for concurrent use.
 * @param ctx RAND context that should serialize access internally.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_RAND_enable_locking(EVP_RAND_CTX *ctx);

/**
 * @brief Confirm whether the internal DRBG state of @p ctx is currently zeroed.
 * @param ctx RAND context to inspect (used by FIPS mandatory self-tests).
 * @return 1 if zeroized, or 0 otherwise / on failure.
 */
int EVP_RAND_verify_zeroization(EVP_RAND_CTX *ctx);
/**
 * @brief Return the current security strength in bits of a RAND context.
 * @param ctx RAND context to query.
 * @return Strength in bits, or 0 if unavailable.
 */
unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx);
/**
 * @brief Return the current lifecycle state of a RAND context.
 * @param ctx RAND context to query.
 * @return EVP_RAND_STATE_UNINITIALISED, EVP_RAND_STATE_READY, or EVP_RAND_STATE_ERROR.
 */
int EVP_RAND_get_state(EVP_RAND_CTX *ctx);

#define EVP_RAND_STATE_UNINITIALISED 0
#define EVP_RAND_STATE_READY 1
#define EVP_RAND_STATE_ERROR 2

/* PKEY stuff */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Decrypt a session key with a private key using the legacy EVP_PKEY path (deprecated).
 * @param dec_key Output buffer for the recovered plaintext key material.
 * @param enc_key Encrypted key bytes.
 * @param enc_key_len Length of @p enc_key in bytes.
 * @param private_key Private key used for decryption.
 * @return Length of decrypted key on success, or a negative value on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_decrypt_old(unsigned char *dec_key,
    const unsigned char *enc_key,
    int enc_key_len,
    EVP_PKEY *private_key);
/**
 * @brief Encrypt a session key with a public key using the legacy EVP_PKEY path (deprecated).
 * @param enc_key Output buffer for the encrypted key material.
 * @param key Plaintext key bytes to encrypt.
 * @param key_len Length of @p key in bytes.
 * @param pub_key Public key used for encryption (typically RSA).
 * @return Number of encrypted bytes written to @p enc_key, or a negative value on error.
 *
 * Prefer EVP_PKEY_encrypt_init() / EVP_PKEY_encrypt().
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_encrypt_old(unsigned char *enc_key,
    const unsigned char *key,
    int key_len, EVP_PKEY *pub_key);
#endif
/**
 * @brief Test whether a public-key object is known under the given algorithm name.
 * @param pkey Key to query.
 * @param name Algorithm name or synonym (for example "RSA" or "EC").
 * @return 1 if @p pkey matches @p name, or 0 otherwise (including when @p pkey is NULL).
 */
int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);
/**
 * @brief Invoke @p fn for every algorithm name associated with @p pkey's type.
 * @param pkey Key whose type names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_type_names_do_all(const EVP_PKEY *pkey,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Map a public-key type NID to its base algorithm type NID.
 * @param type Key type NID (possibly an alias such as EVP_PKEY_RSA2).
 * @return Base type NID (for example EVP_PKEY_RSA), or NID_undef if unknown.
 */
int EVP_PKEY_type(int type);
/**
 * @brief Return the numeric type identifier of a public-key object.
 * @param pkey Key whose type NID (or EVP_PKEY_NONE) is reported.
 * @return Type constant such as EVP_PKEY_RSA, or EVP_PKEY_NONE if unset.
 */
int EVP_PKEY_get_id(const EVP_PKEY *pkey);
#define EVP_PKEY_id EVP_PKEY_get_id
/**
 * @brief Return the base EVP_PKEY type id for @p pkey (for example EVP_PKEY_RSA).
 * @param pkey Key to query.
 * @return EVP_PKEY_* type constant, or EVP_PKEY_NONE if unset.
 */
int EVP_PKEY_get_base_id(const EVP_PKEY *pkey);
#define EVP_PKEY_base_id EVP_PKEY_get_base_id
/**
 * @brief Return the cryptographic size of a key in bits (for example RSA modulus length).
 * @param pkey Key to query.
 * @return Key size in bits, or 0 if unavailable.
 */
int EVP_PKEY_get_bits(const EVP_PKEY *pkey);
#define EVP_PKEY_bits EVP_PKEY_get_bits
/**
 * @brief Return the estimated security strength of a key in bits.
 * @param pkey Key to query.
 * @return Security bits (for example 128), or 0 if unavailable.
 */
int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey);
#define EVP_PKEY_security_bits EVP_PKEY_get_security_bits
/**
 * @brief Return the maximum signature or related output size for a key in bytes.
 * @param pkey Key to query (for example RSA or EC).
 * @return Maximum size in bytes suitable for allocating signature buffers, or 0 on error.
 */
int EVP_PKEY_get_size(const EVP_PKEY *pkey);
#define EVP_PKEY_size EVP_PKEY_get_size
/**
 * @brief Test whether a key type supports signing operations.
 * @param pkey Key to query.
 * @return 1 if the key can be used for signing, or 0 otherwise.
 */
int EVP_PKEY_can_sign(const EVP_PKEY *pkey);
/**
 * @brief Assign the algorithm type of an empty EVP_PKEY by NID / EVP_PKEY_* id.
 * @param pkey Key object to type (typically freshly EVP_PKEY_new()'d).
 * @param type Key type identifier (for example EVP_PKEY_RSA).
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
/**
 * @brief Assign the algorithm type of @p pkey from an algorithm name string.
 * @param pkey Key object to type.
 * @param str Algorithm name bytes (need not be NUL-terminated when @p len >= 0).
 * @param len Length of @p str, or -1 if @p str is NUL-terminated.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
/**
 * @brief Assign the algorithm type of @p pkey from a fetched EVP_KEYMGMT.
 * @param pkey Key object to type.
 * @param keymgmt Key management implementation that defines the type.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt);
#ifndef OPENSSL_NO_DEPRECATED_3_0
#ifndef OPENSSL_NO_ENGINE
/**
 * @brief Associate an ENGINE with an EVP_PKEY for subsequent low-level operations (deprecated).
 * @param pkey Key whose ENGINE reference is set.
 * @param e ENGINE to attach, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);
/**
 * @brief Return the ENGINE associated with @p pkey, if any (deprecated).
 * @param pkey Key to query.
 * @return ENGINE pointer, or NULL if the key is not engine-backed.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey);
#endif
/**
 * @brief Assign a low-level key object of @p type to an EVP_PKEY (deprecated).
 * @param pkey Destination key wrapper; previous key material is freed.
 * @param type Key type NID such as EVP_PKEY_RSA or EVP_PKEY_EC.
 * @param key Type-specific key pointer (for example RSA *) that @p pkey will own.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
/**
 * @brief Return the legacy low-level key pointer stored in an EVP_PKEY (deprecated).
 * @param pkey Key wrapper to query.
 * @return Internal type-specific key pointer (for example RSA *), or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
/**
 * @brief Return a pointer to the HMAC key material inside an EVP_PKEY (deprecated).
 * @param pkey Key of type EVP_PKEY_HMAC.
 * @param len Receives the key length in bytes.
 * @return Pointer to the internal key bytes (do not free), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);
#ifndef OPENSSL_NO_POLY1305
/**
 * @brief Return a pointer to the Poly1305 key material inside an EVP_PKEY (deprecated).
 * @param pkey Key of type EVP_PKEY_POLY1305.
 * @param len Receives the key length in bytes.
 * @return Pointer to the internal key bytes (do not free), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len);
#endif
#ifndef OPENSSL_NO_SIPHASH
/**
 * @brief Return a pointer to the SipHash key material inside an EVP_PKEY (deprecated).
 * @param pkey Key of type EVP_PKEY_SIPHASH.
 * @param len Receives the key length in bytes.
 * @return Pointer to the internal key bytes (do not free), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len);
#endif

struct rsa_st;
/**
 * @brief Set the RSA key referenced by an EVP_PKEY, incrementing the RSA reference count (deprecated).
 * @param pkey Destination EVP_PKEY to assign.
 * @param key RSA key to associate; its reference count is incremented.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
/**
 * @brief Return the legacy RSA handle inside @p pkey without incrementing its refcount (deprecated).
 * @param pkey Key expected to contain an RSA key.
 * @return Borrowed RSA pointer, or NULL if @p pkey is not RSA / on error.
 */
OSSL_DEPRECATEDIN_3_0
const struct rsa_st *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
/**
 * @brief Return a new reference to the RSA key held by @p pkey (deprecated).
 * @param pkey Key that must hold an RSA key.
 * @return RSA pointer with an incremented reference count (caller frees with RSA_free()), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);

#ifndef OPENSSL_NO_DSA
struct dsa_st;
/**
 * @brief Set the DSA key referenced by an EVP_PKEY, incrementing the DSA reference count.
 * @param pkey Destination EVP_PKEY to assign.
 * @param key DSA key to associate; its reference count is incremented.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, struct dsa_st *key);
OSSL_DEPRECATEDIN_3_0
/**
 * @brief Return the DSA key referenced by @p pkey without incrementing its reference count (deprecated).
 * @param pkey Key that must hold a DSA key.
 * @return Internal DSA pointer, or NULL if @p pkey is not a DSA key; do not free the result.
 */
const struct dsa_st *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey);
/**
 * @brief Return a new reference to the DSA key held by @p pkey (deprecated).
 * @param pkey Key that must hold a DSA key.
 * @return DSA pointer with an incremented reference count (caller frees with DSA_free()), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
#endif

#ifndef OPENSSL_NO_DH
struct dh_st;
/**
 * @brief Set the DH key referenced by an EVP_PKEY, incrementing the DH reference count.
 * @param pkey Destination EVP_PKEY to assign.
 * @param key DH key to associate; its reference count is incremented.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_set1_DH(EVP_PKEY *pkey, struct dh_st *key);
/**
 * @brief Return the DH key referenced by @p pkey without incrementing its reference count (deprecated).
 * @param pkey Key that must hold a DH key.
 * @return Internal DH pointer, or NULL if @p pkey is not a DH key; do not free the result.
 */
OSSL_DEPRECATEDIN_3_0 const struct dh_st *EVP_PKEY_get0_DH(const EVP_PKEY *pkey);
/**
 * @brief Return a new reference to the DH key held by @p pkey (deprecated).
 * @param pkey Key that must hold a DH key.
 * @return DH with an incremented reference count, or NULL if not a DH key; free with DH_free().
 */
OSSL_DEPRECATEDIN_3_0 struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
#endif

#ifndef OPENSSL_NO_EC
struct ec_key_st;
/**
 * @brief Assign an EC_KEY to an EVP_PKEY, incrementing the EC_KEY reference count (deprecated).
 * @param pkey Destination key wrapper.
 * @param key EC_KEY to associate; its reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
/**
 * @brief Return a borrowed pointer to the EC_KEY held by @p pkey (deprecated).
 * @param pkey Key that must hold an EC key.
 * @return Internal EC_KEY pointer (do not free), or NULL if not an EC key.
 */
OSSL_DEPRECATEDIN_3_0
const struct ec_key_st *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
/**
 * @brief Return a new reference to the EC_KEY held by @p pkey (deprecated).
 * @param pkey Key that must hold an EC key.
 * @return EC_KEY with an incremented reference count, or NULL if not an EC key; free with EC_KEY_free().
 */
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
#endif
#endif /* OPENSSL_NO_DEPRECATED_3_0 */

/**
 * @brief Allocate an empty EVP_PKEY object.
 * @return New EVP_PKEY with reference count 1, or NULL on allocation failure.
 */
EVP_PKEY *EVP_PKEY_new(void);
/**
 * @brief Increment the reference count of an EVP_PKEY.
 * @param pkey Key whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_up_ref(EVP_PKEY *pkey);
/**
 * @brief Duplicate an EVP_PKEY (not supported for ENGINE-based or raw keys).
 * @param pkey Key to copy.
 * @return Newly allocated copy, or NULL on failure.
 */
EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey);
/**
 * @brief Free an EVP_PKEY, decrementing its reference count.
 * @param pkey Key to free, or NULL.
 */
void EVP_PKEY_free(EVP_PKEY *pkey);
/**
 * @brief Return a human-readable description of the key type associated with an EVP_PKEY.
 * @param pkey Key to query.
 * @return Static description string from the key management implementation, or NULL if unavailable.
 */
const char *EVP_PKEY_get0_description(const EVP_PKEY *pkey);
/**
 * @brief Return the provider that implements @p key, if provider-backed.
 * @param key Key to query.
 * @return OSSL_PROVIDER pointer, or NULL for legacy/engine keys.
 */
const OSSL_PROVIDER *EVP_PKEY_get0_provider(const EVP_PKEY *key);

/**
 * @brief Decode a public key of the given type from DER into an EVP_PKEY.
 * @param type Expected key type NID (for example EVP_PKEY_RSA).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Encode the public key from an EVP_PKEY to DER in the algorithm-native public-key format.
 * @param a Key whose public component is encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_PublicKey(const EVP_PKEY *a, unsigned char **pp);

/**
 * @brief Decode a private key of type @p type from DER using a library context.
 * @param type Key type NID (for example EVP_PKEY_RSA), or 0 to attempt type-specific legacy decoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Decode a private key of the given algorithm from DER using the default library context.
 * @param type Expected key type (for example EVP_PKEY_RSA); the decoded key must match.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded EVP_PKEY, or NULL on error.
 *
 * Equivalent to d2i_PrivateKey_ex() with a NULL library context and property query.
 */
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Decode a private key from DER, auto-detecting the algorithm, using a library context.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string for provider selection, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error.
 *
 * Accepts PKCS#8 and traditional private-key encodings without requiring an explicit type.
 */
EVP_PKEY *d2i_AutoPrivateKey_ex(EVP_PKEY **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Decode a private key from DER, detecting the algorithm automatically.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Encode the private key from an EVP_PKEY to DER in the algorithm-native private-key format.
 * @param a Key whose private component is encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);

/**
 * @brief Encode algorithm parameters from an EVP_PKEY to DER.
 * @param a Key whose parameters are encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp);
/**
 * @brief Decode algorithm parameters of the given key type from DER into an EVP_PKEY.
 * @param type Expected key type (for example EVP_PKEY_DH or EVP_PKEY_EC).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded parameters.
 * @param length Number of bytes available at *@p pp.
 * @return EVP_PKEY holding parameters only, or NULL on error.
 */
EVP_PKEY *d2i_KeyParams(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Encode algorithm parameters from an EVP_PKEY to a BIO in DER form.
 * @param bp Output BIO that receives the encoded parameters.
 * @param pkey Key whose parameters are written.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey);
/**
 * @brief Decode algorithm parameters from a BIO into an EVP_PKEY of the given type.
 * @param type Expected key type NID (for example EVP_PKEY_EC).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in BIO supplying the DER-encoded parameters.
 * @return Decoded EVP_PKEY holding parameters only, or NULL on error.
 */
EVP_PKEY *d2i_KeyParams_bio(int type, EVP_PKEY **a, BIO *in);

/**
 * @brief Copy algorithm parameters from one EVP_PKEY into another of the same type.
 * @param to Destination key that receives the parameters.
 * @param from Source key whose parameters are copied.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
/**
 * @brief Test whether an EVP_PKEY lacks required algorithm parameters.
 * @param pkey Key to inspect.
 * @return Non-zero if parameters are missing, or 0 if parameters are present (or not required).
 */
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
/**
 * @brief Control whether algorithm parameters are written when serializing @p pkey.
 * @param pkey Key whose parameter-export preference is updated.
 * @param mode Non-zero to include parameters on output, or 0 to omit them when possible.
 * @return Previous mode value.
 */
int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);
/**
 * @brief Compare the domain parameters of two keys for equality.
 * @param a First key.
 * @param b Second key.
 * @return 1 if parameters match, 0 if they differ, or a negative value on error.
 */
int EVP_PKEY_parameters_eq(const EVP_PKEY *a, const EVP_PKEY *b);
/**
 * @brief Compare two keys for equality of type, parameters, and key material.
 * @param a First key.
 * @param b Second key.
 * @return 1 if equal, 0 if not equal, or a negative value on error.
 */
int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Compare the algorithm parameters of two keys (deprecated; use EVP_PKEY_parameters_eq).
 * @param a First key.
 * @param b Second key.
 * @return 1 if parameters match, 0 if they differ, or -1/-2 on type mismatch or error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
/**
 * @brief Compare two keys for equality including parameters when present (deprecated; use EVP_PKEY_eq).
 * @param a First key.
 * @param b Second key.
 * @return 1 if equal, 0 if they differ, or -1/-2 on type mismatch or error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);
#endif

/**
 * @brief Print the public components of @p pkey to a BIO in human-readable form.
 * @param out Output BIO.
 * @param pkey Key whose public material is printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print a private key (including private components) to a BIO.
 * @param out Output BIO.
 * @param pkey Key to print.
 * @param indent Indentation depth in spaces.
 * @param pctx ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print a key's domain parameters to a BIO in human-readable form.
 * @param out Output BIO.
 * @param pkey Key whose parameters are printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Print the public components of @p pkey to a FILE.
 * @param fp Output stream.
 * @param pkey Key whose public material is printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_public_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print the private components of @p pkey to a FILE in human-readable form.
 * @param fp Output stream.
 * @param pkey Key whose private material is printed.
 * @param indent Indentation depth for the printed text.
 * @param pctx Optional ASN.1 print options, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_private_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print the algorithm parameters of @p pkey to a FILE in human-readable form.
 * @param fp Output stream.
 * @param pkey Key whose parameters are printed.
 * @param indent Indentation depth for the printed text.
 * @param pctx Optional ASN.1 print options, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_params_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
#endif

/**
 * @brief Return the default message-digest NID associated with @p pkey.
 * @param pkey Key whose signature defaults are queried.
 * @param pnid Receives the NID (for example NID_sha256), or NID_undef when unrestricted.
 * @return 1 if an advisory default was returned, 2 if the digest is mandatory, or a non-positive value on error.
 */
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);
/**
 * @brief Write the default digest name recommended for signing with @p pkey.
 * @param pkey Key whose signature defaults are queried.
 * @param mdname Output buffer receiving a NUL-terminated digest name (for example "SHA256").
 * @param mdname_sz Capacity of @p mdname in bytes.
 * @return 1 if a default digest is required, 2 if any digest is allowed, or a negative/zero value on error.
 */
int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey,
    char *mdname, size_t mdname_sz);
/**
 * @brief Query whether digest @p name can be used for DigestSign/Verify with @p pkey.
 * @param pkey Public key whose signature algorithm is checked.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param name Digest algorithm name (for example "SHA256").
 * @param propq Property query for provider selection, or NULL.
 * @return 1 if supported, 0 if not, or a negative value on failure.
 */
int EVP_PKEY_digestsign_supports_digest(EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *name, const char *propq);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use EVP_PKEY_set1_encoded_public_key in
 * preference
 */
#define EVP_PKEY_set1_tls_encodedpoint(pkey, pt, ptlen) \
    EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))
#endif

/**
 * @brief Set the public key on @p pkey from an encoded public-key octet string.
 * @param pkey Key object that receives the public key (type must already be set).
 * @param pub Encoded public-key bytes (format is algorithm-specific, for example a TLS point).
 * @param publen Length of @p pub in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey,
    const unsigned char *pub, size_t publen);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use EVP_PKEY_get1_encoded_public_key in
 * preference
 */
#define EVP_PKEY_get1_tls_encodedpoint(pkey, ppt) \
    EVP_PKEY_get1_encoded_public_key((pkey), (ppt))
#endif

/**
 * @brief Allocate and return the encoded public-key octet string for @p pkey.
 * @param pkey Key whose public key is exported.
 * @param ppub On success, set to a newly allocated buffer holding the encoded public key; free with OPENSSL_free().
 * @return Length of the encoded public key in bytes, or 0 on failure.
 */
size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);

/* calls methods */
/**
 * @brief Encode cipher parameters (typically including the IV) from @p c into an ASN1_TYPE.
 * @param c Cipher context whose AlgorithmIdentifier parameters are written; the IV must already be set.
 * @param type Destination ASN.1 type that receives the parameters.
 * @return 1 on success, or 0/-1 on failure (for example if the cipher lacks ASN.1 support).
 */
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
/**
 * @brief Decode cipher AlgorithmIdentifier parameters from @p type into cipher context @p c.
 * @param c Cipher context that receives parameters (typically including the IV).
 * @param type ASN.1 type holding the AlgorithmIdentifier parameters.
 * @return 1 on success, or 0/-1 on failure (for example if the cipher lacks ASN.1 support).
 */
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* These are used by EVP_CIPHER methods */
/**
 * @brief Encode the cipher context IV into an ASN.1 OCTET STRING inside @p type.
 * @param c Cipher context whose IV is serialized.
 * @param type ASN1_TYPE that receives an OCTET STRING encoding of the IV.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
/**
 * @brief Decode an IV from an ASN.1 OCTET STRING in @p type into cipher context @p c.
 * @param c Cipher context whose IV is updated.
 * @param type ASN1_TYPE expected to hold an OCTET STRING encoding of the IV.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* PKCS5 password based encryption */
/**
 * @brief Derive a PBE key and IV and initialize @p ctx for encryption/decryption (PKCS #5 v1.5).
 * @param ctx Cipher context to initialize.
 * @param pass Password octets (may be NULL if @p passlen is 0).
 * @param passlen Password length in bytes, or -1 to use strlen(@p pass).
 * @param param ASN.1 PBE parameters (salt, iteration count, and related fields).
 * @param cipher Cipher algorithm used for PBE.
 * @param md Digest used by the PBE key derivation.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de);
/**
 * @brief Derive a key and IV for password-based encryption and initialize @p cctx (library-context variant).
 * @param cctx Cipher context to initialize with the derived key and IV.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param param ASN.1 PBE parameters (salt, iteration count, and related fields).
 * @param cipher Cipher algorithm used for PBE.
 * @param md Digest used by the PBE key derivation.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for provider-aware derivation, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBE_keyivgen_ex(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Derive a key from a password with PBKDF2-HMAC-SHA1 (RFC 2898).
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param salt Salt bytes, or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @param iter Iteration count (should be large; typically at least 1000).
 * @param keylen Desired derived key length in bytes.
 * @param out Buffer of at least @p keylen bytes that receives the derived key.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    int keylen, unsigned char *out);
/**
 * @brief Derive a key from a password with PBKDF2-HMAC (RFC 2898) using @p digest.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param salt Salt bytes, or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @param iter Iteration count (should be greater than zero).
 * @param digest HMAC digest algorithm (for example EVP_sha256()).
 * @param keylen Desired derived-key length in bytes.
 * @param out Buffer that receives the derived key of @p keylen bytes.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    const EVP_MD *digest, int keylen, unsigned char *out);
/**
 * @brief Derive a key and IV from a PKCS#5 v2 PBE AlgorithmIdentifier and initialize @p ctx.
 * @param ctx Cipher context to initialize for encryption or decryption.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if @p pass is a NUL-terminated string.
 * @param param ASN.1 parameters from the PBE AlgorithmIdentifier.
 * @param cipher Cipher suggested by the caller (may be overridden by @p param).
 * @param md Digest suggested by the caller (may be overridden by @p param).
 * @param en_de Non-zero to encrypt, zero to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de);
/**
 * @brief Derive a key and IV with PKCS#5 PBES2 and initialize @p ctx for encrypt/decrypt.
 * @param ctx Cipher context to initialize.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param param ASN.1 PBES2 parameters describing KDF and cipher settings.
 * @param cipher Cipher algorithm to initialize (may be taken from @p param).
 * @param md Digest used by the KDF when required by the parameters.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string for provider selection, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);

#ifndef OPENSSL_NO_SCRYPT
/**
 * @brief Derive a key with scrypt from a password and salt.
 * @param pass Password bytes (may be NULL when @p passlen is 0).
 * @param passlen Length of @p pass in bytes.
 * @param salt Salt octets.
 * @param saltlen Length of @p salt in bytes.
 * @param N CPU/memory cost parameter (power of two).
 * @param r Block size parameter.
 * @param p Parallelization parameter.
 * @param maxmem Memory limit in bytes (0 selects the library default).
 * @param key Output buffer for the derived key.
 * @param keylen Desired derived-key length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_scrypt(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen);
/**
 * @brief Derive a key from a password using scrypt with an explicit library context.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes.
 * @param salt Salt bytes, or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @param N CPU/memory cost parameter (must be a power of two greater than 1).
 * @param r Block size parameter.
 * @param p Parallelization parameter.
 * @param maxmem Maximum memory in bytes the derivation may use, or 0 for the default limit.
 * @param key Buffer that receives the derived key.
 * @param keylen Desired derived key length in bytes.
 * @param ctx Library context for provider selection, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_scrypt_ex(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Initialize @p ctx for PBE using scrypt parameters from ASN.1 (PKCS#5 v2).
 * @param ctx Cipher context to initialize.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if NUL-terminated.
 * @param param ASN.1 parameters describing salt and scrypt settings.
 * @param c Content cipher to initialize.
 * @param md Unused for scrypt (may be NULL); retained for keygen callback signature compatibility.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de);
/**
 * @brief Initialize @p ctx for scrypt-based PBE using a library context.
 * @param ctx Cipher context to initialize.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if NUL-terminated.
 * @param param ASN.1 parameters describing salt and scrypt settings.
 * @param c Content cipher to initialize.
 * @param md Unused for scrypt (may be NULL).
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_scrypt_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);
#endif

/**
 * @brief Register the built-in PKCS#5 password-based encryption algorithms with the EVP PBE table.
 *
 * Historically populated OpenSSL's PBE algorithm list; retained for compatibility and typically a no-op in modern builds.
 */
void PKCS5_PBE_add(void);

/**
 * @brief Initialize a cipher context for password-based encryption from a PBE OID and parameters.
 * @param pbe_obj OID identifying the PBE algorithm.
 * @param pass Password bytes.
 * @param passlen Length of @p pass in bytes, or -1 if @p pass is NUL-terminated.
 * @param param Algorithm parameters associated with @p pbe_obj.
 * @param ctx Cipher context to initialize.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 *
 * Equivalent to EVP_PBE_CipherInit_ex() with a NULL library context and property query.
 */
int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
    ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);

/**
 * @brief Initialize a cipher context for password-based encryption using a library context.
 * @param pbe_obj OID identifying the PBE algorithm.
 * @param pass Password bytes.
 * @param passlen Length of @p pass in bytes, or -1 if @p pass is NUL-terminated.
 * @param param Algorithm parameters associated with @p pbe_obj.
 * @param ctx Cipher context to initialize.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for fetching algorithms, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_CipherInit_ex(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
    ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);

/* PBE type */

/* Can appear as the outermost AlgorithmIdentifier */
#define EVP_PBE_TYPE_OUTER 0x0
/* Is an PRF type OID */
#define EVP_PBE_TYPE_PRF 0x1
/* Is a PKCS#5 v2.0 KDF */
#define EVP_PBE_TYPE_KDF 0x2

/**
 * @brief Register a password-based encryption algorithm by type and NIDs.
 * @param pbe_type PBE category such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE algorithm OID being registered.
 * @param cipher_nid Cipher NID used by the algorithm, or -1 if none.
 * @param md_nid Digest NID used by the algorithm, or -1 if none.
 * @param keygen Key/IV derivation callback invoked for this PBE algorithm.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
    int md_nid, EVP_PBE_KEYGEN *keygen);
/**
 * @brief Register a password-based encryption algorithm by NID with cipher, digest, and keygen.
 * @param nid NID of the PBE algorithm OID being registered.
 * @param cipher Cipher used by the algorithm, or NULL if none.
 * @param md Digest used by the algorithm, or NULL if none.
 * @param keygen Key/IV derivation callback invoked for this PBE algorithm.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
    EVP_PBE_KEYGEN *keygen);
/**
 * @brief Look up a registered password-based encryption (PBE) algorithm by NID.
 * @param type PBE application type such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE AlgorithmIdentifier.
 * @param pcnid Optional destination for the cipher NID, or NULL.
 * @param pmnid Optional destination for the digest/PRF NID, or NULL.
 * @param pkeygen Optional destination for the keygen function pointer, or NULL.
 * @return 1 if found, or 0 otherwise.
 */
int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen);
/**
 * @brief Look up a registered PBE algorithm, returning both classic and extended keygen callbacks.
 * @param type PBE application type such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE AlgorithmIdentifier.
 * @param pcnid Optional destination for the cipher NID, or NULL.
 * @param pmnid Optional destination for the digest/PRF NID, or NULL.
 * @param pkeygen Optional destination for the classic keygen function pointer, or NULL.
 * @param pkeygen_ex Optional destination for the extended (libctx-aware) keygen, or NULL.
 * @return 1 if found, or 0 otherwise.
 */
int EVP_PBE_find_ex(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen, EVP_PBE_KEYGEN_EX **pkeygen_ex);
/**
 * @brief Free the global password-based encryption (PBE) algorithm registry.
 *
 * Intended for process teardown; after this call, PBE algorithms must be
 * re-registered before use.
 */
void EVP_PBE_cleanup(void);
/**
 * @brief Return the PBE algorithm type and NID at index @p num in the registry.
 * @param ptype Optional destination for the PBE type (EVP_PBE_TYPE_*), or NULL.
 * @param ppbe_nid Optional destination for the PBE algorithm NID, or NULL.
 * @param num Zero-based index into the registered PBE table.
 * @return 1 if @p num is valid, or 0 if out of range.
 */
int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);

#define ASN1_PKEY_ALIAS 0x1
#define ASN1_PKEY_DYNAMIC 0x2
#define ASN1_PKEY_SIGPARAM_NULL 0x4

#define ASN1_PKEY_CTRL_PKCS7_SIGN 0x1
#define ASN1_PKEY_CTRL_PKCS7_ENCRYPT 0x2
#define ASN1_PKEY_CTRL_DEFAULT_MD_NID 0x3
#define ASN1_PKEY_CTRL_CMS_SIGN 0x5
#define ASN1_PKEY_CTRL_CMS_ENVELOPE 0x7
#define ASN1_PKEY_CTRL_CMS_RI_TYPE 0x8

#define ASN1_PKEY_CTRL_SET1_TLS_ENCPT 0x9
#define ASN1_PKEY_CTRL_GET1_TLS_ENCPT 0xa
#define ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED 0xb

/**
 * @brief Return the number of registered EVP_PKEY_ASN1_METHOD implementations.
 * @return Count of ASN.1 methods available via EVP_PKEY_asn1_get0().
 */
int EVP_PKEY_asn1_get_count(void);
/**
 * @brief Return the registered EVP_PKEY_ASN1_METHOD at index @p idx.
 * @param idx Zero-based index in the range [0, EVP_PKEY_asn1_get_count()).
 * @return Internal ASN.1 method pointer, or NULL if @p idx is out of range.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
/**
 * @brief Find the ASN.1 method implementing a public-key algorithm NID.
 * @param pe Optional ENGINE pointer updated when the method comes from an ENGINE, or NULL.
 * @param type Algorithm NID such as EVP_PKEY_RSA.
 * @return Internal EVP_PKEY_ASN1_METHOD pointer, or NULL if not found.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);
/**
 * @brief Find an EVP_PKEY_ASN1_METHOD by PEM type string.
 * @param pe Optional ENGINE search: if non-NULL, may be set to an engine providing the method.
 * @param str PEM algorithm name to look up.
 * @param len Length of @p str, or -1 to use strlen(@p str).
 * @return Matching ASN.1 method, or NULL if not found.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe,
    const char *str, int len);
/**
 * @brief Register an EVP_PKEY_ASN1_METHOD in the global ASN.1 method table.
 * @param ameth ASN.1 method to add; ownership is transferred on success.
 * @return 1 on success, or 0 on failure (for example duplicate id).
 */
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
/**
 * @brief Alias ASN.1 method NID @p from so it is treated as NID @p to.
 * @param to Destination algorithm NID that already has an ASN.1 method.
 * @param from Alias NID to map onto @p to.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_asn1_add_alias(int to, int from);
/**
 * @brief Extract identifying metadata from an EVP_PKEY_ASN1_METHOD.
 * @param ppkey_id Optional; receives the method's EVP_PKEY type NID.
 * @param pkey_base_id Optional; receives the base key type NID.
 * @param ppkey_flags Optional; receives ASN1 method flags (ASN1_PKEY_*).
 * @param pinfo Optional; receives the human-readable info string, or NULL.
 * @param ppem_str Optional; receives the PEM string name used for this key type.
 * @param ameth ASN.1 method to query; must not be NULL.
 * @return 1 on success, or 0 if @p ameth is NULL.
 */
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
    int *ppkey_flags, const char **pinfo,
    const char **ppem_str,
    const EVP_PKEY_ASN1_METHOD *ameth);

/**
 * @brief Return the EVP_PKEY_ASN1_METHOD associated with a key.
 * @param pkey Key whose ASN.1 method is queried.
 * @return Internal ASN.1 method pointer, or NULL if unavailable; do not free.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_get0_asn1(const EVP_PKEY *pkey);
/**
 * @brief Allocate a new custom EVP_PKEY_ASN1_METHOD for algorithm @p id.
 * @param id Public-key algorithm NID for the method.
 * @param flags ASN1 method flags such as ASN1_PKEY_SIGPARAM_NULL.
 * @param pem_str PEM algorithm name string associated with this method, or NULL.
 * @param info Optional human-readable description stored on the method, or NULL.
 * @return New mutable ASN.1 method, or NULL on allocation failure.
 */
EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_new(int id, int flags,
    const char *pem_str,
    const char *info);
/**
 * @brief Copy an EVP_PKEY_ASN1_METHOD from @p src into @p dst (not thread-safe).
 * @param dst Destination method object to overwrite.
 * @param src Source method whose function pointers and metadata are copied.
 */
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst,
    const EVP_PKEY_ASN1_METHOD *src);
/**
 * @brief Free an EVP_PKEY_ASN1_METHOD allocated with EVP_PKEY_asn1_new().
 * @param ameth Method object to free; NULL is ignored.
 */
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
/**
 * @brief Install public-key decode, encode, compare, print, size, and bits callbacks on an ASN.1 method.
 * @param ameth ASN.1 method being customized.
 * @param pub_decode Decode an X509_PUBKEY into @p pk.
 * @param pub_encode Encode @p pk into an X509_PUBKEY.
 * @param pub_cmp Compare two public keys (1 match, 0 differ, negative on error).
 * @param pub_print Print the public key to a BIO.
 * @param pkey_size Return the maximum output size in bytes for operations with @p pk.
 * @param pkey_bits Return the key size in bits for @p pk.
 */
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pub_decode)(EVP_PKEY *pk,
        const X509_PUBKEY *pub),
    int (*pub_encode)(X509_PUBKEY *pub,
        const EVP_PKEY *pk),
    int (*pub_cmp)(const EVP_PKEY *a,
        const EVP_PKEY *b),
    int (*pub_print)(BIO *out,
        const EVP_PKEY *pkey,
        int indent, ASN1_PCTX *pctx),
    int (*pkey_size)(const EVP_PKEY *pk),
    int (*pkey_bits)(const EVP_PKEY *pk));
/**
 * @brief Install PKCS#8 private-key decode, encode, and print callbacks on an ASN.1 method.
 * @param ameth ASN.1 method being customized.
 * @param priv_decode Decode a PKCS8_PRIV_KEY_INFO into @p pk.
 * @param priv_encode Encode @p pk into a PKCS8_PRIV_KEY_INFO.
 * @param priv_print Print the private key to a BIO.
 */
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,
    int (*priv_decode)(EVP_PKEY *pk,
        const PKCS8_PRIV_KEY_INFO
            *p8inf),
    int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8,
        const EVP_PKEY *pk),
    int (*priv_print)(BIO *out,
        const EVP_PKEY *pkey,
        int indent,
        ASN1_PCTX *pctx));
/**
 * @brief Install parameter encode/decode, missing, copy, compare, and print callbacks on an ASN.1 method.
 * @param ameth ASN.1 method being customized.
 * @param param_decode Decode algorithm parameters from DER into @p pkey.
 * @param param_encode Encode algorithm parameters from @p pkey to DER.
 * @param param_missing Return nonzero if @p pk lacks required parameters.
 * @param param_copy Copy parameters from @p from into @p to.
 * @param param_cmp Compare parameters of two keys (1 match, 0 differ, negative on error).
 * @param param_print Print parameters to a BIO.
 */
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,
    int (*param_decode)(EVP_PKEY *pkey,
        const unsigned char **pder,
        int derlen),
    int (*param_encode)(const EVP_PKEY *pkey,
        unsigned char **pder),
    int (*param_missing)(const EVP_PKEY *pk),
    int (*param_copy)(EVP_PKEY *to,
        const EVP_PKEY *from),
    int (*param_cmp)(const EVP_PKEY *a,
        const EVP_PKEY *b),
    int (*param_print)(BIO *out,
        const EVP_PKEY *pkey,
        int indent,
        ASN1_PCTX *pctx));

/**
 * @brief Set the private-key free callback on a custom EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being constructed.
 * @param pkey_free Callback that releases algorithm-specific key material in @p pkey.
 */
void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
    void (*pkey_free)(EVP_PKEY *pkey));
/**
 * @brief Set the control callback on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method table under construction.
 * @param pkey_ctrl Callback for ASN.1/method control ops (for example PKCS#7/CMS), or NULL to clear.
 */
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_ctrl)(EVP_PKEY *pkey, int op,
        long arg1, void *arg2));
/**
 * @brief Install ASN.1 item sign and verify callbacks on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being customized.
 * @param item_verify Optional callback used by ASN1_item_verify() for custom signature verification, or NULL.
 * @param item_sign Optional callback used by ASN1_item_sign() for custom signature generation, or NULL.
 */
void EVP_PKEY_asn1_set_item(EVP_PKEY_ASN1_METHOD *ameth,
    int (*item_verify)(EVP_MD_CTX *ctx,
        const ASN1_ITEM *it,
        const void *data,
        const X509_ALGOR *a,
        const ASN1_BIT_STRING *sig,
        EVP_PKEY *pkey),
    int (*item_sign)(EVP_MD_CTX *ctx,
        const ASN1_ITEM *it,
        const void *data,
        X509_ALGOR *alg1,
        X509_ALGOR *alg2,
        ASN1_BIT_STRING *sig));

/**
 * @brief Install the X509_SIG_INFO setup callback on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being customized.
 * @param siginf_set Callback that fills signature metadata from @p alg and @p sig, or NULL to clear.
 */
void EVP_PKEY_asn1_set_siginf(EVP_PKEY_ASN1_METHOD *ameth,
    int (*siginf_set)(X509_SIG_INFO *siginf,
        const X509_ALGOR *alg,
        const ASN1_STRING *sig));

/**
 * @brief Install the full-key consistency check callback on an ASN.1 method.
 * @param ameth ASN.1 method being configured.
 * @param pkey_check Callback that returns 1 if @p pk is consistent, or NULL to clear.
 */
void EVP_PKEY_asn1_set_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_check)(const EVP_PKEY *pk));

/**
 * @brief Install the public-key consistency check callback on an ASN.1 method.
 * @param ameth ASN.1 method being configured.
 * @param pkey_pub_check Callback that returns 1 if @p pk's public key is valid, or NULL to clear.
 */
void EVP_PKEY_asn1_set_public_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_pub_check)(const EVP_PKEY *pk));

/**
 * @brief Install a callback that validates algorithm parameters on an EVP_PKEY.
 * @param ameth ASN.1 method object to update.
 * @param pkey_param_check Function that returns 1 if @p pk parameters are valid.
 */
void EVP_PKEY_asn1_set_param_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_param_check)(const EVP_PKEY *pk));

/**
 * @brief Install a callback that sets raw private-key octets on an EVP_PKEY.
 * @param ameth ASN.1 method being customized.
 * @param set_priv_key Callback that imports @p len bytes of raw private key material into @p pk.
 */
void EVP_PKEY_asn1_set_set_priv_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*set_priv_key)(EVP_PKEY *pk,
        const unsigned char
            *priv,
        size_t len));
/**
 * @brief Install a callback that sets raw public-key octets on an EVP_PKEY.
 * @param ameth ASN.1 method being customized.
 * @param set_pub_key Callback that imports @p len bytes of raw public key material into @p pk.
 */
void EVP_PKEY_asn1_set_set_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*set_pub_key)(EVP_PKEY *pk,
        const unsigned char *pub,
        size_t len));
/**
 * @brief Install the raw private-key export callback on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method table to update.
 * @param get_priv_key Callback that writes the private key octets for @c pk into @c priv and reports the length via @c len.
 */
void EVP_PKEY_asn1_set_get_priv_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*get_priv_key)(const EVP_PKEY *pk,
        unsigned char *priv,
        size_t *len));
/**
 * @brief Install a callback that exports the raw public key encoding from an EVP_PKEY.
 * @param ameth ASN.1 method table to update.
 * @param get_pub_key Callback that writes the public key into @c pub / updates @c len.
 */
void EVP_PKEY_asn1_set_get_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*get_pub_key)(const EVP_PKEY *pk,
        unsigned char *pub,
        size_t *len));

/**
 * @brief Set the security-bits callback on a custom EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being constructed.
 * @param pkey_security_bits Callback returning an estimate of security strength in bits.
 */
void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_security_bits)(const EVP_PKEY
            *pk));

/**
 * @brief Retrieve the message digest currently configured for signing or verifying with @p ctx.
 * @param ctx Key context configured for a signature operation.
 * @param md Set to the digest algorithm previously set with EVP_PKEY_CTX_set_signature_md(), or NULL if unset.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
/**
 * @brief Set the message digest used when signing or verifying with @p ctx.
 * @param ctx Key context configured for a signature operation.
 * @param md Digest algorithm (for example EVP_sha256()), or NULL to clear.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * @brief Set an algorithm-specific identity value on a key operation context (copied).
 * @param ctx Key context that supports an ID parameter (for example SM2).
 * @param id Identity bytes to copy into the context.
 * @param len Length of @p id in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len);
/**
 * @brief Copy the algorithm-specific ID bytes from @p ctx into @p id.
 * @param ctx Key context that previously received an ID via EVP_PKEY_CTX_set1_id().
 * @param id Caller-allocated buffer of size reported by EVP_PKEY_CTX_get1_id_len().
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX *ctx, void *id);
/**
 * @brief Return the length of an algorithm-specific ID associated with a key context.
 * @param ctx Key context that holds an ID (for example SM2 user id).
 * @param id_len Receives the ID length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len);

/**
 * @brief Select the KEM operation mode on a key context (for example "encapsulate").
 * @param ctx Key context prepared for a KEM algorithm.
 * @param op Operation name understood by the provider.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX *ctx, const char *op);

/**
 * @brief Return the algorithm type name of a key (for example "RSA" or "EC").
 * @param key Key to query.
 * @return NUL-terminated type name owned by OpenSSL, or NULL if unavailable.
 */
const char *EVP_PKEY_get0_type_name(const EVP_PKEY *key);

#define EVP_PKEY_OP_UNDEFINED 0
#define EVP_PKEY_OP_PARAMGEN (1 << 1)
#define EVP_PKEY_OP_KEYGEN (1 << 2)
#define EVP_PKEY_OP_FROMDATA (1 << 3)
#define EVP_PKEY_OP_SIGN (1 << 4)
#define EVP_PKEY_OP_VERIFY (1 << 5)
#define EVP_PKEY_OP_VERIFYRECOVER (1 << 6)
#define EVP_PKEY_OP_SIGNCTX (1 << 7)
#define EVP_PKEY_OP_VERIFYCTX (1 << 8)
#define EVP_PKEY_OP_ENCRYPT (1 << 9)
#define EVP_PKEY_OP_DECRYPT (1 << 10)
#define EVP_PKEY_OP_DERIVE (1 << 11)
#define EVP_PKEY_OP_ENCAPSULATE (1 << 12)
#define EVP_PKEY_OP_DECAPSULATE (1 << 13)

#define EVP_PKEY_OP_TYPE_SIG                                           \
    (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER \
        | EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX)

#define EVP_PKEY_OP_TYPE_CRYPT \
    (EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT)

#define EVP_PKEY_OP_TYPE_NOGEN \
    (EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_DERIVE)

#define EVP_PKEY_OP_TYPE_GEN \
    (EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN)

/**
 * @brief Set the MAC key bytes on a keygen/paramgen EVP_PKEY_CTX (for example HMAC or Poly1305).
 * @param ctx Key generation context for a MAC algorithm.
 * @param key MAC key octets; may be NULL when @p keylen is 0.
 * @param keylen Length of @p key in bytes.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key,
    int keylen);

#define EVP_PKEY_CTRL_MD 1
#define EVP_PKEY_CTRL_PEER_KEY 2
#define EVP_PKEY_CTRL_SET_MAC_KEY 6
#define EVP_PKEY_CTRL_DIGESTINIT 7
/* Used by GOST key encryption in TLS */
#define EVP_PKEY_CTRL_SET_IV 8
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define EVP_PKEY_CTRL_PKCS7_ENCRYPT 3
#define EVP_PKEY_CTRL_PKCS7_DECRYPT 4
#define EVP_PKEY_CTRL_PKCS7_SIGN 5
#define EVP_PKEY_CTRL_CMS_ENCRYPT 9
#define EVP_PKEY_CTRL_CMS_DECRYPT 10
#define EVP_PKEY_CTRL_CMS_SIGN 11
#endif
#define EVP_PKEY_CTRL_CIPHER 12
#define EVP_PKEY_CTRL_GET_MD 13
#define EVP_PKEY_CTRL_SET_DIGEST_SIZE 14
#define EVP_PKEY_CTRL_SET1_ID 15
#define EVP_PKEY_CTRL_GET1_ID 16
#define EVP_PKEY_CTRL_GET1_ID_LEN 17

#define EVP_PKEY_ALG_CTRL 0x1000

#define EVP_PKEY_FLAG_AUTOARGLEN 2
/*
 * Method handles all operations: don't assume any digest related defaults.
 */
#define EVP_PKEY_FLAG_SIGCTX_CUSTOM 4
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Find a registered EVP_PKEY_METHOD by key type NID (deprecated).
 * @param type Key type such as EVP_PKEY_RSA.
 * @return Matching method, or NULL if none is registered.
 */
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);
/**
 * @brief Allocate a new custom EVP_PKEY_METHOD for algorithm @p id (deprecated).
 * @param id Public-key algorithm NID this method implements.
 * @param flags Method flags such as EVP_PKEY_FLAG_AUTOARGLEN or EVP_PKEY_FLAG_SIGCTX_CUSTOM.
 * @return New EVP_PKEY_METHOD, or NULL on allocation failure.
 *
 * Prefer provider-based EVP_KEYMGMT / EVP_SIGNATURE implementations for new code.
 */
OSSL_DEPRECATEDIN_3_0 EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags);
/**
 * @brief Read the algorithm id and flags from an EVP_PKEY_METHOD (deprecated).
 * @param ppkey_id Optional output receiving the method's EVP_PKEY_* id.
 * @param pflags Optional output receiving the method flags.
 * @param meth Method object to query.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
    const EVP_PKEY_METHOD *meth);
/**
 * @brief Copy all callbacks and flags from one EVP_PKEY_METHOD to another (deprecated).
 * @param dst Destination method (existing object overwritten).
 * @param src Source method whose callbacks/flags are copied.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,
    const EVP_PKEY_METHOD *src);
/**
 * @brief Free an application-defined EVP_PKEY_METHOD allocated with EVP_PKEY_meth_new (deprecated).
 * @param pmeth Method table to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
/**
 * @brief Register an application-defined EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to add to the global list; must remain valid.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer providers for new algorithms.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);
/**
 * @brief Unregister a previously added EVP_PKEY_METHOD from the global list (deprecated).
 * @param pmeth Method table previously passed to EVP_PKEY_meth_add0().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth);
/**
 * @brief Return the number of registered EVP_PKEY_METHOD implementations (deprecated).
 * @return Count of methods available via EVP_PKEY_meth_get0().
 */
OSSL_DEPRECATEDIN_3_0 size_t EVP_PKEY_meth_get_count(void);
/**
 * @brief Return the registered EVP_PKEY_METHOD at index @p idx (deprecated).
 * @param idx Zero-based index in the range [0, EVP_PKEY_meth_get_count()).
 * @return Internal method pointer, or NULL if @p idx is out of range.
 */
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx);
#endif

/**
 * @brief Fetch a key-management implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "RSA" or "EC".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEYMGMT, or NULL on error; free with EVP_KEYMGMT_free.
 */
EVP_KEYMGMT *EVP_KEYMGMT_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Increment the reference count on a key management method.
 * @param keymgmt Method object to retain.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYMGMT_up_ref(EVP_KEYMGMT *keymgmt);
/**
 * @brief Release a reference to a key-management algorithm implementation.
 * @param keymgmt Implementation to free; NULL is ignored. Frees when the last reference is dropped.
 */
void EVP_KEYMGMT_free(EVP_KEYMGMT *keymgmt);
/**
 * @brief Return the provider that implements a key management method.
 * @param keymgmt Method to query.
 * @return OSSL_PROVIDER pointer, or NULL.
 */
const OSSL_PROVIDER *EVP_KEYMGMT_get0_provider(const EVP_KEYMGMT *keymgmt);
/**
 * @brief Return the algorithm name of a key management method.
 * @param keymgmt Method to query.
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEYMGMT_get0_name(const EVP_KEYMGMT *keymgmt);
/**
 * @brief Return a human-readable description of a keymgmt implementation.
 * @param keymgmt Key management method to query.
 * @return Description string, or NULL if none is available.
 */
const char *EVP_KEYMGMT_get0_description(const EVP_KEYMGMT *keymgmt);
/**
 * @brief Test whether a key-management implementation is known under the given name.
 * @param keymgmt Keymgmt method to query.
 * @param name Algorithm name to match (for example "RSA").
 * @return 1 if @p name is an alias for @p keymgmt, or 0 otherwise.
 */
int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name);
/**
 * @brief Invoke @p fn for every KEYMGMT implementation available in @p libctx.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each keymgmt and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_KEYMGMT_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYMGMT *keymgmt, void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every name (including aliases) associated with a keymgmt.
 * @param keymgmt Key management implementation whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYMGMT_names_do_all(const EVP_KEYMGMT *keymgmt,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Describe parameters that can be read from keys managed by a keymgmt.
 * @param keymgmt Key management implementation to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL on error.
 */
const OSSL_PARAM *EVP_KEYMGMT_gettable_params(const EVP_KEYMGMT *keymgmt);
/**
 * @brief Return the OSSL_PARAM descriptors settable on an existing key via this keymgmt.
 * @param keymgmt Key management implementation to query.
 * @return Constant OSSL_PARAM array, or NULL on error.
 */
const OSSL_PARAM *EVP_KEYMGMT_settable_params(const EVP_KEYMGMT *keymgmt);
/**
 * @brief Return the OSSL_PARAM descriptors for key-generation parameters settable on this keymgmt.
 * @param keymgmt Key management implementation to query.
 * @return Constant OSSL_PARAM array, or NULL on error.
 */
const OSSL_PARAM *EVP_KEYMGMT_gen_settable_params(const EVP_KEYMGMT *keymgmt);

/**
 * @brief Allocate a key context for operations with @p pkey.
 * @param pkey Key that supplies the algorithm and material for the context.
 * @param e Optional ENGINE implementing the algorithm, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on error; free with EVP_PKEY_CTX_free().
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
/**
 * @brief Allocate a key context for algorithm @p id, optionally using an ENGINE.
 * @param id Algorithm identifier such as EVP_PKEY_RSA.
 * @param e ENGINE implementing the algorithm, or NULL for the default implementation.
 * @return New EVP_PKEY_CTX, or NULL on failure.
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
/**
 * @brief Allocate a key context for an algorithm fetched by name from providers.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param name Algorithm name (for example "RSA" or "EC").
 * @param propquery Property query string, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on error; free with EVP_PKEY_CTX_free().
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);
/**
 * @brief Allocate a key context for operations on an existing EVP_PKEY.
 * @param libctx Library context used to fetch algorithms, or NULL for the default.
 * @param pkey Key that determines the algorithm and provides key material.
 * @param propquery Property query for algorithm fetches, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on failure.
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey, const char *propquery);
/**
 * @brief Duplicate a public-key algorithm context (not supported during keygen).
 * @param ctx Source context to copy.
 * @return Newly allocated copy, or NULL on failure.
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_dup(const EVP_PKEY_CTX *ctx);
/**
 * @brief Free an EVP_PKEY_CTX and release associated resources.
 * @param ctx Key context to free, or NULL.
 */
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
/**
 * @brief Test whether a key context is for the named key type.
 * @param ctx Key context to query.
 * @param keytype Algorithm name such as "RSA" or "EC".
 * @return 1 if @p ctx matches @p keytype, or 0 otherwise.
 */
int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);

/**
 * @brief Retrieve parameters from a key context into an OSSL_PARAM array.
 * @param ctx Key context to query.
 * @param params Array of OSSL_PARAM request/response descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a key context.
 * @param ctx Key context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_CTX_gettable_params(const EVP_PKEY_CTX *ctx);
/**
 * @brief Set parameters on a key context via an OSSL_PARAM array.
 * @param ctx Key context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params);
/**
 * @brief Describe OSSL_PARAM keys that may be set on key context @p ctx.
 * @param ctx Key operation context.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx);
/**
 * @brief Send an algorithm-specific control command to a key context.
 * @param ctx Key context receiving the command.
 * @param keytype Expected key type, or -1 to skip the type check.
 * @param optype Expected operation type, or -1 to skip the operation check.
 * @param cmd Algorithm-specific control command.
 * @param p1 Integer argument for @p cmd.
 * @param p2 Pointer argument for @p cmd, or NULL.
 * @return Positive on success, 0 or negative on failure.
 */
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
/**
 * @brief Send a named string control to a key context (for example "rsa_padding").
 * @param ctx Key context receiving the control.
 * @param type Control name understood by the algorithm.
 * @param value Control value as a NUL-terminated string, or NULL when unused.
 * @return Positive on success, 0 or negative on failure.
 */
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
    const char *value);
/**
 * @brief Send a control command with a uint64_t argument to a key context.
 * @param ctx Key context receiving the command.
 * @param keytype Expected key type, or -1 to skip the type check.
 * @param optype Expected operation type, or -1 to skip the operation check.
 * @param cmd Algorithm-specific control command.
 * @param value 64-bit integer argument for @p cmd.
 * @return Positive value on success, or a non-positive value on failure / unsupported command.
 */
int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, uint64_t value);

/**
 * @brief Pass a NUL-terminated string to EVP_PKEY_CTX_ctrl as the p2 argument.
 * @param ctx Key context that receives the control.
 * @param cmd Control command number understood by the key method.
 * @param str NUL-terminated string passed as @c p2 (length is strlen(@p str)).
 * @return Positive on success, 0 or negative on failure (same convention as EVP_PKEY_CTX_ctrl).
 */
int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str);
/**
 * @brief Decode a hex string to bytes and pass them to EVP_PKEY_CTX_ctrl as the p2 buffer.
 * @param ctx Key context that receives the control.
 * @param cmd Control command number understood by the key method.
 * @param hex NUL-terminated hexadecimal encoding of the binary value.
 * @return Positive on success, 0 or negative on failure (same convention as EVP_PKEY_CTX_ctrl).
 */
int EVP_PKEY_CTX_hex2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *hex);

/**
 * @brief Set a digest algorithm on a key context by name for the given operation.
 * @param ctx Key context to update.
 * @param optype Operation type such as EVP_PKEY_OP_TYPE_SIG.
 * @param cmd Control command that expects an EVP_MD (for example EVP_PKEY_CTRL_MD).
 * @param md Digest name such as "SHA256".
 * @return Positive value on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);

/**
 * @brief Return the operation type currently configured on a key context.
 * @param ctx Key context to query.
 * @return One of the EVP_PKEY_OP_* values, or EVP_PKEY_OP_UNDEFINED if unset.
 */
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
/**
 * @brief Attach legacy keygen progress info used by some ENGINE implementations.
 * @param ctx Key context used for key generation.
 * @param dat Array of integers describing generation progress/state (ownership not transferred).
 * @param datlen Number of entries in @p dat.
 */
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);

/**
 * @brief Create an EVP_PKEY holding a MAC key for HMAC, CMAC, Poly1305, or SipHash.
 * @param type Key type NID (for example EVP_PKEY_HMAC).
 * @param e Optional ENGINE implementing the MAC, or NULL.
 * @param key Raw key bytes.
 * @param keylen Length of @p key in bytes.
 * @return New EVP_PKEY, or NULL on error.
 *
 * Prefer EVP_MAC / EVP_PKEY_new_raw_private_key_ex() for new code.
 */
EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
    const unsigned char *key, int keylen);
/**
 * @brief Create an EVP_PKEY from raw private-key octets using a named algorithm and library context.
 * @param libctx Library context used to fetch the key type, or NULL for the default.
 * @param keytype Algorithm name such as "ED25519" or "X25519".
 * @param propq Property query string, or NULL.
 * @param priv Raw private-key bytes in the algorithm-native format.
 * @param len Length of @p priv in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free.
 */
EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype,
    const char *propq,
    const unsigned char *priv, size_t len);
/**
 * @brief Create an EVP_PKEY from raw private-key octets (legacy NID/ENGINE form).
 * @param type Key type NID such as EVP_PKEY_X25519 or EVP_PKEY_ED25519.
 * @param e Optional ENGINE, or NULL (ignored for provider-only types).
 * @param priv Raw private-key bytes in the algorithm-native format.
 * @param len Length of @p priv in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free().
 */
EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
    const unsigned char *priv,
    size_t len);
/**
 * @brief Create an EVP_PKEY from raw public-key octets using a named algorithm and library context.
 * @param libctx Library context used to fetch the key type, or NULL for the default.
 * @param keytype Algorithm name such as "ED25519" or "X25519".
 * @param propq Property query string, or NULL.
 * @param pub Raw public-key bytes in the algorithm-native format.
 * @param len Length of @p pub in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free.
 */
EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype, const char *propq,
    const unsigned char *pub, size_t len);
/**
 * @brief Create an EVP_PKEY from raw public key octets for algorithms that support that form.
 * @param type Key type NID (for example EVP_PKEY_X25519, EVP_PKEY_ED25519, EVP_PKEY_EC).
 * @param e Deprecated ENGINE parameter; pass NULL.
 * @param pub Public key bytes in the algorithm's raw format.
 * @param len Length of @p pub in bytes.
 * @return New EVP_PKEY on success, or NULL on failure.
 */
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub,
    size_t len);
/**
 * @brief Export the raw private key bytes of @p pkey into @p priv.
 * @param pkey Key whose private material is exported (algorithm-dependent format).
 * @param priv Output buffer, or NULL to only query the required length via @p len.
 * @param len On entry, capacity of @p priv when non-NULL; on return, number of bytes written or required.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
    size_t *len);
/**
 * @brief Export the raw public key bytes of @p pkey into @p pub.
 * @param pkey Key whose public material is exported (algorithm-dependent format).
 * @param pub Output buffer, or NULL to only query the required length via @p len.
 * @param len On entry, capacity of @p pub when non-NULL; on return, number of bytes written or required.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
    size_t *len);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Create an EVP_PKEY wrapping a CMAC key (deprecated).
 * @param e Unused legacy ENGINE parameter; pass NULL.
 * @param priv CMAC key bytes.
 * @param len Length of @p priv in bytes.
 * @param cipher Block cipher underlying the CMAC (for example AES-128-CBC).
 * @return New EVP_PKEY of type EVP_PKEY_CMAC, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
    size_t len, const EVP_CIPHER *cipher);
#endif

/**
 * @brief Attach implementation-private data to a key context.
 * @param ctx Key context to update.
 * @param data Opaque pointer stored on @p ctx (not freed by OpenSSL).
 */
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);
/**
 * @brief Return the application-private data pointer previously set on a key context.
 * @param ctx Key context to query.
 * @return Opaque pointer from EVP_PKEY_CTX_set_data(), or NULL if unset.
 */
void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx);
/**
 * @brief Return the primary EVP_PKEY associated with a key context.
 * @param ctx Key context to query.
 * @return Key pointer owned by @p ctx (do not free), or NULL if unset.
 */
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);

/**
 * @brief Return the peer key previously set on a derive context.
 * @param ctx Key context that may hold a peer key from EVP_PKEY_derive_set_peer().
 * @return Peer EVP_PKEY owned by @p ctx (do not free), or NULL if unset.
 */
EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);

/**
 * @brief Store an opaque application pointer on a key context.
 * @param ctx Key context to update.
 * @param data Caller-owned pointer retrieved later with EVP_PKEY_CTX_get_app_data().
 */
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);
/**
 * @brief Return the opaque application pointer previously stored on a key context.
 * @param ctx Key context to query.
 * @return Pointer set with EVP_PKEY_CTX_set_app_data(), or NULL if unset.
 */
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);

/**
 * @brief Free a fetched EVP_SIGNATURE method and release its provider reference.
 * @param signature Signature algorithm object to free, or NULL (no-op).
 */
void EVP_SIGNATURE_free(EVP_SIGNATURE *signature);
/**
 * @brief Increment the reference count on a fetched EVP_SIGNATURE algorithm.
 * @param signature Signature algorithm from EVP_SIGNATURE_fetch().
 * @return 1 on success, or 0 on failure.
 */
int EVP_SIGNATURE_up_ref(EVP_SIGNATURE *signature);
/**
 * @brief Return the provider that implements a fetched EVP_SIGNATURE algorithm.
 * @param signature Signature algorithm object from EVP_SIGNATURE_fetch().
 * @return Borrowed OSSL_PROVIDER pointer (do not free), or NULL if unset.
 */
OSSL_PROVIDER *EVP_SIGNATURE_get0_provider(const EVP_SIGNATURE *signature);
/**
 * @brief Fetch a signature algorithm implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Signature algorithm name (for example "RSA" or "ED25519").
 * @param properties Optional property query string, or NULL.
 * @return Fetched EVP_SIGNATURE (free with EVP_SIGNATURE_free()), or NULL on failure.
 */
EVP_SIGNATURE *EVP_SIGNATURE_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Test whether a signature algorithm implementation matches a name.
 * @param signature Signature algorithm object to query.
 * @param name Algorithm name (for example "RSA" or "ED25519").
 * @return 1 if @p signature is known as @p name, or 0 otherwise.
 */
int EVP_SIGNATURE_is_a(const EVP_SIGNATURE *signature, const char *name);
/**
 * @brief Return the primary algorithm name of a signature implementation.
 * @param signature Signature algorithm object from EVP_SIGNATURE_fetch().
 * @return NUL-terminated name string owned by @p signature, or NULL if unavailable.
 */
const char *EVP_SIGNATURE_get0_name(const EVP_SIGNATURE *signature);
/**
 * @brief Return a human-readable description of a signature algorithm implementation.
 * @param signature Signature algorithm object from EVP_SIGNATURE_fetch().
 * @return NUL-terminated description string owned by @p signature, or NULL if none is available.
 */
const char *EVP_SIGNATURE_get0_description(const EVP_SIGNATURE *signature);
/**
 * @brief Call @p fn for every signature algorithm implementation available from providers.
 * @param libctx Library context whose providers are queried, or NULL for the default context.
 * @param fn Callback invoked once per EVP_SIGNATURE; must not free @p signature.
 * @param data Opaque pointer passed through to @p fn.
 */
void EVP_SIGNATURE_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_SIGNATURE *signature,
        void *data),
    void *data);
/**
 * @brief Call @p fn for every name (including aliases) associated with a signature algorithm.
 * @param signature Signature algorithm whose names are enumerated.
 * @param fn Callback receiving each algorithm name and @p data.
 * @param data Opaque pointer passed through to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_SIGNATURE_names_do_all(const EVP_SIGNATURE *signature,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return the OSSL_PARAM descriptors gettable on a signature context for @p sig.
 * @param sig Signature algorithm whose gettable context parameters are listed.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig);
/**
 * @brief Return the OSSL_PARAM descriptors settable on a signature context for @p sig.
 * @param sig Signature algorithm whose settable context parameters are listed.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_SIGNATURE_settable_ctx_params(const EVP_SIGNATURE *sig);

/**
 * @brief Release a reference to a fetched asymmetric cipher algorithm.
 * @param cipher Algorithm to free; NULL is ignored.
 */
void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER *cipher);
/**
 * @brief Increment the reference count on a fetched asymmetric cipher algorithm.
 * @param cipher Algorithm object whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER *cipher);
/**
 * @brief Return the provider that implemented an asymmetric cipher algorithm.
 * @param cipher Asymmetric cipher method to query.
 * @return Provider pointer (do not free), or NULL if unavailable.
 */
OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher);
/**
 * @brief Fetch an asymmetric cipher (encrypt/decrypt) algorithm from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name (for example "RSA").
 * @param properties Optional property query string, or NULL.
 * @return Fetched EVP_ASYM_CIPHER (free with EVP_ASYM_CIPHER_free()), or NULL on failure.
 */
EVP_ASYM_CIPHER *EVP_ASYM_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Test whether an asymmetric cipher implementation matches a name.
 * @param cipher Asymmetric cipher algorithm object to query.
 * @param name Algorithm name (for example "RSA").
 * @return 1 if @p cipher is known as @p name, or 0 otherwise.
 */
int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER *cipher, const char *name);
/**
 * @brief Return the primary algorithm name of an asymmetric cipher.
 * @param cipher Asymmetric cipher algorithm to query.
 * @return Internal name string (do not free), or NULL if unset.
 */
const char *EVP_ASYM_CIPHER_get0_name(const EVP_ASYM_CIPHER *cipher);
/**
 * @brief Return a human-readable description of an asymmetric cipher algorithm.
 * @param cipher Asymmetric cipher to query.
 * @return Description string (do not free), or NULL if none is available.
 */
const char *EVP_ASYM_CIPHER_get0_description(const EVP_ASYM_CIPHER *cipher);
/**
 * @brief Invoke @p fn for every asymmetric cipher algorithm available in @p libctx.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each fetched cipher and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_ASYM_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_ASYM_CIPHER *cipher,
        void *arg),
    void *arg);
/**
 * @brief Call @p fn for each synonymous name of an asymmetric-cipher algorithm implementation.
 * @param cipher Asymmetric cipher method whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_ASYM_CIPHER_names_do_all(const EVP_ASYM_CIPHER *cipher,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from an asymmetric-cipher context.
 * @param ciph Asymmetric cipher algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_ASYM_CIPHER_gettable_ctx_params(const EVP_ASYM_CIPHER *ciph);
/**
 * @brief Describe OSSL_PARAM keys settable on asymmetric-cipher contexts for @p ciph.
 * @param ciph Asymmetric cipher algorithm to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_ASYM_CIPHER_settable_ctx_params(const EVP_ASYM_CIPHER *ciph);

/**
 * @brief Decrement the reference count of a fetched KEM and free it when it reaches zero.
 * @param wrap KEM object from EVP_KEM_fetch(), or NULL.
 */
void EVP_KEM_free(EVP_KEM *wrap);
/**
 * @brief Increment the reference count on a fetched KEM algorithm.
 * @param wrap KEM object whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEM_up_ref(EVP_KEM *wrap);
/**
 * @brief Return the provider that implemented a fetched EVP_KEM algorithm.
 * @param wrap KEM method from EVP_KEM_fetch().
 * @return Provider handle, or NULL if unavailable; do not free.
 */
OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *wrap);
/**
 * @brief Fetch a key-encapsulation mechanism implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "RSA" or a provider KEM name.
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEM, or NULL on error; free with EVP_KEM_free.
 */
EVP_KEM *EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Test whether a KEM implementation is known by a given name.
 * @param wrap KEM method to query.
 * @param name Algorithm name or alias to compare.
 * @return 1 if @p wrap matches @p name, or 0 otherwise.
 */
int EVP_KEM_is_a(const EVP_KEM *wrap, const char *name);
/**
 * @brief Return the primary name of a fetched KEM algorithm.
 * @param wrap KEM implementation from EVP_KEM_fetch().
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEM_get0_name(const EVP_KEM *wrap);
/**
 * @brief Return a human-readable description of a fetched KEM algorithm.
 * @param wrap KEM implementation from EVP_KEM_fetch().
 * @return Internal description string, or NULL; do not free.
 */
const char *EVP_KEM_get0_description(const EVP_KEM *wrap);
/**
 * @brief Call @p fn for every KEM algorithm available from providers in @p libctx.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback invoked with each EVP_KEM and @p arg.
 * @param arg User argument forwarded to @p fn.
 */
void EVP_KEM_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEM *wrap, void *arg), void *arg);
/**
 * @brief Invoke @p fn for each name synonym associated with a KEM algorithm.
 * @param wrap KEM algorithm object from EVP_KEM_fetch().
 * @param fn Callback receiving each algorithm name and @p data.
 * @param data Opaque pointer passed through to @p fn.
 * @return 1 if all names were processed, or 0 if @p fn requested an early stop / on error.
 */
int EVP_KEM_names_do_all(const EVP_KEM *wrap,
    void (*fn)(const char *name, void *data), void *data);
/**
 * @brief Return the context parameters that can be read from a KEM algorithm.
 * @param kem KEM algorithm to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEM_gettable_ctx_params(const EVP_KEM *kem);
/**
 * @brief Return the OSSL_PARAM descriptors settable on a KEM operation context.
 * @param kem KEM algorithm whose settable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEM_settable_ctx_params(const EVP_KEM *kem);

/**
 * @brief Initialize a key context for signing with the key bound to @p ctx.
 * @param ctx Key context created for a signing-capable algorithm.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for signing and apply optional algorithm parameters.
 * @param ctx Key context created for a signing-capable algorithm.
 * @param params Optional OSSL_PARAM array set on the context before return, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_sign_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Create a signature over data using an initialized signing context.
 * @param ctx Context previously prepared with EVP_PKEY_sign_init() (and optional controls).
 * @param sig Output buffer for the signature, or NULL to only query the required length.
 * @param siglen On entry, capacity of @p sig when non-NULL; on return, signature length in bytes.
 * @param tbs Message or digest bytes to sign.
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 on success, 0 or a negative value on failure.
 */
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
    unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen);
/**
 * @brief Initialise a key context for signature verification with the key bound to @p ctx.
 * @param ctx Key context holding the public key (or key pair) used to verify.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialise @p ctx for signature verification with optional parameters.
 * @param ctx Key context holding the public key (or key pair) used to verify.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Verify a signature over @p tbs using an initialised key context.
 * @param ctx Context previously prepared with EVP_PKEY_verify_init() or _ex().
 * @param sig Signature bytes to verify.
 * @param siglen Length of @p sig in bytes.
 * @param tbs Data that was signed (typically a digest or raw message).
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);
/**
 * @brief Initialize a key context for signature recovery (typically RSA).
 * @param ctx Key context created for a verify-recover-capable algorithm.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for signature recovery and apply algorithm parameters.
 * @param ctx Key context prepared for verify-recover (typically RSA).
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_verify_recover_init_ex(EVP_PKEY_CTX *ctx,
    const OSSL_PARAM params[]);
/**
 * @brief Recover the signed data from a signature (algorithms that support recovery, e.g. RSA).
 * @param ctx Context previously prepared with EVP_PKEY_verify_recover_init().
 * @param rout Output buffer for the recovered data, or NULL to only query the required length.
 * @param routlen On entry, capacity of @p rout when non-NULL; on return, recovered length in bytes.
 * @param sig Signature bytes to recover from.
 * @param siglen Length of @p sig in bytes.
 * @return 1 on success, 0 or a negative value on failure.
 */
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
    unsigned char *rout, size_t *routlen,
    const unsigned char *sig, size_t siglen);
/**
 * @brief Initialise @p ctx for public-key encryption.
 * @param ctx Key context holding the public key (or key pair) used to encrypt.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize a key context for public-key encryption with optional parameters.
 * @param ctx Context holding the public key for encryption.
 * @param params Optional OSSL_PARAM array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Encrypt data with a public key using a context from EVP_PKEY_encrypt_init().
 * @param ctx Encryption context holding the public key.
 * @param out Output buffer for ciphertext, or NULL to query the required size via @p outlen.
 * @param outlen On entry, capacity of @p out when non-NULL; on return, bytes written or required.
 * @param in Plaintext bytes to encrypt.
 * @param inlen Length of @p in in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
/**
 * @brief Initialise @p ctx for private-key decryption.
 * @param ctx Key context holding the private key used to decrypt.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for decryption and apply optional algorithm parameters.
 * @param ctx Key context associated with the decryption key.
 * @param params Optional OSSL_PARAM array configuring the operation, or NULL.
 * @return 1 on success, or 0 / negative on failure.
 */
int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Decrypt data using the private key bound to @p ctx.
 * @param ctx Context previously initialized with EVP_PKEY_decrypt_init().
 * @param out Buffer receiving plaintext, or NULL to query the required size.
 * @param outlen In/out length of @p out; on return holds bytes written or needed.
 * @param in Ciphertext bytes to decrypt.
 * @param inlen Length of @p in in bytes.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);

/**
 * @brief Initialize a key context for shared-secret derivation (key exchange).
 * @param ctx Context created for a key-exchange algorithm.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for key derivation and apply optional algorithm parameters.
 * @param ctx Key context created for a derivation-capable algorithm.
 * @param params Optional OSSL_PARAM array set on the context before return, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Set the peer public key for derivation, optionally validating it first.
 * @param ctx Derivation context previously initialized with EVP_PKEY_derive_init() or _ex().
 * @param peer Peer's public key used to compute the shared secret.
 * @param validate_peer Non-zero to run a public-key check on @p peer before use, or 0 to skip.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *ctx, EVP_PKEY *peer,
    int validate_peer);
/**
 * @brief Set the peer public key used by EVP_PKEY_derive() on a derivation context.
 * @param ctx Initialized derive context from EVP_PKEY_derive_init().
 * @param peer Peer public key; ownership is not transferred.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
/**
 * @brief Derive a shared secret using a context initialized with EVP_PKEY_derive_init().
 * @param ctx Key derivation context that already has a peer key configured when required.
 * @param key Output buffer for the shared secret, or NULL to query the required length.
 * @param keylen On input, size of @p key; on output, number of bytes written or required.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

/**
 * @brief Initialize a key context for a key-encapsulation (KEM) encapsulate operation.
 * @param ctx Context holding the recipient public key.
 * @param params Optional OSSL_PARAM array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Initialize authenticated key encapsulation using a peer public key and auth private key.
 * @param ctx Context created for a KEM algorithm (recipient/public key already set as needed).
 * @param authpriv Private key used for authentication during encapsulation.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_auth_encapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpriv,
    const OSSL_PARAM params[]);
/**
 * @brief Perform key encapsulation: produce a wrapped key and a shared secret.
 * @param ctx Context previously initialized with EVP_PKEY_encapsulate_init().
 * @param wrappedkey Buffer receiving the encapsulated key, or NULL to query lengths.
 * @param wrappedkeylen In/out length of @p wrappedkey.
 * @param genkey Buffer receiving the generated shared secret, or NULL to query lengths.
 * @param genkeylen In/out length of @p genkey.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *wrappedkey, size_t *wrappedkeylen,
    unsigned char *genkey, size_t *genkeylen);
/**
 * @brief Initialise a key context for KEM decapsulation.
 * @param ctx Key context holding the recipient private key.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Initialize authenticated decapsulation on @p ctx using an authentication public key.
 * @param ctx Key context for a KEM / encapsulate-capable algorithm.
 * @param authpub Authentication public key used by the authenticated decapsulation operation.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_auth_decapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpub,
    const OSSL_PARAM params[]);
/**
 * @brief Decapsulate a shared secret from a KEM ciphertext using a context from EVP_PKEY_decapsulate_init().
 * @param ctx Decapsulation context holding the private key.
 * @param unwrapped Buffer for the recovered shared secret, or NULL to query size via @p unwrappedlen.
 * @param unwrappedlen On entry, capacity of @p unwrapped when non-NULL; on return, bytes written or required.
 * @param wrapped Encapsulation ciphertext bytes.
 * @param wrappedlen Length of @p wrapped in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *unwrapped, size_t *unwrappedlen,
    const unsigned char *wrapped, size_t wrappedlen);
/**
 * @brief Callback type invoked during key or parameter generation to report progress or cancel.
 * @param ctx Generation context; query progress via EVP_PKEY_CTX_get_keygen_info().
 * @return Nonzero to continue, or 0 to abort generation with an error.
 */
typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);

/**
 * @brief Prepare a key context to import key material via EVP_PKEY_fromdata().
 * @param ctx Context created for the target key type (for example with EVP_PKEY_CTX_new_from_name).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Build an EVP_PKEY (or parameters) from an OSSL_PARAM array after fromdata_init.
 * @param ctx Context previously prepared with EVP_PKEY_fromdata_init().
 * @param ppkey Destination that receives the created EVP_PKEY on success.
 * @param selection OSSL_KEYMGMT_SELECT_* mask describing which key parts @p param supplies.
 * @param param NULL-terminated OSSL_PARAM array of key material / parameters.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection,
    OSSL_PARAM param[]);
/**
 * @brief Return the OSSL_PARAM descriptors accepted by EVP_PKEY_fromdata() for @p selection.
 * @param ctx Key context created for the target algorithm.
 * @param selection OSSL_KEYMGMT_SELECT_* bitmask describing which key components are imported.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_fromdata_settable(EVP_PKEY_CTX *ctx, int selection);

/**
 * @brief Export selected key components from an EVP_PKEY as a newly allocated OSSL_PARAM array.
 * @param pkey Provider-backed key to export.
 * @param selection OSSL_KEYMGMT_SELECT_* mask describing which parts to export.
 * @param params Receives a newly allocated parameter array; free with OSSL_PARAM_free().
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_todata(const EVP_PKEY *pkey, int selection, OSSL_PARAM **params);
/**
 * @brief Export selected key parameters from an EVP_PKEY via a callback.
 * @param pkey Provider-backed key to export.
 * @param selection OSSL_KEYMGMT_SELECT_* mask describing which parts to export.
 * @param export_cb Callback invoked with a temporary OSSL_PARAM array (not valid after return).
 * @param export_cbarg Application argument passed to @p export_cb.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_export(const EVP_PKEY *pkey, int selection,
    OSSL_CALLBACK *export_cb, void *export_cbarg);

/**
 * @brief Return the OSSL_PARAM descriptors for parameters retrievable from @p pkey.
 * @param pkey Key whose gettable parameter names and types are listed.
 * @return Constant OSSL_PARAM array, or NULL on error.
 */
const OSSL_PARAM *EVP_PKEY_gettable_params(const EVP_PKEY *pkey);
/**
 * @brief Retrieve key parameters from @p pkey into the caller-supplied OSSL_PARAM array.
 * @param pkey Key whose parameters are read.
 * @param params Array of OSSL_PARAM entries requesting named values (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_params(const EVP_PKEY *pkey, OSSL_PARAM params[]);
/**
 * @brief Read an integer parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name such as OSSL_PKEY_PARAM_BITS.
 * @param out Receives the integer value.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_int_param(const EVP_PKEY *pkey, const char *key_name,
    int *out);
/**
 * @brief Fetch a named size_t parameter from an EVP_PKEY.
 * @param pkey Key to query.
 * @param key_name Parameter name (OSSL_PKEY_PARAM_*).
 * @param out On success, receives the parameter value.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_size_t_param(const EVP_PKEY *pkey, const char *key_name,
    size_t *out);
/**
 * @brief Fetch a named BIGNUM parameter from an EVP_PKEY.
 * @param pkey Key to query.
 * @param key_name Parameter name (OSSL_PKEY_PARAM_*).
 * @param bn On success, set to a newly allocated BIGNUM (caller frees with BN_free()).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name,
    BIGNUM **bn);
/**
 * @brief Read a UTF-8 string parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name such as OSSL_PKEY_PARAM_GROUP_NAME.
 * @param str Output buffer for the NUL-terminated string, or NULL to query size only.
 * @param max_buf_sz Capacity of @p str in bytes.
 * @param out_sz Optional pointer receiving the required/written length including NUL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_utf8_string_param(const EVP_PKEY *pkey, const char *key_name,
    char *str, size_t max_buf_sz, size_t *out_sz);
/**
 * @brief Read an octet-string parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name (for example OSSL_PKEY_PARAM_PUB_KEY).
 * @param buf Destination buffer, or NULL to only query the required size.
 * @param max_buf_sz Capacity of @p buf in bytes.
 * @param out_sz Receives the parameter length in bytes.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
    unsigned char *buf, size_t max_buf_sz,
    size_t *out_sz);

/**
 * @brief Return the parameters that may be set on an EVP_PKEY.
 * @param pkey Key to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_settable_params(const EVP_PKEY *pkey);
/**
 * @brief Set multiple algorithm parameters on an EVP_PKEY from an OSSL_PARAM array.
 * @param pkey Key to update.
 * @param params Parameters to apply (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_params(EVP_PKEY *pkey, OSSL_PARAM params[]);
/**
 * @brief Set a named integer parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param in Integer value to assign.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_int_param(EVP_PKEY *pkey, const char *key_name, int in);
/**
 * @brief Set a named size_t parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param in Size value to assign.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_size_t_param(EVP_PKEY *pkey, const char *key_name, size_t in);
/**
 * @brief Set a named BIGNUM parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param bn Integer value to assign (copied; caller retains ownership of @p bn).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name,
    const BIGNUM *bn);
/**
 * @brief Set a UTF-8 string algorithm parameter on an EVP_PKEY by name.
 * @param pkey Key whose provider-side parameters are updated.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param str NUL-terminated UTF-8 value to assign (copied).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_utf8_string_param(EVP_PKEY *pkey, const char *key_name,
    const char *str);
/**
 * @brief Set a named octet-string parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param buf Octet string value to assign (copied).
 * @param bsize Length of @p buf in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key_name,
    const unsigned char *buf, size_t bsize);

/**
 * @brief Return the EC point conversion form stored on an elliptic-curve EVP_PKEY.
 * @param pkey EC or SM2 key (other types return 0 unless a provider supports them).
 * @return Point conversion form (see EC_GROUP_get_point_conversion_form), or 0 on error.
 */
int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY *pkey);
/**
 * @brief Return the EC field type NID for an elliptic-curve EVP_PKEY.
 * @param pkey EC key to query.
 * @return NID_X9_62_prime_field or NID_X9_62_characteristic_two_field, or 0 on error / non-EC keys.
 */
int EVP_PKEY_get_field_type(const EVP_PKEY *pkey);

/**
 * @brief Quickly generate a key of algorithm @p type using varargs size/curve parameters.
 * @param libctx Library context for fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @param type Algorithm name (for example "RSA", "EC", "ED25519").
 * @return Newly allocated EVP_PKEY, or NULL on failure; free with EVP_PKEY_free().
 */
EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
    const char *type, ...);
/**
 * @brief Initialise a key context for algorithm parameter generation.
 * @param ctx Context prepared for a parameter-generation-capable algorithm.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Generate algorithm parameters into *@p ppkey using an initialised paramgen context.
 * @param ctx Context prepared with EVP_PKEY_paramgen_init() (and any controls).
 * @param ppkey Address of an EVP_PKEY pointer that receives the parameters (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
/**
 * @brief Initialise a key context for key-pair generation.
 * @param ctx Context created for the target algorithm (for example via EVP_PKEY_CTX_new_id).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Generate a key pair into *@p ppkey using an initialised keygen context.
 * @param ctx Context prepared with EVP_PKEY_keygen_init() (and any controls).
 * @param ppkey Address of an EVP_PKEY pointer that receives the new key (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
/**
 * @brief Generate parameters or a key pair into *@p ppkey (unified keygen/paramgen entry).
 * @param ctx Context prepared with EVP_PKEY_keygen_init() or EVP_PKEY_paramgen_init().
 * @param ppkey Address of an EVP_PKEY pointer that receives the new object (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
/**
 * @brief Validate the key associated with a key context (public/private consistency checks).
 * @param ctx Context whose key is checked (from EVP_PKEY_CTX_new or similar).
 * @return 1 if the key is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
/**
 * @brief Validate the public key associated with a key context.
 * @param ctx Context whose key is checked (from EVP_PKEY_CTX_new or similar).
 * @return 1 if the public key is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);
/**
 * @brief Perform a fast (non-exhaustive) public-key validity check.
 * @param ctx Context whose key is checked (from EVP_PKEY_CTX_new or similar).
 * @return 1 if the key appears valid, 0 if invalid, or a negative value on error.
 *
 * Skips expensive checks that EVP_PKEY_public_check() may perform for some algorithms.
 */
int EVP_PKEY_public_check_quick(EVP_PKEY_CTX *ctx);
/**
 * @brief Validate domain parameters associated with a key context.
 * @param ctx Context holding parameters (or a key that embeds them).
 * @return 1 if parameters are valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx);
/**
 * @brief Perform a fast/lightweight validation of domain parameters on a key context.
 * @param ctx Context holding parameters (or a key that embeds them).
 * @return 1 if parameters pass the quick check, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_param_check_quick(EVP_PKEY_CTX *ctx);
/**
 * @brief Validate the private key associated with a key context.
 * @param ctx Context holding the key to check (typically created with EVP_PKEY_CTX_new).
 * @return 1 if the private key is valid, or a non-positive value on failure.
 */
int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx);
/**
 * @brief Validate that the public and private components of a key form a consistent pair.
 * @param ctx Context holding the key to check (typically created with EVP_PKEY_CTX_new).
 * @return 1 if the key pair is consistent, 0 if not, or a negative value on error.
 */
int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);

#define EVP_PKEY_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EVP_PKEY, l, p, newf, dupf, freef)
/**
 * @brief Store application-specific data on an EVP_PKEY at a CRYPTO ex_data index.
 * @param key Key that owns the ex_data table.
 * @param idx Index obtained from EVP_PKEY_get_ex_new_index() (or a reserved index).
 * @param arg Pointer to store; ownership remains with the caller unless free callbacks manage it.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_ex_data(EVP_PKEY *key, int idx, void *arg);
/**
 * @brief Retrieve application-specific data previously stored on an EVP_PKEY.
 * @param key Key to query.
 * @param idx Index previously used with EVP_PKEY_set_ex_data().
 * @return Stored pointer, or NULL if unset or on error.
 */
void *EVP_PKEY_get_ex_data(const EVP_PKEY *key, int idx);

/**
 * @brief Install a progress callback for key/parameter generation on a context.
 * @param ctx Key context used for keygen/paramgen.
 * @param cb Generation callback, or NULL to clear.
 */
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);
/**
 * @brief Return the keygen progress callback currently installed on a key context.
 * @param ctx Key context to query.
 * @return Callback pointer, or NULL if none is set.
 */
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);

/**
 * @brief Return a key-generation progress info value previously published on @p ctx.
 * @param ctx Key context during or after keygen.
 * @param idx Info index; -1 returns the number of available values.
 * @return Info value at @p idx, or the count when @p idx is -1.
 */
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Set the context-init callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed with EVP_PKEY_meth_new().
 * @param init Callback invoked when an EVP_PKEY_CTX using @p pmeth is created.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
    int (*init)(EVP_PKEY_CTX *ctx));
/**
 * @brief Set the context-copy callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param copy Callback that copies operation state from @p src into @p dst, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth, int (*copy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));
/**
 * @brief Set the context-cleanup callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param cleanup Callback that releases operation-specific state on @p ctx, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, void (*cleanup)(EVP_PKEY_CTX *ctx));
/**
 * @brief Set parameter-generation callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param paramgen_init Optional initialiser called from EVP_PKEY_paramgen_init(), or NULL.
 * @param paramgen Callback that writes parameters into @p pkey, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, int (*paramgen_init)(EVP_PKEY_CTX *ctx),
    int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
/**
 * @brief Set key-generation callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param keygen_init Optional initialiser called from EVP_PKEY_keygen_init(), or NULL.
 * @param keygen Callback that writes a new key into @p pkey, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth, int (*keygen_init)(EVP_PKEY_CTX *ctx),
    int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
/**
 * @brief Set the signing callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param sign_init Optional initialization callback before signing, or NULL.
 * @param sign Callback that produces a signature over @p tbs into @p sig.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth, int (*sign_init)(EVP_PKEY_CTX *ctx),
    int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
/**
 * @brief Set the signature-verification callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param verify_init Optional initialization callback before verification, or NULL.
 * @param verify Callback that verifies @p sig over @p tbs.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, int (*verify_init)(EVP_PKEY_CTX *ctx),
    int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen));
/**
 * @brief Set verify-recover init/operation callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed.
 * @param verify_recover_init Callback that prepares @p ctx for verify-recover.
 * @param verify_recover Callback that recovers the encoded digest from a signature.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, int (*verify_recover_init)(EVP_PKEY_CTX *ctx),
    int (*verify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, const unsigned char *tbs,
        size_t tbslen));
/**
 * @brief Set digest-context signing callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param signctx_init Optional initialiser called before streaming sign, or NULL.
 * @param signctx Callback that produces @p sig from digest state in @p mctx, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));
/**
 * @brief Set digest-context verification callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param verifyctx_init Optional initialiser called before streaming verify, or NULL.
 * @param verifyctx Callback that verifies @p sig against digest state in @p mctx, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth, int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
        EVP_MD_CTX *mctx));
/**
 * @brief Set public-key encryption callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param encrypt_init Optional initialiser called from EVP_PKEY_encrypt_init(), or NULL.
 * @param encryptfn Callback that encrypts @p in into @p out / *@p outlen, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth, int (*encrypt_init)(EVP_PKEY_CTX *ctx),
    int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
/**
 * @brief Set public-key decryption callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param decrypt_init Optional initialiser called from EVP_PKEY_decrypt_init(), or NULL.
 * @param decrypt Callback that decrypts @p in into @p out / *@p outlen, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth, int (*decrypt_init)(EVP_PKEY_CTX *ctx),
    int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
/**
 * @brief Install key-derivation init/derive callbacks on a legacy EVP_PKEY_METHOD.
 * @param pmeth Method table to update.
 * @param derive_init Optional initializer invoked by EVP_PKEY_derive_init(), or NULL.
 * @param derive Callback that writes the shared secret / derived key.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth, int (*derive_init)(EVP_PKEY_CTX *ctx),
    int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
/**
 * @brief Set the ctrl / ctrl_str callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param ctrl Integer control callback (EVP_PKEY_CTX_ctrl), or NULL.
 * @param ctrl_str String control callback (EVP_PKEY_CTX_ctrl_str), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth, int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value));
/**
 * @brief Set the one-shot DigestSign callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digestsign Callback implementing EVP_DigestSign()-style signing, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD *pmeth,
    int (*digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
/**
 * @brief Set the one-shot DigestVerify callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digestverify Callback implementing EVP_DigestVerify()-style verification, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD *pmeth,
    int (*digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));
/**
 * @brief Set the pairwise key-consistency check callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param check Callback invoked by EVP_PKEY_check(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
/**
 * @brief Set the public-component check callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param check Callback invoked by EVP_PKEY_public_check(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
/**
 * @brief Set the domain-parameter validation callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed.
 * @param check Callback that returns 1 if @p pkey parameters are valid, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
/**
 * @brief Set the digest_custom callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digest_custom Callback invoked by EVP_DigestSignInit()/VerifyInit() to hash algorithm-specific prefix data (for example SM2), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth, int (*digest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
/**
 * @brief Retrieve the init callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method object to query.
 * @param pinit Receives the function pointer that initializes an EVP_PKEY_CTX.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth, int (**pinit)(EVP_PKEY_CTX *ctx));
/**
 * @brief Retrieve the context-copy callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pcopy Receives the copy callback pointer (may be set to NULL if unset).
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth, int (**pcopy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));
/**
 * @brief Retrieve the context-cleanup callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pcleanup Receives the cleanup callback pointer (may be set to NULL if unset).
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth, void (**pcleanup)(EVP_PKEY_CTX *ctx));
/**
 * @brief Retrieve parameter-generation callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pparamgen_init Receives the paramgen_init callback pointer, or NULL.
 * @param pparamgen Receives the paramgen callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth, int (**pparamgen_init)(EVP_PKEY_CTX *ctx),
    int (**pparamgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
/**
 * @brief Retrieve key-generation callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pkeygen_init Receives the keygen_init callback pointer, or NULL.
 * @param pkeygen Receives the keygen callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth, int (**pkeygen_init)(EVP_PKEY_CTX *ctx),
    int (**pkeygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
/**
 * @brief Retrieve the sign_init and sign callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method whose sign hooks are read.
 * @param psign_init Receives the sign_init function pointer, or NULL to skip.
 * @param psign Receives the sign function pointer, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_sign(const EVP_PKEY_METHOD *pmeth, int (**psign_init)(EVP_PKEY_CTX *ctx),
    int (**psign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
/**
 * @brief Retrieve the verify-init and verify callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pverify_init Receives the verify-init callback pointer.
 * @param pverify Receives the verify callback pointer.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth, int (**pverify_init)(EVP_PKEY_CTX *ctx),
    int (**pverify)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs, size_t tbslen));
/**
 * @brief Retrieve the verify-recover callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pverify_recover_init Receives the verify-recover-init callback pointer.
 * @param pverify_recover Receives the verify-recover callback pointer.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth,
    int (**pverify_recover_init)(EVP_PKEY_CTX *ctx),
    int (**pverify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, const unsigned char *tbs,
        size_t tbslen));
/**
 * @brief Retrieve digest-context signing callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param psignctx_init Receives the signctx_init callback pointer, or NULL.
 * @param psignctx Receives the signctx callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth,
    int (**psignctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**psignctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));
/**
 * @brief Retrieve digest-context verification callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pverifyctx_init Receives the verifyctx_init callback pointer, or NULL.
 * @param pverifyctx Receives the verifyctx callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth,
    int (**pverifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**pverifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        int siglen, EVP_MD_CTX *mctx));
/**
 * @brief Retrieve public-key encryption callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pencrypt_init Optional destination for the encrypt_init function pointer, or NULL.
 * @param pencryptfn Optional destination for the encrypt function pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth, int (**pencrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pencryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
/**
 * @brief Return the decrypt_init and decrypt callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pdecrypt_init Optional destination for the decrypt_init function pointer, or NULL.
 * @param pdecrypt Optional destination for the decrypt function pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth, int (**pdecrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pdecrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
/**
 * @brief Retrieve derive_init / derive callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method object to query.
 * @param pderive_init Receives the derive_init callback, or NULL to skip.
 * @param pderive Receives the derive callback, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, int (**pderive_init)(EVP_PKEY_CTX *ctx),
    int (**pderive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
/**
 * @brief Retrieve the ctrl / ctrl_str callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pctrl Optional destination for the integer ctrl callback, or NULL.
 * @param pctrl_str Optional destination for the string ctrl callback, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth,
    int (**pctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (**pctrl_str)(EVP_PKEY_CTX *ctx, const char *type,
        const char *value));
/**
 * @brief Retrieve the one-shot digestsign callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param digestsign Receives the digestsign callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestsign(const EVP_PKEY_METHOD *pmeth,
    int (**digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
/**
 * @brief Retrieve the one-shot digestverify callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param digestverify Receives the digestverify callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestverify(const EVP_PKEY_METHOD *pmeth,
    int (**digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));
/**
 * @brief Retrieve the full key-check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));
/**
 * @brief Retrieve the public-key check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the public_check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));
/**
 * @brief Retrieve the parameter-check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the param_check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));
/**
 * @brief Retrieve the custom digest callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pdigest_custom Receives the digest_custom callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digest_custom(const EVP_PKEY_METHOD *pmeth,
    int (**pdigest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
#endif

/**
 * @brief Free a fetched key-exchange algorithm object.
 * @param exchange Object from EVP_KEYEXCH_fetch(); may be NULL.
 */
void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange);
/**
 * @brief Increment the reference count on a key-exchange algorithm object.
 * @param exchange Key-exchange method to retain.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange);
/**
 * @brief Fetch a key-exchange algorithm implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "DH" or "X25519".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEYEXCH, or NULL on error; free with EVP_KEYEXCH_free.
 */
EVP_KEYEXCH *EVP_KEYEXCH_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Return the provider that implements a key-exchange algorithm.
 * @param exchange Key-exchange method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL on error.
 */
OSSL_PROVIDER *EVP_KEYEXCH_get0_provider(const EVP_KEYEXCH *exchange);
/**
 * @brief Test whether a key-exchange implementation is known by @p name.
 * @param keyexch Key-exchange method to query.
 * @param name Algorithm name or alias.
 * @return 1 if @p keyexch matches @p name, or 0 otherwise.
 */
int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name);
/**
 * @brief Return the primary name of a fetched key-exchange algorithm.
 * @param keyexch Key-exchange implementation from EVP_KEYEXCH_fetch().
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEYEXCH_get0_name(const EVP_KEYEXCH *keyexch);
/**
 * @brief Return a human-readable description of a key-exchange algorithm.
 * @param keyexch Key-exchange method to query.
 * @return Description string (do not free), or NULL if none is available.
 */
const char *EVP_KEYEXCH_get0_description(const EVP_KEYEXCH *keyexch);
/**
 * @brief Invoke a callback for every key-exchange algorithm available from providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each EVP_KEYEXCH and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 */
void EVP_KEYEXCH_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYEXCH *keyexch, void *data),
    void *data);
/**
 * @brief Invoke a callback for every name associated with a key-exchange algorithm.
 * @param keyexch Fetched key-exchange implementation to enumerate names for.
 * @param fn Callback receiving each name string and @p data.
 * @param data User pointer passed through to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYEXCH_names_do_all(const EVP_KEYEXCH *keyexch,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Return the context parameters that can be read from a key-exchange algorithm.
 * @param keyexch Key-exchange method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEYEXCH_gettable_ctx_params(const EVP_KEYEXCH *keyexch);
/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on a key-exchange context.
 * @param keyexch Key-exchange implementation to query.
 * @return Constant OSSL_PARAM array for use with EVP_PKEY_CTX_set_params(), or NULL on error.
 */
const OSSL_PARAM *EVP_KEYEXCH_settable_ctx_params(const EVP_KEYEXCH *keyexch);

/**
 * @brief Register built-in algorithm modules with the EVP subsystem.
 *
 * Called during library initialisation so config-driven algorithm modules
 * are available; safe to ignore from application code.
 */
void EVP_add_alg_module(void);

/**
 * @brief Set the elliptic-curve / DH group name on a key or parameter context.
 * @param ctx Key context used for keygen/paramgen/derive.
 * @param name Group name (for example "P-256" or "ffdhe2048").
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);
/**
 * @brief Copy the elliptic-curve or DH group name from a key context into a caller buffer.
 * @param ctx Key context whose group / curve name is queried.
 * @param name Destination buffer for the NUL-terminated name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX *ctx, char *name, size_t namelen);
/**
 * @brief Copy the elliptic-curve or DH group name from a key into a caller buffer.
 * @param pkey Key whose group / curve name is queried.
 * @param name Optional destination buffer for the NUL-terminated name, or NULL to query length only.
 * @param name_sz Size of @p name in bytes.
 * @param gname_len Optional destination for the name length excluding NUL, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_group_name(const EVP_PKEY *pkey, char *name, size_t name_sz,
    size_t *gname_len);

/**
 * @brief Return the library context associated with a key algorithm context.
 * @param ctx Key context to query.
 * @return OSSL_LIB_CTX used when @p ctx was constructed, or NULL for the default.
 */
OSSL_LIB_CTX *EVP_PKEY_CTX_get0_libctx(EVP_PKEY_CTX *ctx);
/**
 * @brief Return the property query string associated with a key context.
 * @param ctx Key context to query.
 * @return Internal property query string (do not free), or NULL if none was set.
 */
const char *EVP_PKEY_CTX_get0_propq(const EVP_PKEY_CTX *ctx);
/**
 * @brief Return the provider that supplies the algorithm implementation used by @p ctx.
 * @param ctx Key context to query.
 * @return Provider pointer owned by OpenSSL, or NULL if no provider is associated.
 */
const OSSL_PROVIDER *EVP_PKEY_CTX_get0_provider(const EVP_PKEY_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
