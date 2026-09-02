/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_RSA_H
#define OPENSSL_RSA_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_RSA_H
#endif

#include <openssl/opensslconf.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/types.h>
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#include <openssl/bn.h>
#endif
#include <openssl/rsaerr.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
#define OPENSSL_RSA_MAX_MODULUS_BITS 16384
#endif

#define RSA_3 0x3L
#define RSA_F4 0x10001L

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* The types RSA and RSA_METHOD are defined in ossl_typ.h */

#define OPENSSL_RSA_FIPS_MIN_MODULUS_BITS 2048

#ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#endif

/* exponent limit enforced for "large" modulus only */
#ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
#define OPENSSL_RSA_MAX_PUBEXP_BITS 64
#endif
/* based on RFC 8017 appendix A.1.2 */
#define RSA_ASN1_VERSION_DEFAULT 0
#define RSA_ASN1_VERSION_MULTI 1

#define RSA_DEFAULT_PRIME_NUM 2

#define RSA_METHOD_FLAG_NO_CHECK 0x0001
#define RSA_FLAG_CACHE_PUBLIC 0x0002
#define RSA_FLAG_CACHE_PRIVATE 0x0004
#define RSA_FLAG_BLINDING 0x0008
#define RSA_FLAG_THREAD_SAFE 0x0010
/*
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag
 * bn_mod_exp gets called when private key components are absent.
 */
#define RSA_FLAG_EXT_PKEY 0x0020

/*
 * new with 0.9.6j and 0.9.7b; the built-in
 * RSA implementation now uses blinding by
 * default (ignoring RSA_FLAG_BLINDING),
 * but other engines might not need it
 */
#define RSA_FLAG_NO_BLINDING 0x0080
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define RSA_FLAG_NO_CONSTTIME 0x0000
#endif
/* deprecated name for the flag*/
/*
 * new with 0.9.7h; the built-in RSA
 * implementation now uses constant time
 * modular exponentiation for secret exponents
 * by default. This flag causes the
 * faster variable sliding window method to
 * be used for all exponents.
 */
#ifndef OPENSSL_NO_DEPRECATED_0_9_8
#define RSA_FLAG_NO_EXP_CONSTTIME RSA_FLAG_NO_CONSTTIME
#endif

/*-
 * New with 3.0: use part of the flags to denote exact type of RSA key,
 * some of which are limited to specific signature and encryption schemes.
 * These different types share the same RSA structure, but indicate the
 * use of certain fields in that structure.
 * Currently known are:
 * RSA          - this is the "normal" unlimited RSA structure (typenum 0)
 * RSASSA-PSS   - indicates that the PSS parameters are used.
 * RSAES-OAEP   - no specific field used for the moment, but OAEP padding
 *                is expected.  (currently unused)
 *
 * 4 bits allow for 16 types
 */
#define RSA_FLAG_TYPE_MASK 0xF000
#define RSA_FLAG_TYPE_RSA 0x0000
#define RSA_FLAG_TYPE_RSASSAPSS 0x1000
#define RSA_FLAG_TYPE_RSAESOAEP 0x2000

/**
 * @brief Set the RSA padding mode on an EVP_PKEY_CTX.
 * @param ctx Context used for RSA encrypt, decrypt, sign, or verify.
 * @param pad_mode Padding mode such as RSA_PKCS1_PADDING, RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_X931_PADDING, RSA_PKCS1_PSS_PADDING, or RSA_PKCS1_WITH_TLS_PADDING.
 * @return Positive value on success, or 0 / negative on failure (-2 if unsupported).
 */
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
/**
 * @brief Get the RSA padding mode configured on an EVP_PKEY_CTX.
 * @param ctx Context used for RSA encrypt, decrypt, sign, or verify.
 * @param pad_mode Receives the padding mode (for example RSA_PKCS1_PADDING).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode);

/**
 * @brief Set the RSA-PSS salt length for sign/verify on @p ctx.
 * @param ctx Key context for an RSA-PSS operation.
 * @param saltlen Salt length in bytes, or RSA_PSS_SALTLEN_* special values.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
/**
 * @brief Get the RSA-PSS salt length configured on an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must already be RSA_PKCS1_PSS_PADDING.
 * @param saltlen Receives the salt length (or a special RSA_PSS_SALTLEN_* value).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen);

/**
 * @brief Set the RSA modulus size in bits for key generation on an EVP_PKEY_CTX.
 * @param ctx Keygen context for an RSA algorithm.
 * @param bits Desired modulus length in bits (for example 2048 or 3072).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits);
/**
 * @brief Set the RSA public exponent for key generation, copying @p pubexp.
 * @param ctx Keygen context for an RSA algorithm.
 * @param pubexp Public exponent to copy (typically an odd integer such as 65537); caller retains ownership.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
/**
 * @brief Set how many primes to use when generating a multi-prime RSA key.
 * @param ctx Keygen context for an RSA key type.
 * @param primes Number of primes (2 for classic RSA; larger for multi-prime).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes);
/**
 * @brief Set the RSA-PSS salt length used when generating an RSA-PSS key.
 * @param ctx Keygen context for an RSA-PSS key type.
 * @param saltlen Salt length in bytes, or a special value such as RSA_PSS_SALTLEN_DIGEST.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Set the RSA public exponent used when generating a key (deprecated).
 * @param ctx Keygen EVP_PKEY_CTX for an RSA algorithm.
 * @param pubexp Public exponent to use; ownership is not transferred (use EVP_PKEY_CTX_set1_rsa_keygen_pubexp instead).
 * @return 1 on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
#endif

/* Salt length matches digest */
#define RSA_PSS_SALTLEN_DIGEST -1
/* Verify only: auto detect salt length */
#define RSA_PSS_SALTLEN_AUTO -2
/* Set salt length to maximum possible */
#define RSA_PSS_SALTLEN_MAX -3
/* Auto-detect on verify, set salt length to min(maximum possible, digest
 * length) on sign */
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4
/* Old compatible max salt length for sign only */
#define RSA_PSS_SALTLEN_MAX_SIGN -2

/**
 * @brief Set the MGF1 digest used for RSA-PSS or RSA-OAEP on a key context.
 * @param ctx RSA key context.
 * @param md Message digest for MGF1 (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Set the MGF1 digest for RSA-PSS or RSA-OAEP by algorithm name.
 * @param ctx Key operation context configured for RSA padding that uses MGF1.
 * @param mdname Digest name (for example "SHA256").
 * @param mdprops Optional property query for fetching @p mdname, or NULL.
 * @return 1 on success, or a negative value on failure.
 */
int EVP_PKEY_CTX_set_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
    const char *mdprops);
/**
 * @brief Get the MGF1 digest configured for RSA-PSS or RSA-OAEP on a key context.
 * @param ctx RSA key context.
 * @param md Receives a pointer to the digest method (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
/**
 * @brief Get the MGF1 digest algorithm name from an RSA EVP_PKEY_CTX.
 * @param ctx Context whose padding mode uses MGF1 (PSS or OAEP).
 * @param name Buffer receiving the NUL-terminated digest name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
/**
 * @brief Set the MGF1 digest used when generating an RSA-PSS key.
 * @param ctx Key-generation context for an RSA-PSS key.
 * @param md Digest used inside MGF1 (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Set the MGF1 digest name used when generating an RSA-PSS key.
 * @param ctx Keygen context for an RSA-PSS key type.
 * @param mdname Digest name such as "SHA256".
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname);

/**
 * @brief Set the message digest used when generating an RSA-PSS key.
 * @param ctx Key-generation context for an RSA-PSS key.
 * @param md Digest associated with the PSS parameters (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Set the message digest used when generating an RSA-PSS key via an EVP_PKEY_CTX.
 * @param ctx Keygen context for RSA-PSS.
 * @param mdname Digest name such as "SHA256".
 * @param mdprops Optional property query for fetching the digest, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname,
    const char *mdprops);

/**
 * @brief Set the message digest used by RSA-OAEP padding on a key context.
 * @param ctx Encrypt/decrypt context for an RSA key using OAEP.
 * @param md OAEP hash algorithm (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Set the OAEP message digest by name on an RSA key context.
 * @param ctx RSA key context used for encrypt/decrypt.
 * @param mdname Digest name (for example "SHA256").
 * @param mdprops Property query for fetching @p mdname, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
    const char *mdprops);
/**
 * @brief Get the RSA-OAEP message-digest algorithm from an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param md Receives a pointer to the EVP_MD in use (do not free).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
/**
 * @brief Get the RSA-OAEP message-digest algorithm name from an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param name Buffer receiving the NUL-terminated digest name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
/**
 * @brief Set the RSA-OAEP label on an EVP_PKEY_CTX, transferring ownership of @p label.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param label Label bytes to adopt, or NULL (with @p llen 0) to clear the label.
 * @param llen Length of @p label in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 *
 * The library takes ownership of @p label; the caller must not free it afterwards.
 */
int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen);
/**
 * @brief Return a non-owning pointer to the RSA-OAEP label configured on an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param label Receives a pointer to the internal label bytes (do not free); may be NULL.
 * @return Label length in bytes on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label);

#define EVP_PKEY_CTRL_RSA_PADDING (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 2)

#define EVP_PKEY_CTRL_RSA_KEYGEN_BITS (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 5)

#define EVP_PKEY_CTRL_GET_RSA_PADDING (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_GET_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 8)

#define EVP_PKEY_CTRL_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_CTRL_GET_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 12)

#define EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES (EVP_PKEY_ALG_CTRL + 13)

#define EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION (EVP_PKEY_ALG_CTRL + 14)

#define RSA_PKCS1_PADDING 1
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
#define RSA_X931_PADDING 5

/* EVP_PKEY_ only */
#define RSA_PKCS1_PSS_PADDING 6
#define RSA_PKCS1_WITH_TLS_PADDING 7

/* internal RSA_ only */
#define RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING 8

#define RSA_PKCS1_PADDING_SIZE 11

#define RSA_set_app_data(s, arg) RSA_set_ex_data(s, 0, arg)
#define RSA_get_app_data(s) RSA_get_ex_data(s, 0)

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate and initialise an empty RSA key object (deprecated; use EVP_PKEY-RSA).
 * @return New RSA, or NULL on allocation failure; free with RSA_free.
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSA_new(void);
/**
 * @brief Allocate an RSA object that uses @p engine's RSA method (deprecated).
 * @param engine ENGINE providing the RSA implementation, or NULL for the default.
 * @return New RSA, or NULL on error; free with RSA_free().
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSA_new_method(ENGINE *engine);
/**
 * @brief Return the bit length of an RSA modulus (deprecated; use EVP_PKEY_get_bits).
 * @param rsa RSA key to query.
 * @return Number of significant bits in the modulus n.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_bits(const RSA *rsa);
/**
 * @brief Return the RSA modulus size in bytes (deprecated).
 * @param rsa RSA key whose modulus size is queried.
 * @return Byte length of the modulus (RSA_size), or 0 if unset.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_size(const RSA *rsa);
/**
 * @brief Estimate the security strength of @p rsa in bits (deprecated).
 * @param rsa RSA key whose modulus size is assessed.
 * @return Approximate security strength in bits, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_security_bits(const RSA *rsa);

/**
 * @brief Set the RSA modulus and exponents, transferring ownership of the BIGNUMs (deprecated).
 * @param r RSA key to update.
 * @param n Modulus; required on the first call, or NULL to leave unchanged.
 * @param e Public exponent; required on the first call, or NULL to leave unchanged.
 * @param d Private exponent, or NULL to leave unchanged / omit.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
/**
 * @brief Set the RSA prime factors p and q, transferring ownership of the BIGNUMs (deprecated).
 * @param r RSA key to update.
 * @param p First prime factor; required on the first call, or NULL to leave unchanged.
 * @param q Second prime factor; required on the first call, or NULL to leave unchanged.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
/**
 * @brief Set the CRT parameters on an RSA key, transferring ownership (deprecated).
 * @param r RSA key to update.
 * @param dmp1 d mod (p-1), or NULL to leave unchanged (once set, may not clear).
 * @param dmq1 d mod (q-1), or NULL to leave unchanged.
 * @param iqmp q^-1 mod p, or NULL to leave unchanged.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_crt_params(RSA *r,
    BIGNUM *dmp1, BIGNUM *dmq1,
    BIGNUM *iqmp);
/**
 * @brief Set multi-prime RSA factors, exponents, and CRT coefficients (deprecated).
 * @param r RSA key to update.
 * @param primes Array of @p pnum prime factors that @p r will own.
 * @param exps Array of @p pnum CRT exponents that @p r will own.
 * @param coeffs Array of @p pnum CRT coefficients that @p r will own.
 * @param pnum Number of additional primes (beyond the classic two-prime case).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_multi_prime_params(RSA *r,
    BIGNUM *primes[],
    BIGNUM *exps[],
    BIGNUM *coeffs[],
    int pnum);
/**
 * @brief Get const pointers to the RSA modulus and exponents (deprecated).
 * @param r RSA key to query.
 * @param n Receives the modulus, or NULL if not requested.
 * @param e Receives the public exponent, or NULL if not requested.
 * @param d Receives the private exponent, or NULL if not requested.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_get0_key(const RSA *r,
    const BIGNUM **n, const BIGNUM **e,
    const BIGNUM **d);
/**
 * @brief Return the prime factors p and q of an RSA key without transferring ownership (deprecated).
 * @param r RSA key to query.
 * @param p Optional destination for the first prime factor, or NULL.
 * @param q Optional destination for the second prime factor, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_get0_factors(const RSA *r,
    const BIGNUM **p, const BIGNUM **q);
/**
 * @brief Return how many extra primes beyond p and q a multi-prime RSA key has (deprecated).
 * @param r RSA key to query.
 * @return Extra prime count (>=0), or 0 if the key is two-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get_multi_prime_extra_count(const RSA *r);
/**
 * @brief Fill @p primes with borrowed pointers to the extra multi-prime factors (deprecated).
 * @param r RSA key that may have more than two primes.
 * @param primes Array of size RSA_get_multi_prime_extra_count(@p r) receiving factor pointers (do not free).
 * @return 1 on success, or 0 if @p r is not multi-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get0_multi_prime_factors(const RSA *r,
    const BIGNUM *primes[]);
/**
 * @brief Borrow pointers to the RSA CRT parameters d mod (p-1), d mod (q-1), and q^-1 mod p (deprecated).
 * @param r RSA key to query.
 * @param dmp1 Receives dmp1, or NULL to skip; do not free.
 * @param dmq1 Receives dmq1, or NULL to skip; do not free.
 * @param iqmp Receives iqmp, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_get0_crt_params(const RSA *r,
    const BIGNUM **dmp1,
    const BIGNUM **dmq1,
    const BIGNUM **iqmp);
/**
 * @brief Get const pointers to multi-prime CRT exponents and coefficients (deprecated).
 * @param r Multi-prime RSA key to query.
 * @param exps Caller-provided array receiving exponent pointers (length RSA_get_multi_prime_extra_count).
 * @param coeffs Caller-provided array receiving coefficient pointers, or NULL.
 * @return 1 on success, or 0 if @p r is not multi-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
    const BIGNUM *coeffs[]);
/**
 * @brief Return the RSA modulus n (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal modulus BIGNUM (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_n(const RSA *d);
/**
 * @brief Return the public exponent e of an RSA key without transferring ownership (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal BIGNUM for e, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_e(const RSA *d);
/**
 * @brief Return the RSA private exponent d (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal private-exponent BIGNUM (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_d(const RSA *d);
/**
 * @brief Return the first prime factor (p) of an RSA key without transferring ownership.
 * @param d RSA key to query.
 * @return Internal BIGNUM for p, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_p(const RSA *d);
/**
 * @brief Return the second prime factor (q) of an RSA key without transferring ownership.
 * @param d RSA key to query.
 * @return Internal BIGNUM for q, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_q(const RSA *d);
/**
 * @brief Return CRT exponent d mod (p-1) without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for dmp1, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmp1(const RSA *r);
/**
 * @brief Return CRT exponent d mod (q-1) without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for dmq1, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmq1(const RSA *r);
/**
 * @brief Return CRT coefficient q^-1 mod p without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for iqmp, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_iqmp(const RSA *r);
/**
 * @brief Return the RSA-PSS parameters associated with an RSA key (deprecated).
 * @param r RSA key to query.
 * @return Internal RSA_PSS_PARAMS pointer, or NULL if none are set.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_PSS_PARAMS *RSA_get0_pss_params(const RSA *r);
/**
 * @brief Clear the given flag bits on an RSA key object (deprecated).
 * @param r RSA key whose flags are updated.
 * @param flags Flag bits to clear (bitwise AND with the complement of this mask).
 */
OSSL_DEPRECATEDIN_3_0 void RSA_clear_flags(RSA *r, int flags);
/**
 * @brief Return which of the given flag bits are currently set on an RSA object.
 * @param r RSA object to query.
 * @param flags Bitmask of RSA_* flags to test (bitwise OR).
 * @return Subset of @p flags that are set on @p r, or 0 if none are set.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_test_flags(const RSA *r, int flags);
/**
 * @brief Set flag bits on an RSA key object (deprecated).
 * @param r RSA key whose flags are updated.
 * @param flags Flag bits to set (OR'd into the existing mask; does not clear other bits).
 */
OSSL_DEPRECATEDIN_3_0 void RSA_set_flags(RSA *r, int flags);
/**
 * @brief Return whether an RSA key is multi-prime or two-prime (deprecated).
 * @param r RSA key to query.
 * @return RSA_ASN1_VERSION_MULTI or RSA_ASN1_VERSION_DEFAULT (two-prime).
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get_version(RSA *r);
/**
 * @brief Return the ENGINE set on an RSA key (deprecated).
 * @param r RSA key to query.
 * @return ENGINE handle, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *RSA_get0_engine(const RSA *r);
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */

#define EVP_RSA_gen(bits) \
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)(0 + (bits)))

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/**
 * @brief Generate an RSA key pair (very old API; deprecated — prefer RSA_generate_key_ex).
 * @param bits Modulus size in bits.
 * @param e Public exponent (for example 65537).
 * @param callback Optional progress callback, or NULL.
 * @param cb_arg Opaque argument passed to @p callback.
 * @return New RSA key pair, or NULL on error.
 */
OSSL_DEPRECATEDIN_0_9_8 RSA *RSA_generate_key(int bits, unsigned long e, void (*callback)(int, int, void *),
    void *cb_arg);
#endif

/* New version */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Generate a two-prime RSA key pair into an existing RSA object (deprecated).
 * @param rsa RSA object that receives the generated key material.
 * @param bits Desired modulus size in bits.
 * @param e Public exponent (commonly 65537); must be odd.
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e,
    BN_GENCB *cb);
/* Multi-prime version */
/**
 * @brief Generate a multi-prime RSA key pair (deprecated).
 * @param rsa Destination RSA object that receives the generated key.
 * @param bits Desired modulus size in bits.
 * @param primes Number of prime factors (2 or more).
 * @param e Public exponent to use (for example 65537).
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_generate_multi_prime_key(RSA *rsa, int bits,
    int primes, BIGNUM *e,
    BN_GENCB *cb);

/**
 * @brief Derive an RSA key from ANSI X9.31 intermediate values (deprecated).
 * @param rsa Destination RSA object that receives the derived key.
 * @param p1 Optional output for the first p factor component, or NULL.
 * @param p2 Optional output for the second p factor component, or NULL.
 * @param q1 Optional output for the first q factor component, or NULL.
 * @param q2 Optional output for the second q factor component, or NULL.
 * @param Xp1 X9.31 Xp1 input value.
 * @param Xp2 X9.31 Xp2 input value.
 * @param Xp X9.31 Xp input value.
 * @param Xq1 X9.31 Xq1 input value.
 * @param Xq2 X9.31 Xq2 input value.
 * @param Xq X9.31 Xq input value.
 * @param e Public exponent.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2,
    BIGNUM *q1, BIGNUM *q2,
    const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1,
    const BIGNUM *Xq2, const BIGNUM *Xq,
    const BIGNUM *e, BN_GENCB *cb);
/**
 * @brief Generate an RSA key pair using the X9.31 prime-generation method (deprecated).
 * @param rsa Destination RSA object to populate.
 * @param bits Desired modulus size in bits.
 * @param e Public exponent.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_X931_generate_key_ex(RSA *rsa, int bits,
    const BIGNUM *e,
    BN_GENCB *cb);

/**
 * @brief Validate consistency of an RSA key's public/private components (deprecated).
 * @param rsa RSA key to check.
 * @return 1 if the key looks consistent, or 0 on failure (error queue may explain).
 */
OSSL_DEPRECATEDIN_3_0 int RSA_check_key(const RSA *rsa);
/**
 * @brief Validate RSA key components with an optional progress callback (deprecated).
 * @param rsa RSA key to check.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 if the key is valid, or 0 if invalid / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_check_key_ex(const RSA *rsa, BN_GENCB *cb);
/* next 4 return -1 on error */
/**
 * @brief Encrypt @p flen bytes from @p from with RSA public key @p rsa (deprecated).
 * @param flen Length of @p from in bytes.
 * @param from Plaintext bytes to encrypt (often a session key).
 * @param to Output buffer of at least RSA_size(@p rsa) bytes.
 * @param rsa RSA public key.
 * @param padding Padding mode such as RSA_PKCS1_PADDING or RSA_PKCS1_OAEP_PADDING.
 * @return Number of ciphertext bytes written to @p to, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief RSA private-key encryption (raw primitive / signing-style) (deprecated).
 * @param flen Length of @p from in bytes.
 * @param from Input bytes to encrypt with the private key.
 * @param to Output buffer of at least RSA_size(@p rsa) bytes.
 * @param rsa RSA private key.
 * @param padding Padding mode such as RSA_PKCS1_PADDING or RSA_NO_PADDING.
 * @return Number of bytes written to @p to, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief RSA public-key decryption / signature recovery (deprecated).
 * @param flen Length of @p from in bytes.
 * @param from Ciphertext / signature bytes to process with the public key.
 * @param to Output buffer of at least RSA_size(@p rsa) bytes.
 * @param rsa RSA public key.
 * @param padding Padding mode such as RSA_PKCS1_PADDING or RSA_NO_PADDING.
 * @return Number of bytes written to @p to, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Decrypt @p flen ciphertext bytes with RSA private key @p rsa (deprecated).
 * @param flen Length of @p from in bytes (typically RSA_size(@p rsa)).
 * @param from Ciphertext produced by RSA_public_encrypt() (or equivalent).
 * @param to Output buffer large enough for the recovered plaintext.
 * @param rsa RSA private key.
 * @param padding Padding mode that was used when encrypting.
 * @return Length of the recovered plaintext, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Free an RSA key and its BIGNUM components (deprecated).
 * @param r Key to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_free(RSA *r);
/* "up" the RSA object's reference count */
/**
 * @brief Increment the reference count of an RSA key object (deprecated).
 * @param r RSA object to retain.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_up_ref(RSA *r);
/**
 * @brief Return the flag bits from the RSA_METHOD currently bound to @p r (deprecated).
 * @param r RSA key whose method flags are queried.
 * @return Method flags (see RSA_FLAG_*), or 0 if @p r is NULL.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_flags(const RSA *r);

/**
 * @brief Set the default RSA_METHOD used when creating new RSA keys (deprecated; not thread-safe).
 * @param meth Method table that becomes the process default unless an ENGINE overrides it.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_set_default_method(const RSA_METHOD *meth);
/**
 * @brief Return the current default RSA_METHOD (deprecated).
 * @return Default method pointer (do not free).
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_default_method(void);
/**
 * @brief Return the historical "null" RSA_METHOD stub (deprecated; always returns NULL since 1.1.1).
 * @return NULL.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_null_method(void);
/**
 * @brief Return the RSA_METHOD currently associated with an RSA key (deprecated).
 * @param rsa Key to query.
 * @return Pointer to the active RSA_METHOD.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_method(const RSA *rsa);
/**
 * @brief Bind an RSA_METHOD implementation to an RSA key object (deprecated).
 * @param rsa RSA key to update.
 * @param meth Method table that will handle operations on @p rsa.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);

/* these are the actual RSA functions */
/**
 * @brief Return the built-in OpenSSL RSA_METHOD implementing PKCS#1 operations (deprecated).
 * @return Pointer to the default software RSA_METHOD (do not free).
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_PKCS1_OpenSSL(void);

/**
 * @brief Decode an RSA public key from DER in PKCS#1 RSAPublicKey form (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded RSA public key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len);
/**
 * @brief Encode an RSA public key to DER in PKCS#1 RSAPublicKey form (deprecated).
 * @param a RSA key whose public components are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey(const RSA *a, unsigned char **out);
/**
 * @brief Decode an RSA private key from DER in PKCS#1 RSAPrivateKey form (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded RSA private key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len);
/**
 * @brief Encode an RSA private key to DER in PKCS#1 RSAPrivateKey form (deprecated).
 * @param a RSA private key to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPrivateKey(const RSA *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for PKCS#1 RSAPrivateKey (deprecated).
 * @return Pointer to the static ASN1_ITEM for RSAPrivateKey.
 */
OSSL_DEPRECATEDIN_3_0 const ASN1_ITEM *RSAPrivateKey_it(void);
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */

/**
 * @brief Dispatch an RSA-specific control operation on an EVP_PKEY_CTX.
 * @param ctx Key context that must be for an RSA algorithm.
 * @param optype Operation type mask (for example EVP_PKEY_OP_TYPE_SIG) or -1 for any.
 * @param cmd Control command such as EVP_PKEY_CTRL_RSA_PADDING.
 * @param p1 Integer argument for @p cmd.
 * @param p2 Pointer argument for @p cmd, or NULL when unused.
 * @return Positive on success, or a non-positive value on failure / unsupported command.
 */
int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

struct rsa_pss_params_st {
    /** Hash AlgorithmIdentifier used by RSA-PSS (for example SHA-256). */
    X509_ALGOR *hashAlgorithm;
    /** Mask generation AlgorithmIdentifier (typically MGF1 with a hash). */
    X509_ALGOR *maskGenAlgorithm;
    /** PSS salt length in octets; NULL means the ASN.1 default. */
    ASN1_INTEGER *saltLength;
    /** Trailer field value; NULL means the default trailerFieldBC (0xbc). */
    ASN1_INTEGER *trailerField;
    /** Hash AlgorithmIdentifier decoded from @c maskGenAlgorithm (MGF1). */
    X509_ALGOR *maskHash;
};

/**
 * @brief Allocate empty RSA-PSS algorithm parameters.
 * @return New RSA_PSS_PARAMS, or NULL on allocation failure.
 */
RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void);
/**
 * @brief Free RSA-PSS algorithm parameters and their contents.
 * @param a Value to free, or NULL.
 */
void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a);
/**
 * @brief Decode RSA-PSS parameters from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded RSA_PSS_PARAMS, or NULL on error.
 */
RSA_PSS_PARAMS *d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const unsigned char **in, long len);
/**
 * @brief Encode RSA-PSS parameters to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_RSA_PSS_PARAMS(const RSA_PSS_PARAMS *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for RSA_PSS_PARAMS.
 * @return Pointer to the static ASN1_ITEM for RSA_PSS_PARAMS.
 */
const ASN1_ITEM *RSA_PSS_PARAMS_it(void);
/**
 * @brief Deep-copy RSA-PSS algorithm parameters.
 * @param a Parameters to duplicate.
 * @return Newly allocated copy, or NULL on error; free with RSA_PSS_PARAMS_free.
 */
RSA_PSS_PARAMS *RSA_PSS_PARAMS_dup(const RSA_PSS_PARAMS *a);

struct rsa_oaep_params_st {
    /** AlgorithmIdentifier for the OAEP hash function (for example SHA-256). */
    X509_ALGOR *hashFunc;
    /** AlgorithmIdentifier for the OAEP mask generation function (typically MGF1). */
    X509_ALGOR *maskGenFunc;
    /** AlgorithmIdentifier for the OAEP P-source function (typically pSpecified). */
    X509_ALGOR *pSourceFunc;
    /** Decoded hash AlgorithmIdentifier extracted from @c maskGenFunc (MGF1). */
    X509_ALGOR *maskHash;
};

/**
 * @brief Allocate empty RSA-OAEP algorithm parameters.
 * @return New RSA_OAEP_PARAMS, or NULL on allocation failure.
 */
RSA_OAEP_PARAMS *RSA_OAEP_PARAMS_new(void);
/**
 * @brief Free RSA-OAEP algorithm parameters and their contents.
 * @param a Value to free, or NULL.
 */
void RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS *a);
/**
 * @brief Decode RSA-OAEP parameters from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded RSA_OAEP_PARAMS, or NULL on error.
 */
RSA_OAEP_PARAMS *d2i_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS **a, const unsigned char **in, long len);
/**
 * @brief Encode RSA-OAEP parameters to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_RSA_OAEP_PARAMS(const RSA_OAEP_PARAMS *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for RSA_OAEP_PARAMS.
 * @return Pointer to the static ASN1_ITEM for RSA_OAEP_PARAMS.
 */
const ASN1_ITEM *RSA_OAEP_PARAMS_it(void);

#ifndef OPENSSL_NO_DEPRECATED_3_0
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Print RSA key components to a FILE with indentation (deprecated).
 * @param fp Output stream.
 * @param r RSA key to print.
 * @param offset Indentation in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_print_fp(FILE *fp, const RSA *r, int offset);
#endif

/**
 * @brief Print RSA key components to a BIO with indentation (deprecated).
 * @param bp Output BIO.
 * @param r RSA key to print.
 * @param offset Indentation in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_print(BIO *bp, const RSA *r, int offset);

/*
 * The following 2 functions sign and verify a X509_SIG ASN1 object inside
 * PKCS#1 padded RSA encryption
 */
/**
 * @brief Create an RSA signature with PKCS#1 DigestInfo wrapping (deprecated).
 * @param type Digest NID identifying the hash algorithm (for example NID_sha256).
 * @param m Digest bytes to sign.
 * @param m_length Length of @p m in bytes.
 * @param sigret Buffer of at least RSA_size(@p rsa) bytes receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param rsa RSA private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_sign(int type, const unsigned char *m,
    unsigned int m_length, unsigned char *sigret,
    unsigned int *siglen, RSA *rsa);
/**
 * @brief Verify an RSASSA-PKCS1-v1_5 signature over digest @p m (deprecated).
 * @param type Digest NID that was used to produce @p m (for example NID_sha256).
 * @param m Message digest bytes that were signed.
 * @param m_length Length of @p m in bytes.
 * @param sigbuf Signature bytes to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param rsa Signer's RSA public key.
 * @return 1 if the signature is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_verify(int type, const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen, RSA *rsa);

/*
 * The following 2 function sign and verify a ASN1_OCTET_STRING object inside
 * PKCS#1 padded RSA encryption
 */
/**
 * @brief Sign an ASN.1 OCTET STRING payload with RSA (deprecated).
 * @param type Unused legacy digest type argument.
 * @param m OCTET STRING contents to sign.
 * @param m_length Length of @p m in bytes.
 * @param sigret Buffer of at least RSA_size(@p rsa) bytes receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param rsa RSA private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_sign_ASN1_OCTET_STRING(int type,
    const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen,
    RSA *rsa);
/**
 * @brief Verify an RSA signature that wraps a DigestInfo-style ASN.1 OCTET STRING (deprecated).
 * @param type NID of the digest algorithm expected inside the recovered DigestInfo.
 * @param m Expected digest bytes.
 * @param m_length Length of @p m in bytes.
 * @param sigbuf Signature bytes to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param rsa RSA public key used for verification.
 * @return 1 if the signature is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_verify_ASN1_OCTET_STRING(int type,
    const unsigned char *m, unsigned int m_length,
    unsigned char *sigbuf, unsigned int siglen,
    RSA *rsa);

/**
 * @brief Enable RSA blinding on @p rsa to mitigate timing attacks (deprecated).
 * @param rsa RSA key that will use blinding for private operations.
 * @param ctx Optional BN_CTX for blinding setup, or NULL to allocate internally.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
/**
 * @brief Disable RSA blinding on @p rsa and free any associated blinding state (deprecated).
 * @param rsa RSA key whose blinding factor is cleared.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_blinding_off(RSA *rsa);
/**
 * @brief Create and attach a BN_BLINDING factor for RSA private operations (deprecated).
 * @param rsa RSA key that will use the returned blinding state.
 * @param ctx Optional BN_CTX for blinding setup, or NULL to allocate internally.
 * @return New BN_BLINDING on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);

/**
 * @brief Encode a DigestInfo or similar block with PKCS #1 v1.5 type-1 padding for RSA signatures (deprecated).
 * @param to Destination buffer of length @p tlen that receives the padded block.
 * @param tlen Size of @p to in bytes (typically RSA_size()).
 * @param f Message bytes to pad (usually a DigestInfo encoding).
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 on error (for example if @p fl is too large for @p tlen).
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
    const unsigned char *f, int fl);
/**
 * @brief Verify and remove PKCS#1 v1.5 type-1 (signing) padding (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block to check.
 * @param fl Length of @p f in bytes.
 * @param rsa_len Expected RSA modulus size in bytes.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
/**
 * @brief Encode a message with PKCS #1 v1.5 encryption padding (type 2) (deprecated).
 * @param to Destination buffer of size @p tlen for the padded encoding.
 * @param tlen Size of @p to in bytes (typically RSA_size()).
 * @param f Message bytes to encode.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *f, int fl);
/**
 * @brief Decode and verify PKCS #1 v1.5 type-2 (encryption) padding (deprecated).
 * @param to Destination buffer of capacity @p tlen for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block to check (typically RSA_size() bytes after public/private op).
 * @param fl Length of @p f in bytes.
 * @param rsa_len Expected RSA modulus size in bytes.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
/**
 * @brief Generate a PKCS #1 mask using MGF1 with digest @p dgst (deprecated).
 * @param mask Output buffer that receives @p len mask bytes.
 * @param len Desired mask length in bytes.
 * @param seed MGF seed (mgfSeed).
 * @param seedlen Length of @p seed in bytes.
 * @param dgst Hash function used by MGF1.
 * @return 0 on success, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int PKCS1_MGF1(unsigned char *mask, long len,
    const unsigned char *seed, long seedlen,
    const EVP_MD *dgst);
/**
 * @brief Apply PKCS#1 OAEP padding using SHA-1 / MGF1-SHA-1 defaults (deprecated).
 * @param to Destination encoded block of length @p tlen.
 * @param tlen RSA modulus size in bytes.
 * @param f Message bytes to pad.
 * @param fl Length of @p f in bytes.
 * @param p Optional OAEP encoding parameter / label bytes, or NULL.
 * @param pl Length of @p p in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    const unsigned char *p, int pl);
/**
 * @brief Verify PKCS#1 OAEP padding and recover the encoded message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded message after RSA public operation (typically modulus-sized).
 * @param fl Length of @p f in bytes.
 * @param rsa_len RSA modulus size in bytes (used to validate encoding length).
 * @param p Optional OAEP encoding parameter / label octets, or NULL.
 * @param pl Length of @p p in bytes.
 * @return Length of the recovered message on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl, int rsa_len,
    const unsigned char *p, int pl);
/**
 * @brief Apply PKCS#1 OAEP padding with explicit message and MGF1 digests (deprecated).
 * @param to Destination buffer for the encoded message (typically modulus-sized).
 * @param tlen Capacity of @p to in bytes.
 * @param from Message octets to encode.
 * @param flen Length of @p from in bytes.
 * @param param Optional OAEP encoding parameter / label octets, or NULL.
 * @param plen Length of @p param in bytes.
 * @param md Digest used for OAEP label hashing; NULL selects SHA-1.
 * @param mgf1md Digest used for MGF1; NULL selects the same digest as @p md.
 * @return 1 on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);
/**
 * @brief Verify PKCS#1 OAEP padding with explicit digests and recover the message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param from Encoded OAEP block.
 * @param flen Length of @p from in bytes.
 * @param num RSA modulus size in bytes.
 * @param param Optional OAEP label bytes, or NULL.
 * @param plen Length of @p param in bytes.
 * @param md Hash used by OAEP, or NULL for SHA-1.
 * @param mgf1md Hash used by MGF1, or NULL to use @p md.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    int num,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);
/**
 * @brief Copy @p f into @p to with no padding (lengths must match) (deprecated).
 * @param to Destination block of length @p tlen.
 * @param tlen RSA modulus size in bytes; must equal @p fl.
 * @param f Message bytes.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 if lengths differ / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl);
/**
 * @brief Verify "no padding" by copying @p f into @p to when lengths match (deprecated).
 * @param to Destination buffer of capacity @p tlen.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block bytes to check/copy.
 * @param fl Length of @p f in bytes.
 * @param rsa_len RSA modulus size in bytes (expected encoded length).
 * @return Length of recovered data on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
/**
 * @brief Apply ANSI X9.31 padding to a message block (deprecated).
 * @param to Destination encoded block of length @p tlen.
 * @param tlen RSA modulus size in bytes.
 * @param f Message / hash bytes to pad.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl);
/**
 * @brief Verify ANSI X9.31 padding and recover the message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block to check.
 * @param fl Length of @p f in bytes.
 * @param rsa_len Expected RSA modulus size in bytes.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
/**
 * @brief Return the X9.31 hash algorithm identifier byte for digest NID @p nid (deprecated).
 * @param nid Digest NID such as NID_sha1 or NID_sha256.
 * @return Hash-ID byte used in X9.31 encoding, or -1 if @p nid is unsupported.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_X931_hash_id(int nid);

/**
 * @brief Verify an RSA-PSS encoded message EM against a message hash (deprecated).
 * @param rsa RSA public key used for verification context (size / parameters).
 * @param mHash Hash of the original message.
 * @param Hash Digest that produced @p mHash and is used by PSS.
 * @param EM Encoded message of RSA_size(@p rsa) bytes (typically after RSA public operation).
 * @param sLen PSS salt length in bytes, or a special negative sentinel accepted by the implementation.
 * @return 1 if the PSS encoding is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const unsigned char *EM,
    int sLen);
/**
 * @brief Encode an EMSA-PSS padded block for RSA signature (deprecated).
 * @param rsa RSA key providing the modulus length.
 * @param EM Destination encoded message of length RSA_size(@p rsa).
 * @param mHash Hash of the message being signed.
 * @param Hash Digest method that produced @p mHash (and used by MGF1 unless configured otherwise).
 * @param sLen Salt length in bytes, or RSA_PSS_SALTLEN_* special values.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
    const unsigned char *mHash, const EVP_MD *Hash,
    int sLen);

/**
 * @brief Verify a PKCS#1 PSS-encoded digest using an explicit MGF1 hash (deprecated).
 * @param rsa RSA key whose modulus length defines the encoded message size.
 * @param mHash Message digest that was signed.
 * @param Hash Hash algorithm that produced @p mHash and labels the PSS encoding.
 * @param mgf1Hash Hash algorithm used by MGF1, or NULL to use @p Hash.
 * @param EM Encoded message to verify (typically RSA_size(rsa) bytes).
 * @param sLen Salt length in bytes, or a special RSA_PSS_SALTLEN_* value.
 * @return 1 if the encoding is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int sLen);

/**
 * @brief Encode an EMSA-PSS padded block using an explicit MGF1 hash (deprecated).
 * @param rsa RSA key providing the modulus length.
 * @param EM Destination encoded message of length RSA_size(@p rsa).
 * @param mHash Hash of the message being signed.
 * @param Hash Digest method that produced @p mHash.
 * @param mgf1Hash Hash algorithm used by MGF1, or NULL to use @p Hash.
 * @param sLen Salt length in bytes, or RSA_PSS_SALTLEN_* special values.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
    const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    int sLen);

#define RSA_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)
/**
 * @brief Store application data on an RSA key at CRYPTO_EX index @p idx (deprecated).
 * @param r RSA key receiving the data.
 * @param idx Index from CRYPTO_get_ex_new_index() for RSA.
 * @param arg Pointer to store; ownership rules follow CRYPTO_EX_DATA.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set_ex_data(RSA *r, int idx, void *arg);
/**
 * @brief Return application data previously stored on an RSA key at CRYPTO_EX index @p idx (deprecated).
 * @param r RSA key to query.
 * @param idx Index from CRYPTO_get_ex_new_index() for RSA.
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *RSA_get_ex_data(const RSA *r, int idx);

/**
 * @brief Duplicate an RSA public key via ASN.1 encode/decode (deprecated).
 * @param a RSA key whose public components are duplicated.
 * @return Newly allocated RSA copy, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSAPublicKey_dup(const RSA *a);
/**
 * @brief Deep-copy an RSA private key (RSAPrivateKey_dup) (deprecated).
 * @param a Source RSA key to duplicate.
 * @return Newly allocated RSA copy, or NULL on failure; free with RSA_free().
 */
DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, RSA, RSAPrivateKey)

/**
 * @brief RSA_METHOD flag marking the method as FIPS-validated and usable in FIPS mode.
 *
 * Set on the validated module method. An application that sets this flag on its
 * own methods must ensure the result remains FIPS-compliant.
 */
#define RSA_FLAG_FIPS_METHOD 0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#define RSA_FLAG_NON_FIPS_ALLOW 0x0400
/*
 * Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
#define RSA_FLAG_CHECKED 0x0800

/**
 * @brief Allocate a new RSA_METHOD with the given name and flags (deprecated).
 * @param name Human-readable method name copied into the object.
 * @param flags Method flags such as RSA_METHOD_FLAG_NO_CHECK.
 * @return New RSA_METHOD, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_new(const char *name, int flags);
/**
 * @brief Free an RSA_METHOD allocated with RSA_meth_new() (deprecated).
 * @param meth Method table to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_meth_free(RSA_METHOD *meth);
/**
 * @brief Duplicate an RSA_METHOD structure (deprecated).
 * @param meth Method to copy.
 * @return Newly allocated RSA_METHOD, or NULL on failure; free with RSA_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth);
/**
 * @brief Return the descriptive name stored on an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Internal NUL-terminated name string; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const char *RSA_meth_get0_name(const RSA_METHOD *meth);
/**
 * @brief Set the descriptive name stored on an RSA_METHOD (deprecated).
 * @param meth Method table whose name is replaced.
 * @param name NUL-terminated name to copy into @p meth.
 * @return 1 on success, or 0 on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_set1_name(RSA_METHOD *meth,
    const char *name);
/**
 * @brief Return the flag mask stored on an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Flag bits previously set with RSA_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_get_flags(const RSA_METHOD *meth);
/**
 * @brief Replace the flag mask stored on an RSA_METHOD.
 * @param meth Method table to update.
 * @param flags New RSA_METHOD / RSA_* flag bits (replaces the previous mask).
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_set_flags(RSA_METHOD *meth, int flags);
/**
 * @brief Return the application pointer previously attached to an RSA_METHOD.
 * @param meth Method to query.
 * @return App-data pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *RSA_meth_get0_app_data(const RSA_METHOD *meth);
/**
 * @brief Attach application data to an RSA_METHOD without copying (deprecated).
 * @param meth Method table to update.
 * @param app_data Opaque pointer stored on @p meth (not freed by RSA_meth_free).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_set0_app_data(RSA_METHOD *meth,
    void *app_data);
/**
 * @brief Return the public-encrypt callback installed on a custom RSA_METHOD (deprecated).
 * @param meth Method object to query.
 * @return Pointer to the pub_enc callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Set the public-encrypt callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param pub_enc Callback performing RSA public encryption, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
    int (*pub_enc)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
/**
 * @brief Return the public-decrypt callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the pub_dec callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Set the public-decrypt callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param pub_dec Callback performing RSA public decryption / signature recovery, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
    int (*pub_dec)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
/**
 * @brief Return the private-encrypt (signing) callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the priv_enc callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Set the private-encrypt (signing) callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param priv_enc Callback performing RSA private encryption / raw signing, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
    int (*priv_enc)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
/**
 * @brief Return the private-decrypt callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the priv_dec callback used by RSA_private_decrypt(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
/**
 * @brief Set the private-decrypt callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param priv_dec Callback performing RSA private decryption / signature recovery, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_priv_dec(RSA_METHOD *rsa,
    int (*priv_dec)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
/**
 * @brief Return the CRT modular-exponentiation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(BIGNUM *r0,
    const BIGNUM *i,
    RSA *rsa, BN_CTX *ctx);
/**
 * @brief Set the CRT modular-exponentiation callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param mod_exp Callback used for CRT computations, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_mod_exp(RSA_METHOD *rsa,
    int (*mod_exp)(BIGNUM *r0, const BIGNUM *i, RSA *rsa,
        BN_CTX *ctx));
/**
 * @brief Return the BN modular-exponentiation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the bn_mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(BIGNUM *r,
    const BIGNUM *a,
    const BIGNUM *p,
    const BIGNUM *m,
    BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
/**
 * @brief Set the CRT modular-exponentiation callback on an RSA_METHOD (deprecated).
 * @param rsa Method whose bn_mod_exp hook is replaced.
 * @param bn_mod_exp Callback computing r = a^p mod m (with optional Montgomery context).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_bn_mod_exp(RSA_METHOD *rsa,
    int (*bn_mod_exp)(BIGNUM *r,
        const BIGNUM *a,
        const BIGNUM *p,
        const BIGNUM *m,
        BN_CTX *ctx,
        BN_MONT_CTX *m_ctx));
/**
 * @brief Return the init callback previously set on an RSA_METHOD (deprecated).
 * @param meth Method to query.
 * @return Pointer to the init function, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_init(const RSA_METHOD *meth))(RSA *rsa);
/**
 * @brief Install the init callback on an RSA_METHOD (deprecated).
 * @param rsa Method table to update.
 * @param init Callback invoked when an RSA key using this method is initialized, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_init(RSA_METHOD *rsa, int (*init)(RSA *rsa));
/**
 * @brief Return the finish/cleanup callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_finish(const RSA_METHOD *meth))(RSA *rsa);
/**
 * @brief Set the finish/cleanup callback on an RSA_METHOD (deprecated).
 * @param rsa Method table to update.
 * @param finish Callback invoked when an RSA object using this method is freed, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_finish(RSA_METHOD *rsa, int (*finish)(RSA *rsa));
/**
 * @brief Return the high-level sign callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the sign callback used by RSA_sign(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_sign(const RSA_METHOD *meth))(int type,
    const unsigned char *m,
    unsigned int m_length,
    unsigned char *sigret,
    unsigned int *siglen,
    const RSA *rsa);
/**
 * @brief Set the private-key signing callback on an RSA_METHOD (deprecated).
 * @param rsa Method table to update.
 * @param sign Callback implementing RSA_sign()-style signing, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_sign(RSA_METHOD *rsa,
    int (*sign)(int type, const unsigned char *m,
        unsigned int m_length,
        unsigned char *sigret, unsigned int *siglen,
        const RSA *rsa));
/**
 * @brief Return the high-level verify callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the verify callback used by RSA_verify(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_verify(const RSA_METHOD *meth))(int dtype,
    const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen,
    const RSA *rsa);
/**
 * @brief Set the signature-verification callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param verify Callback invoked by RSA_verify(), with the same parameters, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_verify(RSA_METHOD *rsa,
    int (*verify)(int dtype, const unsigned char *m,
        unsigned int m_length,
        const unsigned char *sigbuf,
        unsigned int siglen, const RSA *rsa));
/**
 * @brief Return the key-generation callback from a custom RSA_METHOD (deprecated).
 * @param meth Method object to query.
 * @return Keygen function pointer used by RSA_generate_key_ex(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_keygen(const RSA_METHOD *meth))(RSA *rsa, int bits,
    BIGNUM *e, BN_GENCB *cb);
/**
 * @brief Set the key-generation callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param keygen Callback implementing RSA_generate_key_ex()-style key generation, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_keygen(RSA_METHOD *rsa,
    int (*keygen)(RSA *rsa, int bits, BIGNUM *e,
        BN_GENCB *cb));
/**
 * @brief Return the multi-prime key-generation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the multi-prime keygen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))(RSA *rsa,
    int bits,
    int primes,
    BIGNUM *e,
    BN_GENCB *cb);
/**
 * @brief Set the multi-prime key-generation callback on a custom RSA_METHOD (deprecated).
 * @param meth Method object to update.
 * @param keygen Callback implementing multi-prime RSA key generation, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_multi_prime_keygen(RSA_METHOD *meth,
    int (*keygen)(RSA *rsa, int bits,
        int primes, BIGNUM *e,
        BN_GENCB *cb));
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */

#ifdef __cplusplus
}
#endif
#endif
