/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DSA_H
#define OPENSSL_DSA_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_DSA_H
#endif

#include <openssl/opensslconf.h>
#include <openssl/types.h>

#include <stdlib.h>

#ifndef OPENSSL_NO_DSA
#include <openssl/e_os2.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#include <openssl/dh.h>
#endif
#include <openssl/dsaerr.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set the DSA prime modulus length in bits for parameter generation.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param nbits Desired bit length of p (for example 2048).
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);
/**
 * @brief Set the DSA subprime (q) length in bits for parameter generation.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param qbits Desired bit length of q (default 224 if unset); ignored when a digest size selects q.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits);
/**
 * @brief Select the digest for DSA parameter generation by name and property query.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param md_name Digest algorithm name such as "SHA256".
 * @param md_properties Optional property query string for fetching the digest, or NULL.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_md_props(EVP_PKEY_CTX *ctx,
    const char *md_name,
    const char *md_properties);
/**
 * @brief Set the DSA parameter-generation gindex (FIPS 186 verifiable g seed index).
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param gindex Non-negative gindex value passed to the DSA provider.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
/**
 * @brief Set the DSA parameter-generation algorithm type by name.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param name Generator type name understood by the DSA provider (for example "fips186_4").
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX *ctx, const char *name);
/**
 * @brief Supply the seed used when generating FIPS 186-style DSA parameters.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param seed Seed bytes consumed by the parameter generator.
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);
/**
 * @brief Set the digest used for DSA parameter generation on an EVP_PKEY_CTX.
 * @param ctx Parameter-generation context for a DSA key.
 * @param md Message digest to use; if unset, SHA-1/224/256 is chosen to match q.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

#define EVP_PKEY_CTRL_DSA_PARAMGEN_BITS (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_DSA_PARAMGEN_MD (EVP_PKEY_ALG_CTRL + 3)

#ifndef OPENSSL_NO_DSA
#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
#define OPENSSL_DSA_MAX_MODULUS_BITS 10000
#endif

#define OPENSSL_DSA_FIPS_MIN_MODULUS_BITS 1024

/**
 * @brief Opaque DSA signature value holding the ASN.1 integers r and s.
 */
typedef struct DSA_SIG_st DSA_SIG;
/**
 * @brief Allocate an empty DSA signature structure holding r and s.
 * @return New DSA_SIG, or NULL on allocation failure; free with DSA_SIG_free().
 */
DSA_SIG *DSA_SIG_new(void);
/**
 * @brief Free a DSA_SIG and its r and s BIGNUM components.
 * @param a Signature to free, or NULL (no-op).
 */
void DSA_SIG_free(DSA_SIG *a);
/**
 * @brief Decode a DSA signature (r, s) from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA_SIG, or NULL on error.
 */
DSA_SIG *d2i_DSA_SIG(DSA_SIG **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA signature (r, s) to DER.
 * @param a Signature to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **out);
/**
 * @brief Borrow pointers to the r and s components of a DSA signature.
 * @param sig Signature to query.
 * @param pr Receives an internal pointer to r, or NULL to skip; do not free.
 * @param ps Receives an internal pointer to s, or NULL to skip; do not free.
 */
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
/**
 * @brief Set the r and s components of a DSA signature, transferring ownership.
 * @param sig Signature object to update.
 * @param r New r value; ownership transferred to @p sig (must not be NULL).
 * @param s New s value; ownership transferred to @p sig (must not be NULL).
 * @return 1 on success, or 0 on failure.
 */
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#define DSA_FLAG_NO_EXP_CONSTTIME 0x00
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DSA_FLAG_CACHE_MONT_P 0x01

/*
 * If this flag is set the DSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

#define DSA_FLAG_FIPS_METHOD 0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#define DSA_FLAG_NON_FIPS_ALLOW 0x0400
#define DSA_FLAG_FIPS_CHECKED 0x0800

/* Already defined in ossl_typ.h */
/* typedef struct dsa_st DSA; */
/* typedef struct dsa_method DSA_METHOD; */

#define d2i_DSAparams_fp(fp, x)                  \
    (DSA *)ASN1_d2i_fp((void *(*)(void))DSA_new, \
        (d2i_of_void *)d2i_DSAparams, (fp),      \
        (void **)(x))
#define i2d_DSAparams_fp(fp, x) \
    ASN1_i2d_fp(i2d_DSAparams, (fp), (unsigned char *)(x))
#define d2i_DSAparams_bio(bp, x) \
    ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAparams, bp, x)
#define i2d_DSAparams_bio(bp, x) \
    ASN1_i2d_bio_of(DSA, i2d_DSAparams, bp, x)

/**
 * @brief Deep-copy DSA domain parameters into a new DSA object (deprecated).
 * @param a Source DSA whose p, q, and g are duplicated.
 * @return New DSA with copied parameters, or NULL on error; free with DSA_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSAparams_dup(const DSA *a);
/**
 * @brief Sign a digest with a DSA private key, returning a DSA_SIG structure (deprecated).
 * @param dgst Digest bytes to sign.
 * @param dlen Length of @p dgst in bytes.
 * @param dsa DSA key containing the private key used for signing.
 * @return Newly allocated DSA_SIG, or NULL on error; free with DSA_SIG_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen,
    DSA *dsa);
/**
 * @brief Verify a DSA signature against a digest using a DSA_SIG structure (deprecated).
 * @param dgst Digest bytes that were signed.
 * @param dgst_len Length of @p dgst in bytes.
 * @param sig Signature containing r and s.
 * @param dsa DSA public key (and parameters) used for verification.
 * @return 1 if the signature is valid, 0 if invalid, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_do_verify(const unsigned char *dgst, int dgst_len,
    DSA_SIG *sig, DSA *dsa);

/**
 * @brief Return the built-in OpenSSL software DSA_METHOD (deprecated).
 * @return Pointer to the default software DSA method implementation.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_OpenSSL(void);

/**
 * @brief Set the process-wide default DSA_METHOD (deprecated).
 * @param meth Method that new DSA objects use unless overridden.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_set_default_method(const DSA_METHOD *meth);
/**
 * @brief Return the current default DSA_METHOD (deprecated).
 * @return Pointer to the default DSA_METHOD.
 *
 * Meaningfulness depends on whether the ENGINE API is in use; prefer providers.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_default_method(void);
/**
 * @brief Select the DSA_METHOD used for operations on @p dsa (deprecated).
 * @param dsa DSA key whose method is replaced.
 * @param meth Method implementation to attach; releases any prior ENGINE method.
 * @return Non-zero on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set_method(DSA *dsa, const DSA_METHOD *meth);
/**
 * @brief Return the DSA_METHOD currently bound to @p d (deprecated).
 * @param d DSA key whose method table is queried.
 * @return Pointer to the method implementation, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_method(DSA *d);

/**
 * @brief Allocate an empty DSA object using the default method (deprecated).
 * @return New DSA, or NULL on failure; free with DSA_free().
 *
 * Prefer EVP_PKEY-based DSA APIs for new code.
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSA_new(void);
/**
 * @brief Allocate a DSA object that uses methods from @p engine (deprecated).
 * @param engine ENGINE providing DSA implementation, or NULL for the default software method.
 * @return New DSA, or NULL on failure; free with DSA_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSA_new_method(ENGINE *engine);
/**
 * @brief Free a DSA object and its associated resources (deprecated).
 * @param r DSA object to free; NULL is ignored.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_free(DSA *r);
/**
 * @brief Increment the reference count of a DSA object (deprecated).
 * @param r DSA object whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_up_ref(DSA *r);
/**
 * @brief Return the maximum ASN.1 encoded DSA signature size for @p dsa in bytes (deprecated).
 * @param dsa DSA key whose signature size is queried.
 * @return Maximum signature length in bytes, or 0 if @p dsa has no usable parameters.
 *
 * Prefer EVP_PKEY_get_size() for new code.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_size(const DSA *dsa);
/**
 * @brief Return the bit length of the DSA prime modulus p (deprecated).
 * @param d DSA key whose parameters are queried.
 * @return Bit length of p, or -1 if parameters are unavailable.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_bits(const DSA *d);
/**
 * @brief Estimate the security strength in bits of a DSA key from its parameters (deprecated).
 * @param d DSA key whose p/q sizes are examined.
 * @return Approximate security bits, or 0 if parameters are incomplete.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_security_bits(const DSA *d);
/* next 4 return -1 on error */
/**
 * @brief Legacy DSA precomputation stub retained for ABI compatibility (deprecated; do not use).
 * @param dsa DSA key (unused for signature math since OpenSSL 1.1.0 opaque DSA).
 * @param ctx_in Optional BN_CTX, or NULL.
 * @param kinvp Receives allocated BIGNUM output historically used as k^-1 (caller frees); may be unused.
 * @param rp Receives allocated BIGNUM output historically used as r (caller frees); may be unused.
 * @return 1 on success, or 0 / -1 on error.
 *
 * Calling this only adds overhead; it does not affect DSA_sign().
 */
OSSL_DEPRECATEDIN_3_0 int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp);
/**
 * @brief Create a DER-encoded DSA signature over a message digest (deprecated).
 * @param type Historical digest NID; ignored by modern implementations.
 * @param dgst Digest octets to sign.
 * @param dlen Length of @p dgst in bytes.
 * @param sig Output buffer receiving the DER signature (at least DSA_size(@p dsa) bytes).
 * @param siglen Receives the number of signature bytes written.
 * @param dsa DSA key containing the private key used for signing.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_sign(int type, const unsigned char *dgst,
    int dlen, unsigned char *sig,
    unsigned int *siglen, DSA *dsa);
/**
 * @brief Verify a DSA signature over a message digest (deprecated).
 * @param type Historical digest NID; ignored by modern implementations.
 * @param dgst Digest octets that were signed.
 * @param dgst_len Length of @p dgst in bytes.
 * @param sigbuf DER-encoded DSA signature to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param dsa DSA key containing the public key used for verification.
 * @return 1 if the signature is valid, 0 if invalid, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_verify(int type, const unsigned char *dgst,
    int dgst_len, const unsigned char *sigbuf,
    int siglen, DSA *dsa);

#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
/**
 * @brief Store application-specific data on a DSA object at a CRYPTO ex_data index (deprecated).
 * @param d DSA object to update.
 * @param idx Index obtained from DSA_get_ex_new_index() / CRYPTO_get_ex_new_index().
 * @param arg Pointer to store (ownership rules follow CRYPTO_set_ex_data()).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set_ex_data(DSA *d, int idx, void *arg);
/**
 * @brief Retrieve application data previously stored on a DSA object (deprecated).
 * @param d DSA object to query.
 * @param idx Index obtained from DSA_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *DSA_get_ex_data(const DSA *d, int idx);

/**
 * @brief Decode a DSA public key from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA public key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPublicKey(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA public key to DER (deprecated).
 * @param a DSA key whose public components are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPublicKey(const DSA *a, unsigned char **out);
/**
 * @brief Decode a DSA private key from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA private key to DER (deprecated).
 * @param a DSA key to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey(const DSA *a, unsigned char **out);
/**
 * @brief Decode DSA domain parameters from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return DSA object holding the decoded parameters, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAparams(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode DSA domain parameters to DER (deprecated).
 * @param a DSA object whose p, q, and g parameters are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAparams(const DSA *a, unsigned char **out);
#endif

#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/* Deprecated version */
/**
 * @brief Generate DSA domain parameters with a legacy progress callback (deprecated).
 * @param bits Desired length of the prime p in bits.
 * @param seed Optional seed bytes for reproducible generation, or NULL.
 * @param seed_len Length of @p seed in bytes.
 * @param counter_ret Optional out-parameter receiving the counter used, or NULL.
 * @param h_ret Optional out-parameter receiving the h value used, or NULL.
 * @param callback Optional progress callback, or NULL.
 * @param cb_arg Opaque pointer passed to @p callback.
 * @return Newly allocated DSA with generated parameters, or NULL on failure.
 */
OSSL_DEPRECATEDIN_0_9_8
DSA *DSA_generate_parameters(int bits, unsigned char *seed, int seed_len,
    int *counter_ret, unsigned long *h_ret,
    void (*callback)(int, int, void *),
    void *cb_arg);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* New version */
/**
 * @brief Generate DSA domain parameters into an existing DSA object (deprecated).
 * @param dsa Destination DSA that receives p, q, and g.
 * @param bits Desired length of the prime p in bits.
 * @param seed Optional seed for deterministic generation, or NULL.
 * @param seed_len Length of @p seed in bytes.
 * @param counter_ret Optional output for the generation counter, or NULL.
 * @param h_ret Optional output for the generator counter h, or NULL.
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_generate_parameters_ex(DSA *dsa, int bits,
    const unsigned char *seed,
    int seed_len,
    int *counter_ret,
    unsigned long *h_ret,
    BN_GENCB *cb);

/**
 * @brief Generate a DSA public/private key pair from parameters already in @p a.
 * @param a DSA object that already holds domain parameters; receives pub_key and priv_key.
 * @return 1 on success, or 0 on failure.
 *
 * Deprecated; prefer EVP_PKEY_keygen_init() / EVP_PKEY_keygen() for DSA.
 * The CSPRNG must be seeded; failure to seed or reseed causes this call to fail.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_generate_key(DSA *a);

/**
 * @brief Print DSA domain parameters (p, q, g) to a BIO in human-readable form (deprecated).
 * @param bp BIO that receives the textual dump.
 * @param x DSA object whose parameters are printed.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSAparams_print(BIO *bp, const DSA *x);
/**
 * @brief Print a human-readable representation of a DSA key to a BIO (deprecated).
 * @param bp BIO that receives the textual dump.
 * @param x DSA key (parameters and/or key pair) to print.
 * @param off Indentation width in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_print(BIO *bp, const DSA *x, int off);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Print DSA domain parameters to a FILE (deprecated).
 * @param fp Output FILE.
 * @param x DSA object whose parameters are printed.
 * @return 1 on success, or 0 or a negative value on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSAparams_print_fp(FILE *fp, const DSA *x);
/**
 * @brief Print a human-readable representation of a DSA key to a FILE (deprecated).
 * @param bp Output FILE stream.
 * @param x DSA key (parameters and/or key pair) to print.
 * @param off Indentation width in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_print_fp(FILE *bp, const DSA *x, int off);
#endif

#define DSS_prime_checks 64
/*
 * Primality test according to FIPS PUB 186-4, Appendix C.3. Since we only
 * have one value here we set the number of checks to 64 which is the 128 bit
 * security level that is the highest level and valid for creating a 3072 bit
 * DSA key.
 */
#define DSA_is_prime(n, callback, cb_arg) \
    BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

#ifndef OPENSSL_NO_DH
/**
 * @brief Duplicate DSA parameters (and key material when present) into a new DH object (deprecated).
 * @param r Source DSA object whose p/q/g (and optional keys) are copied.
 * @return New DH object, or NULL on error; free with DH_free().
 *
 * Be careful to avoid small-subgroup attacks when using the resulting DH key.
 */
OSSL_DEPRECATEDIN_3_0 DH *DSA_dup_DH(const DSA *r);
#endif

/**
 * @brief Return pointers to the DSA domain parameters p, q, and g without transferring ownership (deprecated).
 * @param d DSA object to query.
 * @param p Optional destination for the prime modulus, or NULL.
 * @param q Optional destination for the subprime, or NULL.
 * @param g Optional destination for the generator, or NULL.
 *
 * Prefer EVP_PKEY_get_bn_param() for new code. Returned BIGNUMs must not be freed by the caller.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_get0_pqg(const DSA *d, const BIGNUM **p,
    const BIGNUM **q, const BIGNUM **g);
/**
 * @brief Set the DSA domain parameters p, q, and g, transferring ownership (deprecated).
 * @param d DSA object to update.
 * @param p Prime modulus; ownership transfers to @p d.
 * @param q Subprime / order of g; ownership transfers to @p d.
 * @param g Generator; ownership transfers to @p d.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_PKEY_set_bn_param() for new code. Do not free @p p, @p q, or @p g after success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
/**
 * @brief Return pointers to the DSA public and private key components without transferring ownership (deprecated).
 * @param d DSA object to query.
 * @param pub_key Optional destination for the public key, or NULL.
 * @param priv_key Optional destination for the private key, or NULL.
 *
 * Returned BIGNUMs must not be freed by the caller.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_get0_key(const DSA *d, const BIGNUM **pub_key,
    const BIGNUM **priv_key);
/**
 * @brief Set the public and optional private key components of a DSA object (deprecated).
 * @param d DSA object to update.
 * @param pub_key Public key y; ownership transferred (must not be NULL).
 * @param priv_key Private key x; ownership transferred, or NULL to leave/clear private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set0_key(DSA *d, BIGNUM *pub_key,
    BIGNUM *priv_key);
/**
 * @brief Return the DSA prime modulus p without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for p, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_p(const DSA *d);
/**
 * @brief Return the DSA subgroup order q without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for q, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_q(const DSA *d);
/**
 * @brief Return the DSA generator g without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for g, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_g(const DSA *d);
/**
 * @brief Return the public key component of a DSA object without duplicating it (deprecated).
 * @param d DSA key to query.
 * @return Internal BIGNUM pointer for the public key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_pub_key(const DSA *d);
/**
 * @brief Return the private key component of a DSA object without duplicating it (deprecated).
 * @param d DSA key to query.
 * @return Internal BIGNUM pointer for the private key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_priv_key(const DSA *d);
/**
 * @brief Clear selected flag bits on a DSA object (deprecated).
 * @param d DSA object to update.
 * @param flags Bitmask of DSA_FLAG_* values to clear.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_clear_flags(DSA *d, int flags);
/**
 * @brief Test whether all bits in @p flags are set on a DSA object (deprecated).
 * @param d DSA object whose flag word is queried.
 * @param flags Bitmask of DSA_FLAG_* values to test.
 * @return Non-zero if every bit in @p flags is set, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_test_flags(const DSA *d, int flags);
/**
 * @brief Set flag bits on a DSA object without clearing existing flags (deprecated).
 * @param d DSA object to update.
 * @param flags Bitmask of DSA_FLAG_* values to set.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_set_flags(DSA *d, int flags);
/**
 * @brief Return the ENGINE associated with a DSA key, if any.
 * @param d DSA object to query.
 * @return ENGINE handle previously set on @p d, or NULL if none.
 *
 * Deprecated; ENGINE-based DSA methods are superseded by providers.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *DSA_get0_engine(DSA *d);

/**
 * @brief Allocate a new DSA_METHOD with the given name and default flags (deprecated).
 * @param name NUL-terminated descriptive name; duplicated into the method object.
 * @param flags Flag bits copied onto DSA objects that use this method.
 * @return New DSA_METHOD, or NULL on failure; free with DSA_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_new(const char *name, int flags);
/**
 * @brief Free a DSA_METHOD structure and any associated memory (deprecated).
 * @param dsam Method to free; NULL is ignored.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_meth_free(DSA_METHOD *dsam);
/**
 * @brief Duplicate a DSA_METHOD object (deprecated).
 * @param dsam Method to copy.
 * @return Newly allocated DSA_METHOD copy, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_dup(const DSA_METHOD *dsam);
/**
 * @brief Return the descriptive name stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Internal name string (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const char *DSA_meth_get0_name(const DSA_METHOD *dsam);
/**
 * @brief Set the descriptive name of a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param name NUL-terminated name copied into @p dsam.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set1_name(DSA_METHOD *dsam,
    const char *name);
/**
 * @brief Return the flag mask stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Flags previously set with DSA_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_get_flags(const DSA_METHOD *dsam);
/**
 * @brief Set the flag mask on a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param flags New flag bits for the method.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_flags(DSA_METHOD *dsam, int flags);
/**
 * @brief Return the opaque application data pointer stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Application data previously set with DSA_meth_set0_app_data(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void *DSA_meth_get0_app_data(const DSA_METHOD *dsam);
/**
 * @brief Store an opaque application pointer on a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param app_data Caller-owned pointer retrieved later with DSA_meth_get0_app_data().
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set0_app_data(DSA_METHOD *dsam,
    void *app_data);
/**
 * @brief Return the signing callback installed on a DSA_METHOD.
 * @param dsam Method object to query.
 * @return Function pointer used to create a DSA_SIG, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 DSA_SIG *(*DSA_meth_get_sign(const DSA_METHOD *dsam))(const unsigned char *, int, DSA *);
/**
 * @brief Install the DSA signing callback on a DSA_METHOD (deprecated).
 * @param dsam Method being configured.
 * @param sign Callback that signs a digest and returns a DSA_SIG, or NULL to clear.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign(DSA_METHOD *dsam,
    DSA_SIG *(*sign)(const unsigned char *, int, DSA *));
/**
 * @brief Return the sign-setup callback installed on a DSA_METHOD (deprecated).
 * @param dsam Method to query.
 * @return Sign-setup function pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_sign_setup(const DSA_METHOD *dsam))(DSA *, BN_CTX *, BIGNUM **, BIGNUM **);
/**
 * @brief Set the signature precomputation callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param sign_setup Callback that prepares signing intermediates, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign_setup(DSA_METHOD *dsam,
    int (*sign_setup)(DSA *, BN_CTX *, BIGNUM **, BIGNUM **));
/**
 * @brief Return the signature-verification callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the verify callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_verify(const DSA_METHOD *dsam))(const unsigned char *, int, DSA_SIG *, DSA *);
/**
 * @brief Set the DSA signature-verification callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param verify Callback invoked by DSA_do_verify()/DSA_verify(), or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_verify(DSA_METHOD *dsam,
    int (*verify)(const unsigned char *, int, DSA_SIG *, DSA *));
/**
 * @brief Return the modular-exponentiation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the mod_exp callback used during signing/verification, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
/**
 * @brief Set the modular-exponentiation callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param mod_exp Callback performing the DSA modular exponentiation, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_mod_exp(DSA_METHOD *dsam,
    int (*mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
        BN_MONT_CTX *));
/**
 * @brief Return the modular-exponentiation callback from a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Pointer to the bn_mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    BN_CTX *, BN_MONT_CTX *);
/**
 * @brief Set the modular-exponentiation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param bn_mod_exp Callback computing r = a^p mod m (with optional Montgomery ctx), or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam,
    int (*bn_mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, BN_CTX *, BN_MONT_CTX *));
/**
 * @brief Return the DSA object-initialization callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_init(const DSA_METHOD *dsam))(DSA *);
/**
 * @brief Set the DSA object-initialization callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param init Callback invoked when a DSA object using this method is created, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_init(DSA_METHOD *dsam,
    int (*init)(DSA *));
/**
 * @brief Return the DSA object-finalization callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_finish(const DSA_METHOD *dsam))(DSA *);
/**
 * @brief Set the DSA object-finalization callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param finish Callback invoked when a DSA object using this method is freed, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_finish(DSA_METHOD *dsam,
    int (*finish)(DSA *));
/**
 * @brief Return the parameter-generation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the paramgen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_paramgen(const DSA_METHOD *dsam))(DSA *, int, const unsigned char *, int, int *, unsigned long *,
    BN_GENCB *);
/**
 * @brief Set the parameter-generation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param paramgen Callback that generates DSA domain parameters, or NULL to clear.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_paramgen(DSA_METHOD *dsam,
    int (*paramgen)(DSA *, int, const unsigned char *, int, int *,
        unsigned long *, BN_GENCB *));
/**
 * @brief Return the key-generation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the keygen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_keygen(const DSA_METHOD *dsam))(DSA *);
/**
 * @brief Set the key-generation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param keygen Callback that fills public/private key values on a DSA object, or NULL to clear.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_keygen(DSA_METHOD *dsam,
    int (*keygen)(DSA *));

#endif
#endif
#ifdef __cplusplus
}
#endif
#endif
