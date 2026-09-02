/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DH_H
#define OPENSSL_DH_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_DH_H
#endif

#include <openssl/opensslconf.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

/*
 * DH parameter generation types used by EVP_PKEY_CTX_set_dh_paramgen_type()
 * Note that additions/changes to this set of values requires corresponding
 * adjustments to range checks in dh_gen()
 */
#define DH_PARAMGEN_TYPE_GENERATOR 0 /* Use a safe prime generator */
#define DH_PARAMGEN_TYPE_FIPS_186_2 1 /* Use FIPS186-2 standard */
#define DH_PARAMGEN_TYPE_FIPS_186_4 2 /* Use FIPS186-4 standard */
#define DH_PARAMGEN_TYPE_GROUP 3 /* Use a named safe prime group */

/**
 * @brief Select the DH parameter-generation algorithm for a keygen/paramgen context.
 * @param ctx EVP_PKEY_CTX configured for DH (or DHX) parameter generation.
 * @param typ One of DH_PARAMGEN_TYPE_* (generator, FIPS 186-2/186-4, or named group).
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_type(EVP_PKEY_CTX *ctx, int typ);
/**
 * @brief Set the FIPS 186-4 gindex used when generating DH parameters.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param gindex Canonical gindex selecting the generator construction.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
/**
 * @brief Set a fixed seed for DH parameter generation (testing / reproducible params).
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param seed Seed octets used instead of a random seed; must yield primes on the first iteration.
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or a non-positive value on error.
 *
 * Persist @p seed if later validation of p, q, and verifiable g is required; it is not part of a stored key.
 */
int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);
/**
 * @brief Set the DH parameter-generation prime (p) length in bits.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param pbits Desired bit length of the prime modulus p.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits);
/**
 * @brief Set the DH parameter-generation subprime (q) length in bits.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param qlen Desired bit length of the subprime q.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qlen);
/**
 * @brief Set the DH parameter-generation generator (g) on @p ctx.
 * @param ctx Keygen/paramgen context for a DH key type.
 * @param gen Generator value (commonly 2 or 5).
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
/**
 * @brief Select named Diffie-Hellman parameters (RFC 7919 / RFC 3526) by NID.
 * @param ctx EVP_PKEY_CTX used for DH parameter or key generation.
 * @param nid Named group such as NID_ffdhe2048 or NID_modp_2048, or NID_undef to clear.
 * @return 1 on success, or a non-positive value on error.
 *
 * Mutually exclusive with EVP_PKEY_CTX_set_dh_rfc5114() / set_dhx_rfc5114().
 */
int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid);
/**
 * @brief Select RFC 5114 DH parameters (sections 2.1–2.3) on a DHX key context.
 * @param ctx EVP_PKEY_CTX with key type EVP_PKEY_DHX used for parameter generation.
 * @param gen 1, 2, or 3 for RFC 5114 §2.1/§2.2/§2.3, or 0 to clear.
 * @return 1 on success, or a non-positive value on error.
 *
 * Mutually exclusive with EVP_PKEY_CTX_set_dh_nid().
 */
int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen);
/**
 * @brief Select an RFC 5114 DHX (X9.42 DH) named parameter set on a keygen/paramgen context.
 * @param ctx EVP_PKEY_CTX for a DHX operation.
 * @param gen RFC 5114 parameter-set index (1, 2, or 3).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen);
/**
 * @brief Enable or disable leading-zero padding of the DH shared secret to the prime length.
 * @param ctx Key-derivation / derive context for a DH key.
 * @param pad Non-zero to pad the secret to BN_num_bytes(p); 0 to return the minimal big-endian form.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad);

/**
 * @brief Set the DH key-derivation function type on an EVP_PKEY_CTX.
 * @param ctx Key derivation / encapsulate context for a DH key.
 * @param kdf KDF type such as EVP_PKEY_DH_KDF_NONE or EVP_PKEY_DH_KDF_X9_42.
 * @return 1 on success, or a negative value for unsupported / failure.
 *
 * When using EVP_PKEY_DH_KDF_X9_42, also set the KDF OID, digest, and output length.
 */
int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);
/**
 * @brief Return the DH key-derivation function type configured on @p ctx.
 * @param ctx Key context for a DHX KDF / derive operation.
 * @return EVP_PKEY_DH_KDF_NONE, EVP_PKEY_DH_KDF_X9_42, or a negative value on error.
 */
int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx);
/**
 * @brief Set the X9.42 KDF OID for DH key derivation, transferring ownership of @p oid.
 * @param ctx Key context configured for a DHX KDF / derive operation.
 * @param oid ASN.1 object identifying the CEK algorithm; @p ctx takes ownership.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid);
/**
 * @brief Return the X9.42 KDF OID currently configured on a DH key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param oid Receives an internal ASN1_OBJECT pointer (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid);
/**
 * @brief Set the message digest used for DH key-derivation (KDF) on a key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param md Digest method such as EVP_sha256(); ownership is not transferred.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Get the message digest used for DH key-derivation (KDF) on a key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param md Receives a pointer to the digest method (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
/**
 * @brief Set the output length in bytes of the DH key-derivation function.
 * @param ctx Key context configured for a DH KDF operation.
 * @param len Desired KDF output length in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int len);
/**
 * @brief Return the configured DH KDF output length in bytes.
 * @param ctx Key context configured for a DH KDF operation.
 * @param len Receives the current KDF output length.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);
/**
 * @brief Set the DH KDF User Keying Material, transferring ownership of @p ukm.
 * @param ctx Key-exchange context configured for DH KDF.
 * @param ukm UKM bytes that @p ctx will own and free; may be NULL when @p len is 0.
 * @param len Length of @p ukm in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Borrow the DH KDF User Keying Material pointer and return its length (deprecated).
 * @param ctx Key context configured for a DH KDF operation.
 * @param ukm Receives an internal pointer to the UKM bytes (do not free).
 * @return UKM length in bytes on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
#endif

#define EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_DH_RFC5114 (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_DH_PARAMGEN_TYPE (EVP_PKEY_ALG_CTRL + 5)
#define EVP_PKEY_CTRL_DH_KDF_TYPE (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_DH_KDF_MD (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_GET_DH_KDF_MD (EVP_PKEY_ALG_CTRL + 8)
#define EVP_PKEY_CTRL_DH_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN (EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTRL_DH_KDF_UKM (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_GET_DH_KDF_UKM (EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_DH_KDF_OID (EVP_PKEY_ALG_CTRL + 13)
#define EVP_PKEY_CTRL_GET_DH_KDF_OID (EVP_PKEY_ALG_CTRL + 14)
#define EVP_PKEY_CTRL_DH_NID (EVP_PKEY_ALG_CTRL + 15)
#define EVP_PKEY_CTRL_DH_PAD (EVP_PKEY_ALG_CTRL + 16)

/* KDF types */
#define EVP_PKEY_DH_KDF_NONE 1
#define EVP_PKEY_DH_KDF_X9_42 2

#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/e_os2.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#include <openssl/bn.h>
#endif
#include <openssl/dherr.h>

#ifndef OPENSSL_DH_MAX_MODULUS_BITS
#define OPENSSL_DH_MAX_MODULUS_BITS 10000
#endif

#ifndef OPENSSL_DH_CHECK_MAX_MODULUS_BITS
#define OPENSSL_DH_CHECK_MAX_MODULUS_BITS 32768
#endif

#define OPENSSL_DH_FIPS_MIN_MODULUS_BITS 1024

#define DH_FLAG_CACHE_MONT_P 0x01

#define DH_FLAG_TYPE_MASK 0xF000
#define DH_FLAG_TYPE_DH 0x0000
#define DH_FLAG_TYPE_DHX 0x1000

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#define DH_FLAG_NO_EXP_CONSTTIME 0x00
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * If this flag is set the DH method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

#define DH_FLAG_FIPS_METHOD 0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#define DH_FLAG_NON_FIPS_ALLOW 0x0400
#endif

/* Already defined in ossl_typ.h */
/* typedef struct dh_st DH; */
/* typedef struct dh_method DH_METHOD; */

/**
 * @brief Return the ASN.1 item descriptor for Diffie-Hellman domain parameters.
 * @return Pointer to the static ASN1_ITEM for DHparams.
 */
const ASN1_ITEM *DHparams_it(void);

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DH_GENERATOR_2 2
#define DH_GENERATOR_3 3
#define DH_GENERATOR_5 5

/* DH_check error codes, some of them shared with DH_check_pub_key */
/*
 * NB: These values must align with the equivalently named macros in
 * internal/ffc.h.
 */
#define DH_CHECK_P_NOT_PRIME 0x01
#define DH_CHECK_P_NOT_SAFE_PRIME 0x02
#define DH_UNABLE_TO_CHECK_GENERATOR 0x04
#define DH_NOT_SUITABLE_GENERATOR 0x08
#define DH_CHECK_Q_NOT_PRIME 0x10
#define DH_CHECK_INVALID_Q_VALUE 0x20 /* +DH_check_pub_key */
#define DH_CHECK_INVALID_J_VALUE 0x40
#define DH_MODULUS_TOO_SMALL 0x80
#define DH_MODULUS_TOO_LARGE 0x100 /* +DH_check_pub_key */

/* DH_check_pub_key error codes */
#define DH_CHECK_PUBKEY_TOO_SMALL 0x01
#define DH_CHECK_PUBKEY_TOO_LARGE 0x02
#define DH_CHECK_PUBKEY_INVALID 0x04

/*
 * primes p where (p-1)/2 is prime too are called "safe"; we define this for
 * backward compatibility:
 */
#define DH_CHECK_P_NOT_STRONG_PRIME DH_CHECK_P_NOT_SAFE_PRIME

#define d2i_DHparams_fp(fp, x)                 \
    (DH *)ASN1_d2i_fp((void *(*)(void))DH_new, \
        (d2i_of_void *)d2i_DHparams,           \
        (fp),                                  \
        (void **)(x))
#define i2d_DHparams_fp(fp, x) \
    ASN1_i2d_fp(i2d_DHparams, (fp), (unsigned char *)(x))
#define d2i_DHparams_bio(bp, x) \
    ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
#define i2d_DHparams_bio(bp, x) \
    ASN1_i2d_bio_of(DH, i2d_DHparams, bp, x)

#define d2i_DHxparams_fp(fp, x)                \
    (DH *)ASN1_d2i_fp((void *(*)(void))DH_new, \
        (d2i_of_void *)d2i_DHxparams,          \
        (fp),                                  \
        (void **)(x))
#define i2d_DHxparams_fp(fp, x) \
    ASN1_i2d_fp(i2d_DHxparams, (fp), (unsigned char *)(x))
#define d2i_DHxparams_bio(bp, x) \
    ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)
#define i2d_DHxparams_bio(bp, x) \
    ASN1_i2d_bio_of(DH, i2d_DHxparams, bp, x)

/**
 * @brief Duplicate Diffie-Hellman domain parameters (DHparams_dup) (deprecated).
 * @param a Source DH object whose p, q, and g are copied.
 * @return Newly allocated DH with duplicated parameters, or NULL on failure.
 */
DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, DH, DHparams)

/**
 * @brief Return the built-in OpenSSL software DH_METHOD (deprecated).
 * @return Pointer to the default internal Diffie-Hellman method table.
 */
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_OpenSSL(void);

/**
 * @brief Set the process-wide default DH_METHOD (deprecated).
 * @param meth Method that new DH objects use unless overridden.
 */
OSSL_DEPRECATEDIN_3_0 void DH_set_default_method(const DH_METHOD *meth);
/**
 * @brief Return the process-wide default DH_METHOD (deprecated).
 * @return Pointer to the current default method.
 */
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_get_default_method(void);
/**
 * @brief Select the DH_METHOD used for operations on @p dh (deprecated).
 * @param dh DH object whose method is replaced.
 * @param meth Method implementation to attach; releases any prior ENGINE method.
 * @return Non-zero on success.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_method(DH *dh, const DH_METHOD *meth);
/**
 * @brief Allocate a DH object that uses @p engine for DH operations (deprecated).
 * @param engine ENGINE to use, or NULL for the default DH ENGINE / method.
 * @return New DH, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_new_method(ENGINE *engine);

/**
 * @brief Allocate and initialize an empty DH object (deprecated).
 * @return New DH, or NULL on allocation failure.
 *
 * Prefer EVP_PKEY-based Diffie-Hellman APIs for new code.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_new(void);
/**
 * @brief Free a DH object and decrement its reference count (deprecated).
 * @param dh Object to free; NULL is ignored. The structure is released when the last reference drops.
 */
OSSL_DEPRECATEDIN_3_0 void DH_free(DH *dh);
/**
 * @brief Increment the reference count of a DH object (deprecated).
 * @param dh Diffie-Hellman object whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_up_ref(DH *dh);
/**
 * @brief Return the bit length of the Diffie-Hellman prime modulus p (deprecated).
 * @param dh DH object whose parameters are queried; @p dh and its p must be non-NULL.
 * @return Number of significant bits in p.
 */
OSSL_DEPRECATEDIN_3_0 int DH_bits(const DH *dh);
/**
 * @brief Return the Diffie-Hellman shared-secret size in bytes (deprecated).
 * @param dh DH key whose prime modulus length is queried.
 * @return Number of bytes needed to hold a shared secret (BN_num_bytes of p), or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_size(const DH *dh);
/**
 * @brief Estimate the security strength in bits of a DH key's parameters (deprecated).
 * @param dh DH object whose prime size is assessed.
 * @return Approximate security strength in bits, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_security_bits(const DH *dh);

#define DH_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef)

/**
 * @brief Store application data on a DH object at a CRYPTO_EX index (deprecated).
 * @param d DH object to update.
 * @param idx Index from DH_get_ex_new_index().
 * @param arg Application pointer to store (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_ex_data(DH *d, int idx, void *arg);
/**
 * @brief Return application data previously stored on a DH object (deprecated).
 * @param d DH object to query.
 * @param idx Index obtained from DH_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *DH_get_ex_data(const DH *d, int idx);

/**
 * @brief Generate Diffie-Hellman domain parameters into @p dh (deprecated).
 * @param dh Destination DH object that receives p and g.
 * @param prime_len Desired bit length of the prime modulus p.
 * @param generator Generator g (commonly 2 or 5).
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_PKEY_paramgen for new code.
 */
OSSL_DEPRECATEDIN_3_0 int DH_generate_parameters_ex(DH *dh, int prime_len,
    int generator,
    BN_GENCB *cb);

/**
 * @brief Validate Diffie-Hellman p/g (and q if present) and report problems via the error queue (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @return 1 if the parameters look suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_params_ex(const DH *dh);
/**
 * @brief Validate Diffie-Hellman parameters and report problems via the error queue (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @return 1 if the parameters look suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_ex(const DH *dh);
/**
 * @brief Validate a Diffie-Hellman public key and report problems via the error queue (deprecated).
 * @param dh DH object providing the domain parameters used for the check.
 * @param pub_key Public key value to validate against those parameters.
 * @return 1 if the public key looks suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key);
/**
 * @brief Perform a lightweight check that DH parameters p and g look plausible (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @param ret Receives zero or DH_CHECK_* reason bits describing problems found.
 * @return 1 if the check routine ran successfully (inspect @p ret), or 0 on hard failure.
 *
 * Prefer DH_check() when a more thorough validation is required.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_params(const DH *dh, int *ret);
/**
 * @brief Validate Diffie-Hellman parameters and return a bitmask of problems (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @param codes Receives zero or a combination of DH_CHECK_* reason bits.
 * @return 1 if the check routine ran successfully (inspect @p codes), or 0 on hard failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check(const DH *dh, int *codes);
/**
 * @brief Validate a Diffie-Hellman public key and return a bitmask of problems (deprecated).
 * @param dh DH object providing the domain parameters used for the check.
 * @param pub_key Public key value to validate against those parameters.
 * @param codes Receives zero or a combination of DH_CHECK_PUBKEY_* reason bits.
 * @return 1 if the check routine ran successfully (inspect @p codes), or 0 on hard failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key,
    int *codes);
/**
 * @brief Generate a Diffie-Hellman private/public key pair on @p dh (deprecated).
 * @param dh DH object that already holds domain parameters; receives the new key pair.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_PKEY_keygen / EVP_PKEY_derive for new code.
 */
OSSL_DEPRECATEDIN_3_0 int DH_generate_key(DH *dh);
/**
 * @brief Derive the DH shared secret from a peer public key (deprecated).
 * @param key Output buffer of at least DH_size(@p dh) bytes.
 * @param pub_key Peer public value.
 * @param dh DH object holding the private key and domain parameters.
 * @return Number of bytes written, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_compute_key(unsigned char *key,
    const BIGNUM *pub_key, DH *dh);
/**
 * @brief Derive the DH shared secret with NIST SP 800-56A leading-zero padding (deprecated).
 *
 * Like DH_compute_key() but always writes DH_size(@p dh) bytes, retaining leading zeros
 * (constant-time w.r.t. the secret length). Prefer EVP_PKEY_derive for new code.
 * @param key Output buffer of at least DH_size(@p dh) bytes.
 * @param pub_key Peer public value.
 * @param dh DH object holding the private key and domain parameters.
 * @return DH_size(@p dh) on success, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_compute_key_padded(unsigned char *key,
    const BIGNUM *pub_key, DH *dh);

/**
 * @brief Decode Diffie-Hellman domain parameters from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DH parameters, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DH *d2i_DHparams(DH **a, const unsigned char **in, long len);
/**
 * @brief Encode Diffie-Hellman domain parameters to DER (deprecated).
 * @param a DH object whose parameters are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DHparams(const DH *a, unsigned char **out);
/**
 * @brief Decode Diffie-Hellman X9.42 domain parameters (with q/j/seed) from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DH with X9.42 parameters, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DH *d2i_DHxparams(DH **a, const unsigned char **in, long len);
/**
 * @brief Encode Diffie-Hellman X9.42 domain parameters (with q/j/seed) to DER (deprecated).
 * @param a DH object whose X9.42 parameters are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DHxparams(const DH *a, unsigned char **out);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Print DH parameters to a FILE in human-readable form (deprecated).
 * @param fp Output FILE.
 * @param x DH object whose parameters are printed.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DHparams_print_fp(FILE *fp, const DH *x);
#endif
/**
 * @brief Print Diffie-Hellman parameters to a BIO in human-readable form (deprecated).
 * @param bp Output BIO.
 * @param x DH object whose parameters are printed.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DHparams_print(BIO *bp, const DH *x);

/* RFC 5114 parameters */
/**
 * @brief Allocate a DH object with the RFC 5114 1024-bit MODP group using a 160-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_1024_160(void);
/**
 * @brief Allocate a DH object with the RFC 5114 2048-bit MODP group using a 224-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_224(void);
/**
 * @brief Allocate a DH object with the RFC 5114 2048-bit MODP group using a 256-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_256(void);

/**
 * @brief Allocate a DH object preloaded with named safe-prime parameters.
 * @param nid Named group NID such as NID_ffdhe2048 or NID_modp_2048.
 * @return New DH with the named parameters set, or NULL if @p nid is unsupported or on allocation failure.
 *
 * Deprecated since OpenSSL 3.0; prefer EVP_PKEY_fromdata() with a named group.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_new_by_nid(int nid);
/**
 * @brief Return the named-group NID for a DH object if its parameters match a known group (deprecated).
 * @param dh DH object to query.
 * @return Matching NID such as NID_ffdhe2048, or NID_undef if the parameters are not a named group.
 */
OSSL_DEPRECATEDIN_3_0 int DH_get_nid(const DH *dh);

/* RFC2631 KDF */
/**
 * @brief Derive keying material with the ANSI X9.42 / RFC 2631 KDF (deprecated).
 * @param out Output buffer of @p outlen bytes receiving the derived key.
 * @param outlen Desired derived-key length.
 * @param Z Shared secret bytes.
 * @param Zlen Length of @p Z.
 * @param key_oid Algorithm OID embedded in the OtherInfo structure.
 * @param ukm Optional partyInfo/UKM bytes, or NULL.
 * @param ukmlen Length of @p ukm when non-NULL.
 * @param md Message digest used by the KDF.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_KDF_X9_42(unsigned char *out, size_t outlen,
    const unsigned char *Z, size_t Zlen,
    ASN1_OBJECT *key_oid,
    const unsigned char *ukm,
    size_t ukmlen, const EVP_MD *md);

/**
 * @brief Borrow pointers to the prime, optional subprime, and generator of a DH object (deprecated).
 * @param dh DH object to query.
 * @param p Receives an internal pointer to p, or NULL to skip; do not free.
 * @param q Receives an internal pointer to q when present, or NULL to skip; do not free.
 * @param g Receives an internal pointer to g, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void DH_get0_pqg(const DH *dh, const BIGNUM **p,
    const BIGNUM **q, const BIGNUM **g);
/**
 * @brief Set the prime, optional subprime, and generator on a DH object, transferring ownership (deprecated).
 * @param dh DH object to update.
 * @param p New modulus p; ownership transfers to @p dh (must not be freed by the caller on success).
 * @param q Optional subprime q, or NULL; ownership transfers when non-NULL.
 * @param g New generator g; ownership transfers to @p dh.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
/**
 * @brief Borrow pointers to the public and private key BIGNUMs of a DH object (deprecated).
 * @param dh DH object to query.
 * @param pub_key Receives an internal pointer to the public value, or NULL to skip; do not free.
 * @param priv_key Receives an internal pointer to the private value, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
    const BIGNUM **priv_key);
/**
 * @brief Set the public and/or private key BIGNUMs on a DH object, transferring ownership (deprecated).
 * @param dh DH object to update.
 * @param pub_key New public value, or NULL to leave the existing public key unchanged.
 * @param priv_key New private value, or NULL to leave the existing private key unchanged.
 * @return 1 on success, or 0 on failure.
 *
 * Non-NULL values are owned by @p dh after a successful call and must not be freed by the caller.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
/**
 * @brief Return the prime modulus p stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_p(const DH *dh);
/**
 * @brief Return the optional subprime q stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_q(const DH *dh);
/**
 * @brief Return the generator g stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_g(const DH *dh);
/**
 * @brief Return the private key BIGNUM stored in a DH object, if any.
 * @param dh DH object to query.
 * @return Internal pointer to the private key (do not free), or NULL if unset.
 *
 * Deprecated; prefer EVP_PKEY_get_bn_param() / provider-based key APIs.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_priv_key(const DH *dh);
/**
 * @brief Return the public key component of a DH object without duplicating it (deprecated).
 * @param dh DH key to query.
 * @return Internal BIGNUM pointer for the public key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_pub_key(const DH *dh);
/**
 * @brief Clear selected flag bits on a DH object (deprecated).
 * @param dh DH object to update.
 * @param flags Bitmask of DH_FLAG_* values to clear.
 */
OSSL_DEPRECATEDIN_3_0 void DH_clear_flags(DH *dh, int flags);
/**
 * @brief Return which of the requested flag bits are currently set on a DH object (deprecated).
 * @param dh DH object to query.
 * @param flags Bitmask of DH_FLAG_* values to test (may combine several bits).
 * @return Subset of @p flags that are set, or 0 if none match.
 */
OSSL_DEPRECATEDIN_3_0 int DH_test_flags(const DH *dh, int flags);
/**
 * @brief Set flag bits on a DH object without clearing existing flags (deprecated).
 * @param dh DH object to update.
 * @param flags Bitmask of DH_FLAG_* values to set.
 */
OSSL_DEPRECATEDIN_3_0 void DH_set_flags(DH *dh, int flags);
/**
 * @brief Return the ENGINE bound to a DH object, if any (deprecated).
 * @param d DH object to query.
 * @return ENGINE handle, or NULL when no ENGINE is set.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *DH_get0_engine(DH *d);
/**
 * @brief Return the optional private-value length hint stored on a DH object (deprecated).
 * @param dh DH object to query.
 * @return Preferred secret-exponent length in bits, or 0 if the default should be used.
 */
OSSL_DEPRECATEDIN_3_0 long DH_get_length(const DH *dh);
/**
 * @brief Set the optional private-value length hint on a DH object (deprecated).
 * @param dh DH object to update.
 * @param length Preferred length in bits of the secret exponent, or 0 for the default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_length(DH *dh, long length);

/**
 * @brief Allocate a custom DH_METHOD with a duplicated name (deprecated).
 * @param name Display name copied into the method object.
 * @param flags Initial DH_METHOD flag bits.
 * @return New DH_METHOD, or NULL on failure; free with DH_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_new(const char *name, int flags);
/**
 * @brief Free a DH_METHOD structure and any associated memory (deprecated).
 * @param dhm Method to free; NULL is ignored.
 */
OSSL_DEPRECATEDIN_3_0 void DH_meth_free(DH_METHOD *dhm);
/**
 * @brief Duplicate a DH_METHOD, copying its name and callbacks (deprecated).
 * @param dhm Method table to clone.
 * @return New DH_METHOD, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_dup(const DH_METHOD *dhm);
/**
 * @brief Return the display name stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return NUL-terminated name string owned by @p dhm.
 */
OSSL_DEPRECATEDIN_3_0 const char *DH_meth_get0_name(const DH_METHOD *dhm);
/**
 * @brief Replace the display name stored on a DH_METHOD (deprecated).
 * @param dhm Method object to update.
 * @param name NUL-terminated name that is duplicated into @p dhm; the caller retains @p name.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set1_name(DH_METHOD *dhm, const char *name);
/**
 * @brief Return the flag mask stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Flags previously set with DH_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_get_flags(const DH_METHOD *dhm);
/**
 * @brief Replace the flag mask stored on a DH_METHOD (deprecated).
 * @param dhm Method object to update.
 * @param flags New flag mask (for example DH_FLAG_CACHE_MONT_P).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_flags(DH_METHOD *dhm, int flags);
/**
 * @brief Return the opaque application data pointer stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Application data previously set with DH_meth_set0_app_data(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void *DH_meth_get0_app_data(const DH_METHOD *dhm);
/**
 * @brief Attach opaque application data to a DH_METHOD, transferring ownership of the pointer (deprecated).
 * @param dhm Method object to update.
 * @param app_data Caller-owned pointer stored on the method (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data);
/**
 * @brief Return the key-generation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the generate_key callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_key(const DH_METHOD *dhm))(DH *);
/**
 * @brief Set the key-generation callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param generate_key Callback that fills a DH object's public/private values, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_key(DH_METHOD *dhm,
    int (*generate_key)(DH *));
/**
 * @brief Return the shared-secret compute_key callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the compute_key callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_compute_key(const DH_METHOD *dhm))(unsigned char *key,
    const BIGNUM *pub_key,
    DH *dh);
/**
 * @brief Set the shared-secret compute_key callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param compute_key Callback invoked by DH_compute_key(), or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_compute_key(DH_METHOD *dhm,
    int (*compute_key)(unsigned char *key,
        const BIGNUM *pub_key,
        DH *dh));
/**
 * @brief Return the modular-exponentiation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the bn_mod_exp callback used during DH operations, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_bn_mod_exp(const DH_METHOD *dhm))(const DH *, BIGNUM *,
    const BIGNUM *,
    const BIGNUM *,
    const BIGNUM *, BN_CTX *,
    BN_MONT_CTX *);
/**
 * @brief Set the modular-exponentiation callback on a DH_METHOD (deprecated).
 *
 * The callback computes r = a^p mod m and is used by the default DH_generate_key()
 * implementation. Prefer provider APIs for new code.
 * @param dhm Method table to update.
 * @param bn_mod_exp Callback implementing modular exponentiation, or NULL to clear
 *        (must be non-NULL when using the default generate_key).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_bn_mod_exp(DH_METHOD *dhm,
    int (*bn_mod_exp)(const DH *, BIGNUM *,
        const BIGNUM *, const BIGNUM *,
        const BIGNUM *, BN_CTX *,
        BN_MONT_CTX *));
/**
 * @brief Return the DH object-initialization callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_init(const DH_METHOD *dhm))(DH *);
/**
 * @brief Set the DH object-initialization callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param init Callback invoked when a DH object using this method is initialized, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *));
/**
 * @brief Return the finish/cleanup callback installed on a custom DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_finish(const DH_METHOD *dhm))(DH *);
/**
 * @brief Set the DH object teardown callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param finish Callback invoked from DH_free() for method-specific cleanup (must not free the DH itself), or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_finish(DH_METHOD *dhm, int (*finish)(DH *));
/**
 * @brief Return the parameter-generation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the generate_params callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_params(const DH_METHOD *dhm))(DH *, int, int,
    BN_GENCB *);
/**
 * @brief Set the parameter-generation callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param generate_params Callback that fills domain parameters for a DH object, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_params(DH_METHOD *dhm,
    int (*generate_params)(DH *, int, int,
        BN_GENCB *));
#endif /* OPENSSL_NO_DEPRECATED_3_0 */

#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/**
 * @brief Generate Diffie-Hellman parameters with a legacy progress callback (deprecated).
 * @param prime_len Desired length of the prime p in bits.
 * @param generator DH generator g (commonly 2 or 5).
 * @param callback Optional progress callback (int, int, void *), or NULL.
 * @param cb_arg Opaque pointer passed to @p callback.
 * @return Newly allocated DH with generated parameters, or NULL on failure.
 */
OSSL_DEPRECATEDIN_0_9_8 DH *DH_generate_parameters(int prime_len, int generator,
    void (*callback)(int, int,
        void *),
    void *cb_arg);
#endif

#endif
#ifdef __cplusplus
}
#endif
#endif
