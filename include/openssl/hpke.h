/*
 * Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* APIs and data structures for HPKE (RFC9180)  */
#ifndef OSSL_HPKE_H
#define OSSL_HPKE_H
#pragma once

/* Patched for the Mr.Docs demo: this header uses size_t but is not
 * self-contained (glibc does not leak size_t through <openssl/types.h> the
 * way the macOS SDK does), and Mr.Docs parses every header standalone. */
#include <stddef.h>
#include <openssl/types.h>

/* HPKE modes */
#define OSSL_HPKE_MODE_BASE 0 /* Base mode  */
#define OSSL_HPKE_MODE_PSK 1 /* Pre-shared key mode */
#define OSSL_HPKE_MODE_AUTH 2 /* Authenticated mode */
#define OSSL_HPKE_MODE_PSKAUTH 3 /* PSK+authenticated mode */

/*
 * Max for ikm, psk, pskid, info and exporter contexts.
 * RFC9180, section 7.2.1 RECOMMENDS 64 octets but we have test vectors from
 * Appendix A.6.1 with a 66 octet IKM so we'll allow that.
 */
#define OSSL_HPKE_MAX_PARMLEN 66
#define OSSL_HPKE_MIN_PSKLEN 32
#define OSSL_HPKE_MAX_INFOLEN 1024

/*
 * The (16bit) HPKE algorithm ID IANA codepoints
 * If/when new IANA codepoints are added there are tables in
 * crypto/hpke/hpke_util.c that must also be updated.
 */
#define OSSL_HPKE_KEM_ID_RESERVED 0x0000 /* not used */
#define OSSL_HPKE_KEM_ID_P256 0x0010 /* NIST P-256 */
#define OSSL_HPKE_KEM_ID_P384 0x0011 /* NIST P-384 */
#define OSSL_HPKE_KEM_ID_P521 0x0012 /* NIST P-521 */
#define OSSL_HPKE_KEM_ID_X25519 0x0020 /* Curve25519 */
#define OSSL_HPKE_KEM_ID_X448 0x0021 /* Curve448 */

#define OSSL_HPKE_KDF_ID_RESERVED 0x0000 /* not used */
#define OSSL_HPKE_KDF_ID_HKDF_SHA256 0x0001 /* HKDF-SHA256 */
#define OSSL_HPKE_KDF_ID_HKDF_SHA384 0x0002 /* HKDF-SHA384 */
#define OSSL_HPKE_KDF_ID_HKDF_SHA512 0x0003 /* HKDF-SHA512 */

#define OSSL_HPKE_AEAD_ID_RESERVED 0x0000 /* not used */
#define OSSL_HPKE_AEAD_ID_AES_GCM_128 0x0001 /* AES-GCM-128 */
#define OSSL_HPKE_AEAD_ID_AES_GCM_256 0x0002 /* AES-GCM-256 */
#define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /* Chacha20-Poly1305 */
#define OSSL_HPKE_AEAD_ID_EXPORTONLY 0xFFFF /* export-only fake ID */

/* strings for suite components */
#define OSSL_HPKE_KEMSTR_P256 "P-256" /* KEM id 0x10 */
#define OSSL_HPKE_KEMSTR_P384 "P-384" /* KEM id 0x11 */
#define OSSL_HPKE_KEMSTR_P521 "P-521" /* KEM id 0x12 */
#define OSSL_HPKE_KEMSTR_X25519 "X25519" /* KEM id 0x20 */
#define OSSL_HPKE_KEMSTR_X448 "X448" /* KEM id 0x21 */
#define OSSL_HPKE_KDFSTR_256 "hkdf-sha256" /* KDF id 1 */
#define OSSL_HPKE_KDFSTR_384 "hkdf-sha384" /* KDF id 2 */
#define OSSL_HPKE_KDFSTR_512 "hkdf-sha512" /* KDF id 3 */
#define OSSL_HPKE_AEADSTR_AES128GCM "aes-128-gcm" /* AEAD id 1 */
#define OSSL_HPKE_AEADSTR_AES256GCM "aes-256-gcm" /* AEAD id 2 */
#define OSSL_HPKE_AEADSTR_CP "chacha20-poly1305" /* AEAD id 3 */
#define OSSL_HPKE_AEADSTR_EXP "exporter" /* AEAD id 0xff */

/*
 * Roles for use in creating an OSSL_HPKE_CTX, most
 * important use of this is to control nonce reuse.
 */
#define OSSL_HPKE_ROLE_SENDER 0
#define OSSL_HPKE_ROLE_RECEIVER 1

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief HPKE cipher suite identifying the KEM, KDF, and AEAD algorithms (RFC 9180).
 */
typedef struct {
    /** @brief IANA HPKE KEM identifier (OSSL_HPKE_KEM_ID_*). */
    uint16_t kem_id; /* Key Encapsulation Method id */
    /** @brief IANA HPKE KDF identifier (OSSL_HPKE_KDF_ID_*). */
    uint16_t kdf_id; /* Key Derivation Function id */
    /** @brief IANA HPKE AEAD identifier (OSSL_HPKE_AEAD_ID_*), or OSSL_HPKE_AEAD_ID_EXPORTONLY. */
    uint16_t aead_id; /* AEAD alg id */
} OSSL_HPKE_SUITE;

/**
 * Suite constants, use this like:
 *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
#ifndef OPENSSL_NO_ECX
#define OSSL_HPKE_SUITE_DEFAULT       \
    {                                 \
        OSSL_HPKE_KEM_ID_X25519,      \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }
#else
#define OSSL_HPKE_SUITE_DEFAULT       \
    {                                 \
        OSSL_HPKE_KEM_ID_P256,        \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }
#endif

/**
 * @brief Opaque HPKE session state holding secrets and sequence for sender or receiver role.
 */
struct ossl_hpke_ctx_st;
/**
 * @brief Opaque HPKE context used for encapsulation, sealing, opening, and export (RFC 9180).
 */
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

/**
 * @brief Create an HPKE context for the given mode, suite, and sender/receiver role.
 * @param mode HPKE mode (OSSL_HPKE_MODE_BASE, PSK, AUTH, or PSKAUTH).
 * @param suite KEM/KDF/AEAD suite identifiers.
 * @param role OSSL_HPKE_ROLE_SENDER or OSSL_HPKE_ROLE_RECEIVER.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Optional property query string, or NULL.
 * @return New context, or NULL on error; free with OSSL_HPKE_CTX_free().
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Free an HPKE context and clear associated secrets.
 * @param ctx Context to free, or NULL (no-op).
 */
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

/**
 * @brief Encapsulate to a recipient public key and derive sender HPKE secrets.
 * @param ctx Sender HPKE context (only one successful call allowed per context).
 * @param enc Destination for the encapsulated public value; on input *@p enclen is capacity.
 * @param enclen In/out length of @p enc (updated with bytes written).
 * @param pub Recipient public key octets for the suite's KEM.
 * @param publen Length of @p pub in bytes.
 * @param info Optional application info bound into key schedule, or NULL if @p infolen is 0.
 * @param infolen Length of @p info in bytes (must not exceed OSSL_HPKE_MAX_INFOLEN).
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx,
    unsigned char *enc, size_t *enclen,
    const unsigned char *pub, size_t publen,
    const unsigned char *info, size_t infolen);
/**
 * @brief Encrypt plaintext with AEAD using secrets derived by a prior OSSL_HPKE_encap().
 * @param ctx Sender HPKE context after successful encapsulation.
 * @param ct Destination ciphertext buffer; on input *@p ctlen is its capacity.
 * @param ctlen In/out ciphertext length (updated with bytes written).
 * @param aad Optional additional authenticated data, or NULL if @p aadlen is 0.
 * @param aadlen Length of @p aad in bytes.
 * @param pt Plaintext to encrypt.
 * @param ptlen Length of @p pt in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx,
    unsigned char *ct, size_t *ctlen,
    const unsigned char *aad, size_t aadlen,
    const unsigned char *pt, size_t ptlen);

/**
 * @brief Generate an HPKE recipient key pair for @p suite, optionally from IKM.
 * @param suite Suite whose KEM determines the key type.
 * @param pub Destination for the encoded public key; on input *@p publen is capacity.
 * @param publen In/out public-key length.
 * @param priv Address of an EVP_PKEY* set to the new private key on success.
 * @param ikm Optional input key material for deterministic generation, or NULL for random.
 * @param ikmlen Length of @p ikm (0 when @p ikm is NULL); should be >= recommended IKM length.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Optional property query string, or NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite,
    unsigned char *pub, size_t *publen, EVP_PKEY **priv,
    const unsigned char *ikm, size_t ikmlen,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Decapsulate a sender's encapsulated key and derive the shared HPKE secrets.
 * @param ctx Receiver HPKE context (only one successful call allowed per context).
 * @param enc Encapsulated public value from OSSL_HPKE_encap().
 * @param enclen Length of @p enc in bytes.
 * @param recippriv Recipient private key matching the suite's KEM.
 * @param info Optional application info bound into key schedule, or NULL if @p infolen is 0.
 * @param infolen Length of @p info in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx,
    const unsigned char *enc, size_t enclen,
    EVP_PKEY *recippriv,
    const unsigned char *info, size_t infolen);
/**
 * @brief Decrypt ciphertext with AEAD using secrets derived by a prior OSSL_HPKE_decap().
 * @param ctx Receiver HPKE context after successful decapsulation.
 * @param pt Destination plaintext buffer; on input *@p ptlen is its capacity.
 * @param ptlen In/out plaintext length (updated with bytes written).
 * @param aad Optional additional authenticated data, or NULL if @p aadlen is 0.
 * @param aadlen Length of @p aad in bytes.
 * @param ct Ciphertext to decrypt (same order as produced by OSSL_HPKE_seal()).
 * @param ctlen Length of @p ct in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx,
    unsigned char *pt, size_t *ptlen,
    const unsigned char *aad, size_t aadlen,
    const unsigned char *ct, size_t ctlen);

/**
 * @brief Derive an exporter secret from an established HPKE context (after encap/decap).
 * @param ctx HPKE context with derived secrets.
 * @param secret Destination buffer for the exported secret.
 * @param secretlen Desired export length in bytes.
 * @param label Application-supplied exporter context label.
 * @param labellen Length of @p label in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx,
    unsigned char *secret,
    size_t secretlen,
    const unsigned char *label,
    size_t labellen);

/**
 * @brief Set the sender authentication private key for AUTH / PSKAUTH modes.
 * @param ctx Sender HPKE context (call before OSSL_HPKE_encap()).
 * @param priv Sender authentication private key using the same KEM as the suite.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv);
/**
 * @brief Set the sender authentication public key for AUTH / PSKAUTH modes.
 * @param ctx Receiver HPKE context (call before OSSL_HPKE_decap()).
 * @param pub Encoded sender authentication public key.
 * @param publen Length of @p pub in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
    const unsigned char *pub,
    size_t publen);
/**
 * @brief Set the pre-shared key and PSK identifier for PSK / PSKAUTH modes.
 * @param ctx HPKE context on sender or receiver (call before encap/decap).
 * @param pskid NUL-terminated PSK identity string (non-NULL when a PSK is used).
 * @param psk PSK bytes (non-NULL; length at least OSSL_HPKE_MIN_PSKLEN).
 * @param psklen Length of @p psk in bytes.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
    const char *pskid,
    const unsigned char *psk, size_t psklen);

/**
 * @brief Override the sender's ephemeral IKM used inside OSSL_HPKE_encap() (deterministic).
 * @param ctx Sender HPKE context (optional; call before OSSL_HPKE_encap()).
 * @param ikme Input key material for deterministic ephemeral key generation.
 * @param ikmelen Length of @p ikme; should be >= OSSL_HPKE_get_recommended_ikmelen().
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
    const unsigned char *ikme, size_t ikmelen);

/**
 * @brief Set the AEAD sequence number used on the next seal/open call (receivers only).
 * @param ctx Receiver HPKE context; fails if @p ctx is a sender context.
 * @param seq Sequence / nonce increment value to install.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
/**
 * @brief Return the AEAD sequence number that will be used on the next seal/open call.
 * @param ctx HPKE context to query.
 * @param seq Receives the next sequence / nonce increment value.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);

/**
 * @brief Test whether the local build supports the given HPKE suite.
 * @param suite Suite identifiers to validate.
 * @return 1 if supported, or 0 if not.
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
/**
 * @brief Produce GREASE-like random encap and ciphertext buffers sized for an HPKE suite.
 * @param suite_in Preferred suite for sizing, or NULL to pick a random supported suite.
 * @param suite Optional output receiving the suite actually used for sizing.
 * @param enc Destination for a random encapsulated-key-sized buffer.
 * @param enclen In/out length of @p enc.
 * @param ct Destination for a random ciphertext-sized buffer of length @p ctlen.
 * @param ctlen Desired ciphertext buffer length (and plaintext-equivalent sizing input).
 * @param libctx Library context, or NULL for the default.
 * @param propq Optional property query string, or NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_get_grease_value(const OSSL_HPKE_SUITE *suite_in,
    OSSL_HPKE_SUITE *suite,
    unsigned char *enc, size_t *enclen,
    unsigned char *ct, size_t ctlen,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Parse a comma-separated "kem,kdf,aead" string into an OSSL_HPKE_SUITE.
 * @param str Suite string such as "x25519,hkdf-sha256,aes-128-gcm" (case-insensitive names or numeric ids).
 * @param suite Destination suite filled on success.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
/**
 * @brief Return the ciphertext size needed to seal a plaintext of length @p clearlen.
 * @param suite Suite whose AEAD tag expansion is applied.
 * @param clearlen Plaintext length in bytes.
 * @return Required ciphertext length, or 0 on error.
 */
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);
/**
 * @brief Return the encapsulated public-key size produced by OSSL_HPKE_encap() for @p suite.
 * @param suite Suite whose KEM determines the encap length.
 * @return Encapsulated key length in bytes, or 0 on error.
 */
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);
/**
 * @brief Return the recommended IKM length for deterministic key generation with @p suite.
 * @param suite Suite whose KEM determines the recommended IKM size.
 * @return Recommended IKM length in bytes, or 0 on error.
 */
size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite);

#ifdef __cplusplus
}
#endif

#endif
