/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_SELF_TEST_H
#define OPENSSL_SELF_TEST_H
#pragma once

#include <openssl/core.h> /* OSSL_CALLBACK */

#ifdef __cplusplus
extern "C" {
#endif

/* The test event phases */
#define OSSL_SELF_TEST_PHASE_NONE "None"
#define OSSL_SELF_TEST_PHASE_START "Start"
#define OSSL_SELF_TEST_PHASE_CORRUPT "Corrupt"
#define OSSL_SELF_TEST_PHASE_PASS "Pass"
#define OSSL_SELF_TEST_PHASE_FAIL "Fail"

/* Test event categories */
#define OSSL_SELF_TEST_TYPE_NONE "None"
#define OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY "Module_Integrity"
#define OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY "Install_Integrity"
#define OSSL_SELF_TEST_TYPE_CRNG "Continuous_RNG_Test"
#define OSSL_SELF_TEST_TYPE_PCT "Conditional_PCT"
#define OSSL_SELF_TEST_TYPE_PCT_KAT "Conditional_KAT"
#define OSSL_SELF_TEST_TYPE_KAT_INTEGRITY "KAT_Integrity"
#define OSSL_SELF_TEST_TYPE_KAT_CIPHER "KAT_Cipher"
#define OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER "KAT_AsymmetricCipher"
#define OSSL_SELF_TEST_TYPE_KAT_DIGEST "KAT_Digest"
#define OSSL_SELF_TEST_TYPE_KAT_SIGNATURE "KAT_Signature"
#define OSSL_SELF_TEST_TYPE_PCT_SIGNATURE "PCT_Signature"
#define OSSL_SELF_TEST_TYPE_KAT_KDF "KAT_KDF"
#define OSSL_SELF_TEST_TYPE_KAT_KA "KAT_KA"
#define OSSL_SELF_TEST_TYPE_DRBG "DRBG"

/* Test event sub categories */
#define OSSL_SELF_TEST_DESC_NONE "None"
#define OSSL_SELF_TEST_DESC_INTEGRITY_HMAC "HMAC"
#define OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1 "RSA"
#define OSSL_SELF_TEST_DESC_PCT_ECDSA "ECDSA"
#define OSSL_SELF_TEST_DESC_PCT_EDDSA "EDDSA"
#define OSSL_SELF_TEST_DESC_PCT_DSA "DSA"
#define OSSL_SELF_TEST_DESC_CIPHER_AES_GCM "AES_GCM"
#define OSSL_SELF_TEST_DESC_CIPHER_AES_ECB "AES_ECB_Decrypt"
#define OSSL_SELF_TEST_DESC_CIPHER_TDES "TDES"
#define OSSL_SELF_TEST_DESC_ASYM_RSA_ENC "RSA_Encrypt"
#define OSSL_SELF_TEST_DESC_ASYM_RSA_DEC "RSA_Decrypt"
#define OSSL_SELF_TEST_DESC_MD_SHA1 "SHA1"
#define OSSL_SELF_TEST_DESC_MD_SHA2 "SHA2"
#define OSSL_SELF_TEST_DESC_MD_SHA3 "SHA3"
#define OSSL_SELF_TEST_DESC_SIGN_DSA "DSA"
#define OSSL_SELF_TEST_DESC_SIGN_RSA "RSA"
#define OSSL_SELF_TEST_DESC_SIGN_ECDSA "ECDSA"
#define OSSL_SELF_TEST_DESC_DRBG_CTR "CTR"
#define OSSL_SELF_TEST_DESC_DRBG_HASH "HASH"
#define OSSL_SELF_TEST_DESC_DRBG_HMAC "HMAC"
#define OSSL_SELF_TEST_DESC_KA_DH "DH"
#define OSSL_SELF_TEST_DESC_KA_ECDH "ECDH"
#define OSSL_SELF_TEST_DESC_KDF_HKDF "HKDF"
#define OSSL_SELF_TEST_DESC_KDF_SSKDF "SSKDF"
#define OSSL_SELF_TEST_DESC_KDF_X963KDF "X963KDF"
#define OSSL_SELF_TEST_DESC_KDF_X942KDF "X942KDF"
#define OSSL_SELF_TEST_DESC_KDF_PBKDF2 "PBKDF2"
#define OSSL_SELF_TEST_DESC_KDF_SSHKDF "SSHKDF"
#define OSSL_SELF_TEST_DESC_KDF_TLS12_PRF "TLS12_PRF"
#define OSSL_SELF_TEST_DESC_KDF_KBKDF "KBKDF"
#define OSSL_SELF_TEST_DESC_KDF_KBKDF_KMAC "KBKDF_KMAC"
#define OSSL_SELF_TEST_DESC_KDF_TLS13_EXTRACT "TLS13_KDF_EXTRACT"
#define OSSL_SELF_TEST_DESC_KDF_TLS13_EXPAND "TLS13_KDF_EXPAND"
#define OSSL_SELF_TEST_DESC_RNG "RNG"

/**
 * @brief Register a callback invoked during provider self-test operations.
 * @param libctx Library context, or NULL for the default.
 * @param cb Self-test event callback, or NULL to clear.
 * @param cbarg Opaque argument passed to @p cb.
 */
void OSSL_SELF_TEST_set_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK *cb,
    void *cbarg);
/**
 * @brief Retrieve the self-test callback previously set on a library context.
 * @param libctx Library context, or NULL for the default.
 * @param cb Address updated to the registered callback, or NULL if unset.
 * @param cbarg Address updated to the opaque argument passed to the callback, or NULL if unset.
 */
void OSSL_SELF_TEST_get_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK **cb,
    void **cbarg);

/**
 * @brief Allocate an OSSL_SELF_TEST handle that invokes @p cb during self-test phases.
 * @param cb Self-test event callback receiving phase/type/desc params.
 * @param cbarg Opaque argument passed to @p cb.
 * @return New self-test object, or NULL on allocation failure; free with OSSL_SELF_TEST_free().
 */
OSSL_SELF_TEST *OSSL_SELF_TEST_new(OSSL_CALLBACK *cb, void *cbarg);
/**
 * @brief Free an OSSL_SELF_TEST object allocated by OSSL_SELF_TEST_new().
 * @param st Object to free, or NULL.
 */
void OSSL_SELF_TEST_free(OSSL_SELF_TEST *st);

/**
 * @brief Signal the start of a self-test block (callback phase "Start").
 * @param st Self-test object from OSSL_SELF_TEST_new().
 * @param type Test category string (for example OSSL_SELF_TEST_TYPE_KAT_DIGEST).
 * @param desc Test subcategory string (for example OSSL_SELF_TEST_DESC_MD_SHA2).
 */
void OSSL_SELF_TEST_onbegin(OSSL_SELF_TEST *st, const char *type,
    const char *desc);
/**
 * @brief Optionally corrupt the first byte of @p bytes when the callback requests failure injection.
 * @param st Self-test object whose callback decides whether to corrupt.
 * @param bytes Buffer whose first byte may be altered (phase "Corrupt").
 * @return 1 if the first byte was corrupted, or 0 if the buffer was left unchanged.
 */
int OSSL_SELF_TEST_oncorrupt_byte(OSSL_SELF_TEST *st, unsigned char *bytes);
/**
 * @brief Signal the end of a self-test block with pass/fail (callback phase "Pass" or "Fail").
 * @param st Self-test object from OSSL_SELF_TEST_new().
 * @param ret Non-zero if the test passed; zero if it failed.
 */
void OSSL_SELF_TEST_onend(OSSL_SELF_TEST *st, int ret);

#ifdef __cplusplus
}
#endif
#endif /* OPENSSL_SELF_TEST_H */
