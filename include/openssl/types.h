/*
 * Copyright 2001-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Unfortunate workaround to avoid symbol conflict with wincrypt.h
 * See https://github.com/openssl/openssl/issues/9981
 */
#ifdef _WIN32
#define WINCRYPT_USE_SYMBOL_PREFIX
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#ifndef OPENSSL_TYPES_H
#define OPENSSL_TYPES_H

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/e_os2.h>
#include <openssl/safestack.h>
#include <openssl/macros.h>

/**
 * @brief Opaque provider object representing a loaded algorithm implementation module.
 */
typedef struct ossl_provider_st OSSL_PROVIDER;

#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER ASN1_STRING
#define ASN1_ENUMERATED ASN1_STRING
#define ASN1_BIT_STRING ASN1_STRING
#define ASN1_OCTET_STRING ASN1_STRING
#define ASN1_PRINTABLESTRING ASN1_STRING
#define ASN1_T61STRING ASN1_STRING
#define ASN1_IA5STRING ASN1_STRING
#define ASN1_UTCTIME ASN1_STRING
#define ASN1_GENERALIZEDTIME ASN1_STRING
#define ASN1_TIME ASN1_STRING
#define ASN1_GENERALSTRING ASN1_STRING
#define ASN1_UNIVERSALSTRING ASN1_STRING
#define ASN1_BMPSTRING ASN1_STRING
#define ASN1_VISIBLESTRING ASN1_STRING
#define ASN1_UTF8STRING ASN1_STRING
#define ASN1_BOOLEAN int
#define ASN1_NULL int
#else
/**
 * @brief ASN.1 INTEGER stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_INTEGER;
/**
 * @brief ASN.1 ENUMERATED stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_ENUMERATED;
/**
 * @brief ASN.1 BIT STRING stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_BIT_STRING;
/**
 * @brief ASN.1 OCTET STRING stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_OCTET_STRING;
/** @brief ASN.1 PrintableString stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
/** @brief ASN.1 TeletexString/T61String stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_T61STRING;
/**
 * @brief ASN.1 IA5String stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_IA5STRING;
/**
 * @brief ASN.1 GeneralString stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_GENERALSTRING;
/** @brief ASN.1 UniversalString stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
/**
 * @brief ASN.1 BMPString (UCS-2 / Basic Multilingual Plane) stored as an asn1_string_st.
 */
typedef struct asn1_string_st ASN1_BMPSTRING;
/** @brief ASN.1 UTCTime value stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UTCTIME;
/** @brief ASN.1 Time choice (UTCTime or GeneralizedTime) stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_TIME;
/** @brief ASN.1 GeneralizedTime value stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
/**
 * @brief ASN.1 VisibleString stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_VISIBLESTRING;
/** @brief ASN.1 UTF8String stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UTF8STRING;
/**
 * @brief Generic ASN.1 string container (length, type, and data bytes).
 */
typedef struct asn1_string_st ASN1_STRING;
/** @brief ASN.1 BOOLEAN represented as an int (-1 unset, 0 FALSE, 0xff TRUE). */
typedef int ASN1_BOOLEAN;
/** @brief ASN.1 NULL placeholder type (no payload). */
typedef int ASN1_NULL;
#endif

/**
 * @brief ASN.1 ANY / CHOICE container holding a typed value and its V_ASN1_* tag.
 */
typedef struct asn1_type_st ASN1_TYPE;
/**
 * @brief Opaque ASN.1 OBJECT IDENTIFIER (OID) value.
 */
typedef struct asn1_object_st ASN1_OBJECT;
/**
 * @brief Table entry describing size limits and encoding masks for an ASN.1 string NID.
 */
typedef struct asn1_string_table_st ASN1_STRING_TABLE;

/**
 * @brief Opaque ASN.1 item descriptor used by the generic encode/decode/print APIs.
 */
typedef struct ASN1_ITEM_st ASN1_ITEM;
/**
 * @brief Opaque ASN.1 print context controlling formatting flags for item printers.
 */
typedef struct asn1_pctx_st ASN1_PCTX;
/**
 * @brief Opaque ASN.1 scan context used while decoding constructed types.
 */
struct asn1_sctx_st;
/**
 * @brief Opaque ASN.1 scan context used while decoding constructed types.
 */
typedef struct asn1_sctx_st ASN1_SCTX;

#ifdef BIGNUM
#undef BIGNUM
#endif

/**
 * @brief Opaque Basic I/O abstraction (filters and source/sink streams).
 */
typedef struct bio_st BIO;
/**
 * @brief Arbitrary-precision integer used throughout OpenSSL's public-key math.
 */
typedef struct bignum_st BIGNUM;
/**
 * @brief Temporary-variable pool used by BIGNUM arithmetic helpers.
 */
typedef struct bignum_ctx BN_CTX;
/**
 * @brief Opaque RSA/modular blinding state (BN_BLINDING_*).
 */
struct bn_blinding_st;
/**
 * @brief Opaque RSA/modular blinding state (BN_BLINDING_*).
 */
typedef struct bn_blinding_st BN_BLINDING;
/**
 * @brief Montgomery multiplication context for a fixed odd modulus (BN_MONT_CTX_*).
 */
typedef struct bn_mont_ctx_st BN_MONT_CTX;
/**
 * @brief Reciprocal context accelerating repeated modular division/remainder.
 */
typedef struct bn_recp_ctx_st BN_RECP_CTX;
/**
 * @brief Progress-callback object used by prime generation and similar BN routines.
 */
typedef struct bn_gencb_st BN_GENCB;

/**
 * @brief Growable memory buffer used by BIO memory BIOs and similar helpers.
 */
typedef struct buf_mem_st BUF_MEM;

/** @brief STACK_OF container for mutable BIGNUM pointers. */
STACK_OF(BIGNUM);
/** @brief STACK_OF container for const BIGNUM pointers. */
STACK_OF(BIGNUM_const);

/**
 * @brief Opaque per-thread (or saved) OpenSSL error-queue state.
 */
typedef struct err_state_st ERR_STATE;

/**
 * @brief Opaque symmetric cipher method (algorithm implementation) used with EVP_CIPHER_CTX.
 */
typedef struct evp_cipher_st EVP_CIPHER;
/**
 * @brief Opaque symmetric-cipher operation context (EVP_EncryptInit and related EVP_Cipher APIs).
 */
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
/**
 * @brief Opaque message-digest method (algorithm implementation) used with EVP_MD_CTX.
 */
typedef struct evp_md_st EVP_MD;
/**
 * @brief Opaque message-digest operation context (EVP_Digest* / EVP_DigestSign*).
 */
struct evp_md_ctx_st;
/**
 * @brief Opaque message-digest operation context (EVP_Digest* / EVP_DigestSign*).
 */
typedef struct evp_md_ctx_st EVP_MD_CTX;
/**
 * @brief Opaque MAC algorithm (EVP_MAC_fetch / EVP_Q_mac).
 */
struct evp_mac_st;
/**
 * @brief Opaque MAC algorithm (EVP_MAC_fetch / EVP_Q_mac).
 */
typedef struct evp_mac_st EVP_MAC;
/**
 * @brief Opaque MAC operation context (EVP_MAC_CTX_new / EVP_MAC_init / EVP_MAC_update / EVP_MAC_final).
 */
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
/**
 * @brief Opaque public/private key handle used throughout the EVP and X.509 APIs.
 */
typedef struct evp_pkey_st EVP_PKEY;

/**
 * @brief Opaque ASN.1 method table describing how an EVP_PKEY type is encoded.
 */
struct evp_pkey_asn1_method_st;
/**
 * @brief Opaque ASN.1 method table describing how an EVP_PKEY type is encoded.
 */
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

/**
 * @brief Opaque legacy method table implementing an EVP_PKEY algorithm (deprecated in 3.0).
 */
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
/**
 * @brief Opaque context for public-key operations (sign, verify, encrypt, derive, keygen, and related controls).
 */
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

/**
 * @brief Opaque key-management algorithm implementation (provider keymgmt).
 */
struct evp_keymgmt_st;
/**
 * @brief Opaque key-management algorithm implementation (provider keymgmt).
 */
typedef struct evp_keymgmt_st EVP_KEYMGMT;

/**
 * @brief Opaque key-derivation function method returned by EVP_KDF_fetch().
 */
typedef struct evp_kdf_st EVP_KDF;
/**
 * @brief Opaque key-derivation function context (EVP_KDF_CTX_*).
 */
struct evp_kdf_ctx_st;
/**
 * @brief Opaque key-derivation function context (EVP_KDF_CTX_*).
 */
typedef struct evp_kdf_ctx_st EVP_KDF_CTX;

/**
 * @brief Opaque random-number generator method fetched from a provider (DRBG and related).
 */
typedef struct evp_rand_st EVP_RAND;
/**
 * @brief Opaque RAND operation context created from an EVP_RAND method.
 */
typedef struct evp_rand_ctx_st EVP_RAND_CTX;

/**
 * @brief Opaque key-exchange algorithm method (EVP_KEYEXCH_fetch).
 */
typedef struct evp_keyexch_st EVP_KEYEXCH;

/**
 * @brief Opaque signature algorithm method (EVP_SIGNATURE_fetch).
 */
typedef struct evp_signature_st EVP_SIGNATURE;

/**
 * @brief Opaque asymmetric cipher method (EVP_ASYM_CIPHER_fetch).
 */
typedef struct evp_asym_cipher_st EVP_ASYM_CIPHER;

/**
 * @brief Opaque key-encapsulation mechanism algorithm (EVP_KEM_*).
 */
struct evp_kem_st;
/**
 * @brief Opaque key-encapsulation mechanism algorithm (EVP_KEM_*).
 */
typedef struct evp_kem_st EVP_KEM;

/**
 * @brief Opaque context for EVP_Encode and EVP_Decode base64 streaming.
 */
typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;

/**
 * @brief Opaque HMAC computation context (legacy HMAC_* API).
 */
typedef struct hmac_ctx_st HMAC_CTX;

/**
 * @brief Opaque Diffie-Hellman key/parameters object (deprecated low-level DH_* API).
 */
typedef struct dh_st DH;
/**
 * @brief Opaque DH method table (deprecated engine-style DH_METHOD_*).
 */
struct dh_method;
/**
 * @brief Opaque DH method table (deprecated engine-style DH_METHOD_*).
 */
typedef struct dh_method DH_METHOD;

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Opaque DSA key/parameters object (deprecated low-level DSA_* API).
 */
typedef struct dsa_st DSA;
/**
 * @brief Opaque DSA_METHOD table of low-level DSA callbacks (deprecated).
 */
typedef struct dsa_method DSA_METHOD;
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Opaque RSA key object (deprecated; prefer EVP_PKEY).
 */
typedef struct rsa_st RSA;
/**
 * @brief Opaque RSA method table for ENGINE-style RSA implementations (deprecated).
 */
typedef struct rsa_meth_st RSA_METHOD;
#endif

/**
 * @brief Opaque RSASSA-PSS parameter structure (hashAlg / maskGenAlg / saltLength / trailerField).
 */
struct rsa_pss_params_st;
/**
 * @brief Opaque RSASSA-PSS parameter structure (hashAlg / maskGenAlg / saltLength / trailerField).
 */
typedef struct rsa_pss_params_st RSA_PSS_PARAMS;
/**
 * @brief Opaque RSAES-OAEP parameter structure (hashFunc / maskGenFunc / pSourceFunc).
 */
struct rsa_oaep_params_st;
/**
 * @brief Opaque RSAES-OAEP parameter structure (hashFunc / maskGenFunc / pSourceFunc).
 */
typedef struct rsa_oaep_params_st RSA_OAEP_PARAMS;

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Opaque elliptic-curve key containing group parameters and public/private points.
 */
typedef struct ec_key_st EC_KEY;
/**
 * @brief Opaque method table customizing EC_KEY operations (deprecated ENGINE-style API).
 */
typedef struct ec_key_method_st EC_KEY_METHOD;
#endif

/**
 * @brief Legacy RAND method table (deprecated; prefer EVP_RAND providers).
 */
typedef struct rand_meth_st RAND_METHOD;
/**
 * @brief Legacy deterministic random bit generator handle (deprecated; prefer EVP_RAND).
 */
typedef struct rand_drbg_st RAND_DRBG;

/**
 * @brief Opaque DANE (DNS-based Authentication of Named Entities) state for TLS.
 */
typedef struct ssl_dane_st SSL_DANE;
/**
 * @brief Opaque X.509 certificate (RFC 5280 Certificate).
 */
typedef struct x509_st X509;
/**
 * @brief Opaque ASN.1 AlgorithmIdentifier (algorithm OID plus optional parameters).
 */
typedef struct X509_algor_st X509_ALGOR;
/**
 * @brief Opaque X.509 certificate revocation list.
 */
struct X509_crl_st;
/**
 * @brief Opaque X.509 certificate revocation list.
 */
typedef struct X509_crl_st X509_CRL;
/**
 * @brief Opaque method table customizing CRL lookup/verification behaviour.
 */
struct x509_crl_method_st;
/**
 * @brief Opaque method table customizing CRL lookup/verification behaviour.
 */
typedef struct x509_crl_method_st X509_CRL_METHOD;
/**
 * @brief Opaque single revoked-certificate entry within an X509_CRL.
 */
typedef struct x509_revoked_st X509_REVOKED;
/**
 * @brief Opaque X.509 distinguished name (SEQUENCE OF RelativeDistinguishedName).
 */
typedef struct X509_name_st X509_NAME;
/**
 * @brief Opaque SubjectPublicKeyInfo container (algorithm + public key BIT STRING).
 */
typedef struct X509_pubkey_st X509_PUBKEY;
/**
 * @brief Opaque trust store of certificates and CRLs used during verification.
 */
struct x509_store_st;
/**
 * @brief Opaque trust store of certificates and CRLs used during verification.
 */
typedef struct x509_store_st X509_STORE;
/**
 * @brief Opaque certificate-verification context (one chain validation attempt).
 */
typedef struct x509_store_ctx_st X509_STORE_CTX;

/**
 * @brief Opaque X509_STORE cache entry holding a certificate or CRL.
 */
typedef struct x509_object_st X509_OBJECT;
/**
 * @brief Opaque certificate/CRL lookup method instance attached to an X509_STORE.
 */
typedef struct x509_lookup_st X509_LOOKUP;
/**
 * @brief Opaque method table describing how an X509_LOOKUP finds certificates/CRLs.
 */
typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
/**
 * @brief Opaque verification-parameter object (purpose, trust, time, flags, …).
 */
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

/**
 * @brief Opaque signature metadata (security bits / TLS usage flags) for an X.509 signature.
 */
struct x509_sig_info_st;
/**
 * @brief Opaque signature metadata (security bits / TLS usage flags) for an X.509 signature.
 */
typedef struct x509_sig_info_st X509_SIG_INFO;

/**
 * @brief Opaque PKCS#8 PrivateKeyInfo structure (RFC 5208).
 */
typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

/**
 * @brief Opaque context passed to X.509v3 extension helpers (issuer/subject/cert/request).
 */
typedef struct v3_ext_ctx X509V3_CTX;
/**
 * @brief Opaque NCONF configuration object holding sections and name/value pairs.
 */
typedef struct conf_st CONF;
/**
 * @brief Opaque OpenSSL library initialization settings passed to OPENSSL_init_crypto().
 */
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

/**
 * @brief Opaque interactive user-interface object used with UI_METHOD prompting.
 */
typedef struct ui_st UI;
/**
 * @brief Opaque UI_METHOD table implementing interactive user prompting.
 */
typedef struct ui_method_st UI_METHOD;

/**
 * @brief Opaque cryptographic ENGINE handle for legacy algorithm implementations (deprecated; prefer providers).
 */
typedef struct engine_st ENGINE;
/**
 * @brief Opaque TLS/DTLS/QUIC connection object.
 */
typedef struct ssl_st SSL;
/**
 * @brief Opaque TLS/DTLS/QUIC context holding shared configuration and certificates.
 */
typedef struct ssl_ctx_st SSL_CTX;

/**
 * @brief Opaque compression/decompression stream context used with COMP_METHOD.
 */
typedef struct comp_ctx_st COMP_CTX;
/**
 * @brief Opaque compression method table (zlib, brotli, zstd, and related COMP_* APIs).
 */
typedef struct comp_method_st COMP_METHOD;

/**
 * @brief Opaque node in an X.509 certificate policy tree.
 */
typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
/**
 * @brief Opaque single depth level within an X.509 certificate policy tree.
 */
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
/**
 * @brief Opaque X.509 certificate policy tree built during path validation (RFC 5280).
 */
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
/**
 * @brief Opaque cache of processed certificate policy data used during path validation.
 */
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

/**
 * @brief X.509v3 AuthorityKeyIdentifier extension value.
 */
typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
/**
 * @brief Opaque CRL distribution-point structure from a certificate extension.
 */
typedef struct DIST_POINT_st DIST_POINT;
/**
 * @brief Opaque Issuing Distribution Point extension value (CRL IDP).
 */
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
/**
 * @brief Opaque Name Constraints extension value (permitted/excluded subtrees).
 */
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

/**
 * @brief Opaque bag of application-specific ex_data slots attached to OpenSSL objects.
 */
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

/**
 * @brief Opaque HTTP request context used by OSSL_HTTP_* client helpers.
 */
typedef struct ossl_http_req_ctx_st OSSL_HTTP_REQ_CTX;
/**
 * @brief Opaque OCSP response structure (RFC 6960).
 */
typedef struct ocsp_response_st OCSP_RESPONSE;
/**
 * @brief Opaque OCSP ResponderID (byName or byKey).
 */
struct ocsp_responder_id_st;
/**
 * @brief Opaque OCSP ResponderID (byName or byKey).
 */
typedef struct ocsp_responder_id_st OCSP_RESPID;

/**
 * @brief Opaque Certificate Transparency Signed Certificate Timestamp.
 */
typedef struct sct_st SCT;
/**
 * @brief Opaque context used when verifying Certificate Transparency SCTs.
 */
typedef struct sct_ctx_st SCT_CTX;
/**
 * @brief Opaque Certificate Transparency log identity (public key + description).
 */
struct ctlog_st;
/**
 * @brief Opaque Certificate Transparency log identity (public key + description).
 */
typedef struct ctlog_st CTLOG;
/**
 * @brief Opaque store of Certificate Transparency logs trusted for SCT verification.
 */
typedef struct ctlog_store_st CTLOG_STORE;
/**
 * @brief Opaque Certificate Transparency policy evaluation context.
 */
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

/**
 * @brief Opaque object returned by OSSL_STORE describing a loaded key, cert, or CRL.
 */
typedef struct ossl_store_info_st OSSL_STORE_INFO;
/**
 * @brief Opaque search criterion object used with OSSL_STORE_expect / find APIs.
 */
typedef struct ossl_store_search_st OSSL_STORE_SEARCH;

/**
 * @brief Opaque library context that scopes providers, properties, and algorithm fetches.
 */
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

/**
 * @brief Function-pointer dispatch table entry exchanged between libcrypto and providers.
 */
typedef struct ossl_dispatch_st OSSL_DISPATCH;
/**
 * @brief Opaque provider item pairing an identifier with a pointer payload.
 */
typedef struct ossl_item_st OSSL_ITEM;
/**
 * @brief Opaque provider algorithm description (name, property, implementation).
 */
struct ossl_algorithm_st;
/**
 * @brief Opaque provider algorithm description (name, property, implementation).
 */
typedef struct ossl_algorithm_st OSSL_ALGORITHM;
/**
 * @brief Key/type/data triple used to pass parameters across provider boundaries.
 */
typedef struct ossl_param_st OSSL_PARAM;
/**
 * @brief Opaque builder that assembles a dynamic OSSL_PARAM array.
 */
struct ossl_param_bld_st;
/**
 * @brief Opaque builder that assembles a dynamic OSSL_PARAM array.
 */
typedef struct ossl_param_bld_st OSSL_PARAM_BLD;

/**
 * @brief Callback that supplies a passphrase when reading or writing encrypted PEM.
 * @param buf Output buffer that receives a NUL-terminated password.
 * @param size Capacity of @p buf in bytes.
 * @param rwflag 0 when reading (decrypt), nonzero when writing (encrypt).
 * @param userdata Application pointer from the PEM API that invoked the callback.
 * @return Number of password bytes written to @p buf (excluding NUL), or 0 on failure.
 */
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

/**
 * @brief Opaque encoder method that serializes keys and related objects.
 */
struct ossl_encoder_st;
/**
 * @brief Opaque encoder method that serializes keys and related objects.
 */
typedef struct ossl_encoder_st OSSL_ENCODER;
/**
 * @brief Opaque encoder context that drives OSSL_ENCODER output of keys and related objects.
 */
typedef struct ossl_encoder_ctx_st OSSL_ENCODER_CTX;
/**
 * @brief Opaque decoder method that converts external key/cert encodings into OpenSSL objects.
 */
typedef struct ossl_decoder_st OSSL_DECODER;
/**
 * @brief Opaque context that drives OSSL_DECODER providers when decoding keys/objects.
 */
typedef struct ossl_decoder_ctx_st OSSL_DECODER_CTX;

/**
 * @brief Opaque self-test event object used by provider FIPS self-test callbacks.
 */
typedef struct ossl_self_test_st OSSL_SELF_TEST;

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_TYPES_H */
