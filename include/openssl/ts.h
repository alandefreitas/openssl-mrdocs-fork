/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_TS_H
#define OPENSSL_TS_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_TS_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_TS
#include <openssl/symhacks.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/tserr.h>
#include <openssl/ess.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RFC 3161 MessageImprint: hash algorithm and hashed message octets.
 */
struct TS_msg_imprint_st;
/**
 * @brief RFC 3161 MessageImprint: hash algorithm and hashed message octets.
 */
typedef struct TS_msg_imprint_st TS_MSG_IMPRINT;
/**
 * @brief RFC 3161 TimeStampReq: version, message imprint, policy, nonce, and extensions.
 */
struct TS_req_st;
/**
 * @brief RFC 3161 TimeStampReq: version, message imprint, policy, nonce, and extensions.
 */
typedef struct TS_req_st TS_REQ;
/**
 * @brief RFC 3161 Accuracy: optional seconds, millis, and micros time precision.
 */
struct TS_accuracy_st;
/**
 * @brief RFC 3161 Accuracy: optional seconds, millis, and micros time precision.
 */
typedef struct TS_accuracy_st TS_ACCURACY;
/**
 * @brief RFC 3161 TSTInfo: policy, imprint, serial, time, accuracy, and TSA fields.
 */
struct TS_tst_info_st;
/**
 * @brief RFC 3161 TSTInfo: policy, imprint, serial, time, accuracy, and TSA fields.
 */
typedef struct TS_tst_info_st TS_TST_INFO;

/* Possible values for status. */
#define TS_STATUS_GRANTED 0
#define TS_STATUS_GRANTED_WITH_MODS 1
#define TS_STATUS_REJECTION 2
#define TS_STATUS_WAITING 3
#define TS_STATUS_REVOCATION_WARNING 4
#define TS_STATUS_REVOCATION_NOTIFICATION 5

/* Possible values for failure_info. */
#define TS_INFO_BAD_ALG 0
#define TS_INFO_BAD_REQUEST 2
#define TS_INFO_BAD_DATA_FORMAT 5
#define TS_INFO_TIME_NOT_AVAILABLE 14
#define TS_INFO_UNACCEPTED_POLICY 15
#define TS_INFO_UNACCEPTED_EXTENSION 16
#define TS_INFO_ADD_INFO_NOT_AVAILABLE 17
#define TS_INFO_SYSTEM_FAILURE 25

/**
 * @brief RFC 3161 PKIStatusInfo: status, optional statusString, and failureInfo.
 */
struct TS_status_info_st;
/**
 * @brief RFC 3161 PKIStatusInfo: status, optional statusString, and failureInfo.
 */
typedef struct TS_status_info_st TS_STATUS_INFO;
/**
 * @brief RFC 3161 TimeStampResp: status info and optional signed time-stamp token.
 */
struct TS_resp_st;
/**
 * @brief RFC 3161 TimeStampResp: status info and optional signed time-stamp token.
 */
typedef struct TS_resp_st TS_RESP;

/**
 * @brief Allocate an empty time-stamp request (TS_REQ).
 * @return New TS_REQ, or NULL on allocation failure.
 */
TS_REQ *TS_REQ_new(void);
/**
 * @brief Free a time-stamp request (TS_REQ) and its contents.
 * @param a Value to free, or NULL.
 */
void TS_REQ_free(TS_REQ *a);
/**
 * @brief Decode a time-stamp request from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_REQ, or NULL on error.
 */
TS_REQ *d2i_TS_REQ(TS_REQ **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp request to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_REQ(const TS_REQ *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp request.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_REQ *TS_REQ_dup(const TS_REQ *a);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Decode a time-stamp request from a FILE stream containing DER.
 * @param fp Input FILE positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_REQ, or NULL on error.
 */
TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a);
/**
 * @brief Encode a time-stamp request as DER to a FILE stream.
 * @param fp Output FILE receiving the DER encoding.
 * @param a Request to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_REQ_fp(FILE *fp, const TS_REQ *a);
#endif
/**
 * @brief Decode a time-stamp request from a BIO containing DER.
 * @param fp BIO supplying the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_REQ, or NULL on error.
 */
TS_REQ *d2i_TS_REQ_bio(BIO *fp, TS_REQ **a);
/**
 * @brief Encode a time-stamp request as DER to a BIO.
 * @param fp BIO receiving the DER encoding.
 * @param a Request to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_REQ_bio(BIO *fp, const TS_REQ *a);

/**
 * @brief Allocate an empty time-stamp message imprint.
 * @return New TS_MSG_IMPRINT, or NULL on allocation failure.
 */
TS_MSG_IMPRINT *TS_MSG_IMPRINT_new(void);
/**
 * @brief Free a time-stamp message imprint and its contents.
 * @param a Value to free, or NULL.
 */
void TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a);
/**
 * @brief Decode a time-stamp message imprint from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_MSG_IMPRINT, or NULL on error.
 */
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp message imprint to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_MSG_IMPRINT(const TS_MSG_IMPRINT *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp message imprint.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_MSG_IMPRINT *TS_MSG_IMPRINT_dup(const TS_MSG_IMPRINT *a);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Decode a message imprint from a FILE stream containing DER.
 * @param fp Input FILE positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_MSG_IMPRINT, or NULL on error.
 */
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a);
/**
 * @brief Encode a message imprint as DER to a FILE stream.
 * @param fp Output FILE receiving the DER encoding.
 * @param a Message imprint to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_MSG_IMPRINT_fp(FILE *fp, const TS_MSG_IMPRINT *a);
#endif
/**
 * @brief Decode a message imprint from a BIO containing DER.
 * @param bio BIO supplying the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_MSG_IMPRINT, or NULL on error.
 */
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *bio, TS_MSG_IMPRINT **a);
/**
 * @brief Encode a message imprint as DER to a BIO.
 * @param bio BIO receiving the DER encoding.
 * @param a Message imprint to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_MSG_IMPRINT_bio(BIO *bio, const TS_MSG_IMPRINT *a);

/**
 * @brief Allocate an empty time-stamp response (TS_RESP).
 * @return New TS_RESP, or NULL on allocation failure.
 */
TS_RESP *TS_RESP_new(void);
/**
 * @brief Free a time-stamp response (TS_RESP) and its contents.
 * @param a Value to free, or NULL.
 */
void TS_RESP_free(TS_RESP *a);
/**
 * @brief Decode a time-stamp response from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_RESP, or NULL on error.
 */
TS_RESP *d2i_TS_RESP(TS_RESP **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp response to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_RESP(const TS_RESP *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp response.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_RESP *TS_RESP_dup(const TS_RESP *a);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Decode a time-stamp response from a FILE stream containing DER.
 * @param fp Input FILE positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_RESP, or NULL on error.
 */
TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a);
/**
 * @brief Encode a time-stamp response as DER to a FILE stream.
 * @param fp Output FILE receiving the DER encoding.
 * @param a Response to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_RESP_fp(FILE *fp, const TS_RESP *a);
#endif
/**
 * @brief Decode a time-stamp response from a BIO containing DER.
 * @param bio BIO supplying the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_RESP, or NULL on error.
 */
TS_RESP *d2i_TS_RESP_bio(BIO *bio, TS_RESP **a);
/**
 * @brief Encode a time-stamp response as DER to a BIO.
 * @param bio BIO receiving the DER encoding.
 * @param a Response to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_RESP_bio(BIO *bio, const TS_RESP *a);

/**
 * @brief Allocate an empty time-stamp PKIStatusInfo.
 * @return New TS_STATUS_INFO, or NULL on allocation failure.
 */
TS_STATUS_INFO *TS_STATUS_INFO_new(void);
/**
 * @brief Free a time-stamp PKIStatusInfo and its contents.
 * @param a Value to free, or NULL.
 */
void TS_STATUS_INFO_free(TS_STATUS_INFO *a);
/**
 * @brief Decode a time-stamp PKIStatusInfo from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_STATUS_INFO, or NULL on error.
 */
TS_STATUS_INFO *d2i_TS_STATUS_INFO(TS_STATUS_INFO **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp PKIStatusInfo to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_STATUS_INFO(const TS_STATUS_INFO *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp PKIStatusInfo.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_STATUS_INFO *TS_STATUS_INFO_dup(const TS_STATUS_INFO *a);

/**
 * @brief Allocate an empty time-stamp token info (TSTInfo).
 * @return New TS_TST_INFO, or NULL on allocation failure.
 */
TS_TST_INFO *TS_TST_INFO_new(void);
/**
 * @brief Free a time-stamp token info (TSTInfo) and its contents.
 * @param a Value to free, or NULL.
 */
void TS_TST_INFO_free(TS_TST_INFO *a);
/**
 * @brief Decode a time-stamp token info from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_TST_INFO, or NULL on error.
 */
TS_TST_INFO *d2i_TS_TST_INFO(TS_TST_INFO **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp token info to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_TST_INFO(const TS_TST_INFO *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp token info.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_TST_INFO *TS_TST_INFO_dup(const TS_TST_INFO *a);
/**
 * @brief Extract the TSTInfo content from a PKCS#7 time-stamp token.
 * @param token Signed PKCS#7 ContentInfo expected to encapsulate id-ct-TSTInfo.
 * @return Newly allocated TS_TST_INFO, or NULL on error.
 */
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Decode TSTInfo from a FILE stream containing DER.
 * @param fp Input FILE positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_TST_INFO, or NULL on error.
 */
TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a);
/**
 * @brief Encode TSTInfo as DER to a FILE stream.
 * @param fp Output FILE receiving the DER encoding.
 * @param a TSTInfo to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_TST_INFO_fp(FILE *fp, const TS_TST_INFO *a);
#endif
/**
 * @brief Decode TSTInfo from a BIO containing DER.
 * @param bio BIO supplying the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded TS_TST_INFO, or NULL on error.
 */
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bio, TS_TST_INFO **a);
/**
 * @brief Encode TSTInfo as DER to a BIO.
 * @param bio BIO receiving the DER encoding.
 * @param a TSTInfo to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_TS_TST_INFO_bio(BIO *bio, const TS_TST_INFO *a);

/**
 * @brief Allocate an empty time-stamp Accuracy.
 * @return New TS_ACCURACY, or NULL on allocation failure.
 */
TS_ACCURACY *TS_ACCURACY_new(void);
/**
 * @brief Free a time-stamp Accuracy and its contents.
 * @param a Value to free, or NULL.
 */
void TS_ACCURACY_free(TS_ACCURACY *a);
/**
 * @brief Decode a time-stamp Accuracy from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded TS_ACCURACY, or NULL on error.
 */
TS_ACCURACY *d2i_TS_ACCURACY(TS_ACCURACY **a, const unsigned char **in, long len);
/**
 * @brief Encode a time-stamp Accuracy to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_TS_ACCURACY(const TS_ACCURACY *a, unsigned char **out);
/**
 * @brief Duplicate a time-stamp Accuracy.
 * @param a Value to copy.
 * @return Deep copy of @p a, or NULL on error.
 */
TS_ACCURACY *TS_ACCURACY_dup(const TS_ACCURACY *a);

/**
 * @brief Set the version field of a time-stamp request (typically 1).
 * @param a Request to update.
 * @param version Version number to store.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_version(TS_REQ *a, long version);
/**
 * @brief Return the version field of a time-stamp request.
 * @param a Request to query.
 * @return Version number (typically 1).
 */
long TS_REQ_get_version(const TS_REQ *a);

/**
 * @brief Set the PKIStatus integer in a status-info structure.
 * @param a Status info to update.
 * @param i Status value such as TS_STATUS_GRANTED or TS_STATUS_REJECTION.
 * @return 1 on success, or 0 on failure.
 */
int TS_STATUS_INFO_set_status(TS_STATUS_INFO *a, int i);
/**
 * @brief Return the PKIStatus integer from a status-info structure.
 * @param a Status info to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_STATUS_INFO_get0_status(const TS_STATUS_INFO *a);

/**
 * @brief Return the optional statusString texts from a status-info structure.
 * @param a Status info to query.
 * @return Internal stack of UTF8String messages, or NULL if absent.
 */
const STACK_OF(ASN1_UTF8STRING) *
TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

/**
 * @brief Return the optional PKIFailureInfo bit string from a status-info structure.
 * @param a Status info to query.
 * @return Internal ASN1_BIT_STRING pointer, or NULL if absent.
 */
const ASN1_BIT_STRING *
TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

/**
 * @brief Set the message imprint of a time-stamp request.
 * @param a Request to update.
 * @param msg_imprint Message imprint to copy into the request.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint);
/**
 * @brief Return the message imprint from a time-stamp request.
 * @param a Request to query.
 * @return Internal TS_MSG_IMPRINT pointer, or NULL if unset.
 */
TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a);

/**
 * @brief Set the hash AlgorithmIdentifier of a message imprint.
 * @param a Message imprint to update.
 * @param alg Digest algorithm identifier to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg);
/**
 * @brief Return the hash AlgorithmIdentifier from a message imprint (borrowed).
 * @param a Message imprint to query.
 * @return Internal X509_ALGOR pointer, or NULL if unset.
 */
X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a);

/**
 * @brief Set the hashed message octets of a message imprint.
 * @param a Message imprint to update.
 * @param d Hash bytes to copy.
 * @param len Number of bytes at @p d.
 * @return 1 on success, or 0 on failure.
 */
int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len);
/**
 * @brief Return the hashed message octets from a message imprint.
 * @param a Message imprint to query.
 * @return Internal OCTET STRING pointer, or NULL if unset.
 */
ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a);

/**
 * @brief Set the optional TSA policy OID requested in a time-stamp request.
 * @param a Request to update.
 * @param policy Policy object identifier to copy into the request.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy);
/**
 * @brief Return the optional TSA policy OID from a time-stamp request.
 * @param a Request to query.
 * @return Internal ASN1_OBJECT pointer, or NULL if no policy was requested.
 */
ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a);

/**
 * @brief Set the optional nonce in a time-stamp request.
 * @param a Request to update.
 * @param nonce Nonce value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce);
/**
 * @brief Return the optional nonce from a time-stamp request (borrowed).
 * @param a Request to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if no nonce is set.
 */
const ASN1_INTEGER *TS_REQ_get_nonce(const TS_REQ *a);

/**
 * @brief Set whether the TSA should include its signing certificate in the response.
 * @param a Request to update.
 * @param cert_req Nonzero to request certificates (certReq TRUE), zero otherwise.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_cert_req(TS_REQ *a, int cert_req);
/**
 * @brief Return whether the request asks the TSA to include certificates.
 * @param a Request to query.
 * @return Nonzero if certReq is TRUE, otherwise 0.
 */
int TS_REQ_get_cert_req(const TS_REQ *a);

/**
 * @brief Return the extension stack from a time-stamp request.
 * @param a Request to query.
 * @return Internal STACK_OF(X509_EXTENSION), or NULL if none are present.
 */
STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
/**
 * @brief Free all extensions attached to a time-stamp request.
 * @param a Request whose extension stack is cleared and freed.
 */
void TS_REQ_ext_free(TS_REQ *a);
/**
 * @brief Return the number of extensions in a time-stamp request.
 * @param a Request to query.
 * @return Extension count, or 0 if none.
 */
int TS_REQ_get_ext_count(TS_REQ *a);
/**
 * @brief Find the next request extension with NID @p nid.
 * @param a Request whose extensions are searched.
 * @param nid Numeric identifier of the extension type.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos);
/**
 * @brief Find the next request extension with object identifier @p obj.
 * @param a Request whose extensions are searched.
 * @param obj ASN.1 object identifier to match.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos);
/**
 * @brief Find the next request extension with criticality @p crit.
 * @param a Request whose extensions are searched.
 * @param crit Nonzero to match critical extensions, zero for non-critical.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos);
/**
 * @brief Return the time-stamp request extension at index @p loc.
 * @param a Request to query.
 * @param loc Zero-based extension index.
 * @return Internal X509_EXTENSION pointer, or NULL if @p loc is out of range.
 */
X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc);
/**
 * @brief Remove and return the request extension at index @p loc.
 * @param a Request to update.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is invalid.
 */
X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc);
/**
 * @brief Insert an extension into a time-stamp request.
 * @param a Request to update.
 * @param ex Extension to add (duplicated into the request).
 * @param loc Insertion index, or -1 to append.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc);
/**
 * @brief Decode the first request extension of type @p nid into its native structure.
 * @param a Request to query.
 * @param nid NID of the extension type to extract.
 * @param crit Optional output for criticality; may be NULL.
 * @param idx Optional in/out extension index for iteration; may be NULL.
 * @return Newly allocated decoded extension value, or NULL if absent or on error.
 */
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx);

/* Function declarations for TS_REQ defined in ts/ts_req_print.c */

/**
 * @brief Print a human-readable dump of a time-stamp request to a BIO.
 * @param bio Output BIO.
 * @param a Request to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_print_bio(BIO *bio, TS_REQ *a);

/* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

/**
 * @brief Set the PKIStatusInfo of a time-stamp response.
 * @param a Response to update.
 * @param info Status info to copy into the response.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *info);
/**
 * @brief Return the PKIStatusInfo from a time-stamp response.
 * @param a Response to query.
 * @return Internal TS_STATUS_INFO pointer, or NULL if unset.
 */
TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a);

/* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
/**
 * @brief Attach a signed time-stamp token and parsed TSTInfo to a response.
 * @param a Response that takes ownership of @p p7 and @p tst_info.
 * @param p7 PKCS#7 ContentInfo token (caller loses ownership).
 * @param tst_info Parsed TSTInfo extracted from @p p7 (caller loses ownership).
 */
void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info);
/**
 * @brief Return the PKCS#7 time-stamp token from a response.
 * @param a Response to query.
 * @return Internal PKCS7 pointer, or NULL if no token is present.
 */
PKCS7 *TS_RESP_get_token(TS_RESP *a);
/**
 * @brief Return the parsed TSTInfo from a time-stamp response.
 * @param a Response to query.
 * @return Internal TS_TST_INFO pointer, or NULL if no token/info is present.
 */
TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a);

/**
 * @brief Set the version field of a TSTInfo structure (typically 1).
 * @param a TSTInfo to update.
 * @param version Version number to store.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_version(TS_TST_INFO *a, long version);
/**
 * @brief Return the version field from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Version number, or -1 if unset.
 */
long TS_TST_INFO_get_version(const TS_TST_INFO *a);

/**
 * @brief Set the TSA policy OID in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param policy_id Policy object identifier to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
/**
 * @brief Return the TSA policy OID from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal ASN1_OBJECT pointer, or NULL if unset.
 */
ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);

/**
 * @brief Set the message imprint in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param msg_imprint Message imprint to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint);
/**
 * @brief Return the message imprint from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal TS_MSG_IMPRINT pointer, or NULL if unset.
 */
TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a);

/**
 * @brief Set the serial number uniquely identifying a time-stamp token.
 * @param a TSTInfo to update.
 * @param serial Serial number to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial);
/**
 * @brief Return the serial number from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a);

/**
 * @brief Set the genTime time-stamp instant in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param gtime GeneralizedTime value to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime);
/**
 * @brief Return the genTime time-stamp instant from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal GeneralizedTime pointer, or NULL if unset.
 */
const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a);

/**
 * @brief Set the optional accuracy field of a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param accuracy Accuracy to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy);
/**
 * @brief Return the optional accuracy field from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal TS_ACCURACY pointer, or NULL if absent.
 */
TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);

/**
 * @brief Set the seconds component of a time-stamp accuracy structure.
 * @param a Accuracy structure to update.
 * @param seconds Seconds value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds);
/**
 * @brief Return the seconds component of a time-stamp accuracy structure.
 * @param a Accuracy structure to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);

/**
 * @brief Set the optional milliseconds component of a time-stamp accuracy.
 * @param a Accuracy structure to update.
 * @param millis Milliseconds value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
/**
 * @brief Return the optional milliseconds component of a time-stamp accuracy.
 * @param a Accuracy structure to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_ACCURACY_get_millis(const TS_ACCURACY *a);

/**
 * @brief Set the optional microseconds component of a time-stamp accuracy.
 * @param a Accuracy structure to update.
 * @param micros Microseconds value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros);
/**
 * @brief Return the optional microseconds component of a time-stamp accuracy.
 * @param a Accuracy structure to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_ACCURACY_get_micros(const TS_ACCURACY *a);

/**
 * @brief Set the ordering flag indicating whether time-stamps from this TSA are ordered.
 * @param a TSTInfo to update.
 * @param ordering Nonzero for TRUE, zero for FALSE.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering);
/**
 * @brief Return the ordering flag from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Nonzero if ordering is TRUE, otherwise 0.
 */
int TS_TST_INFO_get_ordering(const TS_TST_INFO *a);

/**
 * @brief Set the optional nonce echoed from the request in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param nonce Nonce value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
/**
 * @brief Return the optional nonce echoed from the request in a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if absent.
 */
const ASN1_INTEGER *TS_TST_INFO_get_nonce(const TS_TST_INFO *a);

/**
 * @brief Set the optional TSA name in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param tsa GeneralName identifying the TSA, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa);
/**
 * @brief Return the optional TSA name from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal GENERAL_NAME pointer, or NULL if absent.
 */
GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a);

/**
 * @brief Return the extension stack from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal STACK_OF(X509_EXTENSION), or NULL if none are present.
 */
STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
/**
 * @brief Free all extensions attached to a TSTInfo structure.
 * @param a TSTInfo whose extension stack is cleared and freed.
 */
void TS_TST_INFO_ext_free(TS_TST_INFO *a);
/**
 * @brief Return the number of extensions in a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Extension count, or 0 if none.
 */
int TS_TST_INFO_get_ext_count(TS_TST_INFO *a);
/**
 * @brief Find the next TSTInfo extension with NID @p nid.
 * @param a TSTInfo whose extensions are searched.
 * @param nid Numeric identifier of the extension type.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos);
/**
 * @brief Find the next TSTInfo extension with object identifier @p obj.
 * @param a TSTInfo whose extensions are searched.
 * @param obj ASN.1 object identifier to match.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, const ASN1_OBJECT *obj,
    int lastpos);
/**
 * @brief Find the next TSTInfo extension with criticality @p crit.
 * @param a TSTInfo whose extensions are searched.
 * @param crit Nonzero to match critical extensions, zero for non-critical.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos);
/**
 * @brief Return the TSTInfo extension at index @p loc.
 * @param a TSTInfo to query.
 * @param loc Zero-based extension index.
 * @return Internal X509_EXTENSION pointer, or NULL if @p loc is out of range.
 */
X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc);
/**
 * @brief Remove and return the TSTInfo extension at index @p loc.
 * @param a TSTInfo to update.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is invalid.
 */
X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc);
/**
 * @brief Insert an extension into a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param ex Extension to add (duplicated into the TSTInfo).
 * @param loc Insertion index, or -1 to append.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
/**
 * @brief Decode the first TSTInfo extension of type @p nid into its native structure.
 * @param a TSTInfo to query.
 * @param nid NID of the extension type to extract.
 * @param crit Optional output for criticality; may be NULL.
 * @param idx Optional in/out extension index for iteration; may be NULL.
 * @return Newly allocated decoded extension value, or NULL if absent or on error.
 */
void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx);

/*
 * Declarations related to response generation, defined in ts/ts_resp_sign.c.
 */

/* Optional flags for response generation. */

/* Don't include the TSA name in response. */
#define TS_TSA_NAME 0x01

/* Set ordering to true in response. */
#define TS_ORDERING 0x02

/*
 * Include the signer certificate and the other specified certificates in
 * the ESS signing certificate attribute beside the PKCS7 signed data.
 * Only the signer certificates is included by default.
 */
#define TS_ESS_CERT_ID_CHAIN 0x04

/**
 * @brief Opaque context used while generating RFC 3161 time-stamp responses.
 */
struct TS_resp_ctx;

/**
 * @brief Callback that allocates a unique TSTInfo serial number for a response.
 * @param ctx Response context requesting a serial.
 * @param data Application pointer supplied to TS_RESP_CTX_set_serial_cb().
 * @return New ASN1_INTEGER serial (less than 160 bits), or NULL on failure.
 */
typedef ASN1_INTEGER *(*TS_serial_cb)(struct TS_resp_ctx *ctx, void *data);

/**
 * @brief Callback that supplies the current time for TSTInfo genTime.
 * @param ctx Response context requesting the time.
 * @param data Application pointer supplied to TS_RESP_CTX_set_time_cb().
 * @param sec Output seconds since 1970-01-01 00:00:00 UTC.
 * @param usec Output microseconds in [0, 999999].
 * @return Nonzero on success, or 0 on failure.
 */
typedef int (*TS_time_cb)(struct TS_resp_ctx *ctx, void *data, long *sec,
    long *usec);

/**
 * @brief Callback that processes a requested extension while building TSTInfo.
 * @param ctx Response context whose TSTInfo may be modified.
 * @param ext Extension from the request to handle.
 * @param data Application pointer supplied to TS_RESP_CTX_set_extension_cb().
 * @return Nonzero if processed, or 0 on error (must set status/failure info).
 */
typedef int (*TS_extension_cb)(struct TS_resp_ctx *ctx, X509_EXTENSION *ext,
    void *data);

/**
 * @brief Opaque context used while generating RFC 3161 time-stamp responses.
 */
typedef struct TS_resp_ctx TS_RESP_CTX;

/**
 * @brief Allocate a time-stamp response context using the default library context.
 * @return New TS_RESP_CTX, or NULL on allocation failure.
 */
TS_RESP_CTX *TS_RESP_CTX_new(void);
/**
 * @brief Allocate a time-stamp response context with an explicit library context.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New TS_RESP_CTX, or NULL on allocation failure.
 */
TS_RESP_CTX *TS_RESP_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Free a time-stamp response context and associated resources.
 * @param ctx Context to free, or NULL.
 */
void TS_RESP_CTX_free(TS_RESP_CTX *ctx);

/**
 * @brief Set the TSA signing certificate used when creating responses.
 * @param ctx Response context to configure.
 * @param signer Certificate whose private key will sign the token.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer);

/* This parameter must be set. */
/**
 * @brief Set the private key used to sign time-stamp responses.
 * @param ctx Response context to configure.
 * @param key Private key corresponding to the configured signer certificate.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key);

/**
 * @brief Set the message digest used when signing the PKCS#7 time-stamp token.
 * @param ctx Response context to configure.
 * @param signer_digest Digest method for the signer signature.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_signer_digest(TS_RESP_CTX *ctx,
    const EVP_MD *signer_digest);
/**
 * @brief Set the digest used for ESS signing-certificate attributes in responses.
 * @param ctx Response context to configure.
 * @param md Message digest for ESS CertID / CertIDv2 hashes.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_ess_cert_id_digest(TS_RESP_CTX *ctx, const EVP_MD *md);

/**
 * @brief Set the default TSA policy OID used when the request omits a policy.
 * @param ctx Response context to configure.
 * @param def_policy Default policy object identifier.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *def_policy);

/* No additional certs are included in the response by default. */
/**
 * @brief Set additional certificates included with generated time-stamp responses.
 * @param ctx Response context to configure.
 * @param certs Certificate chain to include (referenced), or NULL to clear; none are included by default.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);

/*
 * Adds a new acceptable policy, only the default policy is accepted by
 * default.
 */
/**
 * @brief Add an acceptable TSA policy OID in addition to the default policy.
 * @param ctx Response context to configure.
 * @param policy Policy object identifier that incoming requests may select.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, const ASN1_OBJECT *policy);

/*
 * Adds a new acceptable message digest. Note that no message digests are
 * accepted by default. The md argument is shared with the caller.
 */
/**
 * @brief Add an acceptable message-digest algorithm for incoming requests.
 * @param ctx Response context to configure.
 * @param md Digest method shared with the caller (not copied).
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md);

/* Accuracy is not included by default. */
/**
 * @brief Set the Accuracy values included in generated TSTInfo structures.
 * @param ctx Response context to configure.
 * @param secs Seconds component of accuracy.
 * @param millis Milliseconds component of accuracy.
 * @param micros Microseconds component of accuracy.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx,
    int secs, int millis, int micros);

/*
 * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
 * '3' msec, '6' usec, and so on. Default is 0.
 */
/**
 * @brief Set how many fractional-second digits are included in genTime.
 * @param ctx Response context to configure.
 * @param clock_precision_digits Digits after the second (0=sec, 3=msec, 6=usec); at most TS_MAX_CLOCK_PRECISION_DIGITS.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx,
    unsigned clock_precision_digits);
/* At most we accept usec precision. */
#define TS_MAX_CLOCK_PRECISION_DIGITS 6

/* Maximum status message length */
#define TS_MAX_STATUS_LENGTH (1024 * 1024)

/* No flags are set by default. */
/**
 * @brief OR additional TS_RESP_CTX_* behaviour flags into a response context.
 * @param ctx Response context to update.
 * @param flags Flag bits such as TS_TSA_NAME or TS_ORDERING.
 */
void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags);

/* Default callback always returns a constant. */
/**
 * @brief Install the callback that supplies serial numbers for new TSTInfo structures.
 * @param ctx Response context to configure.
 * @param cb Serial-number callback, or NULL to restore the default constant serial.
 * @param data Opaque pointer passed to @p cb.
 */
void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data);

/* Default callback uses the gettimeofday() and gmtime() system calls. */
/**
 * @brief Install the callback that supplies the genTime value for new TSTInfo structures.
 * @param ctx Response context to configure.
 * @param cb Time callback, or NULL to use the default gettimeofday/gmtime path.
 * @param data Opaque pointer passed to @p cb.
 */
void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data);

/*
 * Default callback rejects all extensions. The extension callback is called
 * when the TS_TST_INFO object is already set up and not signed yet.
 */
/* FIXME: extension handling is not tested yet. */
/**
 * @brief Install a callback that handles request extensions while building TSTInfo.
 * @param ctx Response context to configure.
 * @param cb Extension callback, or NULL to reject all extensions.
 * @param data Opaque pointer passed to @p cb.
 */
void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx,
    TS_extension_cb cb, void *data);

/* The following methods can be used in the callbacks. */
/**
 * @brief Set the response status and optional statusString text (unconditionally).
 * @param ctx Response context being built.
 * @param status PKIStatus value such as TS_STATUS_GRANTED.
 * @param text Optional UTF-8 status text, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx,
    int status, const char *text);

/* Sets the status info only if it is still TS_STATUS_GRANTED. */
/**
 * @brief Set status info only while the current status is still TS_STATUS_GRANTED.
 * @param ctx Response context being built.
 * @param status New PKIStatus value.
 * @param text Optional UTF-8 status text, or NULL.
 * @return 1 on success (including when unchanged), or 0 on failure.
 */
int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx,
    int status, const char *text);

/**
 * @brief Add a PKIFailureInfo bit to the status info of a response context.
 * @param ctx Response context being built.
 * @param failure Failure-info bit (TS_INFO_* such as TS_INFO_BAD_ALG).
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure);

/* The get methods below can be used in the extension callback. */
/**
 * @brief Return the parsed time-stamp request associated with a response context.
 * @param ctx Response context during response creation or an extension callback.
 * @return Internal TS_REQ pointer, or NULL if no request is set.
 */
TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx);

/**
 * @brief Return the TSTInfo being built in a response context (for extension callbacks).
 * @param ctx Response context during response creation.
 * @return Internal TS_TST_INFO pointer, or NULL if not yet created.
 */
TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx);

/*
 * Creates the signed TS_TST_INFO and puts it in TS_RESP.
 * In case of errors it sets the status info properly.
 * Returns NULL only in case of memory allocation/fatal error.
 */
/**
 * @brief Create a signed time-stamp response for the DER request read from @p req_bio.
 * @param ctx Configured response context (signer, policy, digests, and callbacks).
 * @param req_bio BIO supplying a DER-encoded TimeStampReq.
 * @return New TS_RESP on success (may carry a rejection status), or NULL only on fatal/allocation error.
 */
TS_RESP *TS_RESP_create_response(TS_RESP_CTX *ctx, BIO *req_bio);

/*
 * Declarations related to response verification,
 * they are defined in ts/ts_resp_verify.c.
 */

/**
 * @brief Verify the signer certificate and signature of a PKCS#7 time-stamp token.
 * @param token Signed PKCS#7 ContentInfo containing the TSTInfo.
 * @param certs Optional additional certificates for path building, or NULL.
 * @param store Trusted certificate store used for verification.
 * @param signer_out Optional output receiving the signer certificate; may be NULL.
 * @return 1 on successful verification, or 0 on failure.
 */
int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
    X509_STORE *store, X509 **signer_out);

/* Context structure for the generic verify method. */

/* Verify the signer's certificate and the signature of the response. */
#define TS_VFY_SIGNATURE (1u << 0)
/* Verify the version number of the response. */
#define TS_VFY_VERSION (1u << 1)
/* Verify if the policy supplied by the user matches the policy of the TSA. */
#define TS_VFY_POLICY (1u << 2)
/*
 * Verify the message imprint provided by the user. This flag should not be
 * specified with TS_VFY_DATA.
 */
#define TS_VFY_IMPRINT (1u << 3)
/*
 * Verify the message imprint computed by the verify method from the user
 * provided data and the MD algorithm of the response. This flag should not
 * be specified with TS_VFY_IMPRINT.
 */
#define TS_VFY_DATA (1u << 4)
/* Verify the nonce value. */
#define TS_VFY_NONCE (1u << 5)
/* Verify if the TSA name field matches the signer certificate. */
#define TS_VFY_SIGNER (1u << 6)
/* Verify if the TSA name field equals to the user provided name. */
#define TS_VFY_TSA_NAME (1u << 7)

/* You can use the following convenience constants. */
#define TS_VFY_ALL_IMPRINT (TS_VFY_SIGNATURE \
    | TS_VFY_VERSION                         \
    | TS_VFY_POLICY                          \
    | TS_VFY_IMPRINT                         \
    | TS_VFY_NONCE                           \
    | TS_VFY_SIGNER                          \
    | TS_VFY_TSA_NAME)
#define TS_VFY_ALL_DATA (TS_VFY_SIGNATURE \
    | TS_VFY_VERSION                      \
    | TS_VFY_POLICY                       \
    | TS_VFY_DATA                         \
    | TS_VFY_NONCE                        \
    | TS_VFY_SIGNER                       \
    | TS_VFY_TSA_NAME)

/**
 * @brief Opaque context holding flags and expected values for time-stamp verification.
 */
struct TS_verify_ctx;
/**
 * @brief Opaque context holding flags and expected values for time-stamp verification.
 */
typedef struct TS_verify_ctx TS_VERIFY_CTX;

/**
 * @brief Verify a time-stamp response against the criteria in @p ctx.
 * @param ctx Verification context with TS_VFY_* flags and expected imprint/data/store.
 * @param response Time-stamp response to verify.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response);
/**
 * @brief Verify a PKCS#7 time-stamp token against the criteria in @p ctx.
 * @param ctx Verification context with TS_VFY_* flags and expected imprint/data/store.
 * @param token PKCS#7 ContentInfo containing a TimeStampToken.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);

/*
 * Declarations related to response verification context,
 */
/**
 * @brief Allocate an empty time-stamp verification context.
 * @return New TS_VERIFY_CTX, or NULL on allocation failure.
 */
TS_VERIFY_CTX *TS_VERIFY_CTX_new(void);
/**
 * @brief Initialize a verification context to a cleared empty state.
 * @param ctx Context storage to initialize (must not be NULL).
 */
void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx);
/**
 * @brief Free a verification context allocated by TS_VERIFY_CTX_new().
 * @param ctx Context to free, or NULL.
 */
void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx);
/**
 * @brief Release resources held by a verification context and clear it for reuse.
 * @param ctx Context to clean up; remains allocated when created with TS_VERIFY_CTX_new().
 */
void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx);
/**
 * @brief Replace the verification flags with @p f.
 * @param ctx Verification context to update.
 * @param f Bitmask of TS_VFY_* flags.
 * @return The flags now stored in @p ctx.
 */
int TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f);
/**
 * @brief Add TS_VFY_* bits to the verification flags.
 * @param ctx Verification context to update.
 * @param f Flag bits to OR into the existing flags.
 * @return The flags now stored in @p ctx.
 */
int TS_VERIFY_CTX_add_flags(TS_VERIFY_CTX *ctx, int f);
/**
 * @brief Set the BIO of raw data used when TS_VFY_DATA is enabled.
 * @param ctx Verification context to update.
 * @param b BIO providing data to hash for imprint comparison (not freed by the context).
 * @return The BIO now stored in @p ctx.
 */
BIO *TS_VERIFY_CTX_set_data(TS_VERIFY_CTX *ctx, BIO *b);
/**
 * @brief Set the expected message imprint used when TS_VFY_IMPRINT is enabled.
 * @param ctx Verification context to update.
 * @param hexstr Imprint bytes taken over by the context (freed on cleanup).
 * @param len Length of @p hexstr in bytes.
 * @return The imprint pointer now stored in @p ctx.
 */
unsigned char *TS_VERIFY_CTX_set_imprint(TS_VERIFY_CTX *ctx,
    unsigned char *hexstr, long len);
/**
 * @brief Set the trusted certificate store used when verifying a time-stamp token.
 * @param ctx Verification context to update.
 * @param s Certificate store taken over by the context (freed on cleanup), or NULL.
 * @return The store pointer now stored in @p ctx.
 */
X509_STORE *TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s);
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define TS_VERIFY_CTS_set_certs(ctx, cert) TS_VERIFY_CTX_set_certs(ctx, cert)
#endif
/**
 * @brief Set the untrusted certificate stack used when verifying a time-stamp token.
 * @param ctx Verification context to update.
 * @param certs Certificate stack taken over by the context (freed on cleanup), or NULL.
 * @return The certificate stack now stored in @p ctx.
 */
STACK_OF(X509) *TS_VERIFY_CTX_set_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) *certs);

/*-
 * If ctx is NULL, it allocates and returns a new object, otherwise
 * it returns ctx. It initialises all the members as follows:
 * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
 * certs = NULL
 * store = NULL
 * policy = policy from the request or NULL if absent (in this case
 *      TS_VFY_POLICY is cleared from flags as well)
 * md_alg = MD algorithm from request
 * imprint, imprint_len = imprint from request
 * data = NULL
 * nonce, nonce_len = nonce from the request or NULL if absent (in this case
 *      TS_VFY_NONCE is cleared from flags as well)
 * tsa_name = NULL
 * Important: after calling this method TS_VFY_SIGNATURE should be added!
 */
/**
 * @brief Initialise a verification context from the imprint, policy, and nonce of a request.
 * @param req Time-stamp request providing expected verification fields.
 * @param ctx Existing context to reuse, or NULL to allocate a new one.
 * @return Initialised TS_VERIFY_CTX (same as @p ctx when non-NULL), or NULL on error.
 *
 * Sets flags to TS_VFY_ALL_IMPRINT without TS_VFY_TSA_NAME or TS_VFY_SIGNATURE;
 * callers typically OR in TS_VFY_SIGNATURE afterward.
 */
TS_VERIFY_CTX *TS_REQ_to_TS_VERIFY_CTX(TS_REQ *req, TS_VERIFY_CTX *ctx);

/* Function declarations for TS_RESP defined in ts/ts_resp_print.c */

/**
 * @brief Print a human-readable dump of a time-stamp response to a BIO.
 * @param bio Output BIO.
 * @param a Response to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_print_bio(BIO *bio, TS_RESP *a);
/**
 * @brief Print a human-readable dump of a TS_STATUS_INFO structure to a BIO.
 * @param bio Output BIO.
 * @param a Status info to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a);
/**
 * @brief Print a human-readable dump of a TSTInfo structure to a BIO.
 * @param bio Output BIO.
 * @param a TSTInfo to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a);

/* Common utility functions defined in ts/ts_lib.c */

/**
 * @brief Print an ASN.1 INTEGER in decimal form to a BIO.
 * @param bio Output BIO.
 * @param num Integer to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num);
/**
 * @brief Print an ASN.1 object identifier in textual form to a BIO.
 * @param bio Output BIO.
 * @param obj Object identifier to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj);
/**
 * @brief Print a stack of X.509 extensions in human-readable form to a BIO.
 * @param bio Output BIO.
 * @param extensions Extension stack to print, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int TS_ext_print_bio(BIO *bio, const STACK_OF(X509_EXTENSION) *extensions);
/**
 * @brief Print an X509_ALGOR AlgorithmIdentifier to a BIO.
 * @param bio Output BIO.
 * @param alg Algorithm identifier to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg);
/**
 * @brief Print a message imprint (algorithm and hash) to a BIO.
 * @param bio Output BIO.
 * @param msg Message imprint to print.
 * @return 1 on success, or 0 on failure.
 */
int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *msg);

/*
 * Function declarations for handling configuration options, defined in
 * ts/ts_conf.c
 */

/**
 * @brief Load a single X.509 certificate from a PEM file for TSA configuration.
 * @param file Path to a PEM certificate file.
 * @return New X509 certificate, or NULL on error.
 */
X509 *TS_CONF_load_cert(const char *file);
/**
 * @brief Load a stack of X.509 certificates from a PEM file for TSA configuration.
 * @param file Path to a PEM file containing one or more certificates.
 * @return New STACK_OF(X509), or NULL on error.
 */
STACK_OF(X509) *TS_CONF_load_certs(const char *file);
/**
 * @brief Load a private key from a PEM file for TSA signing.
 * @param file Path to a PEM private-key file.
 * @param pass Optional passphrase, or NULL if the key is unencrypted.
 * @return New EVP_PKEY, or NULL on error.
 */
EVP_PKEY *TS_CONF_load_key(const char *file, const char *pass);
/**
 * @brief Resolve the CONF section name used for TSA settings.
 * @param conf Configuration object.
 * @param section Requested section name, or NULL to use the default "tsa" / tsa_section lookup.
 * @return Section name string suitable for other TS_CONF_* helpers, or NULL on error.
 */
const char *TS_CONF_get_tsa_section(CONF *conf, const char *section);
/**
 * @brief Configure the serial-number callback on a response context from CONF.
 * @param conf Configuration object (section looked up for documentation/logging).
 * @param section TSA configuration section name.
 * @param cb Serial callback installed on @p ctx.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_serial(CONF *conf, const char *section, TS_serial_cb cb,
    TS_RESP_CTX *ctx);
#ifndef OPENSSL_NO_ENGINE
/**
 * @brief Set the ENGINE crypto device name from configuration for TSA operations.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param device Optional device name override, or NULL to read from @p conf.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_crypto_device(CONF *conf, const char *section,
    const char *device);
/**
 * @brief Set the default OpenSSL ENGINE by name for time-stamp configuration helpers.
 * @param name ENGINE identifier such as "chil" or "openssl".
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_default_engine(const char *name);
#endif
/**
 * @brief Load and set the TSA signer certificate on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param cert Optional certificate file path override, or NULL to read from @p conf.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_signer_cert(CONF *conf, const char *section,
    const char *cert, TS_RESP_CTX *ctx);
/**
 * @brief Load and set additional certificates included with TSA responses from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param certs Optional certificate-file path override, or NULL to read from @p conf.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_certs(CONF *conf, const char *section, const char *certs,
    TS_RESP_CTX *ctx);
/**
 * @brief Load and set the TSA signer private key on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param key Optional private-key file path override, or NULL to read from @p conf.
 * @param pass Optional passphrase for an encrypted key, or NULL.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_signer_key(CONF *conf, const char *section,
    const char *key, const char *pass,
    TS_RESP_CTX *ctx);
/**
 * @brief Set the TSA signer digest on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param md Optional digest name override, or NULL to read from @p conf.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_signer_digest(CONF *conf, const char *section,
    const char *md, TS_RESP_CTX *ctx);
/**
 * @brief Set the default TSA policy OID on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param policy Optional policy OID string override, or NULL to read from @p conf.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_def_policy(CONF *conf, const char *section,
    const char *policy, TS_RESP_CTX *ctx);
/**
 * @brief Add acceptable TSA policies listed in CONF to a response context.
 * @param conf Configuration object.
 * @param section TSA configuration section name containing policies.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_policies(CONF *conf, const char *section, TS_RESP_CTX *ctx);
/**
 * @brief Add acceptable request digests listed in CONF to a response context.
 * @param conf Configuration object.
 * @param section TSA configuration section name containing digests.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_digests(CONF *conf, const char *section, TS_RESP_CTX *ctx);
/**
 * @brief Set TSTInfo Accuracy seconds/millis/micros on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_accuracy(CONF *conf, const char *section, TS_RESP_CTX *ctx);
/**
 * @brief Set genTime clock precision digits on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_clock_precision_digits(const CONF *conf, const char *section,
    TS_RESP_CTX *ctx);
/**
 * @brief Enable or disable the TSTInfo ordering flag from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_ordering(CONF *conf, const char *section, TS_RESP_CTX *ctx);
/**
 * @brief Enable including the TSA name in generated TSTInfo structures from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_tsa_name(CONF *conf, const char *section, TS_RESP_CTX *ctx);
/**
 * @brief Configure whether ESS cert-id attributes include the certificate chain from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_ess_cert_id_chain(CONF *conf, const char *section,
    TS_RESP_CTX *ctx);
/**
 * @brief Set the ESS signing-certificate digest algorithm from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_ess_cert_id_digest(CONF *conf, const char *section,
    TS_RESP_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
#endif
