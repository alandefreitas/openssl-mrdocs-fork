/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PEM_H
#define OPENSSL_PEM_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_PEM_H
#endif

#include <openssl/e_os2.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pemerr.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PEM_BUFSIZE 1024

#define PEM_STRING_X509_OLD "X509 CERTIFICATE"
#define PEM_STRING_X509 "CERTIFICATE"
#define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
#define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
#define PEM_STRING_X509_REQ "CERTIFICATE REQUEST"
#define PEM_STRING_X509_CRL "X509 CRL"
#define PEM_STRING_EVP_PKEY "ANY PRIVATE KEY"
#define PEM_STRING_PUBLIC "PUBLIC KEY"
#define PEM_STRING_RSA "RSA PRIVATE KEY"
#define PEM_STRING_RSA_PUBLIC "RSA PUBLIC KEY"
#define PEM_STRING_DSA "DSA PRIVATE KEY"
#define PEM_STRING_DSA_PUBLIC "DSA PUBLIC KEY"
#define PEM_STRING_PKCS7 "PKCS7"
#define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
#define PEM_STRING_PKCS8 "ENCRYPTED PRIVATE KEY"
#define PEM_STRING_PKCS8INF "PRIVATE KEY"
#define PEM_STRING_DHPARAMS "DH PARAMETERS"
#define PEM_STRING_DHXPARAMS "X9.42 DH PARAMETERS"
#define PEM_STRING_SSL_SESSION "SSL SESSION PARAMETERS"
#define PEM_STRING_DSAPARAMS "DSA PARAMETERS"
#define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
#define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
#define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
#define PEM_STRING_PARAMETERS "PARAMETERS"
#define PEM_STRING_CMS "CMS"
#define PEM_STRING_SM2PRIVATEKEY "SM2 PRIVATE KEY"
#define PEM_STRING_SM2PARAMETERS "SM2 PARAMETERS"

#define PEM_TYPE_ENCRYPTED 10
#define PEM_TYPE_MIC_ONLY 20
#define PEM_TYPE_MIC_CLEAR 30
#define PEM_TYPE_CLEAR 40

/*
 * These macros make the PEM_read/PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
 * IMPLEMENT_PEM_rw_cb(...)
 */

#define PEM_read_cb_fnsig(name, type, INTYPE, readname)  \
    type *PEM_##readname##_##name(INTYPE *out, type **x, \
        pem_password_cb *cb, void *u)
#define PEM_read_cb_ex_fnsig(name, type, INTYPE, readname)    \
    type *PEM_##readname##_##name##_ex(INTYPE *out, type **x, \
        pem_password_cb *cb, void *u,                         \
        OSSL_LIB_CTX *libctx,                                 \
        const char *propq)

#define PEM_write_fnsig(name, type, OUTTYPE, writename) \
    int PEM_##writename##_##name(OUTTYPE *out, const type *x)
#define PEM_write_cb_fnsig(name, type, OUTTYPE, writename)    \
    int PEM_##writename##_##name(OUTTYPE *out, const type *x, \
        const EVP_CIPHER *enc,                                \
        const unsigned char *kstr, int klen,                  \
        pem_password_cb *cb, void *u)
#define PEM_write_ex_fnsig(name, type, OUTTYPE, writename)         \
    int PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x, \
        OSSL_LIB_CTX *libctx,                                      \
        const char *propq)
#define PEM_write_cb_ex_fnsig(name, type, OUTTYPE, writename)      \
    int PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x, \
        const EVP_CIPHER *enc,                                     \
        const unsigned char *kstr, int klen,                       \
        pem_password_cb *cb, void *u,                              \
        OSSL_LIB_CTX *libctx,                                      \
        const char *propq)

#ifdef OPENSSL_NO_STDIO

#define IMPLEMENT_PEM_read_fp(name, type, str, asn1) /**/
#define IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#endif
#define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
#endif
#else

#define IMPLEMENT_PEM_read_fp(name, type, str, asn1)                        \
    type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u) \
    {                                                                       \
        return PEM_ASN1_read((d2i_of_void *)d2i_##asn1, str, fp,            \
            (void **)x, cb, u);                                             \
    }

#define IMPLEMENT_PEM_write_fp(name, type, str, asn1)              \
    PEM_write_fnsig(name, type, FILE, write)                       \
    {                                                              \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1, str, out, \
            x, NULL, NULL, 0, NULL, NULL);                         \
    }

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_fp(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)           \
    PEM_write_cb_fnsig(name, type, FILE, write)                    \
    {                                                              \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1, str, out, \
            x, enc, kstr, klen, cb, u);                            \
    }

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)
#endif
#endif

#define IMPLEMENT_PEM_read_bio(name, type, str, asn1)                \
    type *PEM_read_bio_##name(BIO *bp, type **x,                     \
        pem_password_cb *cb, void *u)                                \
    {                                                                \
        return PEM_ASN1_read_bio((d2i_of_void *)d2i_##asn1, str, bp, \
            (void **)x, cb, u);                                      \
    }

#define IMPLEMENT_PEM_write_bio(name, type, str, asn1)                 \
    PEM_write_fnsig(name, type, BIO, write_bio)                        \
    {                                                                  \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, out, \
            x, NULL, NULL, 0, NULL, NULL);                             \
    }

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_bio(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)              \
    PEM_write_cb_fnsig(name, type, BIO, write_bio)                     \
    {                                                                  \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, out, \
            x, enc, kstr, klen, cb, u);                                \
    }

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_write(name, type, str, asn1) \
    IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
    IMPLEMENT_PEM_write_fp(name, type, str, asn1)

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_write_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_write_cb_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
    IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_read(name, type, str, asn1) \
    IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
    IMPLEMENT_PEM_read_fp(name, type, str, asn1)

#define IMPLEMENT_PEM_rw(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)   \
    IMPLEMENT_PEM_write(name, type, str, asn1)

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define IMPLEMENT_PEM_rw_const(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)         \
    IMPLEMENT_PEM_write_const(name, type, str, asn1)
#endif

#define IMPLEMENT_PEM_rw_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)      \
    IMPLEMENT_PEM_write_cb(name, type, str, asn1)

/* These are the same except they are for the declarations */

/*
 * The mysterious 'extern' that's passed to some macros is innocuous,
 * and is there to quiet pre-C99 compilers that may complain about empty
 * arguments in macro calls.
 */
#if defined(OPENSSL_NO_STDIO)

#define DECLARE_PEM_read_fp_attr(attr, name, type) /**/
#define DECLARE_PEM_read_fp_ex_attr(attr, name, type) /**/
#define DECLARE_PEM_write_fp_attr(attr, name, type) /**/
#define DECLARE_PEM_write_fp_ex_attr(attr, name, type) /**/
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_write_fp_const_attr(attr, name, type) /**/
#endif
#define DECLARE_PEM_write_cb_fp_attr(attr, name, type) /**/
#define DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type) /**/

#else

#define DECLARE_PEM_read_fp_attr(attr, name, type) \
    attr PEM_read_cb_fnsig(name, type, FILE, read);
#define DECLARE_PEM_read_fp_ex_attr(attr, name, type) \
    attr PEM_read_cb_fnsig(name, type, FILE, read);   \
    attr PEM_read_cb_ex_fnsig(name, type, FILE, read);

#define DECLARE_PEM_write_fp_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, FILE, write);
#define DECLARE_PEM_write_fp_ex_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, FILE, write);     \
    attr PEM_write_ex_fnsig(name, type, FILE, write);
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_write_fp_const_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, FILE, write);
#endif
#define DECLARE_PEM_write_cb_fp_attr(attr, name, type) \
    attr PEM_write_cb_fnsig(name, type, FILE, write);
#define DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type) \
    attr PEM_write_cb_fnsig(name, type, FILE, write);     \
    attr PEM_write_cb_ex_fnsig(name, type, FILE, write);

#endif

#define DECLARE_PEM_read_fp(name, type) \
    DECLARE_PEM_read_fp_attr(extern, name, type)
#define DECLARE_PEM_write_fp(name, type) \
    DECLARE_PEM_write_fp_attr(extern, name, type)
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_write_fp_const(name, type) \
    DECLARE_PEM_write_fp_const_attr(extern, name, type)
#endif
#define DECLARE_PEM_write_cb_fp(name, type) \
    DECLARE_PEM_write_cb_fp_attr(extern, name, type)

#define DECLARE_PEM_read_bio_attr(attr, name, type) \
    attr PEM_read_cb_fnsig(name, type, BIO, read_bio);
#define DECLARE_PEM_read_bio_ex_attr(attr, name, type) \
    attr PEM_read_cb_fnsig(name, type, BIO, read_bio); \
    attr PEM_read_cb_ex_fnsig(name, type, BIO, read_bio);
#define DECLARE_PEM_read_bio(name, type) \
    DECLARE_PEM_read_bio_attr(extern, name, type)
#define DECLARE_PEM_read_bio_ex(name, type) \
    DECLARE_PEM_read_bio_ex_attr(extern, name, type)

#define DECLARE_PEM_write_bio_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, BIO, write_bio);
#define DECLARE_PEM_write_bio_ex_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, BIO, write_bio);   \
    attr PEM_write_ex_fnsig(name, type, BIO, write_bio);
#define DECLARE_PEM_write_bio(name, type) \
    DECLARE_PEM_write_bio_attr(extern, name, type)
#define DECLARE_PEM_write_bio_ex(name, type) \
    DECLARE_PEM_write_bio_ex_attr(extern, name, type)

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_write_bio_const_attr(attr, name, type) \
    attr PEM_write_fnsig(name, type, BIO, write_bio);
#define DECLARE_PEM_write_bio_const(name, type) \
    DECLARE_PEM_write_bio_const_attr(extern, name, type)
#endif

#define DECLARE_PEM_write_cb_bio_attr(attr, name, type) \
    attr PEM_write_cb_fnsig(name, type, BIO, write_bio);
#define DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type) \
    attr PEM_write_cb_fnsig(name, type, BIO, write_bio);   \
    attr PEM_write_cb_ex_fnsig(name, type, BIO, write_bio);
#define DECLARE_PEM_write_cb_bio(name, type) \
    DECLARE_PEM_write_cb_bio_attr(extern, name, type)
#define DECLARE_PEM_write_cb_ex_bio(name, type) \
    DECLARE_PEM_write_cb_bio_ex_attr(extern, name, type)

#define DECLARE_PEM_write_attr(attr, name, type) \
    DECLARE_PEM_write_bio_attr(attr, name, type) \
    DECLARE_PEM_write_fp_attr(attr, name, type)
#define DECLARE_PEM_write_ex_attr(attr, name, type) \
    DECLARE_PEM_write_bio_ex_attr(attr, name, type) \
    DECLARE_PEM_write_fp_ex_attr(attr, name, type)
#define DECLARE_PEM_write(name, type) \
    DECLARE_PEM_write_attr(extern, name, type)
#define DECLARE_PEM_write_ex(name, type) \
    DECLARE_PEM_write_ex_attr(extern, name, type)
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_write_const_attr(attr, name, type) \
    DECLARE_PEM_write_bio_const_attr(attr, name, type) \
    DECLARE_PEM_write_fp_const_attr(attr, name, type)
#define DECLARE_PEM_write_const(name, type) \
    DECLARE_PEM_write_const_attr(extern, name, type)
#endif
#define DECLARE_PEM_write_cb_attr(attr, name, type) \
    DECLARE_PEM_write_cb_bio_attr(attr, name, type) \
    DECLARE_PEM_write_cb_fp_attr(attr, name, type)
#define DECLARE_PEM_write_cb_ex_attr(attr, name, type) \
    DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type) \
    DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type)
#define DECLARE_PEM_write_cb(name, type) \
    DECLARE_PEM_write_cb_attr(extern, name, type)
#define DECLARE_PEM_write_cb_ex(name, type) \
    DECLARE_PEM_write_cb_ex_attr(extern, name, type)
#define DECLARE_PEM_read_attr(attr, name, type) \
    DECLARE_PEM_read_bio_attr(attr, name, type) \
    DECLARE_PEM_read_fp_attr(attr, name, type)
#define DECLARE_PEM_read_ex_attr(attr, name, type) \
    DECLARE_PEM_read_bio_ex_attr(attr, name, type) \
    DECLARE_PEM_read_fp_ex_attr(attr, name, type)
#define DECLARE_PEM_read(name, type) \
    DECLARE_PEM_read_attr(extern, name, type)
#define DECLARE_PEM_read_ex(name, type) \
    DECLARE_PEM_read_ex_attr(extern, name, type)
#define DECLARE_PEM_rw_attr(attr, name, type) \
    DECLARE_PEM_read_attr(attr, name, type)   \
    DECLARE_PEM_write_attr(attr, name, type)
#define DECLARE_PEM_rw_ex_attr(attr, name, type) \
    DECLARE_PEM_read_ex_attr(attr, name, type)   \
    DECLARE_PEM_write_ex_attr(attr, name, type)
#define DECLARE_PEM_rw(name, type) \
    DECLARE_PEM_rw_attr(extern, name, type)
#define DECLARE_PEM_rw_ex(name, type) \
    DECLARE_PEM_rw_ex_attr(extern, name, type)
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define DECLARE_PEM_rw_const_attr(attr, name, type) \
    DECLARE_PEM_read_attr(attr, name, type)         \
    DECLARE_PEM_write_const_attr(attr, name, type)
#define DECLARE_PEM_rw_const(name, type) \
    DECLARE_PEM_rw_const_attr(extern, name, type)
#endif
#define DECLARE_PEM_rw_cb_attr(attr, name, type) \
    DECLARE_PEM_read_attr(attr, name, type)      \
    DECLARE_PEM_write_cb_attr(attr, name, type)
#define DECLARE_PEM_rw_cb_ex_attr(attr, name, type) \
    DECLARE_PEM_read_ex_attr(attr, name, type)      \
    DECLARE_PEM_write_cb_ex_attr(attr, name, type)
#define DECLARE_PEM_rw_cb(name, type) \
    DECLARE_PEM_rw_cb_attr(extern, name, type)
#define DECLARE_PEM_rw_cb_ex(name, type) \
    DECLARE_PEM_rw_cb_ex_attr(extern, name, type)

/**
 * @brief Parse a PEM encapsulation header for cipher and IV (legacy PEM encryption).
 * @param header Encapsulation header returned by PEM_read() / PEM_read_bio().
 * @param cipher Receives the cipher and IV when the PEM data is encrypted.
 * @return 1 on success, or 0 if the header is missing, malformed, or unsupported.
 *
 * Deprecated: prefer PKCS#8 with PKCS#5 v2.0 PBE for new private-key storage.
 */
int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
/**
 * @brief Decrypt PEM payload bytes in place using cipher info and a password callback.
 * @param cipher Cipher and IV previously filled by PEM_get_EVP_CIPHER_INFO().
 * @param data Encoded payload buffer; decrypted octets overwrite the same buffer.
 * @param len On input, length of @p data; on output, length of the decrypted payload.
 * @param callback Password callback used when @p cipher indicates encryption; may be NULL.
 * @param u Application pointer forwarded to @p callback.
 * @return 1 on success, or 0 on failure.
 *
 * Deprecated: prefer PKCS#8 with PKCS#5 v2.0 PBE for new private-key storage.
 */
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
    pem_password_cb *callback, void *u);

/**
 * @brief Read one PEM object from a BIO, returning name, header, and decoded data.
 * @param bp BIO to read from.
 * @param name Receives a newly allocated PEM type name (caller frees with OPENSSL_free).
 * @param header Receives a newly allocated PEM header block, or an empty string.
 * @param data Receives newly allocated decoded payload bytes.
 * @param len Receives the length of *@p data in bytes.
 * @return 1 on success, or 0 on failure / end of input.
 */
int PEM_read_bio(BIO *bp, char **name, char **header,
    unsigned char **data, long *len);
#define PEM_FLAG_SECURE 0x1
#define PEM_FLAG_EAY_COMPATIBLE 0x2
#define PEM_FLAG_ONLY_B64 0x4
/**
 * @brief Read one PEM object from a BIO with controllable decoding behaviour.
 * @param bp BIO to read from.
 * @param name Receives the allocated type name from the BEGIN line; caller frees it.
 * @param header Receives allocated encapsulation headers, or an empty string; caller frees it.
 * @param data Receives allocated base64-decoded payload; caller frees it.
 * @param len Receives the length of @p data in bytes.
 * @param flags Bitwise OR of PEM_FLAG_SECURE, PEM_FLAG_EAY_COMPATIBLE, and/or PEM_FLAG_ONLY_B64.
 * @return 1 on success, or 0 on failure.
 */
int PEM_read_bio_ex(BIO *bp, char **name, char **header,
    unsigned char **data, long *len, unsigned int flags);
/**
 * @brief Read a named PEM object from a BIO into secure memory, decrypting if needed.
 * @param pdata Receives newly allocated DER payload in secure memory (caller frees with OPENSSL_secure_free).
 * @param plen Receives the length of *@p pdata in bytes.
 * @param pnm Optional; receives the actual PEM type name from the BEGIN line (caller frees).
 * @param name Expected PEM type label (for example "CERTIFICATE"); non-matching types are skipped.
 * @param bp BIO to read from.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
/**
 * @brief Write a PEM object (header, optional headers, and base64 body) to a BIO.
 * @param bp BIO that receives the PEM text.
 * @param name PEM type label such as "CERTIFICATE".
 * @param hdr Optional additional header lines, or NULL / empty string.
 * @param data Binary payload to base64-encode.
 * @param len Length of @p data in bytes.
 * @return 1 on success, or 0 on error.
 */
int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
    const unsigned char *data, long len);
/**
 * @brief Read a named PEM object from a BIO, decrypting if needed, and return its DER bytes.
 * @param pdata Receives newly allocated DER payload (caller frees with OPENSSL_free).
 * @param plen Receives the length of *@p pdata in bytes.
 * @param pnm Optional; receives the actual PEM type name from the BEGIN line (caller frees).
 * @param name Expected PEM type label (for example "CERTIFICATE"); non-matching types are skipped.
 * @param bp BIO to read from.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
/**
 * @brief Read a named PEM object from a BIO and decode it with @p d2i.
 * @param d2i ASN.1 decode callback for the expected type.
 * @param name PEM type label expected on the BEGIN line (e.g. "CERTIFICATE").
 * @param bp BIO to read from.
 * @param x Optional address of an object pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Decoded object on success, or NULL on failure.
 */
void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode an ASN.1 object with @p i2d and write it as a PEM block to a BIO.
 * @param i2d Encoder such as i2d_X509.
 * @param name PEM type label written after "-----BEGIN ".
 * @param bp BIO that receives the PEM text.
 * @param x Object passed to @p i2d.
 * @param enc Optional cipher for encrypting the PEM, or NULL for cleartext.
 * @param kstr Optional encryption key bytes when @p enc is non-NULL, or NULL to use @p cb.
 * @param klen Length of @p kstr in bytes.
 * @param cb Password callback used when @p enc is set and @p kstr is NULL, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
    const void *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);

/**
 * @brief Read successive PEM objects from a BIO into a stack of X509_INFO.
 * @param bp BIO to read from.
 * @param sk Existing stack to append to, or NULL to allocate a new stack.
 * @param cb Password callback for encrypted private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @return Stack of X509_INFO (certificate, CRL, and/or key groups), or NULL on failure.
 */
STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,
    pem_password_cb *cb, void *u);
/**
 * @brief Read successive PEM X509_INFO objects (cert, CRL, and/or key) from a BIO with an explicit library context.
 * @param bp BIO to read from.
 * @param sk Existing stack to append to, or NULL to allocate a new stack.
 * @param cb Password callback for encrypted private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context for provider-backed key decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Stack of X509_INFO groups, or NULL on failure.
 */
STACK_OF(X509_INFO)
*PEM_X509_INFO_read_bio_ex(BIO *bp, STACK_OF(X509_INFO) *sk,
    pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx,
    const char *propq);

/**
 * @brief Write the certificate, CRL, and/or private key from an X509_INFO as PEM.
 * @param bp BIO to write to.
 * @param xi Bundle whose non-NULL members are encoded.
 * @param enc Optional cipher for encrypting a private key, or NULL.
 * @param kstr Optional key material for @p enc, or NULL to prompt via @p cd.
 * @param klen Length of @p kstr in bytes.
 * @param cd Password callback used when encrypting without @p kstr, or NULL.
 * @param u Application data passed to @p cd.
 * @return 1 on success, or 0 on failure.
 */
int PEM_X509_INFO_write_bio(BIO *bp, const X509_INFO *xi, EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *cd, void *u);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read one PEM object from a FILE, returning name, header, and decoded data.
 * @param fp FILE to read from.
 * @param name Receives a newly allocated PEM type name (caller frees with OPENSSL_free).
 * @param header Receives a newly allocated PEM header block, or an empty string.
 * @param data Receives newly allocated decoded payload bytes.
 * @param len Receives the length of *@p data in bytes.
 * @return 1 on success, or 0 on failure / end of input.
 */
int PEM_read(FILE *fp, char **name, char **header,
    unsigned char **data, long *len);
/**
 * @brief Write a PEM object (header, optional headers, and base64 body) to a FILE.
 * @param fp FILE that receives the PEM text.
 * @param name PEM type label such as "CERTIFICATE".
 * @param hdr Optional additional header lines, or NULL / empty string.
 * @param data Binary payload to base64-encode.
 * @param len Length of @p data in bytes.
 * @return 1 on success, or 0 on error.
 */
int PEM_write(FILE *fp, const char *name, const char *hdr,
    const unsigned char *data, long len);
/**
 * @brief Read a named PEM object from a FILE and decode it with @p d2i.
 * @param d2i ASN.1 decode callback for the expected type.
 * @param name PEM type label expected on the BEGIN line (e.g. "CERTIFICATE").
 * @param fp FILE to read from.
 * @param x Optional address of an object pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Decoded object on success, or NULL on failure.
 */
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode an ASN.1 object with @p i2d and write it as PEM to a FILE.
 * @param i2d ASN.1 encode callback for the object type.
 * @param name PEM type label used on the BEGIN/END lines.
 * @param fp FILE to write to.
 * @param x Object to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL.
 * @param kstr Optional key material for @p enc, or NULL to prompt via @p callback.
 * @param klen Length of @p kstr in bytes.
 * @param callback Password callback when encrypting without @p kstr, or NULL.
 * @param u Application data passed to @p callback.
 * @return 1 on success, or 0 on failure.
 */
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
    const void *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *callback, void *u);
/**
 * @brief Read certificates, CRLs, and keys from a PEM FILE into X509_INFO objects.
 * @param fp FILE positioned at PEM input.
 * @param sk Existing stack to append to, or NULL to allocate a new one.
 * @param cb Password callback for encrypted PEM private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @return Stack of X509_INFO on success, or NULL on failure.
 */
STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
    pem_password_cb *cb, void *u);
/**
 * @brief Read certificates, CRLs, and keys from a PEM FILE with a library context.
 * @param fp FILE positioned at PEM input.
 * @param sk Existing stack to append to, or NULL to allocate a new one.
 * @param cb Password callback for encrypted PEM private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Stack of X509_INFO on success, or NULL on failure.
 */
STACK_OF(X509_INFO)
*PEM_X509_INFO_read_ex(FILE *fp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb,
    void *u, OSSL_LIB_CTX *libctx, const char *propq);
#endif

/**
 * @brief Initialize an EVP_MD_CTX for signing with digest @p type (used by PEM_Sign*).
 * @param ctx Digest context to initialize for signing.
 * @param type Message digest algorithm (for example EVP_sha256()).
 * @return 1 on success, or 0 on failure.
 */
int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
/**
 * @brief Absorb more message bytes into a PEM signing digest context.
 * @param ctx Digest context initialised for PEM signing (for example via PEM_SignInit).
 * @param d Message bytes to hash.
 * @param cnt Number of bytes at @p d.
 * @return 1 on success, or 0 on failure.
 */
int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);
/**
 * @brief Finalize a PEM signing operation and write the signature.
 * @param ctx Digest context previously updated with data to sign.
 * @param sigret Buffer receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param pkey Private key used to generate the signature.
 * @return 1 on success, or 0 on error.
 */
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    unsigned int *siglen, EVP_PKEY *pkey);

/* The default pem_password_cb that's used internally */
/**
 * @brief Default pem_password_cb that prompts on the terminal (or copies @p userdata).
 * @param buf Destination buffer for the password bytes.
 * @param num Capacity of @p buf in bytes.
 * @param rwflag 0 when reading/decrypting, non-zero when writing/encrypting.
 * @param userdata Optional default password string, or NULL to prompt.
 * @return Password length written to @p buf, or 0 on failure / empty input.
 */
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
/**
 * @brief Append a Proc-Type encapsulation header line to a PEM header buffer.
 * @param buf NUL-terminated buffer of size PEM_BUFSIZE to append into.
 * @param type One of PEM_TYPE_ENCRYPTED, PEM_TYPE_MIC_ONLY, PEM_TYPE_MIC_CLEAR, or PEM_TYPE_CLEAR.
 */
void PEM_proc_type(char *buf, int type);
/**
 * @brief Append a DEK-Info encapsulation header (cipher name and hex IV) to a PEM header.
 * @param buf NUL-terminated buffer of size PEM_BUFSIZE to append into.
 * @param type Cipher name string (for example from EVP_CIPHER_get0_name()).
 * @param len Number of IV bytes at @p str.
 * @param str IV bytes written as uppercase hex after the cipher name.
 */
void PEM_dek_info(char *buf, const char *type, int len, const char *str);

#include <openssl/symhacks.h>

/**
 * @brief Read an X.509 certificate from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate on success, or NULL on failure.
 */
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write an X.509 certificate to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Certificate to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509(BIO *bp, const X509 *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an X.509 certificate from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of an X509 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate on success, or NULL on failure.
 */
X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write an X.509 certificate to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x Certificate to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509(FILE *fp, const X509 *x);
#endif

/**
 * @brief Read a trusted X.509 certificate (with aux trust info) from a PEM BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate on success, or NULL on failure.
 */
X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a trusted X.509 certificate (with aux trust info) to a BIO as PEM.
 * @param bp BIO to write to.
 * @param x Certificate to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_AUX(BIO *bp, const X509 *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a trusted X.509 certificate (with aux trust info) from a PEM FILE.
 * @param fp FILE to read from.
 * @param x Optional address of an X509 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate on success, or NULL on failure.
 */
X509 *PEM_read_X509_AUX(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a trusted X.509 certificate (with aux trust info) to a FILE as PEM.
 * @param fp FILE to write to.
 * @param x Certificate to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_AUX(FILE *fp, const X509 *x);
#endif

/**
 * @brief Read a certificate request from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509_REQ pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate request on success, or NULL on failure.
 */
X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a certificate request to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_REQ(BIO *bp, const X509_REQ *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a certificate request from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of an X509_REQ pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate request on success, or NULL on failure.
 */
X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a certificate request to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_REQ(FILE *fp, const X509_REQ *x);
#endif
/**
 * @brief Write a certificate request using the legacy "NEW CERTIFICATE REQUEST" PEM label.
 * @param bp BIO to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_REQ_NEW(BIO *bp, const X509_REQ *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Write a certificate request using the legacy "NEW CERTIFICATE REQUEST" PEM label.
 * @param fp FILE to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_REQ_NEW(FILE *fp, const X509_REQ *x);
#endif

/**
 * @brief Read an X.509 CRL from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509_CRL pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return CRL on success, or NULL on failure.
 */
X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb,
    void *u);
/**
 * @brief Write an X.509 CRL to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x CRL to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_CRL(BIO *bp, const X509_CRL *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an X.509 CRL from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of an X509_CRL pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return CRL on success, or NULL on failure.
 */
X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x, pem_password_cb *cb,
    void *u);
/**
 * @brief Write an X.509 CRL to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x CRL to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_CRL(FILE *fp, const X509_CRL *x);
#endif

/**
 * @brief Read an X.509 SubjectPublicKeyInfo from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509_PUBKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Public key on success, or NULL on failure.
 */
X509_PUBKEY *PEM_read_bio_X509_PUBKEY(BIO *bp, X509_PUBKEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an X.509 SubjectPublicKeyInfo to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Public key to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_PUBKEY(BIO *bp, const X509_PUBKEY *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an X.509 SubjectPublicKeyInfo from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of an X509_PUBKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Public key on success, or NULL on failure.
 */
X509_PUBKEY *PEM_read_X509_PUBKEY(FILE *fp, X509_PUBKEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an X.509 SubjectPublicKeyInfo to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x Public key to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_PUBKEY(FILE *fp, const X509_PUBKEY *x);
#endif

/**
 * @brief Read a PKCS#7 structure from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of a PKCS7 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return PKCS#7 object on success, or NULL on failure.
 */
PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#7 structure to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x PKCS#7 object to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS7(BIO *bp, const PKCS7 *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a PKCS#7 structure from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of a PKCS7 pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return PKCS#7 object on success, or NULL on failure.
 */
PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#7 structure to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x PKCS#7 object to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PKCS7(FILE *fp, const PKCS7 *x);
#endif

/**
 * @brief Read a Netscape certificate sequence from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of a NETSCAPE_CERT_SEQUENCE pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Sequence on success, or NULL on failure.
 */
NETSCAPE_CERT_SEQUENCE *PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp,
    NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a Netscape certificate sequence to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Sequence to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp,
    const NETSCAPE_CERT_SEQUENCE *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a Netscape certificate sequence from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of a NETSCAPE_CERT_SEQUENCE pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Sequence on success, or NULL on failure.
 */
NETSCAPE_CERT_SEQUENCE *PEM_read_NETSCAPE_CERT_SEQUENCE(FILE *fp,
    NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a Netscape certificate sequence to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x Sequence to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE *fp,
    const NETSCAPE_CERT_SEQUENCE *x);
#endif
/**
 * @brief Read a PKCS#8 encrypted private-key envelope (X509_SIG) from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509_SIG pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Encrypted PKCS#8 structure on success, or NULL on failure.
 */
X509_SIG *PEM_read_bio_PKCS8(BIO *bp, X509_SIG **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#8 encrypted private-key envelope (X509_SIG) to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Encrypted PKCS#8 structure to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS8(BIO *bp, const X509_SIG *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a PKCS#8 encrypted private-key envelope (X509_SIG) from a PEM-encoded FILE.
 * @param fp FILE to read from.
 * @param x Optional address of an X509_SIG pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Encrypted PKCS#8 structure on success, or NULL on failure.
 */
X509_SIG *PEM_read_PKCS8(FILE *fp, X509_SIG **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#8 encrypted private-key envelope (X509_SIG) to a FILE in PEM form.
 * @param fp FILE to write to.
 * @param x Encrypted PKCS#8 structure to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PKCS8(FILE *fp, const X509_SIG *x);
#endif

/**
 * @brief Read a PKCS#8 PrivateKeyInfo from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of a PKCS8_PRIV_KEY_INFO pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return PrivateKeyInfo on success, or NULL on failure.
 */
PKCS8_PRIV_KEY_INFO *PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO *bp,
    PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#8 PrivateKeyInfo to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x PrivateKeyInfo to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS8_PRIV_KEY_INFO(BIO *bp, const PKCS8_PRIV_KEY_INFO *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a PKCS#8 PrivateKeyInfo from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of a PKCS8_PRIV_KEY_INFO pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return PrivateKeyInfo on success, or NULL on failure.
 */
PKCS8_PRIV_KEY_INFO *PEM_read_PKCS8_PRIV_KEY_INFO(FILE *fp,
    PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a PKCS#8 PrivateKeyInfo to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x PrivateKeyInfo to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PKCS8_PRIV_KEY_INFO(FILE *fp, const PKCS8_PRIV_KEY_INFO *x);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Read a traditional RSA private key from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional RSA private key to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x RSA key to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_RSAPrivateKey(BIO *bp, const RSA *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a traditional RSA private key from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional RSA private key to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x RSA key to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_RSAPrivateKey(FILE *fp, const RSA *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#endif

/**
 * @brief Read a traditional PKCS#1 RSA public key from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional PKCS#1 RSA public key to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x RSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_RSAPublicKey(BIO *bp, const RSA *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a traditional PKCS#1 RSA public key from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional PKCS#1 RSA public key to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x RSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_RSAPublicKey(FILE *fp, const RSA *x);
#endif

/**
 * @brief Read an RSA SubjectPublicKeyInfo from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an RSA SubjectPublicKeyInfo to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x RSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_RSA_PUBKEY(BIO *bp, const RSA *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an RSA SubjectPublicKeyInfo from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an RSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return RSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an RSA SubjectPublicKeyInfo to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x RSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_RSA_PUBKEY(FILE *fp, const RSA *x);
#endif
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
#ifndef OPENSSL_NO_DSA
/**
 * @brief Read a traditional DSA private key from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional DSA private key to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x DSA key to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_DSAPrivateKey(BIO *bp, const DSA *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a traditional DSA private key from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a traditional DSA private key to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x DSA key to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_DSAPrivateKey(FILE *fp, const DSA *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#endif
/**
 * @brief Read a DSA SubjectPublicKeyInfo from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_bio_DSA_PUBKEY(BIO *bp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a DSA SubjectPublicKeyInfo to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x DSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_DSA_PUBKEY(BIO *bp, const DSA *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a DSA SubjectPublicKeyInfo from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA key on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_DSA_PUBKEY(FILE *fp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a DSA SubjectPublicKeyInfo to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x DSA key to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_DSA_PUBKEY(FILE *fp, const DSA *x);
#endif

/**
 * @brief Read DSA domain parameters from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA parameters on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_bio_DSAparams(BIO *bp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write DSA domain parameters to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x DSA parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_DSAparams(BIO *bp, const DSA *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read DSA domain parameters from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of a DSA pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DSA parameters on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA *PEM_read_DSAparams(FILE *fp, DSA **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write DSA domain parameters to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x DSA parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_DSAparams(FILE *fp, const DSA *x);
#endif
#endif
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
#ifndef OPENSSL_NO_EC
/**
 * @brief Read EC domain parameters (ECPKParameters) from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an EC_GROUP pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_GROUP on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write EC domain parameters (ECPKParameters) to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x EC_GROUP parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_ECPKParameters(BIO *bp, const EC_GROUP *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read EC domain parameters (ECPKParameters) from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an EC_GROUP pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_GROUP on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_GROUP *PEM_read_ECPKParameters(FILE *fp, EC_GROUP **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write EC domain parameters (ECPKParameters) to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x EC_GROUP parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_ECPKParameters(FILE *fp, const EC_GROUP *x);
#endif

/**
 * @brief Read an EC private key from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an EC_KEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_KEY on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an EC private key to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x EC_KEY to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_ECPrivateKey(BIO *bp, const EC_KEY *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an EC private key from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an EC_KEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_KEY on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an EC private key to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x EC_KEY to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional encryption key bytes used with @p enc, or NULL to prompt via @p cb.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when encryption needs a passphrase, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_ECPrivateKey(FILE *fp, const EC_KEY *x,
    const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
#endif

/**
 * @brief Read an EC SubjectPublicKeyInfo from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of an EC_KEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_KEY on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an EC SubjectPublicKeyInfo to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x EC_KEY to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_EC_PUBKEY(BIO *bp, const EC_KEY *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read an EC SubjectPublicKeyInfo from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of an EC_KEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return EC_KEY on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *PEM_read_EC_PUBKEY(FILE *fp, EC_KEY **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write an EC SubjectPublicKeyInfo to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x EC_KEY to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_EC_PUBKEY(FILE *fp, const EC_KEY *x);
#endif
#endif
#endif

#ifndef OPENSSL_NO_DH
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Read Diffie-Hellman domain parameters from a PEM-encoded BIO (deprecated).
 * @param bp BIO to read from.
 * @param x Optional address of a DH pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DH parameters on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *PEM_read_bio_DHparams(BIO *bp, DH **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write Diffie-Hellman domain parameters to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x DH parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_DHparams(BIO *bp, const DH *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read Diffie-Hellman domain parameters from a PEM-encoded FILE (deprecated).
 * @param fp FILE to read from.
 * @param x Optional address of a DH pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return DH parameters on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *PEM_read_DHparams(FILE *fp, DH **x,
    pem_password_cb *cb, void *u);
/**
 * @brief Write Diffie-Hellman domain parameters to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x DH parameters to encode.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_DHparams(FILE *fp, const DH *x);
#endif
/**
 * @brief Write Diffie-Hellman X9.42 domain parameters to a BIO in PEM form (deprecated).
 * @param bp BIO to write to.
 * @param x DH parameters to encode (X9.42 / DHxparams form).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_bio_DHxparams(BIO *bp, const DH *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Write Diffie-Hellman X9.42 domain parameters to a FILE in PEM form (deprecated).
 * @param fp FILE to write to.
 * @param x DH parameters to encode (X9.42 / DHxparams form).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int PEM_write_DHxparams(FILE *fp, const DH *x);
#endif
#endif
#endif

/**
 * @brief Read a private key from a PEM-encoded BIO (traditional or PKCS#8).
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM / PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
/**
 * @brief Read a private key from a PEM-encoded BIO with an explicit library context.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM / PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a private key from a PEM-encoded FILE (traditional or PKCS#8).
 * @param fp FILE to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM / PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
/**
 * @brief Read a private key from a PEM-encoded FILE with an explicit library context.
 * @param fp FILE to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM / PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_PrivateKey_ex(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#endif
/**
 * @brief Write a private key to a BIO as PEM, preferring PKCS#8 EncryptedPrivateKeyInfo.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase bytes; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PrivateKey(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
/**
 * @brief Write a private key to a BIO as PEM with an explicit library context.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase bytes; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed encoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PrivateKey_ex(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Write a private key to a FILE as PEM, preferring PKCS#8 EncryptedPrivateKeyInfo.
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase bytes; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PrivateKey(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
/**
 * @brief Write a private key to a FILE as PEM with an explicit library context.
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase bytes; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed encoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PrivateKey_ex(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#endif

/**
 * @brief Read a SubjectPublicKeyInfo public key from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
/**
 * @brief Read a SubjectPublicKeyInfo public key from a PEM BIO with a library context.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_PUBKEY_ex(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a SubjectPublicKeyInfo public key from a PEM-encoded FILE.
 * @param fp FILE to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
/**
 * @brief Read a SubjectPublicKeyInfo public key from a PEM FILE with a library context.
 * @param fp FILE to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for provider-backed decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_PUBKEY_ex(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
#endif
/**
 * @brief Write a SubjectPublicKeyInfo public key to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Public key to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PUBKEY(BIO *bp, const EVP_PKEY *x);
/**
 * @brief Write a SubjectPublicKeyInfo public key to a BIO with a library context.
 * @param bp BIO to write to.
 * @param x Public key to encode.
 * @param libctx Library context used for provider-backed encoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PUBKEY_ex(BIO *bp, const EVP_PKEY *x, OSSL_LIB_CTX *libctx, const char *propq);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Write a SubjectPublicKeyInfo public key to a FILE in PEM form.
 * @param fp FILE to write to.
 * @param x Public key to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PUBKEY(FILE *fp, const EVP_PKEY *x);
/**
 * @brief Write a SubjectPublicKeyInfo public key to a FILE with a library context.
 * @param fp FILE to write to.
 * @param x Public key to encode.
 * @param libctx Library context used for provider-backed encoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PUBKEY_ex(FILE *fp, const EVP_PKEY *x, OSSL_LIB_CTX *libctx, const char *propq);
#endif

/**
 * @brief Write a private key to a BIO using the legacy "traditional" PEM private-key format.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param enc Optional cipher for traditional PEM encryption, or NULL for cleartext.
 * @param kstr Optional passphrase bytes; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer PEM_write_bio_PrivateKey() / PKCS#8 for new keys; this exists for legacy compatibility.
 */
int PEM_write_bio_PrivateKey_traditional(BIO *bp, const EVP_PKEY *x,
    const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);

/* Why do these take a signed char *kstr? */
/**
 * @brief Write a private key as PEM PKCS#8 using a PKCS#5 v1.5 / PKCS#12 PBE NID.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param nid NID of the PBE algorithm OBJECT IDENTIFIER.
 * @param kstr Optional passphrase; if NULL, @p cb is used when encryption requires one.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, const EVP_PKEY *x, int nid,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a private key as PEM PKCS#8 EncryptedPrivateKeyInfo (PKCS#5 v2.0).
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param enc Cipher used at the PKCS#8 level, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS8PrivateKey(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode a private key as DER PKCS#8 and write it to a BIO.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS8PrivateKey_bio(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode a private key as DER PKCS#8 using a PKCS#5 v1.5 / PKCS#12 PBE NID.
 * @param bp BIO to write to.
 * @param x Private key to encode.
 * @param nid NID of the PBE algorithm OBJECT IDENTIFIER.
 * @param kstr Optional passphrase; if NULL, @p cb is used when encryption requires one.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, const EVP_PKEY *x, int nid,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Decode a DER PKCS#8 private key (encrypted or plain) from a BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
    void *u);

#ifndef OPENSSL_NO_STDIO
/**
 * @brief Encode a private key as DER PKCS#8 and write it to a FILE.
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param enc Cipher for PKCS#8 encryption, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase; if NULL and @p enc is set, @p cb is used.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS8PrivateKey_fp(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode a private key as DER PKCS#8 using a PKCS#5 v1.5 / PKCS#12 PBE NID.
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param nid NID of the PBE algorithm OBJECT IDENTIFIER.
 * @param kstr Optional passphrase; if NULL, @p cb is used when encryption requires one.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, const EVP_PKEY *x, int nid,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);
/**
 * @brief Write a private key as PEM PKCS#8 using a PKCS#5 v1.5 / PKCS#12 PBE NID.
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param nid NID of the PBE algorithm OBJECT IDENTIFIER.
 * @param kstr Optional passphrase; if NULL, @p cb is used when encryption requires one.
 * @param klen Length of @p kstr when provided.
 * @param cb Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, const EVP_PKEY *x, int nid,
    const char *kstr, int klen,
    pem_password_cb *cb, void *u);

/**
 * @brief Decode a DER PKCS#8 private key (encrypted or plain) from a FILE.
 * @param fp FILE to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PKCS#8, or NULL.
 * @param u Application data passed to @p cb.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
    void *u);

/**
 * @brief Write a private key as PEM PKCS#8 EncryptedPrivateKeyInfo (PKCS#5 v2.0).
 * @param fp FILE to write to.
 * @param x Private key to encode.
 * @param enc Cipher used at the PKCS#8 level, or NULL for unencrypted PrivateKeyInfo.
 * @param kstr Optional passphrase; if NULL and @p enc is set, @p cd is used.
 * @param klen Length of @p kstr when provided.
 * @param cd Password callback when a passphrase is needed, or NULL.
 * @param u Application data passed to @p cd.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_PKCS8PrivateKey(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
    const char *kstr, int klen,
    pem_password_cb *cd, void *u);
#endif
/**
 * @brief Read algorithm parameters (e.g. DH/DSA) from PEM into an EVP_PKEY with a library context.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @param libctx Library context used for provider-backed decoding, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Parameter EVP_PKEY on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_Parameters_ex(BIO *bp, EVP_PKEY **x,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Read algorithm parameters (e.g. DH/DSA) from PEM into an EVP_PKEY.
 * @param bp BIO to read from.
 * @param x Optional address of an EVP_PKEY pointer to reuse, or NULL.
 * @return Parameter EVP_PKEY on success, or NULL on failure.
 */
EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
/**
 * @brief Write algorithm parameters from an EVP_PKEY to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Key whose parameters are encoded (encoding depends on the key type).
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_Parameters(BIO *bp, const EVP_PKEY *x);

/**
 * @brief Decode a Microsoft MSBLOB private key from a memory buffer.
 * @param in Address of a pointer to the input bytes; advanced past the decoded key.
 * @param length Number of bytes available at *@p in.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
/**
 * @brief Decode a Microsoft MSBLOB public key from a memory buffer.
 * @param in Address of a pointer to the input bytes; advanced past the decoded key.
 * @param length Number of bytes available at *@p in.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
/**
 * @brief Decode a Microsoft MSBLOB private key from a BIO.
 * @param in BIO to read from.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
/**
 * @brief Decode a Microsoft MSBLOB public key from a BIO.
 * @param in BIO to read from.
 * @return Public key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
/**
 * @brief Encode a private key in Microsoft MSBLOB format and write it to a BIO.
 * @param out BIO to write to.
 * @param pk Private key to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2b_PrivateKey_bio(BIO *out, const EVP_PKEY *pk);
/**
 * @brief Encode a public key in Microsoft MSBLOB format and write it to a BIO.
 * @param out BIO to write to.
 * @param pk Public key to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2b_PublicKey_bio(BIO *out, const EVP_PKEY *pk);
/**
 * @brief Decode a Microsoft PVK private key from a BIO.
 * @param in BIO to read from.
 * @param cb Password callback if the PVK is encrypted, or NULL.
 * @param u Application data passed to @p cb.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
/**
 * @brief Decode a Microsoft PVK private key from a BIO with a library context.
 * @param in BIO to read from.
 * @param cb Password callback if the PVK is encrypted, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context used for any decrypt operation, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Private key on success, or NULL on failure.
 */
EVP_PKEY *b2i_PVK_bio_ex(BIO *in, pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Encode a private key in Microsoft PVK format and write it to a BIO.
 * @param out BIO to write to.
 * @param pk Private key to encode.
 * @param enclevel 0 for unencrypted PVK, or 1 to encrypt with a passphrase from @p cb.
 * @param cb Password callback used when @p enclevel is nonzero, or NULL.
 * @param u Application data passed to @p cb.
 * @return Number of bytes written, or a negative value on error.
 */
int i2b_PVK_bio(BIO *out, const EVP_PKEY *pk, int enclevel,
    pem_password_cb *cb, void *u);
/**
 * @brief Encode a private key in Microsoft PVK format using an explicit library context.
 * @param out BIO to write to.
 * @param pk Private key to encode.
 * @param enclevel 0 for unencrypted PVK, or 1 to encrypt with a passphrase from @p cb.
 * @param cb Password callback used when @p enclevel is nonzero, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context for any cryptographic operations, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Number of bytes written, or a negative value on error.
 */
int i2b_PVK_bio_ex(BIO *out, const EVP_PKEY *pk, int enclevel,
    pem_password_cb *cb, void *u,
    OSSL_LIB_CTX *libctx, const char *propq);

#ifdef __cplusplus
}
#endif
#endif
