#!/usr/bin/env python3
"""Documentation repair batch 10c: objects, pkcs7, rsa, ssl, x509*."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


def patch_both(rel, old, new, label):
    paths = [INC / rel]
    if not rel.endswith(".in"):
        paths.append(INC / (rel + ".in"))
    found = False
    for path in paths:
        if not path.exists():
            continue
        found = True
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"  MISS: {path.name} :: {label}")
            missing.append(f"{path.name}:{label}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    if not found:
        missing.append(f"{rel}:{label}:no-file")


def asn1_funcs(typename, brief):
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {typename}, or NULL on allocation failure.
 */
{typename} *{typename}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {typename}_free({typename} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {typename}, or NULL on error.
 */
{typename} *d2i_{typename}({typename} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{typename}(const {typename} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {typename}.
 * @return Pointer to the static ASN1_ITEM for {typename}.
 */
const ASN1_ITEM *{typename}_it(void);"""


# ----- objects.h -----
patch_both(
    "objects.h",
    "int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);",
    """/**
 * @brief Format an ASN1_OBJECT as text (dotted OID and/or registered name).
 * @param buf Destination buffer for the NUL-terminated text, or NULL to measure length only.
 * @param buf_len Capacity of @p buf in bytes when non-NULL.
 * @param a Object identifier to render.
 * @param no_name When non-zero, always emit numeric OID form; when zero, prefer a known name.
 * @return Length of the text (excluding NUL) that was or would be written, or -1 on error.
 */
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);""",
    "OBJ_obj2txt",
)

# ----- pkcs7.h fields + functions -----
patch_both(
    "pkcs7.h",
    """    ASN1_INTEGER *version; /* version 1 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;""",
    """    ASN1_INTEGER *version; /* version 1 */
    /** Issuer name and serial number identifying the signing certificate. */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;""",
    "issuer_and_serial",
)

patch_both(
    "pkcs7.h",
    """    STACK_OF(X509_CRL) *crl; /**< Certificate revocation lists included with the signed-and-enveloped data ([1]). */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    /** Encrypted content info for SignedAndEnvelopedData. */""",
    """    STACK_OF(X509_CRL) *crl; /**< Certificate revocation lists included with the signed-and-enveloped data ([1]). */
    /** Signer infos for SignedAndEnvelopedData. */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    /** Encrypted content info for SignedAndEnvelopedData. */""",
    "signer_info",
)

patch_both(
    "pkcs7.h",
    """#define PKCS7_S_TAIL 2
    int state; /* used during processing */
    /** Non-zero when the PKCS#7 content is detached from the signedData structure. */""",
    """#define PKCS7_S_TAIL 2
    /** Streaming parse/write state (PKCS7_S_HEADER, PKCS7_S_BODY, or PKCS7_S_TAIL). */
    int state; /* used during processing */
    /** Non-zero when the PKCS#7 content is detached from the signedData structure. */""",
    "state",
)

patch_both(
    "pkcs7.h",
    """        /* NID_pkcs7_enveloped */
        PKCS7_ENVELOPE *enveloped;
        /* NID_pkcs7_signedAndEnveloped */""",
    """        /* NID_pkcs7_enveloped */
        /** EnvelopedData content when type is NID_pkcs7_enveloped. */
        PKCS7_ENVELOPE *enveloped;
        /* NID_pkcs7_signedAndEnveloped */""",
    "enveloped",
)

patch_both(
    "pkcs7.h",
    """        ASN1_TYPE *other;
    } d;
    PKCS7_CTX ctx;
} PKCS7;""",
    """        ASN1_TYPE *other;
    } d;
    /** Library/provider context associated with this PKCS#7 object. */
    PKCS7_CTX ctx;
} PKCS7;""",
    "PKCS7.ctx",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_FUNCTIONS(PKCS7_SIGNER_INFO)",
    asn1_funcs("PKCS7_SIGNER_INFO", "PKCS#7 SignerInfo") + "\n",
    "PKCS7_SIGNER_INFO ASN.1",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_FUNCTIONS(PKCS7_ENC_CONTENT)",
    asn1_funcs("PKCS7_ENC_CONTENT", "PKCS#7 EncryptedContentInfo") + "\n",
    "PKCS7_ENC_CONTENT ASN.1",
)

patch_both(
    "pkcs7.h",
    "int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);",
    """/**
 * @brief Set the inner content of a SignedData / DigestedData PKCS#7 to @p p7_data.
 * @param p7 Outer PKCS#7 whose content type supports nested content.
 * @param p7_data Inner PKCS#7 content object; ownership is transferred on success.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);""",
    "PKCS7_set_content",
)

patch_both(
    "pkcs7.h",
    "X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);",
    """/**
 * @brief Find the certificate in @p p7 that matches a signer info's issuer and serial.
 * @param p7 PKCS#7 object whose certificate set is searched.
 * @param si Signer info whose issuerAndSerialNumber is matched.
 * @return Matching X509 from @p p7 (do not free), or NULL if none is present.
 */
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);""",
    "PKCS7_cert_from_signer_info",
)

patch_both(
    "pkcs7.h",
    """PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7,
    X509 *signcert, EVP_PKEY *pkey,
    const EVP_MD *md, int flags);""",
    """/**
 * @brief Add a signer to an existing SignedData PKCS#7 created for incremental signing.
 * @param p7 PKCS#7 SignedData object previously prepared for signing.
 * @param signcert Certificate corresponding to @p pkey.
 * @param pkey Private key used to sign.
 * @param md Message digest algorithm, or NULL to use the key's default.
 * @param flags PKCS7_* signing flags (for example PKCS7_REUSE_DIGEST or PKCS7_PARTIAL).
 * @return New signer info on success, or NULL on failure.
 */
PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7,
    X509 *signcert, EVP_PKEY *pkey,
    const EVP_MD *md, int flags);""",
    "PKCS7_sign_add_signer",
)

# ----- rsa.h -----
patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen);",
    """/**
 * @brief Set the RSA-PSS salt length used when generating an RSA-PSS key.
 * @param ctx Keygen context for an RSA-PSS key type.
 * @param saltlen Salt length in bytes, or a special value such as RSA_PSS_SALTLEN_DIGEST.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen);""",
    "EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen",
)

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname);""",
    """/**
 * @brief Set the MGF1 digest name used when generating an RSA-PSS key.
 * @param ctx Keygen context for an RSA-PSS key type.
 * @param mdname Digest name such as "SHA256".
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname);""",
    "EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name",
)

patch_both(
    "rsa.h",
    "OSSL_DEPRECATEDIN_3_0 int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);",
    """/**
 * @brief Bind an RSA_METHOD implementation to an RSA key object (deprecated).
 * @param rsa RSA key to update.
 * @param meth Method table that will handle operations on @p rsa.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);""",
    "RSA_set_method",
)

patch_both(
    "rsa.h",
    """struct rsa_oaep_params_st {
    X509_ALGOR *hashFunc;
    X509_ALGOR *maskGenFunc;
    X509_ALGOR *pSourceFunc;""",
    """struct rsa_oaep_params_st {
    X509_ALGOR *hashFunc;
    X509_ALGOR *maskGenFunc;
    /** AlgorithmIdentifier for the OAEP P-source function (typically pSpecified). */
    X509_ALGOR *pSourceFunc;""",
    "pSourceFunc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_verify_ASN1_OCTET_STRING(int type,
    const unsigned char *m, unsigned int m_length,
    unsigned char *sigbuf, unsigned int siglen,
    RSA *rsa);""",
    """/**
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
    RSA *rsa);""",
    "RSA_verify_ASN1_OCTET_STRING",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_sign(RSA_METHOD *rsa,
    int (*sign)(int type, const unsigned char *m,
        unsigned int m_length,
        unsigned char *sigret, unsigned int *siglen,
        const RSA *rsa));""",
    """/**
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
        const RSA *rsa));""",
    "RSA_meth_set_sign",
)

# ----- ssl.h -----
patch_both(
    "ssl.h",
    """void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb)(SSL *ssl,
        const unsigned char *cookie,
        size_t cookie_len));""",
    """/**
 * @brief Set the callback that verifies a TLS 1.3 stateless HelloRetryRequest cookie.
 * @param ctx Server SSL_CTX that will validate cookies.
 * @param verify_stateless_cookie_cb Callback returning 1 if @p cookie is valid for @p ssl.
 */
void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb)(SSL *ssl,
        const unsigned char *cookie,
        size_t cookie_len));""",
    "SSL_CTX_set_stateless_cookie_verify_cb",
)

patch_both(
    "ssl.h",
    "void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb);",
    """/**
 * @brief Set the client PSK identity/key callback used by connections from @p ctx.
 * @param ctx Client SSL_CTX that will use PSK authentication.
 * @param cb Callback that supplies the PSK identity and key, or NULL to clear.
 */
void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb);""",
    "SSL_CTX_set_psk_client_callback",
)

patch_both(
    "ssl.h",
    "__owur long SSL_CTX_get_timeout(const SSL_CTX *ctx);",
    """/**
 * @brief Return the default session lifetime configured on @p ctx.
 * @param ctx SSL_CTX to query.
 * @return Session timeout in seconds.
 */
__owur long SSL_CTX_get_timeout(const SSL_CTX *ctx);""",
    "SSL_CTX_get_timeout",
)

patch_both(
    "ssl.h",
    "__owur int SSL_use_certificate_chain_file(SSL *ssl, const char *file);",
    """/**
 * @brief Load a PEM certificate chain from @p file into @p ssl.
 * @param ssl SSL object that receives the end-entity certificate and intermediates.
 * @param file Path to a PEM file containing the leaf certificate followed by optional CA certs.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_use_certificate_chain_file(SSL *ssl, const char *file);""",
    "SSL_use_certificate_chain_file",
)

patch_both(
    "ssl.h",
    """int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
    const char *dir);""",
    """/**
 * @brief Append subject names from every certificate file in @p dir to @p stackCAs.
 * @param stackCAs Destination stack of X509_NAME values (typically CA subjects).
 * @param dir Directory whose certificate files are scanned.
 * @return 1 on success, or 0 on failure.
 */
int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
    const char *dir);""",
    "SSL_add_dir_cert_subjects_to_stack",
)

patch_both(
    "ssl.h",
    """SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
    long length);""",
    """/**
 * @brief Decode an SSL_SESSION from its ASN.1 DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded value.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded SSL_SESSION, or NULL on error; free with SSL_SESSION_free().
 */
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
    long length);""",
    "d2i_SSL_SESSION",
)

patch_both(
    "ssl.h",
    "__owur SSL_SESSION *SSL_get1_session(SSL *ssl); /* obtain a reference count */",
    """/**
 * @brief Return the current SSL_SESSION for @p ssl with an incremented reference count.
 * @param ssl SSL connection to query.
 * @return SSL_SESSION (caller must SSL_SESSION_free()), or NULL if none is available.
 */
__owur SSL_SESSION *SSL_get1_session(SSL *ssl); /* obtain a reference count */""",
    "SSL_get1_session",
)

patch_both(
    "ssl.h",
    "__owur int SSL_get_stream_type(SSL *s);",
    """/**
 * @brief Return the QUIC stream type of an SSL connection or stream object.
 * @param s SSL object representing a QUIC connection or stream.
 * @return SSL_STREAM_TYPE_* constant describing bidirectional/uni/none behaviour.
 */
__owur int SSL_get_stream_type(SSL *s);""",
    "SSL_get_stream_type",
)

# ----- x509.h types / fields -----
patch_both(
    "x509.h",
    """typedef struct X509_val_st {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
} X509_VAL;""",
    """/**
 * @brief Validity period (notBefore / notAfter) used inside X.509 certificates and CRLs.
 */
typedef struct X509_val_st {
    /** Time at which the certificate or CRL becomes valid. */
    ASN1_TIME *notBefore;
    /** Time after which the certificate or CRL is no longer valid. */
    ASN1_TIME *notAfter;
} X509_VAL;""",
    "X509_VAL",
)

patch_both(
    "x509.h",
    "typedef struct x509_attributes_st X509_ATTRIBUTE;",
    """/**
 * @brief Opaque X.509 Attribute (AttributeTypeAndValue sequence) used in CSRs and PKCS#12.
 */
typedef struct x509_attributes_st X509_ATTRIBUTE;""",
    "X509_ATTRIBUTE",
)

patch_both(
    "x509.h",
    """typedef struct X509_req_info_st X509_REQ_INFO;
typedef struct X509_req_st X509_REQ;""",
    """/**
 * @brief Opaque TBSCertificateRequest / certification request info inside an X509_REQ.
 */
typedef struct X509_req_info_st X509_REQ_INFO;
/**
 * @brief Opaque PKCS#10 certification request (CertificateRequest).
 */
typedef struct X509_req_st X509_REQ;""",
    "X509_REQ_INFO/REQ",
)

patch_both(
    "x509.h",
    "typedef struct x509_cinf_st X509_CINF;",
    """/**
 * @brief Opaque TBSCertificate structure holding the unsigned certificate fields.
 */
typedef struct x509_cinf_st X509_CINF;""",
    "X509_CINF",
)

patch_both(
    "x509.h",
    """typedef struct private_key_st {
    int version;""",
    """typedef struct private_key_st {
    /** PKCS#8 version number for the encrypted private key container. */
    int version;""",
    "X509_PKEY.version",
)

patch_both(
    "x509.h",
    """    char *key_data;
    int key_free; /* true if we should auto free key_data */
    /* expanded version of 'enc_algor' */
    EVP_CIPHER_INFO cipher;
} X509_PKEY;

typedef struct X509_info_st {
    X509 *x509;
    X509_CRL *crl;""",
    """    char *key_data;
    /** Non-zero when @c key_data was allocated and should be freed with the structure. */
    int key_free; /* true if we should auto free key_data */
    /* expanded version of 'enc_algor' */
    /** Symmetric cipher parameters used to encrypt/decrypt @c key_data. */
    EVP_CIPHER_INFO cipher;
} X509_PKEY;

/**
 * @brief Bundle of certificate, CRL, and/or encrypted private key as found in PEM info files.
 */
typedef struct X509_info_st {
    /** Certificate contained in this info entry, or NULL. */
    X509 *x509;
    /** CRL contained in this info entry, or NULL. */
    X509_CRL *crl;""",
    "X509_INFO + fields",
)

patch_both(
    "x509.h",
    """    EVP_CIPHER_INFO enc_cipher;
    int enc_len;
    char *enc_data;
} X509_INFO;""",
    """    EVP_CIPHER_INFO enc_cipher;
    int enc_len;
    /** Encrypted private-key bytes of length @c enc_len, or NULL. */
    char *enc_data;
} X509_INFO;""",
    "enc_data",
)

patch_both(
    "x509.h",
    """/*
 * The next 2 structures and their 8 routines are used to manipulate Netscape's
 * spki structures - useful if you are writing a CA web page
 */
typedef struct Netscape_spkac_st {
    /** Public key offered in the Netscape SPKAC challenge response. */
    X509_PUBKEY *pubkey;
    ASN1_IA5STRING *challenge; /* challenge sent in atlas >= PR2 */
} NETSCAPE_SPKAC;

typedef struct Netscape_spki_st {
    /** Signed public key and challenge (SPKAC) payload wrapped by this SPKI. */
    NETSCAPE_SPKAC *spkac; /* signed public key and challenge */
    X509_ALGOR sig_algor;
    /** BIT STRING signature over @c spkac under @c sig_algor. */
    ASN1_BIT_STRING *signature;
} NETSCAPE_SPKI;""",
    """/**
 * @brief Netscape Signed Public Key And Challenge (SPKAC) request body.
 *
 * Used with CA web enrollment flows that present a public key and challenge string.
 */
typedef struct Netscape_spkac_st {
    /** Public key offered in the Netscape SPKAC challenge response. */
    X509_PUBKEY *pubkey;
    /** Challenge string from the CA enrollment form (IA5String). */
    ASN1_IA5STRING *challenge; /* challenge sent in atlas >= PR2 */
} NETSCAPE_SPKAC;

/**
 * @brief Netscape SPKI: an SPKAC plus the signature algorithm and signature bits.
 */
typedef struct Netscape_spki_st {
    /** Signed public key and challenge (SPKAC) payload wrapped by this SPKI. */
    NETSCAPE_SPKAC *spkac; /* signed public key and challenge */
    /** Signature AlgorithmIdentifier covering @c spkac. */
    X509_ALGOR sig_algor;
    /** BIT STRING signature over @c spkac under @c sig_algor. */
    ASN1_BIT_STRING *signature;
} NETSCAPE_SPKI;""",
    "NETSCAPE_SPKAC/SPKI",
)

# ----- x509.h functions -----
patch_both(
    "x509.h",
    "EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);",
    """/**
 * @brief Extract the public key from a Netscape SPKI structure.
 * @param x SPKI object whose SPKAC contains the public key.
 * @return Newly allocated EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);""",
    "NETSCAPE_SPKI_get_pubkey",
)

patch_both(
    "x509.h",
    "int i2d_X509_fp(FILE *fp, const X509 *x509);",
    """/**
 * @brief Write an X.509 certificate to a FILE in DER form.
 * @param fp Output FILE opened for writing.
 * @param x509 Certificate to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_X509_fp(FILE *fp, const X509 *x509);""",
    "i2d_X509_fp",
)

patch_both(
    "x509.h",
    "OSSL_DEPRECATEDIN_3_0 int i2d_RSA_PUBKEY_fp(FILE *fp, const RSA *rsa);",
    """/**
 * @brief Write an RSA public key to a FILE as a SubjectPublicKeyInfo DER blob (deprecated).
 * @param fp Output FILE opened for writing.
 * @param rsa RSA key whose public components are encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSA_PUBKEY_fp(FILE *fp, const RSA *rsa);""",
    "i2d_RSA_PUBKEY_fp",
)

patch_both(
    "x509.h",
    "EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);",
    """/**
 * @brief Read a private key in traditional or PKCS#8 DER form from a FILE.
 * @param fp Input FILE positioned at the DER private key.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);""",
    "d2i_PrivateKey_fp",
)

patch_both(
    "x509.h",
    """EVP_PKEY *d2i_PrivateKey_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    """/**
 * @brief Read a private key from a BIO with an explicit library context and property query.
 * @param bp BIO supplying traditional or PKCS#8 DER private-key bytes.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PrivateKey_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    "d2i_PrivateKey_ex_bio",
)

patch_both(
    "x509.h",
    """EVP_PKEY *d2i_PUBKEY_ex(EVP_PKEY **a, const unsigned char **pp, long length,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    """/**
 * @brief Decode a SubjectPublicKeyInfo from DER with an explicit library context.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded value.
 * @param length Number of bytes available at *@p pp.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PUBKEY_ex(EVP_PKEY **a, const unsigned char **pp, long length,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    "d2i_PUBKEY_ex",
)

patch_both(
    "x509.h",
    "DECLARE_ASN1_FUNCTIONS(X509_EXTENSION)",
    asn1_funcs("X509_EXTENSION", "X.509 extension") + "\n",
    "X509_EXTENSION ASN.1",
)

patch_both(
    "x509.h",
    """int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    EVP_PKEY *pkey);""",
    """/**
 * @brief Verify @p signature over the ASN.1 encoding of @p data described by @p it.
 * @param it ASN.1 item describing the signed structure type of @p data.
 * @param alg Signature AlgorithmIdentifier.
 * @param signature BIT STRING signature value.
 * @param data Pointer to the structure instance to re-encode and verify.
 * @param pkey Public key used for verification.
 * @return 1 if the signature is valid, or 0 / a negative value on failure.
 */
int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    EVP_PKEY *pkey);""",
    "ASN1_item_verify",
)

patch_both(
    "x509.h",
    "ASN1_TIME *X509_getm_notAfter(const X509 *x);",
    """/**
 * @brief Return a mutable pointer to the certificate's notAfter validity time.
 * @param x Certificate to query.
 * @return Internal ASN1_TIME pointer (do not free); modifications update @p x.
 */
ASN1_TIME *X509_getm_notAfter(const X509 *x);""",
    "X509_getm_notAfter",
)

patch_both(
    "x509.h",
    """int X509_print_ex_fp(FILE *bp, X509 *x, unsigned long nmflag,
    unsigned long cflag);""",
    """/**
 * @brief Print an X.509 certificate to a FILE with name and content flags.
 * @param bp Output FILE.
 * @param x Certificate to print.
 * @param nmflag XN_FLAG_* flags controlling X509_NAME formatting.
 * @param cflag X509_FLAG_* flags selecting which certificate fields are shown.
 * @return 1 on success, or 0 on failure.
 */
int X509_print_ex_fp(FILE *bp, X509 *x, unsigned long nmflag,
    unsigned long cflag);""",
    "X509_print_ex_fp",
)

patch_both(
    "x509.h",
    """X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
    const char *field, int type,
    const unsigned char *bytes,
    int len);""",
    """/**
 * @brief Create an X509_NAME_ENTRY from a textual attribute name and value bytes.
 * @param ne Optional destination pointer updated to the result, or NULL.
 * @param field Attribute name such as "CN" or "emailAddress".
 * @param type ASN.1 string type for the value (for example MBSTRING_ASC).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 if @p bytes is NUL-terminated.
 * @return New or updated X509_NAME_ENTRY, or NULL on error.
 */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
    const char *field, int type,
    const unsigned char *bytes,
    int len);""",
    "X509_NAME_ENTRY_create_by_txt",
)

patch_both(
    "x509.h",
    """X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
    int type,
    const unsigned char *bytes,
    int len);""",
    """/**
 * @brief Create an X509_NAME_ENTRY from an attribute NID and value bytes.
 * @param ne Optional destination pointer updated to the result, or NULL.
 * @param nid Attribute type NID such as NID_commonName.
 * @param type ASN.1 string type for the value (for example MBSTRING_ASC).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 if @p bytes is NUL-terminated.
 * @return New or updated X509_NAME_ENTRY, or NULL on error.
 */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
    int type,
    const unsigned char *bytes,
    int len);""",
    "X509_NAME_ENTRY_create_by_NID",
)

patch_both(
    "x509.h",
    """int X509_NAME_get0_der(const X509_NAME *nm, const unsigned char **pder,
    size_t *pderlen);""",
    """/**
 * @brief Return a pointer to the cached DER encoding of an X509_NAME.
 * @param nm Name whose encoding is requested.
 * @param pder Receives a pointer to the internal DER bytes (do not free).
 * @param pderlen Receives the DER length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_get0_der(const X509_NAME *nm, const unsigned char **pder,
    size_t *pderlen);""",
    "X509_NAME_get0_der",
)

patch_both(
    "x509.h",
    """int X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
    const ASN1_OBJECT *obj, int lastpos);""",
    """/**
 * @brief Find the next extension in @p x whose OID matches @p obj.
 * @param x Stack of extensions to search.
 * @param obj Extension OID to match.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Index of the matching extension, or -1 if not found.
 */
int X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
    const ASN1_OBJECT *obj, int lastpos);""",
    "X509v3_get_ext_by_OBJ",
)

patch_both(
    "x509.h",
    """void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atrtype,
    void *data);""",
    """/**
 * @brief Return the typed value pointer for attribute entry @p idx.
 * @param attr Attribute whose values are queried.
 * @param idx Zero-based index into the attribute's value set.
 * @param atrtype Expected ASN.1 type tag for the value.
 * @param data Unused; pass NULL (historical API placeholder).
 * @return Pointer to the value object, or NULL on type/index mismatch.
 */
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atrtype,
    void *data);""",
    "X509_ATTRIBUTE_get0_data",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
    const unsigned char *salt, int saltlen);""",
    """/**
 * @brief Build an AlgorithmIdentifier for PKCS#5 PBE with @p alg, @p iter, and @p salt.
 * @param alg PBE algorithm NID.
 * @param iter Iteration count.
 * @param salt Salt bytes, or NULL to generate a random salt of @p saltlen.
 * @param saltlen Salt length in bytes.
 * @return New X509_ALGOR, or NULL on error; free with X509_ALGOR_free().
 */
X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
    const unsigned char *salt, int saltlen);""",
    "PKCS5_pbe_set",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbe_set_ex(int alg, int iter,
    const unsigned char *salt, int saltlen,
    OSSL_LIB_CTX *libctx);""",
    """/**
 * @brief Build a PKCS#5 PBE AlgorithmIdentifier using an explicit library context.
 * @param alg PBE algorithm NID.
 * @param iter Iteration count.
 * @param salt Salt bytes, or NULL to generate a random salt of @p saltlen.
 * @param saltlen Salt length in bytes.
 * @param libctx Library context used when generating a random salt, or NULL for the default.
 * @return New X509_ALGOR, or NULL on error; free with X509_ALGOR_free().
 */
X509_ALGOR *PKCS5_pbe_set_ex(int alg, int iter,
    const unsigned char *salt, int saltlen,
    OSSL_LIB_CTX *libctx);""",
    "PKCS5_pbe_set_ex",
)

patch_both(
    "x509.h",
    """int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
    const unsigned char **pk, int *ppklen,
    X509_ALGOR **pa, const X509_PUBKEY *pub);""",
    """/**
 * @brief Return pointers to the algorithm and bit-string components of a SubjectPublicKeyInfo.
 * @param ppkalg Optional destination for the public-key algorithm OID, or NULL.
 * @param pk Optional destination for the raw public-key bit string bytes, or NULL.
 * @param ppklen Optional destination for the length of *@p pk, or NULL.
 * @param pa Optional destination for the full AlgorithmIdentifier, or NULL.
 * @param pub Public key structure to query.
 * @return 1 on success, or 0 on failure.
 *
 * Returned pointers refer to internal data and must not be freed by the caller.
 */
int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
    const unsigned char **pk, int *ppklen,
    X509_ALGOR **pa, const X509_PUBKEY *pub);""",
    "X509_PUBKEY_get0_param",
)

# ----- x509_vfy.h -----
patch_both(
    "x509_vfy.h",
    """    int (*check_trust)(struct x509_trust_st *, X509 *, int);
    char *name;
    /** @brief Integer argument associated with this trust entry. */""",
    """    int (*check_trust)(struct x509_trust_st *, X509 *, int);
    /** Short name of this trust purpose (for example "SSL Client"). */
    char *name;
    /** @brief Integer argument associated with this trust entry. */""",
    "X509_TRUST.name",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *xs,
    const X509_NAME *nm);""",
    """/**
 * @brief Return certificates from the store whose subject name matches @p nm.
 * @param xs Verification / lookup context whose store is queried.
 * @param nm Subject name to match.
 * @return New stack of matching certificates (refcount +1 each), or NULL; free with sk_X509_pop_free().
 */
STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *xs,
    const X509_NAME *nm);""",
    "X509_STORE_CTX_get1_certs",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *trust_store,
    X509 *target, STACK_OF(X509) *untrusted);""",
    """/**
 * @brief Initialize a verification context for validating @p target against @p trust_store.
 * @param ctx Store context to initialize (must already be allocated).
 * @param trust_store Trusted certificate store, or NULL.
 * @param target End-entity certificate to verify, or NULL when using raw public keys later.
 * @param untrusted Optional stack of untrusted intermediates, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *trust_store,
    X509 *target, STACK_OF(X509) *untrusted);""",
    "X509_STORE_CTX_init",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
    void (*free_fn)(X509_LOOKUP *ctx));""",
    """/**
 * @brief Set the method callback that frees a lookup context's method-specific state.
 * @param method Lookup method table to update.
 * @param free_fn Callback invoked from X509_LOOKUP_free(), or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
    void (*free_fn)(X509_LOOKUP *ctx));""",
    "X509_LOOKUP_meth_set_free",
)

patch_both(
    "x509_vfy.h",
    """int X509_load_cert_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    """/**
 * @brief Load certificates from @p file into the store behind @p ctx with an explicit libctx.
 * @param ctx Lookup object associated with the destination X509_STORE.
 * @param file Path to a certificate file.
 * @param type File format such as X509_FILETYPE_PEM or X509_FILETYPE_ASN1.
 * @param libctx Library context for decoding, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Number of certificates loaded, or 0 on failure.
 */
int X509_load_cert_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    "X509_load_cert_file_ex",
)

patch_both(
    "x509_vfy.h",
    "X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx);",
    """/**
 * @brief Return the certificate currently being examined during verification.
 * @param ctx Verification context after an error or during a verify callback.
 * @return Current certificate (do not free), or NULL if none is set.
 */
X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx);""",
    "X509_STORE_CTX_get_current_cert",
)

patch_both(
    "x509_vfy.h",
    "void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *target);",
    """/**
 * @brief Set the end-entity certificate that @p ctx will verify.
 * @param ctx Verification context to update.
 * @param target Certificate to validate (not freed by the context).
 */
void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *target);""",
    "X509_STORE_CTX_set_cert",
)

patch_both(
    "x509_vfy.h",
    "void X509_STORE_CTX_set0_rpk(X509_STORE_CTX *ctx, EVP_PKEY *target);",
    """/**
 * @brief Set a raw public key as the verification target, transferring ownership of @p target.
 * @param ctx Verification context to update.
 * @param target Public key to validate in lieu of an end-entity certificate; may be NULL to clear.
 */
void X509_STORE_CTX_set0_rpk(X509_STORE_CTX *ctx, EVP_PKEY *target);""",
    "X509_STORE_CTX_set0_rpk",
)

# ----- x509v3.h -----
patch_both(
    "x509v3.h",
    "BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in, long len);",
    """/**
 * @brief Decode a Basic Constraints extension value from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded BASIC_CONSTRAINTS, or NULL on error.
 */
BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in, long len);""",
    "d2i_BASIC_CONSTRAINTS",
)

patch_both(
    "x509v3.h",
    "int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);",
    """/**
 * @brief Register a NULL-terminated list of custom X.509v3 extension methods.
 * @param extlist Array of X509V3_EXT_METHOD entries ending with a zeroed sentinel.
 * @return 1 on success, or 0 on failure.
 */
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);""",
    "X509V3_EXT_add_list",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  MISSING:", m)
