#!/usr/bin/env python3
"""Documentation repair batch 12c: pkcs7.h + rsa.h."""
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


print("=== batch 12c: pkcs7.h + rsa.h ===")

# ----- pkcs7.h types / fields -----

patch_both(
    "pkcs7.h",
    """typedef struct PKCS7_CTX_st {
    OSSL_LIB_CTX *libctx; /**< Library context used when fetching algorithms for this PKCS#7 object. */
    char *propq;
} PKCS7_CTX;
""",
    """/**
 * @brief Library/provider context carried by PKCS#7 objects when fetching algorithms.
 */
typedef struct PKCS7_CTX_st {
    OSSL_LIB_CTX *libctx; /**< Library context used when fetching algorithms for this PKCS#7 object. */
    /** Property query string for algorithm fetches associated with this PKCS#7 context. */
    char *propq;
} PKCS7_CTX;
""",
    "PKCS7_CTX+propq",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_signer_info_st {
    ASN1_INTEGER *version; /* version 1 */
""",
    """/**
 * @brief PKCS#7 SignerInfo: identity, digest/signature algorithms, attributes, and signature.
 */
typedef struct pkcs7_signer_info_st {
    ASN1_INTEGER *version; /* version 1 */
""",
    "PKCS7_SIGNER_INFO",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_recip_info_st {
    ASN1_INTEGER *version; /* version 0 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *key_enc_algor;
""",
    """/**
 * @brief PKCS#7 RecipientInfo: recipient identity and encrypted content-encryption key.
 */
typedef struct pkcs7_recip_info_st {
    /** CMS/PKCS#7 RecipientInfo version (typically 0). */
    ASN1_INTEGER *version; /* version 0 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    /** Algorithm used to encrypt the content-encryption key for this recipient. */
    X509_ALGOR *key_enc_algor;
""",
    "PKCS7_RECIP_INFO+version+key_enc_algor",
)

patch_both(
    "pkcs7.h",
    """    STACK_OF(X509_CRL) *crl; /**< Certificate revocation lists included with the signed data ([1]). */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    struct pkcs7_st *contents;
} PKCS7_SIGNED;
""",
    """    STACK_OF(X509_CRL) *crl; /**< Certificate revocation lists included with the signed data ([1]). */
    /** Signer infos describing each signature over the SignedData content. */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    struct pkcs7_st *contents;
} PKCS7_SIGNED;
""",
    "signer_info(PKCS7_SIGNED)",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_enc_content_st {
    ASN1_OBJECT *content_type;
""",
    """/**
 * @brief PKCS#7 EncryptedContentInfo: content type, content-encryption algorithm, and ciphertext.
 */
typedef struct pkcs7_enc_content_st {
    /** ASN.1 object identifier of the inner content type being encrypted. */
    ASN1_OBJECT *content_type;
""",
    "pkcs7_enc_content_st+content_type",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_enveloped_st {
    ASN1_INTEGER *version; /* version 0 */
    /** @brief Per-recipient encrypted key infos. */
""",
    """typedef struct pkcs7_enveloped_st {
    /** CMS/PKCS#7 EnvelopedData version (typically 0). */
    ASN1_INTEGER *version; /* version 0 */
    /** @brief Per-recipient encrypted key infos. */
""",
    "version(PKCS7_ENVELOPE)",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_digest_st {
    ASN1_INTEGER *version; /* version 0 */
    X509_ALGOR *md; /* md used */
""",
    """typedef struct pkcs7_digest_st {
    ASN1_INTEGER *version; /* version 0 */
    /** Message-digest AlgorithmIdentifier used for DigestedData. */
    X509_ALGOR *md; /* md used */
""",
    "md(PKCS7_DIGEST)",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_encrypted_st {
    ASN1_INTEGER *version; /* version 0 */
    PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENCRYPT;
""",
    """typedef struct pkcs7_encrypted_st {
    ASN1_INTEGER *version; /* version 0 */
    /** Encrypted content info (algorithm and ciphertext) for EncryptedData. */
    PKCS7_ENC_CONTENT *enc_data;
} PKCS7_ENCRYPT;
""",
    "enc_data(PKCS7_ENCRYPT)",
)

patch_both(
    "pkcs7.h",
    """    /** Non-zero when the PKCS#7 content is detached from the signedData structure. */
    int detached;
    ASN1_OBJECT *type;
""",
    """    /** Non-zero when the PKCS#7 content is detached from the signedData structure. */
    int detached;
    /** ASN.1 object identifier naming the PKCS#7 content type (selects @c d union arm). */
    ASN1_OBJECT *type;
""",
    "type(PKCS7)",
)

patch_both(
    "pkcs7.h",
    """        char *ptr;
        /* NID_pkcs7_data */
        ASN1_OCTET_STRING *data;
""",
    """        char *ptr;
        /* NID_pkcs7_data */
        /** Raw data content when type is NID_pkcs7_data. */
        ASN1_OCTET_STRING *data;
""",
    "data(PKCS7.d)",
)

patch_both(
    "pkcs7.h",
    """        /* NID_pkcs7_encrypted */
        PKCS7_ENCRYPT *encrypted;
""",
    """        /* NID_pkcs7_encrypted */
        /** EncryptedData content when type is NID_pkcs7_encrypted. */
        PKCS7_ENCRYPT *encrypted;
""",
    "encrypted(PKCS7.d)",
)

# ----- pkcs7.h functions -----

patch_both(
    "pkcs7.h",
    """PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7);
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
""",
    """/**
 * @brief Decode a DER-encoded PKCS#7 structure from a BIO.
 * @param bp BIO supplying the DER encoding.
 * @param p7 Optional destination pointer updated to the result, or NULL.
 * @return Decoded PKCS7, or NULL on error.
 */
PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7);
/**
 * @brief Output a PKCS#7 structure in BER format, streaming content from @p in when required.
 * @param out BIO that receives the BER-encoded PKCS#7.
 * @param p7 PKCS#7 object to serialise.
 * @param in Optional content BIO for streaming signed/enveloped data, or NULL.
 * @param flags SMIME_* / PKCS7_* streaming and encoding flags.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
""",
    "d2i_PKCS7_bio+i2d_PKCS7_bio_stream",
)

patch_both(
    "pkcs7.h",
    """PKCS7 *PKCS7_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Allocate an empty PKCS#7 structure with an explicit library context and property query.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return New PKCS7, or NULL on allocation failure; free with PKCS7_free.
 */
PKCS7 *PKCS7_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "PKCS7_new_ex",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_type_is_other(PKCS7 *p7);
int PKCS7_set_type(PKCS7 *p7, int type);
""",
    """/**
 * @brief Return whether a PKCS#7 content type is not one of the standard PKCS#7 content NIDs.
 * @param p7 PKCS#7 object whose content type is examined.
 * @return 1 if the type is "other" (not data/signed/enveloped/signedAndEnveloped/digest/encrypted), or 0 if it matches a standard type.
 */
int PKCS7_type_is_other(PKCS7 *p7);
/**
 * @brief Set the PKCS#7 content type and allocate the corresponding content structure.
 * @param p7 PKCS#7 object to initialise.
 * @param type Content-type NID such as NID_pkcs7_signed or NID_pkcs7_enveloped.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_type(PKCS7 *p7, int type);
""",
    "PKCS7_type_is_other+PKCS7_set_type",
)

patch_both(
    "pkcs7.h",
    """PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
    EVP_PKEY *pkey, const EVP_MD *dgst);
""",
    """/**
 * @brief Create a signer info from @p x509 / @p pkey / @p dgst and add it to signed PKCS#7 @p p7.
 * @param p7 PKCS#7 SignedData (or signed-and-enveloped) object to update.
 * @param x509 Signer certificate identifying the signing key.
 * @param pkey Private key corresponding to @p x509.
 * @param dgst Message digest algorithm used for signing.
 * @return The new PKCS7_SIGNER_INFO on success, or NULL on failure.
 */
PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
    EVP_PKEY *pkey, const EVP_MD *dgst);
""",
    "PKCS7_add_signature",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
""",
    """/**
 * @brief Set the message-digest algorithm on a DigestedData PKCS#7 structure.
 * @param p7 PKCS#7 object of type digestedData.
 * @param md Digest method to record in the DigestedData AlgorithmIdentifier.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
""",
    "PKCS7_set_digest",
)

patch_both(
    "pkcs7.h",
    """void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
    X509_ALGOR **pdig, X509_ALGOR **psig);
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc);
""",
    """/**
 * @brief Return non-owning pointers to a signer info's key and digest/signature algorithms.
 * @param si Signer info to query.
 * @param pk Optional destination for the signing private key pointer, or NULL.
 * @param pdig Optional destination for the digest AlgorithmIdentifier, or NULL.
 * @param psig Optional destination for the signature AlgorithmIdentifier, or NULL.
 */
void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
    X509_ALGOR **pdig, X509_ALGOR **psig);
/**
 * @brief Return a non-owning pointer to a recipient info's key-encryption algorithm.
 * @param ri Recipient info to query.
 * @param penc Destination for the key-encryption AlgorithmIdentifier, or NULL.
 */
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc);
""",
    "PKCS7_SIGNER_INFO_get0_algs+PKCS7_RECIP_INFO_get0_alg",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
""",
    """/**
 * @brief Set the content-encryption cipher on an enveloped or encrypted PKCS#7 structure.
 * @param p7 PKCS#7 EnvelopedData, SignedAndEnvelopedData, or EncryptedData object.
 * @param cipher Symmetric cipher used to encrypt the content (must support ASN.1 parameters).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
""",
    "PKCS7_set_cipher",
)

patch_both(
    "pkcs7.h",
    """ASN1_TYPE *PKCS7_get_attribute(const PKCS7_SIGNER_INFO *si, int nid);
""",
    """/**
 * @brief Return an unauthenticated attribute of type @p nid from a PKCS#7 signer info.
 * @param si Signer info whose unauthenticated attributes are searched.
 * @param nid Attribute type NID to look up.
 * @return Pointer to the attribute value, or NULL if not present.
 */
ASN1_TYPE *PKCS7_get_attribute(const PKCS7_SIGNER_INFO *si, int nid);
""",
    "PKCS7_get_attribute",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,
    STACK_OF(X509_ATTRIBUTE) *sk);
""",
    """/**
 * @brief Replace the unauthenticated attributes on a PKCS#7 signer info.
 * @param p7si Signer info whose unauthenticated attribute set is replaced.
 * @param sk New attribute stack; on success ownership transfers to @p p7si.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,
    STACK_OF(X509_ATTRIBUTE) *sk);
""",
    "PKCS7_set_attributes",
)

patch_both(
    "pkcs7.h",
    """PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
    int flags);
""",
    """/**
 * @brief Create a PKCS#7 envelopedData encrypting @p in for each recipient in @p certs.
 * @param certs Recipient certificates whose public keys encrypt the content-encryption key (RSA keys).
 * @param in BIO supplying the plaintext content.
 * @param cipher Content-encryption cipher (for example triple-DES or AES).
 * @param flags PKCS7_* encryption flags (for example PKCS7_TEXT, PKCS7_BINARY, PKCS7_STREAM).
 * @return New PKCS7 envelopedData object, or NULL on error; free with PKCS7_free.
 */
PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
    int flags);
""",
    "PKCS7_encrypt",
)

patch_both(
    "pkcs7.h",
    """STACK_OF(X509_ALGOR) *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg);
""",
    """/**
 * @brief Return the SMIMECapabilities attribute from a PKCS#7 signer info.
 * @param si Signer info whose authenticated attributes are searched.
 * @return Stack of X509_ALGOR capability descriptors, or NULL if absent; do not free.
 */
STACK_OF(X509_ALGOR) *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
/**
 * @brief Append a simple SMIMECapabilities AlgorithmIdentifier for @p nid to @p sk.
 * @param sk Capability stack receiving the new AlgorithmIdentifier.
 * @param nid Algorithm NID to advertise (cipher or digest).
 * @param arg Optional algorithm parameter (for example key length for RC2), or -1 / 0 when unused.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg);
""",
    "PKCS7_get_smimecap+PKCS7_simple_smimecap",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid);
""",
    """/**
 * @brief Add a PKCS#9 contentType authenticated attribute to a PKCS#7 signer info.
 * @param si Signer info receiving the content-type attribute.
 * @param coid Content-type OID to attach, or NULL to use NID_pkcs7_data.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid);
""",
    "PKCS7_add_attrib_content_type",
)

patch_both(
    "pkcs7.h",
    """PKCS7 *SMIME_read_PKCS7_ex(BIO *bio, BIO **bcont, PKCS7 **p7);
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);

BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7);
""",
    """/**
 * @brief Parse an S/MIME message into a PKCS#7 structure, optionally reusing @p p7.
 * @param bio BIO supplying the S/MIME message.
 * @param bcont Optional destination for a memory BIO holding cleartext signed content, or NULL.
 * @param p7 Optional pre-allocated PKCS7 from PKCS7_new_ex(), or NULL to allocate a new one.
 * @return Parsed PKCS7, or NULL on error; free with PKCS7_free.
 */
PKCS7 *SMIME_read_PKCS7_ex(BIO *bio, BIO **bcont, PKCS7 **p7);
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);

/**
 * @brief Create a filter BIO that finalises and writes streaming PKCS#7 ASN.1 to @p out.
 * @param out Downstream BIO that receives the encoded PKCS#7.
 * @param p7 Partial PKCS#7 structure created with PKCS7_STREAM (or similar streaming flags).
 * @return New BIO filter, or NULL on error; free with BIO_free.
 */
BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7);
""",
    "SMIME_read_PKCS7_ex+BIO_new_PKCS7",
)

# ----- rsa.h -----

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode);
""",
    """/**
 * @brief Get the RSA padding mode configured on an EVP_PKEY_CTX.
 * @param ctx Context used for RSA encrypt, decrypt, sign, or verify.
 * @param pad_mode Receives the padding mode (for example RSA_PKCS1_PADDING).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode);
""",
    "EVP_PKEY_CTX_get_rsa_padding",
)

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
""",
    """/**
 * @brief Set the RSA public exponent for key generation, copying @p pubexp.
 * @param ctx Keygen context for an RSA algorithm.
 * @param pubexp Public exponent to copy (typically an odd integer such as 65537); caller retains ownership.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
""",
    "EVP_PKEY_CTX_set1_rsa_keygen_pubexp",
)

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
""",
    """/**
 * @brief Get the RSA-OAEP message-digest algorithm name from an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param name Buffer receiving the NUL-terminated digest name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
""",
    "EVP_PKEY_CTX_get_rsa_oaep_md_name",
)

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label);
""",
    """/**
 * @brief Return a non-owning pointer to the RSA-OAEP label configured on an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param label Receives a pointer to the internal label bytes (do not free); may be NULL.
 * @return Label length in bytes on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label);
""",
    "EVP_PKEY_CTX_get0_rsa_oaep_label",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 RSA *RSA_new(void);
""",
    """/**
 * @brief Allocate and initialise an empty RSA key object (deprecated; use EVP_PKEY-RSA).
 * @return New RSA, or NULL on allocation failure; free with RSA_free.
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSA_new(void);
""",
    "RSA_new",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
""",
    """/**
 * @brief Set the RSA prime factors p and q, transferring ownership of the BIGNUMs (deprecated).
 * @param r RSA key to update.
 * @param p First prime factor; required on the first call, or NULL to leave unchanged.
 * @param q Second prime factor; required on the first call, or NULL to leave unchanged.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
""",
    "RSA_set0_factors",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 void RSA_clear_flags(RSA *r, int flags);
""",
    """/**
 * @brief Clear the given flag bits on an RSA key object (deprecated).
 * @param r RSA key whose flags are updated.
 * @param flags Flag bits to clear (bitwise AND with the complement of this mask).
 */
OSSL_DEPRECATEDIN_3_0 void RSA_clear_flags(RSA *r, int flags);
""",
    "RSA_clear_flags",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_get_version(RSA *r);
""",
    """/**
 * @brief Return whether an RSA key is multi-prime or two-prime (deprecated).
 * @param r RSA key to query.
 * @return RSA_ASN1_VERSION_MULTI or RSA_ASN1_VERSION_DEFAULT (two-prime).
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get_version(RSA *r);
""",
    "RSA_get_version",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
""",
    """/**
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
""",
    "RSA_public_encrypt",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
OSSL_DEPRECATEDIN_3_0
int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);
""",
    """/**
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
""",
    "RSA_public_decrypt+RSA_private_decrypt",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 void RSA_set_default_method(const RSA_METHOD *meth);
""",
    """/**
 * @brief Set the default RSA_METHOD used when creating new RSA keys (deprecated; not thread-safe).
 * @param meth Method table that becomes the process default unless an ENGINE overrides it.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_set_default_method(const RSA_METHOD *meth);
""",
    "RSA_set_default_method",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_null_method(void);
""",
    """/**
 * @brief Return the historical "null" RSA_METHOD stub (deprecated; always returns NULL since 1.1.1).
 * @return NULL.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_null_method(void);
""",
    "RSA_null_method",
)

patch_both(
    "rsa.h",
    """struct rsa_oaep_params_st {
    X509_ALGOR *hashFunc;
""",
    """struct rsa_oaep_params_st {
    /** AlgorithmIdentifier for the OAEP hash function (for example SHA-256). */
    X509_ALGOR *hashFunc;
""",
    "hashFunc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_verify(int type, const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen, RSA *rsa);
""",
    """/**
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
""",
    "RSA_verify",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
""",
    """/**
 * @brief Create and attach a BN_BLINDING factor for RSA private operations (deprecated).
 * @param rsa RSA key that will use the returned blinding state.
 * @param ctx Optional BN_CTX for blinding setup, or NULL to allocate internally.
 * @return New BN_BLINDING on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
""",
    "RSA_setup_blinding",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
""",
    """/**
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
""",
    "RSA_padding_check_PKCS1_type_2",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_X931_hash_id(int nid);
""",
    """/**
 * @brief Return the X9.31 hash algorithm identifier byte for digest NID @p nid (deprecated).
 * @param nid Digest NID such as NID_sha1 or NID_sha256.
 * @return Hash-ID byte used in X9.31 encoding, or -1 if @p nid is unsupported.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_X931_hash_id(int nid);
""",
    "RSA_X931_hash_id",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
    const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    int sLen);
""",
    """/**
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
""",
    "RSA_padding_add_PKCS1_PSS_mgf1",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 void *RSA_get_ex_data(const RSA *r, int idx);
""",
    """/**
 * @brief Return application data previously stored on an RSA key at CRYPTO_EX index @p idx (deprecated).
 * @param r RSA key to query.
 * @param idx Index from CRYPTO_get_ex_new_index() for RSA.
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *RSA_get_ex_data(const RSA *r, int idx);
""",
    "RSA_get_ex_data",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const char *RSA_meth_get0_name(const RSA_METHOD *meth);
""",
    """/**
 * @brief Return the descriptive name stored on an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Internal NUL-terminated name string; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const char *RSA_meth_get0_name(const RSA_METHOD *meth);
""",
    "RSA_meth_get0_name",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_meth_get_flags(const RSA_METHOD *meth);
""",
    """/**
 * @brief Return the flag mask stored on an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Flag bits previously set with RSA_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_get_flags(const RSA_METHOD *meth);
""",
    "RSA_meth_get_flags",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
    int (*pub_enc)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
""",
    """/**
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
""",
    "RSA_meth_set_pub_enc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
    int (*pub_dec)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
""",
    """/**
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
""",
    "RSA_meth_get_pub_dec+RSA_meth_set_pub_dec",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
    int (*priv_enc)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));
""",
    """/**
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
""",
    "RSA_meth_set_priv_enc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_keygen(RSA_METHOD *rsa,
    int (*keygen)(RSA *rsa, int bits, BIGNUM *e,
        BN_GENCB *cb));
""",
    """/**
 * @brief Set the key-generation callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param keygen Callback implementing RSA_generate_key_ex()-style key generation, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_keygen(RSA_METHOD *rsa,
    int (*keygen)(RSA *rsa, int bits, BIGNUM *e,
        BN_GENCB *cb));
""",
    "RSA_meth_set_keygen",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
