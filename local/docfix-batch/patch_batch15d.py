#!/usr/bin/env python3
"""Documentation repair batch 15d: x509.h symbols."""
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


print("=== batch 15d: x509.h ===")

# ----- early verify / SPKI / sign / digest -----

patch_both(
    "x509.h",
    """void *X509_CRL_get_meth_data(X509_CRL *crl);

const char *X509_verify_cert_error_string(long n);
""",
    """/**
 * @brief Return the method-specific application data previously set on a CRL.
 * @param crl CRL whose X509_CRL_METHOD data pointer is queried.
 * @return Opaque pointer last passed to X509_CRL_set_meth_data(), or NULL if unset.
 */
void *X509_CRL_get_meth_data(X509_CRL *crl);

/**
 * @brief Return a human-readable string for an X509_V_ERR_* verification error code.
 * @param n Error code such as from X509_STORE_CTX_get_error() or X509_verify_cert().
 * @return Static descriptive string; never NULL (unknown codes yield a generic message).
 */
const char *X509_verify_cert_error_string(long n);
""",
    "X509_CRL_get_meth_data+X509_verify_cert_error_string",
)

patch_both(
    "x509.h",
    """int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
""",
    """/**
 * @brief Verify a certificate request's signature with public key @p r.
 * @param a Certificate signing request whose signature is checked.
 * @param r Public key expected to have signed @p a.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
/**
 * @brief Verify a CRL's signature with the issuer public key @p r.
 * @param a Certificate revocation list whose signature is checked.
 * @param r Public key expected to have signed @p a.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
""",
    "X509_REQ_verify+X509_CRL_verify",
)

patch_both(
    "x509.h",
    """NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
""",
    """/**
 * @brief Decode a base64-encoded Netscape SPKI structure from a string.
 * @param str Base64 text of a SignedPublicKeyAndChallenge.
 * @param len Length of @p str in bytes, or -1 if @p str is NUL-terminated.
 * @return Newly allocated NETSCAPE_SPKI, or NULL on error; free with NETSCAPE_SPKI_free().
 */
NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
""",
    "NETSCAPE_SPKI_b64_decode",
)

patch_both(
    "x509.h",
    """int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);

/**
 * @brief Print a human-readable representation of a Netscape signed public key and challenge.
""",
    """/**
 * @brief Set the public key in a Netscape SPKI structure from @p pkey.
 * @param x SPKI whose SPKAC public-key field is replaced.
 * @param pkey Public key (or key pair) whose public component is encoded into @p x.
 * @return 1 on success, or 0 on failure.
 */
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);

/**
 * @brief Print a human-readable representation of a Netscape signed public key and challenge.
""",
    "NETSCAPE_SPKI_set_pubkey",
)

patch_both(
    "x509.h",
    """int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx);
/**
 * @brief Sign a Netscape SPKI with a private key and message digest.
""",
    """/**
 * @brief Sign a CRL using an initialized digest/signing context.
 * @param x CRL whose TBSCertList is signed; signature fields are filled in.
 * @param ctx Digest context already set up with the private key and algorithm parameters.
 * @return Size of the signature in bytes on success, or 0 on failure.
 */
int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx);
/**
 * @brief Sign a Netscape SPKI with a private key and message digest.
""",
    "X509_CRL_sign_ctx",
)

patch_both(
    "x509.h",
    """int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);

/**
 * @brief Download an X.509 certificate from @p url over HTTP(S).
""",
    """/**
 * @brief Compute a digest of the DER encoding of an X.509 Name (DN).
 * @param data Distinguished name to hash.
 * @param type Digest algorithm such as EVP_sha1().
 * @param md Output buffer large enough for the digest (at least EVP_MAX_MD_SIZE).
 * @param len On success, set to the digest length in bytes; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);

/**
 * @brief Download an X.509 certificate from @p url over HTTP(S).
""",
    "X509_NAME_digest",
)

# ----- FILE / BIO I/O helpers -----

patch_both(
    "x509.h",
    """X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
/**
 * @brief Write a DER-encoded X.509 CRL to a FILE stream.
""",
    """/**
 * @brief Decode an X.509 CRL in DER form from a FILE.
 * @param fp Input FILE positioned at the DER encoding.
 * @param crl Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_CRL, or NULL on error; free with X509_CRL_free().
 */
X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
/**
 * @brief Write a DER-encoded X.509 CRL to a FILE stream.
""",
    "d2i_X509_CRL_fp",
)

patch_both(
    "x509.h",
    """int i2d_X509_REQ_fp(FILE *fp, const X509_REQ *req);
#ifndef OPENSSL_NO_DEPRECATED_3_0
""",
    """/**
 * @brief Write an X.509 certificate request to a FILE in DER form.
 * @param fp Output FILE opened for writing.
 * @param req Certificate request to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_X509_REQ_fp(FILE *fp, const X509_REQ *req);
#ifndef OPENSSL_NO_DEPRECATED_3_0
""",
    "i2d_X509_REQ_fp",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
/**
 * @brief Write an RSA public key to a FILE as a SubjectPublicKeyInfo DER blob (deprecated).
""",
    """/**
 * @brief Read an RSA public key in SubjectPublicKeyInfo DER form from a FILE (deprecated).
 * @param fp Input FILE positioned at the DER encoding.
 * @param rsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded RSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
/**
 * @brief Write an RSA public key to a FILE as a SubjectPublicKeyInfo DER blob (deprecated).
""",
    "d2i_RSA_PUBKEY_fp",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
/**
 * @brief Write a DER-encoded DSA private key to a FILE stream (deprecated).
""",
    """/**
 * @brief Read a DER-encoded DSA private key from a FILE (deprecated).
 * @param fp Input FILE positioned at the DER encoding.
 * @param dsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
/**
 * @brief Write a DER-encoded DSA private key to a FILE stream (deprecated).
""",
    "d2i_DSAPrivateKey_fp",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *eckey);
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
OSSL_DEPRECATEDIN_3_0 int i2d_ECPrivateKey_fp(FILE *fp, const EC_KEY *eckey);
#endif /* OPENSSL_NO_EC */
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
""",
    """/**
 * @brief Read an EC public key in SubjectPublicKeyInfo DER form from a FILE (deprecated).
 * @param fp Input FILE positioned at the DER encoding.
 * @param eckey Optional destination pointer updated to the result, or NULL.
 * @return Decoded EC_KEY, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *eckey);
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
/**
 * @brief Write an EC private key in SEC1 ECPrivateKey DER form to a FILE (deprecated).
 * @param fp Output FILE opened for writing.
 * @param eckey EC key whose private key is encoded.
 * @return Number of bytes written, or a negative / zero value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_ECPrivateKey_fp(FILE *fp, const EC_KEY *eckey);
#endif /* OPENSSL_NO_EC */
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
/**
 * @brief Decode a PKCS#8 encrypted private key (X509_SIG) in DER form from a FILE.
 * @param fp Input FILE positioned at the DER encoding.
 * @param p8 Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_SIG, or NULL on error; free with X509_SIG_free().
 */
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
""",
    "d2i_EC_PUBKEY_fp+i2d_ECPrivateKey_fp+d2i_PKCS8_fp",
)

patch_both(
    "x509.h",
    """EVP_PKEY *d2i_PrivateKey_ex_fp(FILE *fp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Read a private key in traditional or PKCS#8 DER form from a FILE.
""",
    """/**
 * @brief Read a private key in traditional or PKCS#8 DER form from a FILE with library context.
 * @param fp Input FILE positioned at the DER private key.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string for algorithm fetches, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PrivateKey_ex_fp(FILE *fp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Read a private key in traditional or PKCS#8 DER form from a FILE.
""",
    "d2i_PrivateKey_ex_fp",
)

patch_both(
    "x509.h",
    """EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
#endif
""",
    """/**
 * @brief Decode an EVP_PKEY in SubjectPublicKeyInfo form from a FILE.
 * @param fp Input FILE positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
#endif
""",
    "d2i_PUBKEY_fp",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int i2d_RSAPrivateKey_bio(BIO *bp, const RSA *rsa);
/**
 * @brief Decode an RSA public key in PKCS#1 RSAPublicKey form from a BIO (deprecated).
""",
    """/**
 * @brief Write an RSA private key in PKCS#1 DER form to a BIO (deprecated).
 * @param bp Output BIO.
 * @param rsa RSA key whose private key encoding is written.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPrivateKey_bio(BIO *bp, const RSA *rsa);
/**
 * @brief Decode an RSA public key in PKCS#1 RSAPublicKey form from a BIO (deprecated).
""",
    "i2d_RSAPrivateKey_bio",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey_bio(BIO *bp, const RSA *rsa);
/**
 * @brief Decode an RSA public key (SubjectPublicKeyInfo) in DER form from a BIO (deprecated).
""",
    """/**
 * @brief Write an RSA public key in PKCS#1 RSAPublicKey DER form to a BIO (deprecated).
 * @param bp Output BIO.
 * @param rsa RSA key whose public components are encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey_bio(BIO *bp, const RSA *rsa);
/**
 * @brief Decode an RSA public key (SubjectPublicKeyInfo) in DER form from a BIO (deprecated).
""",
    "i2d_RSAPublicKey_bio",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
/**
 * @brief Write a DER-encoded DSA private key to a BIO (deprecated).
""",
    """/**
 * @brief Decode a DSA private key in DER form from a BIO (deprecated).
 * @param bp BIO positioned at the DER encoding.
 * @param dsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
/**
 * @brief Write a DER-encoded DSA private key to a BIO (deprecated).
""",
    "d2i_DSAPrivateKey_bio",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_bio(BIO *bp, const EC_KEY *eckey);
/**
 * @brief Read a DER-encoded EC private key from a BIO (deprecated).
""",
    """/**
 * @brief Write an EC public key as SubjectPublicKeyInfo DER to a BIO (deprecated).
 * @param bp Output BIO.
 * @param eckey EC key whose public key is encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_bio(BIO *bp, const EC_KEY *eckey);
/**
 * @brief Read a DER-encoded EC private key from a BIO (deprecated).
""",
    "i2d_EC_PUBKEY_bio",
)

patch_both(
    "x509.h",
    """X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8);
""",
    """/**
 * @brief Decode a PKCS#8 encrypted private key (X509_SIG) in DER form from a BIO.
 * @param bp BIO positioned at the DER encoding.
 * @param p8 Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_SIG, or NULL on error; free with X509_SIG_free().
 */
X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8);
""",
    "d2i_PKCS8_bio",
)

patch_both(
    "x509.h",
    """int i2d_PUBKEY_bio(BIO *bp, const EVP_PKEY *pkey);
/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo into an EVP_PKEY from a BIO with library context.
""",
    """/**
 * @brief Encode an EVP_PKEY as SubjectPublicKeyInfo DER and write it to a BIO.
 * @param bp Output BIO.
 * @param pkey Public key to encode.
 * @return Number of bytes written, or a negative / zero value on error.
 */
int i2d_PUBKEY_bio(BIO *bp, const EVP_PKEY *pkey);
/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo into an EVP_PKEY from a BIO with library context.
""",
    "i2d_PUBKEY_bio",
)

# ----- DUP macros + ALGOR_set0 + time / defaults -----

patch_both(
    "x509.h",
    """DECLARE_ASN1_DUP_FUNCTION(X509_ALGOR)
/**
 * @brief Deep-copy an X.509 Attribute.
""",
    """/**
 * @brief Deep-copy an X509_ALGOR (AlgorithmIdentifier).
 * @param alg AlgorithmIdentifier to duplicate.
 * @return Newly allocated X509_ALGOR copy, or NULL on error; free with X509_ALGOR_free().
 */
X509_ALGOR *X509_ALGOR_dup(const X509_ALGOR *alg);
/**
 * @brief Deep-copy an X.509 Attribute.
""",
    "X509_ALGOR_dup",
)

patch_both(
    "x509.h",
    """DECLARE_ASN1_DUP_FUNCTION(X509_REVOKED)
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype,
    void *pval);
""",
    """/**
 * @brief Deep-copy a CRL revoked-certificate entry.
 * @param r Revoked entry to duplicate.
 * @return Newly allocated X509_REVOKED copy, or NULL on error; free with X509_REVOKED_free().
 */
X509_REVOKED *X509_REVOKED_dup(const X509_REVOKED *r);
/**
 * @brief Set the algorithm OID and parameter of an X509_ALGOR, transferring ownership.
 * @param alg AlgorithmIdentifier to update.
 * @param aobj Algorithm OID; ownership transfers to @p alg on success.
 * @param ptype Parameter type (V_ASN1_*); V_ASN1_UNDEF omits the parameter.
 * @param pval Parameter value whose meaning matches ASN1_TYPE_set(); ownership transfers on success.
 * @return 1 on success, or 0 on failure (@p alg unchanged; caller retains @p aobj / @p pval).
 */
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype,
    void *pval);
""",
    "X509_REVOKED_dup+X509_ALGOR_set0",
)

patch_both(
    "x509.h",
    """DECLARE_ASN1_DUP_FUNCTION(X509_NAME)
/**
 * @brief Deep-copy an X509_NAME_ENTRY.
""",
    """/**
 * @brief Deep-copy an X.509 Name (distinguished name).
 * @param xn Name to duplicate.
 * @return Newly allocated X509_NAME copy, or NULL on error; free with X509_NAME_free().
 */
X509_NAME *X509_NAME_dup(const X509_NAME *xn);
/**
 * @brief Deep-copy an X509_NAME_ENTRY.
""",
    "X509_NAME_dup",
)

patch_both(
    "x509.h",
    """int X509_cmp_current_time(const ASN1_TIME *s);
/**
 * @brief Compare a verification reference time against a notBefore/notAfter window.
""",
    """/**
 * @brief Compare an ASN.1 Time against the current time.
 * @param s Time value in UTCTime or GeneralizedTime form (RFC 5280).
 * @return -1 if @p s is earlier than or equal to now, 1 if later, or 0 on error.
 */
int X509_cmp_current_time(const ASN1_TIME *s);
/**
 * @brief Compare a verification reference time against a notBefore/notAfter window.
""",
    "X509_cmp_current_time",
)

patch_both(
    "x509.h",
    """ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);

/**
 * @brief Return the default OpenSSL certificates area directory path.
""",
    """/**
 * @brief Set an ASN1_TIME to the current time plus a second offset (GMT).
 * @param s Existing ASN1_TIME to update, or NULL to allocate a new one.
 * @param adj Seconds to add to the current time (may be negative).
 * @return Adjusted ASN1_TIME (same as @p s when non-NULL), or NULL on error.
 */
ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);

/**
 * @brief Return the default OpenSSL certificates area directory path.
""",
    "X509_gmtime_adj",
)

patch_both(
    "x509.h",
    """const char *X509_get_default_cert_dir_env(void);
const char *X509_get_default_cert_file_env(void);
""",
    """/**
 * @brief Return the environment variable name for overriding the default CA directory list.
 * @return Static string naming the recommended env var (for example "SSL_CERT_DIR").
 */
const char *X509_get_default_cert_dir_env(void);
const char *X509_get_default_cert_file_env(void);
""",
    "X509_get_default_cert_dir_env",
)

# ----- X509_new_ex, keyid, ASN1_item_verify_ctx -----

patch_both(
    "x509.h",
    """X509 *X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Allocate empty certificate auxiliary info (trust/reject/alias/keyid).
""",
    """/**
 * @brief Allocate an empty X.509 certificate with an explicit library context.
 * @param libctx Library context used for algorithm fetches on this certificate, or NULL for the default.
 * @param propq Property query for provider algorithm fetches, or NULL.
 * @return New X509 with reference count 1, or NULL on allocation failure; free with X509_free().
 */
X509 *X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Allocate empty certificate auxiliary info (trust/reject/alias/keyid).
""",
    "X509_new_ex",
)

patch_both(
    "x509.h",
    """int X509_keyid_set1(X509 *x, const unsigned char *id, int len);
/**
 * @brief Return the friendly-name alias attached to a certificate, if any.
""",
    """/**
 * @brief Set the key identifier on a certificate's auxiliary data (copied).
 * @param x Certificate whose keyid is set (creates aux data if needed).
 * @param id Key identifier bytes, or NULL to clear.
 * @param len Length of @p id in bytes (-1 means NUL-terminated).
 * @return 1 on success, or 0 on failure.
 */
int X509_keyid_set1(X509 *x, const unsigned char *id, int len);
/**
 * @brief Return the friendly-name alias attached to a certificate, if any.
""",
    "X509_keyid_set1",
)

patch_both(
    "x509.h",
    """int ASN1_item_verify_ctx(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    EVP_MD_CTX *ctx);
/**
 * @brief Sign the DER encoding of an ASN.1 value described by @p it.
""",
    """/**
 * @brief Verify @p signature over the ASN.1 encoding of @p data using digest context @p ctx.
 * @param it ASN.1 item describing the signed structure type of @p data.
 * @param alg Signature AlgorithmIdentifier.
 * @param signature BIT STRING signature value.
 * @param data Pointer to the structure instance to re-encode and verify.
 * @param ctx Digest/verify context already configured with the public key and algorithm.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int ASN1_item_verify_ctx(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    EVP_MD_CTX *ctx);
/**
 * @brief Sign the DER encoding of an ASN.1 value described by @p it.
""",
    "ASN1_item_verify_ctx",
)

# ----- REQ subject / extensions -----

patch_both(
    "x509.h",
    """X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
int X509_REQ_set_subject_name(X509_REQ *req, const X509_NAME *name);
""",
    """/**
 * @brief Return the subject name of a certificate request.
 * @param req Certificate request to query.
 * @return Internal X509_NAME pointer (do not free), or NULL on error.
 */
X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
/**
 * @brief Set the subject name of a certificate request by copying @p name.
 * @param req Certificate request to update.
 * @param name Subject distinguished name to copy into @p req.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_set_subject_name(X509_REQ *req, const X509_NAME *name);
""",
    "X509_REQ_get_subject_name+X509_REQ_set_subject_name",
)

patch_both(
    "x509.h",
    """int X509_REQ_extension_nid(int nid);
int *X509_REQ_get_extension_nids(void);
""",
    """/**
 * @brief Test whether @p nid is recognized as a certificate-request extension attribute NID.
 * @param nid Attribute NID to check against the current extension NID list.
 * @return Non-zero if @p nid is an extension-request attribute NID, or 0 otherwise.
 */
int X509_REQ_extension_nid(int nid);
int *X509_REQ_get_extension_nids(void);
""",
    "X509_REQ_extension_nid",
)

patch_both(
    "x509.h",
    """STACK_OF(X509_EXTENSION) *X509_REQ_get_extensions(X509_REQ *req);
/**
 * @brief Add a stack of extensions to a certificate request under attribute OID @p nid.
""",
    """/**
 * @brief Return the first stack of X.509 extensions found in a certificate request's attributes.
 * @param req Certificate request to query.
 * @return Newly allocated STACK_OF(X509_EXTENSION) (possibly empty); caller must free, or NULL on error.
 */
STACK_OF(X509_EXTENSION) *X509_REQ_get_extensions(X509_REQ *req);
/**
 * @brief Add a stack of extensions to a certificate request under attribute OID @p nid.
""",
    "X509_REQ_get_extensions",
)

# ----- REVOKED serial, issuer/serial cmp, NAME_add_entry_by_OBJ -----

patch_both(
    "x509.h",
    """const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
""",
    """/**
 * @brief Return the serial number of a revoked-certificate entry without copying it.
 * @param x CRL revoked entry to query.
 * @return Internal ASN1_INTEGER pointer (do not free).
 */
const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
""",
    "X509_REVOKED_get0_serialNumber",
)

patch_both(
    "x509.h",
    """int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);
""",
    """/**
 * @brief Compare two certificates by issuer name and serial number.
 * @param a First certificate.
 * @param b Second certificate.
 * @return -1, 0, or 1 if @p a is less than, equal to, or greater than @p b; or -2 on error.
 */
int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);
""",
    "X509_issuer_and_serial_cmp",
)

patch_both(
    "x509.h",
    """int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
/**
 * @brief Add an RDN attribute identified by @p nid to @p name.
""",
    """/**
 * @brief Add an RDN attribute identified by ASN.1 object @p obj to @p name.
 * @param name Destination X.509 Name.
 * @param obj Attribute type OID (for example commonName).
 * @param type ASN.1 string type for @p bytes (for example MBSTRING_ASC).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 for a NUL-terminated string.
 * @param loc Insertion index, or -1 to append.
 * @param set -1/0/1 controlling whether to join an existing RDN set at @p loc.
 * @return 1 on success, or 0 on error.
 */
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
/**
 * @brief Add an RDN attribute identified by @p nid to @p name.
""",
    "X509_NAME_add_entry_by_OBJ",
)

# ----- extension helpers -----

patch_both(
    "x509.h",
    """int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
""",
    """/**
 * @brief Find a certificate extension by criticality flag, searching after @p lastpos.
 * @param x Certificate whose extensions are searched.
 * @param crit 1 to match critical extensions, 0 for non-critical.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Extension index on success, or -1 if not found.
 */
int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
""",
    "X509_get_ext_by_critical",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
void *X509_REVOKED_get_ext_d2i(const X509_REVOKED *x, int nid, int *crit,
    int *idx);
""",
    """/**
 * @brief Remove and return the extension at index @p loc from a revoked entry.
 * @param x Revoked-certificate entry to modify.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is out of range.
 */
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
/**
 * @brief Decode the first matching extension of type @p nid from a revoked entry.
 * @param x Revoked-certificate entry whose extensions are searched.
 * @param nid Extension NID to locate and decode.
 * @param crit Optional out-parameter set to 1 if critical, 0 if not, or -1 on error; may be NULL.
 * @param idx Optional in/out index: on entry, search after this index (-1 to start); on success set to the match index; may be NULL.
 * @return Newly allocated extension-specific structure, or NULL if not found / on error; free with the type's free function.
 */
void *X509_REVOKED_get_ext_d2i(const X509_REVOKED *x, int nid, int *crit,
    int *idx);
""",
    "X509_REVOKED_delete_ext+X509_REVOKED_get_ext_d2i",
)

patch_both(
    "x509.h",
    """int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
/**
 * @brief Find the next attribute in a stack with the given NID.
""",
    """/**
 * @brief Return the number of attributes in an X509_ATTRIBUTE stack.
 * @param x Stack of X509_ATTRIBUTE values; may be NULL.
 * @return Attribute count, or -1 if @p x is NULL.
 */
int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
/**
 * @brief Find the next attribute in a stack with the given NID.
""",
    "X509at_get_attr_count",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
    int nid, int type,
    const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
""",
    """/**
 * @brief Append an attribute identified by NID to an EVP_PKEY's attribute set.
 * @param key Key whose attributes are extended.
 * @param nid Attribute type NID.
 * @param type ASN.1 string/type code for @p bytes (for example V_ASN1_UTF8STRING).
 * @param bytes Attribute value bytes interpreted according to @p type.
 * @param len Length of @p bytes in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
    int nid, int type,
    const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
""",
    "EVP_PKEY_add1_attr_by_NID",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
""",
    """/**
 * @brief Build a PKCS#5 PBES2 AlgorithmIdentifier for @p cipher with PBKDF2.
 * @param cipher Content-encryption cipher for the PBES2 encryption scheme.
 * @param iter PBKDF2 iteration count; <=0 selects the default.
 * @param salt Optional salt bytes; NULL generates a random salt of @p saltlen (default 16 if 0).
 * @param saltlen Salt length in bytes when @p salt is NULL / length of @p salt.
 * @return New X509_ALGOR encoding PBES2 parameters, or NULL on error; free with X509_ALGOR_free().
 */
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
""",
    "PKCS5_pbe2_set",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
