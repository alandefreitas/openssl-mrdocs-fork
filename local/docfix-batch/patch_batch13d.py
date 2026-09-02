#!/usr/bin/env python3
"""Documentation repair batch 13d: x509.h + x509_vfy.h + x509v3.h."""
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


print("=== batch 13d: x509 family ===")

patch_both("x509.h",
    "    ASN1_OCTET_STRING *enc_pkey; /* encrypted pub key */\n",
    "    /** Encrypted private-key octets (PKCS#8 encrypted content). */\n"
    "    ASN1_OCTET_STRING *enc_pkey; /* encrypted pub key */\n",
    "X509_PKEY.enc_pkey")

patch_both("x509.h",
    "    char *key_data;\n",
    "    /** Symmetric key bytes of length @c key_length used to encrypt/decrypt @c enc_pkey. */\n"
    "    char *key_data;\n",
    "X509_PKEY.key_data")

patch_both("x509.h",
"""int X509_verify(X509 *a, EVP_PKEY *r);
""",
"""/**
 * @brief Verify a certificate's signature with the issuer public key @p r.
 * @param a Certificate whose signature is verified.
 * @param r Public key expected to have signed @p a (typically the issuer key).
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int X509_verify(X509 *a, EVP_PKEY *r);
""", "X509_verify")

patch_both("x509.h",
"""X509 *d2i_X509_fp(FILE *fp, X509 **x509);
""",
"""/**
 * @brief Decode an X.509 certificate in DER form from a FILE.
 * @param fp Input FILE positioned at the DER encoding.
 * @param x509 Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509, or NULL on error; free with X509_free().
 */
X509 *d2i_X509_fp(FILE *fp, X509 **x509);
""", "d2i_X509_fp")

patch_both("x509.h",
"""X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
""",
"""/**
 * @brief Decode an X.509 certificate request in DER form from a FILE.
 * @param fp Input FILE positioned at the DER encoding.
 * @param req Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_REQ, or NULL on error; free with X509_REQ_free().
 */
X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
""", "d2i_X509_REQ_fp")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 int i2d_RSAPrivateKey_fp(FILE *fp, const RSA *rsa);
""",
"""/**
 * @brief Write an RSA private key in PKCS#1 DER form to a FILE (deprecated).
 * @param fp Output FILE opened for writing.
 * @param rsa RSA key whose private key encoding is written.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPrivateKey_fp(FILE *fp, const RSA *rsa);
""", "i2d_RSAPrivateKey_fp")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey_fp(FILE *fp, const RSA *rsa);
""",
"""/**
 * @brief Write an RSA public key in PKCS#1 RSAPublicKey DER form to a FILE (deprecated).
 * @param fp Output FILE opened for writing.
 * @param rsa RSA key whose public components are encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey_fp(FILE *fp, const RSA *rsa);
""", "i2d_RSAPublicKey_fp")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
""",
"""/**
 * @brief Read a DSA public key in SubjectPublicKeyInfo DER form from a FILE (deprecated).
 * @param fp Input FILE positioned at the DER encoding.
 * @param dsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
""", "d2i_DSA_PUBKEY_fp")

patch_both("x509.h",
"""int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, const PKCS8_PRIV_KEY_INFO *p8inf);
""",
"""/**
 * @brief Write an unencrypted PKCS#8 PrivateKeyInfo structure to a FILE in DER form.
 * @param fp Output FILE opened for writing.
 * @param p8inf PrivateKeyInfo to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, const PKCS8_PRIV_KEY_INFO *p8inf);
""", "i2d_PKCS8_PRIV_KEY_INFO_fp")

patch_both("x509.h",
"""int i2d_X509_bio(BIO *bp, const X509 *x509);
""",
"""/**
 * @brief Write an X.509 certificate to a BIO in DER form.
 * @param bp Output BIO.
 * @param x509 Certificate to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_X509_bio(BIO *bp, const X509 *x509);
""", "i2d_X509_bio")

patch_both("x509.h",
"""int i2d_X509_CRL_bio(BIO *bp, const X509_CRL *crl);
""",
"""/**
 * @brief Write an X.509 CRL to a BIO in DER form.
 * @param bp Output BIO.
 * @param crl CRL to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_X509_CRL_bio(BIO *bp, const X509_CRL *crl);
""", "i2d_X509_CRL_bio")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 int i2d_RSA_PUBKEY_bio(BIO *bp, const RSA *rsa);
""",
"""/**
 * @brief Write an RSA public key as SubjectPublicKeyInfo DER to a BIO (deprecated).
 * @param bp Output BIO.
 * @param rsa RSA key whose public key is encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSA_PUBKEY_bio(BIO *bp, const RSA *rsa);
""", "i2d_RSA_PUBKEY_bio")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 int i2d_DSA_PUBKEY_bio(BIO *bp, const DSA *dsa);
""",
"""/**
 * @brief Write a DSA public key as SubjectPublicKeyInfo DER to a BIO (deprecated).
 * @param bp Output BIO.
 * @param dsa DSA key whose public key is encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSA_PUBKEY_bio(BIO *bp, const DSA *dsa);
""", "i2d_DSA_PUBKEY_bio")

patch_both("x509.h",
"""OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey_bio(BIO *bp, const DSA *dsa);
""",
"""/**
 * @brief Write a DER-encoded DSA private key to a BIO (deprecated).
 * @param bp Output BIO.
 * @param dsa DSA key whose private key encoding is written.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey_bio(BIO *bp, const DSA *dsa);
""", "i2d_DSAPrivateKey_bio")

patch_both("x509.h",
"""int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, const PKCS8_PRIV_KEY_INFO *p8inf);
""",
"""/**
 * @brief Write an unencrypted PKCS#8 PrivateKeyInfo structure to a BIO in DER form.
 * @param bp Output BIO.
 * @param p8inf PrivateKeyInfo to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, const PKCS8_PRIV_KEY_INFO *p8inf);
""", "i2d_PKCS8_PRIV_KEY_INFO_bio")

patch_both("x509.h",
"""EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
""",
"""/**
 * @brief Read a private key in traditional or PKCS#8 DER form from a BIO.
 * @param bp BIO positioned at the DER encoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
""", "d2i_PrivateKey_bio")

patch_both("x509.h",
"""EVP_PKEY *d2i_PUBKEY_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);
""",
"""/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo into an EVP_PKEY from a BIO with library context.
 * @param bp BIO positioned at DER input.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *d2i_PUBKEY_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
    const char *propq);
""", "d2i_PUBKEY_ex_bio")

patch_both("x509.h",
"""DECLARE_ASN1_DUP_FUNCTION(X509)
""",
"""/**
 * @brief Deep-copy an X.509 certificate.
 * @param x Certificate to duplicate.
 * @return Newly allocated X509 copy, or NULL on error; free with X509_free().
 */
X509 *X509_dup(const X509 *x);
""", "X509_dup")

patch_both("x509.h",
"""DECLARE_ASN1_DUP_FUNCTION(X509_CRL)
""",
"""/**
 * @brief Deep-copy an X.509 certificate revocation list.
 * @param crl CRL to duplicate.
 * @return Newly allocated X509_CRL copy, or NULL on error; free with X509_CRL_free().
 */
X509_CRL *X509_CRL_dup(const X509_CRL *crl);
""", "X509_CRL_dup")

patch_both("x509.h",
"""void X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype,
    const void **ppval, const X509_ALGOR *algor);
""",
"""/**
 * @brief Borrow pointers to the algorithm OID and parameter from an X509_ALGOR.
 * @param paobj Optional destination for the algorithm OID pointer, or NULL.
 * @param pptype Optional destination for the parameter type (V_ASN1_*), or NULL.
 * @param ppval Optional destination for the parameter value pointer, or NULL.
 * @param algor AlgorithmIdentifier to query.
 */
void X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype,
    const void **ppval, const X509_ALGOR *algor);
""", "X509_ALGOR_get0")

patch_both("x509.h",
"""ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s,
    int offset_day, long offset_sec, time_t *t);
""",
"""/**
 * @brief Adjust an ASN.1 Time by day and second offsets from a reference time_t.
 * @param s Existing ASN1_TIME to reuse, or NULL to allocate a new one.
 * @param offset_day Number of days to add (may be negative).
 * @param offset_sec Number of seconds to add (may be negative).
 * @param t Reference time; NULL means use the current time.
 * @return Resulting ASN1_TIME (same as @p s when non-NULL), or NULL on error.
 */
ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s,
    int offset_day, long offset_sec, time_t *t);
""", "X509_time_adj_ex")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_PUBKEY)",
asn1_funcs("X509_PUBKEY", "X.509 SubjectPublicKeyInfo (X509_PUBKEY)") + "\n",
"X509_PUBKEY ASN.1")

patch_both("x509.h",
"""EVP_PKEY *X509_PUBKEY_get0(const X509_PUBKEY *key);
""",
"""/**
 * @brief Return the EVP_PKEY decoded from an X509_PUBKEY without incrementing its refcount.
 * @param key SubjectPublicKeyInfo structure to query.
 * @return Internal EVP_PKEY pointer (do not free), or NULL on error.
 */
EVP_PKEY *X509_PUBKEY_get0(const X509_PUBKEY *key);
""", "X509_PUBKEY_get0")

patch_both("x509.h",
"""int X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain);
""",
"""/**
 * @brief Copy missing algorithm parameters into @p pkey from certificates in @p chain.
 * @param pkey Key that may lack parameters (for example DSA/DH without p/q/g).
 * @param chain Certificate chain searched for matching parameters; may be NULL.
 * @return 1 on success (including when no copy was needed), or 0 on failure.
 */
int X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain);
""", "X509_get_pubkey_parameters")

patch_both("x509.h",
"""DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(OSSL_DEPRECATEDIN_3_0, DSA, DSA_PUBKEY)
""",
"""/**
 * @brief Decode a DSA public key from SubjectPublicKeyInfo DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA public key as SubjectPublicKeyInfo DER (deprecated).
 * @param a DSA key whose public key is encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSA_PUBKEY(const DSA *a, unsigned char **out);
""", "d2i_i2d_DSA_PUBKEY")

patch_both("x509.h",
"""void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg,
    const ASN1_OCTET_STRING **pdigest);
""",
"""/**
 * @brief Borrow const pointers to the AlgorithmIdentifier and digest octets of an X509_SIG.
 * @param sig Signature structure to query.
 * @param palg Optional destination for the algorithm pointer, or NULL.
 * @param pdigest Optional destination for the digest OCTET STRING pointer, or NULL.
 */
void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg,
    const ASN1_OCTET_STRING **pdigest);
""", "X509_SIG_get0")

patch_both("x509.h",
"""void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
    ASN1_OCTET_STRING **pdigest);
""",
"""/**
 * @brief Borrow mutable pointers to the AlgorithmIdentifier and digest octets of an X509_SIG.
 * @param sig Signature structure to query.
 * @param palg Optional destination for the algorithm pointer, or NULL.
 * @param pdigest Optional destination for the digest OCTET STRING pointer, or NULL.
 */
void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
    ASN1_OCTET_STRING **pdigest);
""", "X509_SIG_getm")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_REQ)",
asn1_funcs("X509_REQ", "X.509 certificate signing request") + "\n",
"X509_REQ ASN.1")

patch_both("x509.h",
"""int X509_NAME_set(X509_NAME **xn, const X509_NAME *name);
""",
"""/**
 * @brief Replace *@p xn with a duplicate of @p name, freeing any previous value.
 * @param xn Address of an X509_NAME pointer to update (may point to NULL).
 * @param name Distinguished name to copy.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_set(X509_NAME **xn, const X509_NAME *name);
""", "X509_NAME_set")

patch_both("x509.h",
"""void X509_SIG_INFO_set(X509_SIG_INFO *siginf, int mdnid, int pknid,
    int secbits, uint32_t flags);
""",
"""/**
 * @brief Populate an X509_SIG_INFO with digest NID, public-key NID, security bits, and flags.
 * @param siginf Signature-info object to overwrite.
 * @param mdnid Signing digest NID (for example NID_sha256).
 * @param pknid Public-key algorithm NID (for example NID_rsaEncryption).
 * @param secbits Effective security strength in bits.
 * @param flags X509_SIG_INFO_* flag bits.
 */
void X509_SIG_INFO_set(X509_SIG_INFO *siginf, int mdnid, int pknid,
    int secbits, uint32_t flags);
""", "X509_SIG_INFO_set")

patch_both("x509.h",
"""int X509_get_signature_nid(const X509 *x);
""",
"""/**
 * @brief Return the NID of the digest used in a certificate's signature AlgorithmIdentifier.
 * @param x Certificate to query.
 * @return Digest NID, or NID_undef if the algorithm is unknown / has no digest.
 */
int X509_get_signature_nid(const X509 *x);
""", "X509_get_signature_nid")

patch_both("x509.h",
"""void X509_REQ_set0_distinguishing_id(X509_REQ *x, ASN1_OCTET_STRING *d_id);
""",
"""/**
 * @brief Attach a Distinguishing ID to a certificate request, transferring ownership of @p d_id.
 * @param x Certificate request to update.
 * @param d_id Distinguishing ID octets, or NULL to clear; frees any previous value.
 */
void X509_REQ_set0_distinguishing_id(X509_REQ *x, ASN1_OCTET_STRING *d_id);
""", "X509_REQ_set0_distinguishing_id")

patch_both("x509.h",
"""int X509_alias_set1(X509 *x, const unsigned char *name, int len);
""",
"""/**
 * @brief Set the friendly-name alias on a certificate's auxiliary data (copied).
 * @param x Certificate whose alias is set (creates aux data if needed).
 * @param name Alias bytes, or NULL to clear.
 * @param len Length of @p name in bytes (-1 means NUL-terminated).
 * @return 1 on success, or 0 on failure.
 */
int X509_alias_set1(X509 *x, const unsigned char *name, int len);
""", "X509_alias_set1")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_CRL_INFO)",
asn1_funcs("X509_CRL_INFO", "X.509 CRL information (tbsCertList) structure") + "\n",
"X509_CRL_INFO ASN.1")

patch_both("x509.h",
"""int X509_CRL_get0_by_serial(X509_CRL *crl,
    X509_REVOKED **ret, const ASN1_INTEGER *serial);
""",
"""/**
 * @brief Find a revoked-certificate entry in a CRL by serial number.
 * @param crl CRL to search.
 * @param ret Optional destination for the matching X509_REVOKED pointer (do not free), or NULL.
 * @param serial Serial number to look up.
 * @return 1 if found, 2 if found with removeFromCRL reason, or 0 if not found / on error.
 */
int X509_CRL_get0_by_serial(X509_CRL *crl,
    X509_REVOKED **ret, const ASN1_INTEGER *serial);
""", "X509_CRL_get0_by_serial")

patch_both("x509.h",
"""int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);
""",
"""/**
 * @brief Find a revoked-certificate entry in a CRL matching certificate @p x's serial.
 * @param crl CRL to search.
 * @param ret Optional destination for the matching X509_REVOKED pointer (do not free), or NULL.
 * @param x Certificate whose serial number is looked up.
 * @return 1 if found, 2 if found with removeFromCRL reason, or 0 if not found / on error.
 */
int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);
""", "X509_CRL_get0_by_cert")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)",
asn1_funcs("NETSCAPE_SPKI", "Netscape Signed Public Key and Challenge (SPKI)") + "\n",
"NETSCAPE_SPKI ASN.1")

patch_both("x509.h",
"""int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
""",
"""/**
 * @brief Set a certificate's serial number by copying @p serial.
 * @param x Certificate to update.
 * @param serial Serial number to copy (caller retains ownership).
 * @return 1 on success, or 0 on failure.
 */
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
""", "X509_set_serialNumber")

patch_both("x509.h",
"""const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
""",
"""/**
 * @brief Return the certificate extensions stack without duplicating it.
 * @param x Certificate to query.
 * @return Internal STACK_OF(X509_EXTENSION) (do not free), or NULL if none.
 */
const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
""", "X509_get0_extensions")

patch_both("x509.h",
"""EVP_PKEY *X509_get_pubkey(X509 *x);
""",
"""/**
 * @brief Decode and return the certificate subject public key with an incremented reference count.
 * @param x Certificate whose subject public key is extracted.
 * @return New EVP_PKEY reference that must be freed with EVP_PKEY_free(), or NULL on error.
 */
EVP_PKEY *X509_get_pubkey(X509 *x);
""", "X509_get_pubkey")

patch_both("x509.h",
"""long X509_REQ_get_version(const X509_REQ *req);
""",
"""/**
 * @brief Return the version field of a certificate request (0 for v1).
 * @param req Certificate request to query.
 * @return Version number (X509_REQ_VERSION_*), or -1 on error.
 */
long X509_REQ_get_version(const X509_REQ *req);
""", "X509_REQ_get_version")

patch_both("x509.h",
"""int X509_REQ_set_version(X509_REQ *x, long version);
""",
"""/**
 * @brief Set the version field of a certificate request.
 * @param x Certificate request to update.
 * @param version Version value (typically X509_REQ_VERSION_1 which is 0).
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_set_version(X509_REQ *x, long version);
""", "X509_REQ_set_version")

patch_both("x509.h",
"""int X509_aux_print(BIO *out, X509 *x, int indent);
""",
"""/**
 * @brief Print certificate auxiliary trust/reject/alias information to a BIO.
 * @param out BIO that receives the textual dump.
 * @param x Certificate whose aux data is printed.
 * @param indent Indentation width in spaces.
 * @return 1 on success, or 0 on failure.
 */
int X509_aux_print(BIO *out, X509 *x, int indent);
""", "X509_aux_print")

patch_both("x509.h",
"""X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc);
""",
"""/**
 * @brief Return the CRL extension at index @p loc without removing it.
 * @param x CRL to query.
 * @param loc Zero-based extension index.
 * @return Internal X509_EXTENSION pointer (do not free), or NULL if @p loc is out of range.
 */
X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc);
""", "X509_CRL_get_ext")

patch_both("x509.h",
"""int X509_EXTENSION_get_critical(const X509_EXTENSION *ex);
""",
"""/**
 * @brief Report whether an X.509 extension is marked critical.
 * @param ex Extension to query.
 * @return Non-zero if critical, or 0 if not.
 */
int X509_EXTENSION_get_critical(const X509_EXTENSION *ex);
""", "X509_EXTENSION_get_critical")

patch_both("x509.h",
"""int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
    const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len);
""",
"""/**
 * @brief Append an attribute identified by OID to an EVP_PKEY's attribute set.
 * @param key Key whose attributes are extended.
 * @param obj Attribute type OID.
 * @param type ASN.1 string/type code for @p bytes (for example V_ASN1_UTF8STRING).
 * @param bytes Attribute value bytes interpreted according to @p type.
 * @param len Length of @p bytes in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
    const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len);
""", "EVP_PKEY_add1_attr_by_OBJ")

# ----- x509_vfy.h -----
patch_both("x509_vfy.h",
"""X509_TRUST *X509_TRUST_get0(int idx);
""",
"""/**
 * @brief Return the X509_TRUST table entry at index @p idx.
 * @param idx Index from 0 to X509_TRUST_get_count()-1.
 * @return Internal X509_TRUST pointer (do not free), or NULL if @p idx is out of range.
 */
X509_TRUST *X509_TRUST_get0(int idx);
""", "X509_TRUST_get0")

patch_both("x509_vfy.h",
"""int X509_trusted(const X509 *x);
""",
"""/**
 * @brief Report whether a certificate has auxiliary trust information attached.
 * @param x Certificate to query.
 * @return Non-zero if trust aux data is present, or 0 otherwise.
 */
int X509_trusted(const X509 *x);
""", "X509_trusted")

patch_both("x509_vfy.h",
"""STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
""",
"""/**
 * @brief Return the stack of reject OIDs from a certificate's auxiliary data.
 * @param x Certificate to query.
 * @return Internal STACK_OF(ASN1_OBJECT) (do not free), or NULL if none.
 */
STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
""", "X509_get0_reject_objects")

patch_both("x509_vfy.h",
"""STACK_OF(X509) *X509_build_chain(X509 *target, STACK_OF(X509) *certs,
    X509_STORE *store, int with_self_signed,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
"""/**
 * @brief Build a certificate chain for @p target using untrusted @p certs and trusted @p store.
 * @param target End-entity certificate to chain up from.
 * @param certs Optional untrusted intermediate certificates, or NULL.
 * @param store Trusted certificate store used for trust anchors, or NULL.
 * @param with_self_signed Non-zero to include a self-signed trust anchor in the result.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Newly allocated chain stack (caller frees with sk_X509_pop_free), or NULL on failure.
 */
STACK_OF(X509) *X509_build_chain(X509 *target, STACK_OF(X509) *certs,
    X509_STORE *store, int with_self_signed,
    OSSL_LIB_CTX *libctx, const char *propq);
""", "X509_build_chain")

patch_both("x509_vfy.h",
"""X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name);
""",
"""/**
 * @brief Find the first X509_OBJECT in @p h matching @p type and subject @p name.
 * @param h Stack of X509_OBJECT entries to search.
 * @param type X509_LU_X509 or X509_LU_CRL selecting certificate vs CRL.
 * @param name Subject (for certs) or issuer (for CRLs) name to match.
 * @return Matching X509_OBJECT from @p h (do not free), or NULL if none.
 */
X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name);
""", "X509_OBJECT_retrieve_by_subject")

patch_both("x509_vfy.h",
"""STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(const X509_STORE_CTX *st,
    const X509_NAME *nm);
""",
"""/**
 * @brief Retrieve CRLs from the store behind @p st whose issuer matches @p nm.
 * @param st Verification context whose associated X509_STORE is queried.
 * @param nm Issuer name to look up.
 * @return Newly allocated STACK_OF(X509_CRL) with up-reffed CRLs (caller frees), or NULL on failure.
 */
STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(const X509_STORE_CTX *st,
    const X509_NAME *nm);
""", "X509_STORE_CTX_get1_crls")

patch_both("x509_vfy.h",
"""int X509_STORE_set1_param(X509_STORE *xs, const X509_VERIFY_PARAM *pm);
""",
"""/**
 * @brief Copy verification parameters from @p pm onto a certificate store.
 * @param xs Store whose default X509_VERIFY_PARAM is replaced/updated.
 * @param pm Source parameters to copy; must not be NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set1_param(X509_STORE *xs, const X509_VERIFY_PARAM *pm);
""", "X509_STORE_set1_param")

patch_both("x509_vfy.h",
"""void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
""",
"""/**
 * @brief Free an X509_STORE_CTX and release resources it owns.
 * @param ctx Verification context to free, or NULL (no-op).
 */
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
""", "X509_STORE_CTX_free")

patch_both("x509_vfy.h",
"""int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
    int (*new_item)(X509_LOOKUP *ctx));
""",
"""/**
 * @brief Set the per-LOOKUP instance constructor callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param new_item Callback that allocates method-specific state for a new X509_LOOKUP, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
    int (*new_item)(X509_LOOKUP *ctx));
""", "X509_LOOKUP_meth_set_new_item")

patch_both("x509_vfy.h",
"""int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
""",
"""/**
 * @brief Set the intended certificate purpose for a verification context.
 * @param ctx Store context whose verify parameters are updated.
 * @param purpose Purpose id such as X509_PURPOSE_SSL_CLIENT or X509_PURPOSE_SSL_SERVER.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
""", "X509_STORE_CTX_set_purpose")

patch_both("x509_vfy.h",
"""int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,
    const char *name, size_t namelen);
""",
"""/**
 * @brief Set the expected DNS/IP hostname for name checks, clearing any previous hosts.
 * @param param Verification parameters to update.
 * @param name Hostname or IP literal to expect (copied); NULL clears the list.
 * @param namelen Length of @p name in bytes (0 means NUL-terminated).
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,
    const char *name, size_t namelen);
""", "X509_VERIFY_PARAM_set1_host")

# ----- x509v3.h -----
patch_both("x509v3.h",
"""SKM_DEFINE_STACK_OF_INTERNAL(DIST_POINT, DIST_POINT, DIST_POINT)
""",
"""/**
 * @brief Opaque STACK_OF(DIST_POINT) container type.
 */
SKM_DEFINE_STACK_OF_INTERNAL(DIST_POINT, DIST_POINT, DIST_POINT)
""", "stack_st_DIST_POINT")

patch_both("x509v3.h",
"""int i2d_PROXY_CERT_INFO_EXTENSION(const PROXY_CERT_INFO_EXTENSION *a, unsigned char **out);
""",
"""/**
 * @brief Encode a Proxy Certificate Information extension value to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_PROXY_CERT_INFO_EXTENSION(const PROXY_CERT_INFO_EXTENSION *a, unsigned char **out);
""", "i2d_PROXY_CERT_INFO_EXTENSION")

patch_both("x509v3.h",
"""int X509v3_addr_add_prefix(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi,
    unsigned char *a, const int prefixlen);
""",
"""/**
 * @brief Add an IP address prefix to an IPAddrBlocks (RFC 3779) extension value.
 * @param addr Extension value to modify.
 * @param afi Address Family Identifier (IANA AFI).
 * @param safi Optional Subsequent Address Family Identifier, or NULL.
 * @param a Address bytes in network byte order (length implied by @p afi).
 * @param prefixlen Prefix length in bits.
 * @return 1 on success, or 0 on failure.
 */
int X509v3_addr_add_prefix(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi,
    unsigned char *a, const int prefixlen);
""", "X509v3_addr_add_prefix")

patch_both("x509v3.h",
"""int X509v3_addr_inherits(IPAddrBlocks *addr);
""",
"""/**
 * @brief Report whether an IPAddrBlocks value uses inheritance from the issuer.
 * @param addr IP address blocks extension to query.
 * @return 1 if any family inherits, or 0 otherwise.
 */
int X509v3_addr_inherits(IPAddrBlocks *addr);
""", "X509v3_addr_inherits")

patch_both("x509v3.h",
"""int X509v3_addr_validate_resource_set(STACK_OF(X509) *chain,
    IPAddrBlocks *ext, int allow_inheritance);
""",
"""/**
 * @brief Validate that IP address blocks in @p ext are covered by ancestors in @p chain.
 * @param chain Certificate chain (leaf first) used to check nested IPAddrBlocks extensions.
 * @param ext IP address resource set claimed by the leaf (or NULL to treat as empty).
 * @param allow_inheritance Non-zero to permit inherit elements when validating.
 * @return 1 if @p ext is valid given @p chain, or 0 otherwise.
 */
int X509v3_addr_validate_resource_set(STACK_OF(X509) *chain,
    IPAddrBlocks *ext, int allow_inheritance);
""", "X509v3_addr_validate_resource_set")

patch_both("x509v3.h",
"""void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY *n,
    ASN1_IA5STRING *namingAuthorityUrl);
""",
"""/**
 * @brief Set the authority URL on a NAMING_AUTHORITY, taking ownership of @p namingAuthorityUrl.
 * @param n Naming authority to update.
 * @param namingAuthorityUrl New URL IA5String, or NULL to clear; frees any previous value.
 */
void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY *n,
    ASN1_IA5STRING *namingAuthorityUrl);
""", "NAMING_AUTHORITY_set0_authorityURL")

patch_both("x509v3.h",
"""void PROFESSION_INFO_set0_professionItems(
    PROFESSION_INFO *pi, STACK_OF(ASN1_STRING) *as);
""",
"""/**
 * @brief Set the profession items (titles) on a PROFESSION_INFO, taking ownership of @p as.
 * @param pi Profession info whose professionItems field is replaced.
 * @param as Stack of profession-item strings, or NULL to clear; frees any previous stack.
 */
void PROFESSION_INFO_set0_professionItems(
    PROFESSION_INFO *pi, STACK_OF(ASN1_STRING) *as);
""", "PROFESSION_INFO_set0_professionItems")

patch_both("x509v3.h",
"""const ASN1_PRINTABLESTRING *PROFESSION_INFO_get0_registrationNumber(
    const PROFESSION_INFO *pi);
""",
"""/**
 * @brief Return the registration number from a PROFESSION_INFO without duplicating it.
 * @param pi Profession info to query.
 * @return Internal PrintableString pointer (do not free), or NULL if absent.
 */
const ASN1_PRINTABLESTRING *PROFESSION_INFO_get0_registrationNumber(
    const PROFESSION_INFO *pi);
""", "PROFESSION_INFO_get0_registrationNumber")

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print(" ", m)
