#!/usr/bin/env python3
"""Documentation repair batch 17e: pkcs7, rand, rsa, sha, ssl, stack, types, x509*."""
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


def patch_one(rel, old, new, label):
    path = INC / rel
    if not path.exists():
        print(f"  MISS: {rel} :: {label}:no-file")
        missing.append(f"{rel}:{label}:no-file")
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(f"{path.name}:{label}")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {path.name} :: {label}")
    ok.append(f"{path.name}:{label}")


print("=== batch 17e: remaining headers ===")

# ----- pkcs7.h -----

patch_both(
    "pkcs7.h",
    """int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
""",
    """/**
 * @brief Finalize PKCS#7 content processing after data has been written through @p bio.
 * @param p7 PKCS#7 structure being signed, enveloped, or digested.
 * @param bio Filter BIO chain previously obtained from PKCS7_dataInit() / related setup.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
""",
    "PKCS7_dataFinal",
)

# ----- rand.h -----

patch_both(
    "rand.h",
    """int RAND_write_file(const char *file);
""",
    """/**
 * @brief Write a seed file containing entropy from the CSPRNG for later RAND_load_file() use.
 * @param file Path of the seed file to create or overwrite.
 * @return Number of bytes written, or -1 on failure.
 */
int RAND_write_file(const char *file);
""",
    "RAND_write_file",
)

# ----- rsa.h -----

patch_both(
    "rsa.h",
    """    X509_ALGOR *hashFunc;
    X509_ALGOR *maskGenFunc;
""",
    """    X509_ALGOR *hashFunc;
    /** AlgorithmIdentifier for the OAEP mask generation function (typically MGF1). */
    X509_ALGOR *maskGenFunc;
""",
    "maskGenFunc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
""",
    """/**
 * @brief Return the public-encrypt callback installed on a custom RSA_METHOD (deprecated).
 * @param meth Method object to query.
 * @return Pointer to the pub_enc callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
""",
    "RSA_meth_get_pub_enc",
)

# ----- sha.h -----

patch_both(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 void SHA512_Transform(SHA512_CTX *c,
    const unsigned char *data);
""",
    """/**
 * @brief Process one SHA-512 block into @p c (deprecated low-level primitive).
 * @param c SHA-512 context whose state is updated.
 * @param data Exactly SHA512_CBLOCK bytes of input.
 */
OSSL_DEPRECATEDIN_3_0 void SHA512_Transform(SHA512_CTX *c,
    const unsigned char *data);
""",
    "SHA512_Transform",
)

# ----- ssl.h -----

patch_both(
    "ssl.h",
    """__owur const char *SSL_CIPHER_get_version(const SSL_CIPHER *c);
""",
    """/**
 * @brief Return the protocol version name associated with a cipher suite (for example \"TLSv1.2\").
 * @param c Cipher suite to query.
 * @return Static version string, or \"(NONE)\" if @p c is NULL.
 */
__owur const char *SSL_CIPHER_get_version(const SSL_CIPHER *c);
""",
    "SSL_CIPHER_get_version",
)

patch_both(
    "ssl.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
__owur int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
#endif
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Load an RSA private key from a PEM/DER file into an SSL connection (deprecated).
 * @param ssl SSL connection that receives the key.
 * @param file Path to the RSA private-key file.
 * @param type Encoding: SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
__owur int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
#endif
""",
    "SSL_use_RSAPrivateKey_file",
)

patch_both(
    "ssl.h",
    """__owur time_t SSL_SESSION_set_time_ex(SSL_SESSION *s, time_t t);
""",
    """/**
 * @brief Set the session creation time as a time_t (Y2038-safe counterpart to SSL_SESSION_set_time).
 * @param s Session to update.
 * @param t Creation time in seconds since the Epoch.
 * @return @p t on success, or 0 if @p s is NULL.
 */
__owur time_t SSL_SESSION_set_time_ex(SSL_SESSION *s, time_t t);
""",
    "SSL_SESSION_set_time_ex",
)

patch_both(
    "ssl.h",
    """const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
    unsigned int *len);
""",
    """/**
 * @brief Return the session identifier bytes of an SSL_SESSION.
 * @param s Session to query.
 * @param len If non-NULL, receives the session-id length in bytes (0..SSL_MAX_SSL_SESSION_ID_LENGTH).
 * @return Pointer to the internal session-id bytes (do not free).
 */
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
    unsigned int *len);
""",
    "SSL_SESSION_get_id",
)

patch_both(
    "ssl.h",
    """__owur STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s);
""",
    """/**
 * @brief Return the CA names offered for client authentication on this connection.
 * @param s SSL connection to query (typically a client that received CertificateRequest).
 * @return Stack of X509_NAME objects (do not free), or NULL if none are available.
 */
__owur STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s);
""",
    "SSL_get_client_CA_list",
)

patch_both(
    "ssl.h",
    """__owur OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl);
""",
    """/**
 * @brief Return the current TLS/DTLS/QUIC handshake state enumeration for @p ssl.
 * @param ssl SSL connection to query.
 * @return OSSL_HANDSHAKE_STATE value describing where the handshake state machine is.
 */
__owur OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl);
""",
    "SSL_get_state",
)

patch_both(
    "ssl.h",
    """int SSL_set_record_padding_callback(SSL *ssl,
    size_t (*cb)(SSL *ssl, int type,
        size_t len, void *arg));
""",
    """/**
 * @brief Install a TLS 1.3 record-padding callback on a connection.
 * @param ssl SSL connection whose outbound records may be padded.
 * @param cb Callback returning extra padding length for a record of content type @c type and plaintext length @c len; may be NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int SSL_set_record_padding_callback(SSL *ssl,
    size_t (*cb)(SSL *ssl, int type,
        size_t len, void *arg));
""",
    "SSL_set_record_padding_callback",
)

patch_both(
    "ssl.h",
    """#ifndef OPENSSL_NO_QUIC
__owur int SSL_inject_net_dgram(SSL *s, const unsigned char *buf,
    size_t buf_len,
    const BIO_ADDR *peer,
    const BIO_ADDR *local);
#endif
""",
    """#ifndef OPENSSL_NO_QUIC
/**
 * @brief Inject a received UDP datagram into a QUIC SSL object's network BIO path.
 * @param s QUIC connection or listener SSL object.
 * @param buf Datagram payload bytes.
 * @param buf_len Length of @p buf.
 * @param peer Optional peer address associated with the datagram, or NULL.
 * @param local Optional local address associated with the datagram, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_inject_net_dgram(SSL *s, const unsigned char *buf,
    size_t buf_len,
    const BIO_ADDR *peer,
    const BIO_ADDR *local);
#endif
""",
    "SSL_inject_net_dgram",
)

# ----- stack.h -----

patch_one(
    "stack.h",
    """typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
""",
    """/**
 * @brief Comparison callback used to order or search OPENSSL_STACK elements.
 * @param a First element pointer (as stored in the stack).
 * @param b Second element pointer (as stored in the stack).
 * @return Negative, zero, or positive like strcmp() when comparing @p a to @p b.
 */
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
""",
    "OPENSSL_sk_compfunc",
)

# ----- types.h -----

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_IA5STRING;
""",
    """/**
 * @brief ASN.1 IA5String stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_IA5STRING;
""",
    "ASN1_IA5STRING",
)

patch_one(
    "types.h",
    """typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
""",
    """/**
 * @brief Temporary-variable pool used by BIGNUM arithmetic helpers.
 */
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
/**
 * @brief Reciprocal context accelerating repeated modular division/remainder.
 */
typedef struct bn_recp_ctx_st BN_RECP_CTX;
""",
    "BN_CTX+BN_RECP_CTX",
)

patch_one(
    "types.h",
    """typedef struct rand_drbg_st RAND_DRBG;

typedef struct ssl_dane_st SSL_DANE;
""",
    """/**
 * @brief Legacy deterministic random bit generator handle (deprecated; prefer EVP_RAND).
 */
typedef struct rand_drbg_st RAND_DRBG;

/**
 * @brief Opaque DANE (DNS-based Authentication of Named Entities) state for TLS.
 */
typedef struct ssl_dane_st SSL_DANE;
""",
    "RAND_DRBG+SSL_DANE",
)

patch_one(
    "types.h",
    """typedef struct ssl_st SSL;
""",
    """/**
 * @brief Opaque TLS/DTLS/QUIC connection object.
 */
typedef struct ssl_st SSL;
""",
    "SSL",
)

patch_one(
    "types.h",
    """typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;
""",
    """/**
 * @brief Opaque Certificate Transparency policy evaluation context.
 */
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;
""",
    "CT_POLICY_EVAL_CTX",
)

patch_one(
    "types.h",
    """typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
""",
    """/**
 * @brief Callback that supplies a passphrase when reading or writing encrypted PEM.
 * @param buf Output buffer that receives a NUL-terminated password.
 * @param size Capacity of @p buf in bytes.
 * @param rwflag 0 when reading (decrypt), nonzero when writing (encrypt).
 * @param userdata Application pointer from the PEM API that invoked the callback.
 * @return Number of password bytes written to @p buf (excluding NUL), or 0 on failure.
 */
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
""",
    "pem_password_cb",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
""",
    """/**
 * @brief Set the notBefore validity instant on a certificate (copies @p tm).
 * @param x Certificate whose validity period is updated.
 * @param tm New notBefore time; must not be NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
""",
    "X509_set1_notBefore",
)

patch_both(
    "x509.h",
    """const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl);
""",
    """/**
 * @brief Return the thisUpdate (lastUpdate) time of a CRL without copying.
 * @param crl CRL to query.
 * @return Internal ASN1_TIME pointer (do not free), or NULL if unset.
 */
const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl);
""",
    "X509_CRL_get0_lastUpdate",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
""",
    """/**
 * @brief Return the extension at index @p loc on a certificate.
 * @param x Certificate whose extensions are accessed.
 * @param loc Zero-based index in [0, X509_get_ext_count(x)).
 * @return Internal X509_EXTENSION pointer (do not free), or NULL if @p loc is out of range.
 */
X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
""",
    "X509_get_ext",
)

patch_both(
    "x509.h",
    """int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
    unsigned long flags);
""",
    """/**
 * @brief Encode @p value as an extension with NID @p nid and append/replace it on a certificate.
 * @param x Certificate that receives the extension.
 * @param nid Extension OID NID (for example NID_subject_alt_name).
 * @param value Extension-specific C structure matching @p nid's ASN.1 type.
 * @param crit Nonzero to mark the extension critical.
 * @param flags X509V3_ADD_* behaviour flags (append, replace, keep existing, silent).
 * @return 1 on success, 0 on error, or -1 when rejected by @p flags (for example keep-existing).
 */
int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
    unsigned long flags);
""",
    "X509_add1_ext_i2d",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbkdf2_set_ex(int iter, unsigned char *salt, int saltlen,
    int prf_nid, int keylen,
    OSSL_LIB_CTX *libctx);
""",
    """/**
 * @brief Build an X509_ALGOR describing PBKDF2 parameters (library-context aware).
 * @param iter PBKDF2 iteration count.
 * @param salt Salt octets; may be NULL to generate a random salt of @p saltlen.
 * @param saltlen Salt length in bytes.
 * @param prf_nid NID of the PRF digest (for example NID_hmacWithSHA256); <= 0 selects the default.
 * @param keylen Derived key length in bytes to encode in the parameters; <= 0 omits it.
 * @param libctx Library context used for any random salt generation; NULL uses the default.
 * @return New X509_ALGOR on success, or NULL on failure.
 */
X509_ALGOR *PKCS5_pbkdf2_set_ex(int iter, unsigned char *salt, int saltlen,
    int prf_nid, int keylen,
    OSSL_LIB_CTX *libctx);
""",
    "PKCS5_pbkdf2_set_ex",
)

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """    /** @brief Integer argument associated with this trust entry. */
    int arg1;
    void *arg2;
} X509_TRUST;
""",
    """    /** @brief Integer argument associated with this trust entry. */
    int arg1;
    /** Opaque application pointer associated with this trust entry. */
    void *arg2;
} X509_TRUST;
""",
    "X509_TRUST::arg2",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Release verification state inside @p ctx so it can be re-initialised or freed.
 * @param ctx Store context to clean; safe on a freshly zeroed or already-clean context.
 */
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_cleanup",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
""",
    """/**
 * @brief Set the untrusted intermediate certificate stack used during chain building.
 * @param ctx Verification context to update.
 * @param sk Stack of untrusted certificates; ownership transfers to @p ctx (may be NULL).
 */
void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
""",
    "X509_STORE_CTX_set0_untrusted",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the revocation-checking callback installed on a verification context.
 * @param ctx Verification context to query.
 * @return Function pointer used to check revocation, or NULL if unset.
 */
X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_check_revocation",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk);
""",
    """/**
 * @brief Provide an additional CRL stack for revocation checks on @p ctx.
 * @param ctx Verification context to update.
 * @param sk Stack of CRLs; ownership transfers to @p ctx (may be NULL).
 */
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk);
""",
    "X509_STORE_CTX_set0_crls",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
    time_t t);
""",
    """/**
 * @brief Override the validation time used when checking certificate/CRL validity on @p ctx.
 * @param ctx Verification context to update.
 * @param flags Reserved; pass 0.
 * @param t Time instant used instead of the current time for notBefore/notAfter checks.
 */
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
    time_t t);
""",
    "X509_STORE_CTX_set_time",
)

# ----- x509v3.h -----

patch_both(
    "x509v3.h",
    """CERTIFICATEPOLICIES *d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a, const unsigned char **in, long len);
""",
    """/**
 * @brief Decode a DER-encoded certificatePolicies extension into a CERTIFICATEPOLICIES stack.
 * @param a Optional out-parameter receiving the result (reuses *@p a when non-NULL).
 * @param in Address of a pointer to the DER input; advanced past the consumed bytes on success.
 * @param len Number of bytes available at *@p in.
 * @return Decoded CERTIFICATEPOLICIES stack, or NULL on error.
 */
CERTIFICATEPOLICIES *d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a, const unsigned char **in, long len);
""",
    "d2i_CERTIFICATEPOLICIES",
)

patch_both(
    "x509v3.h",
    """int i2d_DIST_POINT(const DIST_POINT *a, unsigned char **out);
""",
    """/**
 * @brief DER-encode a DistributionPoint structure.
 * @param a Distribution point to encode.
 * @param out Optional; when non-NULL, receives allocated DER or advances an existing buffer pointer.
 * @return Length of the DER encoding in bytes, or a negative value on error.
 */
int i2d_DIST_POINT(const DIST_POINT *a, unsigned char **out);
""",
    "i2d_DIST_POINT",
)

patch_both(
    "x509v3.h",
    """void PROFESSION_INFO_set0_addProfessionInfo(
    PROFESSION_INFO *pi, ASN1_OCTET_STRING *aos);
""",
    """/**
 * @brief Set the additionalProfessionInfo OCTET STRING on a PROFESSION_INFO, taking ownership of @p aos.
 * @param pi Profession info whose addProfessionInfo field is replaced.
 * @param aos OCTET STRING to adopt, or NULL to clear the field.
 */
void PROFESSION_INFO_set0_addProfessionInfo(
    PROFESSION_INFO *pi, ASN1_OCTET_STRING *aos);
""",
    "PROFESSION_INFO_set0_addProfessionInfo",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
for m in missing:
    print(" ", m)
