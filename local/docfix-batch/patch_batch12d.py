#!/usr/bin/env python3
"""Documentation repair batch 12d: ssl.h + x509.h + x509_vfy.h + x509v3.h."""
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


print("=== batch 12d: ssl.h + x509.h + x509_vfy.h + x509v3.h ===")

# =============================================================================
# ssl.h
# =============================================================================

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
    const unsigned char *serverinfo,
    size_t serverinfo_length);
""",
    """/**
 * @brief Load serverinfo TLS extensions in V1 or V2 format into an SSL context.
 * @param ctx SSL context whose active certificate receives the extensions.
 * @param version SSL_SERVERINFOV1 or SSL_SERVERINFOV2 describing @p serverinfo layout.
 * @param serverinfo Byte array of one or more serverinfo extensions.
 * @param serverinfo_length Length of @p serverinfo in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
    const unsigned char *serverinfo,
    size_t serverinfo_length);
""",
    "SSL_CTX_use_serverinfo_ex",
)

patch_both(
    "ssl.h",
    """__owur uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s);
""",
    """/**
 * @brief Return the maximum early-data (0-RTT) size allowed for a session.
 * @param s Session to query (typically from a prior handshake with the server).
 * @return Maximum early-data bytes that may be sent when resuming @p s, or 0 if early data is not allowed.
 */
__owur uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s);
""",
    "SSL_SESSION_get_max_early_data",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);
""",
    """/**
 * @brief Return the peer certificate verification mode currently set on an SSL context.
 * @param ctx SSL context to query.
 * @return Bitmask of SSL_VERIFY_* flags previously set with SSL_CTX_set_verify().
 */
__owur int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);
""",
    "SSL_CTX_get_verify_mode",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
    STACK_OF(X509) *chain, int override);
""",
    """/**
 * @brief Assign a certificate, private key, and optional chain onto an SSL context.
 * @param ctx SSL context that receives the credentials.
 * @param x509 End-entity X.509 certificate (reference count incremented on success).
 * @param privatekey Matching private key, or NULL to use @p x509's public key (e.g. hardware ENGINE).
 * @param chain Optional intermediate certificate chain, or NULL.
 * @param override If 0, set only when cert/key/chain were all previously unset; if non-zero, always replace.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
    STACK_OF(X509) *chain, int override);
""",
    "SSL_CTX_use_cert_and_key",
)

patch_both(
    "ssl.h",
    """void SSL_free(SSL *ssl);
""",
    """/**
 * @brief Decrement the reference count of an SSL connection and free it when it reaches zero.
 * @param ssl SSL object to release, or NULL (no-op).
 */
void SSL_free(SSL *ssl);
""",
    "SSL_free",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_method(void); /* TLSv1.0 */
""",
    """/**
 * @brief Return a client-or-server SSL_METHOD restricted to TLS 1.0 (deprecated; prefer TLS_method).
 * @return Pointer to the static TLSv1.0 SSL_METHOD for use with SSL_CTX_new.
 */
OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_method(void); /* TLSv1.0 */
""",
    "TLSv1_method",
)

patch_both(
    "ssl.h",
    """void SSL_set_info_callback(SSL *ssl,
    void (*cb)(const SSL *ssl, int type, int val));
""",
    """/**
 * @brief Set the information callback used to observe state changes, alerts, and errors on a connection.
 * @param ssl SSL connection whose info callback is replaced.
 * @param cb Callback invoked with SSL_CB_* @p type and @p val during handshake and I/O; NULL restores the SSL_CTX callback.
 */
void SSL_set_info_callback(SSL *ssl,
    void (*cb)(const SSL *ssl, int type, int val));
""",
    "SSL_set_info_callback",
)

patch_both(
    "ssl.h",
    """__owur const COMP_METHOD *SSL_get_current_expansion(const SSL *s);
""",
    """/**
 * @brief Return the compression method used for expanding (decompressing) received records.
 * @param s SSL connection to query.
 * @return COMP_METHOD in use for expansion, or NULL if compression is inactive / unavailable.
 */
__owur const COMP_METHOD *SSL_get_current_expansion(const SSL *s);
""",
    "SSL_get_current_expansion",
)

patch_both(
    "ssl.h",
    """__owur int SSL_net_write_desired(SSL *s);
""",
    """/**
 * @brief Report whether the SSL object wants to write to the network BIO.
 * @param s SSL connection (typically QUIC or non-blocking DTLS/TLS).
 * @return 1 if a network write should be attempted, or 0 otherwise.
 */
__owur int SSL_net_write_desired(SSL *s);
""",
    "SSL_net_write_desired",
)

patch_both(
    "ssl.h",
    """int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode);
""",
    """/**
 * @brief Enable Certificate Transparency validation on an SSL context (inherited by new connections).
 * @param ctx SSL context to configure.
 * @param validation_mode SSL_CT_VALIDATION_PERMISSIVE or SSL_CT_VALIDATION_STRICT.
 * @return 1 on success, or 0 on failure.
 */
int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode);
""",
    "SSL_CTX_enable_ct",
)

# =============================================================================
# x509.h — stack_st_X509_NAME_ENTRY
# =============================================================================

patch_one(
    "x509.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(X509_NAME_ENTRY, X509_NAME_ENTRY, X509_NAME_ENTRY)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(X509_NAME_ENTRY) container type.
 */
struct stack_st_X509_NAME_ENTRY;
SKM_DEFINE_STACK_OF_INTERNAL(X509_NAME_ENTRY, X509_NAME_ENTRY, X509_NAME_ENTRY)
""",
    "stack_st_X509_NAME_ENTRY",
)

patch_one(
    "x509.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("X509_NAME_ENTRY");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(X509_NAME_ENTRY) container type.
 */
struct stack_st_X509_NAME_ENTRY;
{-
    generate_stack_macros("X509_NAME_ENTRY");
-}
""",
    "stack_st_X509_NAME_ENTRY",
)

# =============================================================================
# x509.h — remaining symbols
# =============================================================================

patch_both(
    "x509.h",
    """typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
""",
    """/**
 * @brief Typedef for a STACK_OF(X509_EXTENSION) used as an ASN.1 SEQUENCE OF Extension.
 */
typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
""",
    "X509_EXTENSIONS",
)

patch_both(
    "x509.h",
    """void X509_CRL_set_default_method(const X509_CRL_METHOD *meth);
""",
    """/**
 * @brief Install the default custom CRL method used when looking up revoked entries.
 * @param meth CRL method table to use as the process-wide default, or NULL to clear.
 */
void X509_CRL_set_default_method(const X509_CRL_METHOD *meth);
""",
    "X509_CRL_set_default_method",
)

patch_both(
    "x509.h",
    """X509_CRL_METHOD *X509_CRL_METHOD_new(int (*crl_init)(X509_CRL *crl),
    int (*crl_free)(X509_CRL *crl),
    int (*crl_lookup)(X509_CRL *crl,
        X509_REVOKED **ret,
        const ASN1_INTEGER *serial,
        const X509_NAME *issuer),
    int (*crl_verify)(X509_CRL *crl,
        EVP_PKEY *pk));
""",
    """/**
 * @brief Allocate a custom CRL method with optional init, free, lookup, and verify callbacks.
 * @param crl_init Optional per-CRL initialization callback, or NULL.
 * @param crl_free Optional per-CRL cleanup callback, or NULL.
 * @param crl_lookup Optional revoked-entry lookup by serial/issuer, or NULL.
 * @param crl_verify Optional CRL signature verification callback, or NULL.
 * @return New X509_CRL_METHOD, or NULL on allocation failure; free with X509_CRL_METHOD_free.
 */
X509_CRL_METHOD *X509_CRL_METHOD_new(int (*crl_init)(X509_CRL *crl),
    int (*crl_free)(X509_CRL *crl),
    int (*crl_lookup)(X509_CRL *crl,
        X509_REVOKED **ret,
        const ASN1_INTEGER *serial,
        const X509_NAME *issuer),
    int (*crl_verify)(X509_CRL *crl,
        EVP_PKEY *pk));
""",
    "X509_CRL_METHOD_new",
)

patch_both(
    "x509.h",
    """void X509_CRL_set_meth_data(X509_CRL *crl, void *dat);
""",
    """/**
 * @brief Attach method-specific application data to a CRL for its X509_CRL_METHOD callbacks.
 * @param crl CRL whose method data pointer is replaced.
 * @param dat Opaque pointer retrieved later with X509_CRL_get_meth_data().
 */
void X509_CRL_set_meth_data(X509_CRL *crl, void *dat);
""",
    "X509_CRL_set_meth_data",
)

patch_both(
    "x509.h",
    """int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);
""",
    """/**
 * @brief Verify the signature on a Netscape Signed Public Key and Challenge (SPKI) structure.
 * @param a SPKI structure whose signature is checked.
 * @param r Public key expected to have signed @p a.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);
""",
    "NETSCAPE_SPKI_verify",
)

patch_both(
    "x509.h",
    """int X509_signature_print(BIO *bp, const X509_ALGOR *alg,
    const ASN1_STRING *sig);
""",
    """/**
 * @brief Print a signature algorithm and optional signature value to a BIO.
 * @param bp Destination BIO.
 * @param alg Signature algorithm identifier to print.
 * @param sig Signature bit string to dump, or NULL to print only the algorithm.
 * @return 1 on success, or 0 on failure.
 */
int X509_signature_print(BIO *bp, const X509_ALGOR *alg,
    const ASN1_STRING *sig);
""",
    "X509_signature_print",
)

patch_both(
    "x509.h",
    """int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
""",
    """/**
 * @brief Sign a certificate request with a private key and message digest.
 * @param x Certificate request that receives the signature.
 * @param pkey Private key used to sign.
 * @param md Message digest algorithm (for example EVP_sha256()), or NULL when implied by @p pkey.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
""",
    "X509_REQ_sign",
)

patch_both(
    "x509.h",
    """int X509_pubkey_digest(const X509 *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);
""",
    """/**
 * @brief Compute a digest of the DER-encoded public key of an X.509 certificate.
 * @param data Certificate whose SubjectPublicKeyInfo is digested.
 * @param type Digest algorithm such as EVP_sha1().
 * @param md Output buffer large enough for the digest (at least EVP_MAX_MD_SIZE).
 * @param len On success, set to the digest length in bytes; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_pubkey_digest(const X509 *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);
""",
    "X509_pubkey_digest",
)

patch_both(
    "x509.h",
    """int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);
""",
    """/**
 * @brief Compute a digest of the DER encoding of an entire X.509 CRL.
 * @param data CRL to digest.
 * @param type Digest algorithm such as EVP_sha1().
 * @param md Output buffer large enough for the digest (at least EVP_MAX_MD_SIZE).
 * @param len On success, set to the digest length in bytes; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);
""",
    "X509_CRL_digest",
)

patch_both(
    "x509.h",
    """X509_CRL *X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
""",
    """/**
 * @brief Load an X.509 CRL in ASN.1/DER form via HTTP from @p url.
 * @param url HTTP or HTTPS URL of the CRL.
 * @param bio Optional BIO used for the connection when @p rbio is NULL, or NULL for an internal BIO.
 * @param rbio Optional separate read BIO paired with @p bio, or NULL.
 * @param timeout Maximum seconds to wait, or 0 for no timeout / default behaviour.
 * @return Decoded X509_CRL, or NULL on error; free with X509_CRL_free.
 */
X509_CRL *X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
""",
    "X509_CRL_load_http",
)

patch_both(
    "x509.h",
    """EVP_PKEY *X509_PUBKEY_get(const X509_PUBKEY *key);
""",
    """/**
 * @brief Decode an X509_PUBKEY into an EVP_PKEY with an incremented reference count.
 * @param key SubjectPublicKeyInfo structure to decode.
 * @return New EVP_PKEY reference that must be freed with EVP_PKEY_free, or NULL on error.
 */
EVP_PKEY *X509_PUBKEY_get(const X509_PUBKEY *key);
""",
    "X509_PUBKEY_get",
)

patch_both(
    "x509.h",
    """int X509_get_signature_info(X509 *x, int *mdnid, int *pknid, int *secbits,
    uint32_t *flags);
""",
    """/**
 * @brief Retrieve digest NID, public-key NID, security bits, and flags for a certificate signature.
 * @param x Certificate whose signature metadata is queried.
 * @param mdnid Receives the signing digest NID, or NULL if not required.
 * @param pknid Receives the public-key algorithm NID, or NULL if not required.
 * @param secbits Receives the effective security strength in bits, or NULL if not required.
 * @param flags Receives X509_SIG_INFO_* flag bits, or NULL if not required.
 * @return 1 if usable signature info is present, or 0 if unavailable / malformed.
 */
int X509_get_signature_info(X509 *x, int *mdnid, int *pknid, int *secbits,
    uint32_t *flags);
""",
    "X509_get_signature_info",
)

patch_both(
    "x509.h",
    """X509_NAME *X509_get_issuer_name(const X509 *a);
""",
    """/**
 * @brief Return the issuer distinguished name of an X.509 certificate.
 * @param a Certificate to query.
 * @return Internal X509_NAME pointer (do not free), or NULL if unset.
 */
X509_NAME *X509_get_issuer_name(const X509 *a);
""",
    "X509_get_issuer_name",
)

patch_both(
    "x509.h",
    """X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x);
""",
    """/**
 * @brief Return the certificate's SubjectPublicKeyInfo as an X509_PUBKEY (for i2d_X509_PUBKEY).
 * @param x Certificate to query.
 * @return Internal X509_PUBKEY pointer (do not free), or NULL on error.
 */
X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x);
""",
    "X509_get_X509_PUBKEY",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
""",
    """/**
 * @brief Return the X.509 request attribute at index @p loc.
 * @param req Certificate request whose attributes are queried.
 * @param loc Attribute index from 0 to X509_REQ_get_attr_count(@p req) - 1.
 * @return Internal X509_ATTRIBUTE pointer (do not free), or NULL on error.
 */
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
""",
    "X509_REQ_get_attr",
)

patch_both(
    "x509.h",
    """long X509_CRL_get_version(const X509_CRL *crl);
""",
    """/**
 * @brief Return the numerical version field of an X.509 CRL.
 * @param crl CRL to query.
 * @return Version constant such as X509_CRL_VERSION_1 or X509_CRL_VERSION_2 (one less than the human version number).
 */
long X509_CRL_get_version(const X509_CRL *crl);
""",
    "X509_CRL_get_version",
)

patch_both(
    "x509.h",
    """void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg);
""",
    """/**
 * @brief Obtain internal pointers to a CRL's signature value and signature algorithm.
 * @param crl CRL to query.
 * @param psig Set to the signature BIT STRING (do not free), or may be NULL.
 * @param palg Set to the signature AlgorithmIdentifier (do not free), or may be NULL.
 */
void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg);
""",
    "X509_CRL_get0_signature",
)

patch_both(
    "x509.h",
    """int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent,
    unsigned long flags);
""",
    """/**
 * @brief Print a human-readable X509_NAME to a BIO with customizable formatting flags.
 * @param out Destination BIO.
 * @param nm Distinguished name to print.
 * @param indent Spaces of indentation applied to each line for multiline formats.
 * @param flags XN_FLAG_* / ASN1_STRFLGS_* controlling separators, case, and encoding.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent,
    unsigned long flags);
""",
    "X509_NAME_print_ex",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc);
""",
    """/**
 * @brief Return the extension at index @p loc from a stack of X509_EXTENSION.
 * @param x Stack of extensions to query; may be NULL.
 * @param loc Extension index from 0 to X509v3_get_ext_count(@p x) - 1.
 * @return Internal X509_EXTENSION pointer (do not free), or NULL on error.
 */
X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc);
""",
    "X509v3_get_ext",
)

patch_both(
    "x509.h",
    """int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos);
""",
    """/**
 * @brief Find the next extension on a certificate matching ASN.1 object @p obj.
 * @param x Certificate whose extensions are searched.
 * @param obj Extension type OID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Extension index, or -1 if not found.
 */
int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos);
""",
    "X509_get_ext_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
""",
    """/**
 * @brief Find the next extension on a CRL with the given NID.
 * @param x CRL whose extensions are searched.
 * @param nid Extension type NID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Extension index, or -1 if not found.
 */
int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
""",
    "X509_CRL_get_ext_by_NID",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
    int nid, int crit,
    ASN1_OCTET_STRING *data);
""",
    """/**
 * @brief Create (or reuse) an X509_EXTENSION with the given NID, criticality, and octet data.
 * @param ex Optional address of an X509_EXTENSION* to reuse or receive the result; must be NULL or a valid pointer.
 * @param nid Extension type NID.
 * @param crit Non-zero for a critical extension; 0 for non-critical.
 * @param data Extension value octets (duplicated internally).
 * @return New or updated X509_EXTENSION, or NULL on error.
 */
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
    int nid, int crit,
    ASN1_OCTET_STRING *data);
""",
    "X509_EXTENSION_create_by_NID",
)

patch_both(
    "x509.h",
    """int X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, int nid,
    int lastpos);
""",
    """/**
 * @brief Find the next attribute in a stack with the given NID.
 * @param x Stack of X509_ATTRIBUTE to search; may be NULL.
 * @param nid Attribute type NID (see openssl/obj_mac.h).
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Attribute index, -1 if not found, or -2 if @p nid is unknown to OpenSSL.
 */
int X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, int nid,
    int lastpos);
""",
    "X509at_get_attr_by_NID",
)

patch_both(
    "x509.h",
    """int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
    const unsigned char *salt, int saltlen);
""",
    """/**
 * @brief Set a PKCS#5 PBE algorithm OID and parameters into an existing X509_ALGOR.
 * @param algor AlgorithmIdentifier to update in place.
 * @param alg PBE algorithm NID (for example NID_pbeWithMD5AndDES_CBC).
 * @param iter PBKDF iteration count.
 * @param salt Optional salt bytes, or NULL to generate @p saltlen random bytes (0 uses a default length).
 * @param saltlen Salt length in bytes, or size to generate when @p salt is NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
    const unsigned char *salt, int saltlen);
""",
    "PKCS5_pbe_set0_algor",
)

# =============================================================================
# x509_vfy.h
# =============================================================================

patch_both(
    "x509_vfy.h",
    """int X509_TRUST_get_trust(const X509_TRUST *xp);
""",
    """/**
 * @brief Return the trust purpose identifier of an X509_TRUST table entry.
 * @param xp Trust entry to query.
 * @return Trust id such as X509_TRUST_SSL_CLIENT or X509_TRUST_SSL_SERVER.
 */
int X509_TRUST_get_trust(const X509_TRUST *xp);
""",
    "X509_TRUST_get_trust",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE *xs);
""",
    """/**
 * @brief Return the get-issuer callback currently installed on a certificate store.
 * @param xs Store to query.
 * @return Function pointer previously set with X509_STORE_set_get_issuer(), or NULL for the default.
 */
X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE *xs);
""",
    "X509_STORE_get_get_issuer",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509) *X509_STORE_CTX_get0_untrusted(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the stack of untrusted certificates associated with a verification context.
 * @param ctx Store context to query.
 * @return Internal STACK_OF(X509) pointer (do not free the stack itself), or NULL if unset.
 */
STACK_OF(X509) *X509_STORE_CTX_get0_untrusted(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_untrusted",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the get_crl callback currently installed on a verification context.
 * @param ctx Store context to query.
 * @return Function pointer cached from the associated X509_STORE (or set on @p ctx), or NULL for the default.
 */
X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_get_crl",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_alias_fn fn);
""",
    """/**
 * @brief Set the get-by-alias callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param fn Callback that finds an X509_OBJECT by alias string, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_alias_fn fn);
""",
    "X509_LOOKUP_meth_set_get_by_alias",
)

patch_both(
    "x509_vfy.h",
    """int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    """/**
 * @brief Load certificates and CRLs from @p file into the store associated with a lookup.
 * @param ctx Lookup whose associated X509_STORE receives the objects.
 * @param file Path to a PEM file (or ASN.1 when @p type is FILETYPE_ASN1).
 * @param type FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_DEFAULT.
 * @return Number of objects loaded, or 0 on failure.
 */
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    "X509_load_cert_crl_file",
)

patch_both(
    "x509_vfy.h",
    """void X509_LOOKUP_free(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Free an X509_LOOKUP and its method-specific state.
 * @param ctx Lookup to free, or NULL (no-op).
 */
void X509_LOOKUP_free(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_free",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_by_subject_ex(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Look up a certificate or CRL by subject name with an explicit library context.
 * @param ctx Lookup to query.
 * @param type X509_LU_X509 or X509_LU_CRL selecting the object kind.
 * @param name Subject (or CRL issuer) name to match.
 * @param ret Destination X509_OBJECT that receives the result on success.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure / not found.
 */
int X509_LOOKUP_by_subject_ex(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_LOOKUP_by_subject_ex",
)

patch_both(
    "x509_vfy.h",
    """void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx);
""",
    """/**
 * @brief Retrieve application-specific ex_data previously stored on a verification context.
 * @param ctx Store context to query.
 * @param idx Index obtained from X509_STORE_CTX_get_ex_new_index() (0 is used for app_data).
 * @return Pointer previously set with X509_STORE_CTX_set_ex_data(), or NULL if unset.
 */
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx);
""",
    "X509_STORE_CTX_get_ex_data",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the certificate-chain depth at which the current verification error occurred.
 * @param ctx Store context after verification or inside a verify callback.
 * @return Nonnegative depth (0 = end-entity certificate, 1 = its issuer, and so on).
 */
int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_error_depth",
)

patch_both(
    "x509_vfy.h",
    """char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the expected RFC822 email address set on verification parameters.
 * @param param Verification parameters to query.
 * @return Internal email string (do not free), or NULL if unset.
 */
char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get0_email",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the maximum certificate-chain depth allowed by verification parameters.
 * @param param Verification parameters to query.
 * @return Current verification depth limit.
 */
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get_depth",
)

patch_both(
    "x509_vfy.h",
    """int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
    STACK_OF(X509) *certs,
    STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags);
""",
    """/**
 * @brief Build an X.509 certificate policy tree for a chain and optional user policy OIDs.
 * @param ptree On success, set to a newly allocated policy tree; free with X509_policy_tree_free.
 * @param pexplicit_policy Set to nonzero when an explicit policy is required by the chain.
 * @param certs Certificate chain ordered end-entity first.
 * @param policy_oids Optional user-initial-policy-set of ASN1_OBJECT OIDs, or NULL.
 * @param flags Policy evaluation flags (for example X509_V_FLAG_POLICY_CHECK related bits).
 * @return Positive X509_PCY_TREE_* bitmask on success, or a negative value on failure.
 */
int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
    STACK_OF(X509) *certs,
    STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags);
""",
    "X509_policy_check",
)

patch_both(
    "x509_vfy.h",
    """void X509_policy_tree_free(X509_POLICY_TREE *tree);
""",
    """/**
 * @brief Free a certificate policy tree allocated by X509_policy_check().
 * @param tree Policy tree to free, or NULL (no-op).
 */
void X509_policy_tree_free(X509_POLICY_TREE *tree);
""",
    "X509_policy_tree_free",
)

patch_both(
    "x509_vfy.h",
    """X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree,
    int i);
""",
    """/**
 * @brief Return a level of a certificate policy tree by index.
 * @param tree Policy tree from X509_policy_check().
 * @param i Level index from 0 to X509_policy_tree_level_count(@p tree) - 1.
 * @return Internal X509_POLICY_LEVEL pointer (do not free), or NULL if @p i is out of range.
 */
X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree,
    int i);
""",
    "X509_policy_tree_get0_level",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509_POLICY_NODE)
*X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);
""",
    """/**
 * @brief Return the authority-constrained policy set (valid policy nodes) of a policy tree.
 * @param tree Policy tree from X509_policy_check().
 * @return Internal STACK_OF(X509_POLICY_NODE) (do not free), or NULL if empty / unavailable.
 */
STACK_OF(X509_POLICY_NODE)
*X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);
""",
    "X509_policy_tree_get0_policies",
)

patch_both(
    "x509_vfy.h",
    """X509_POLICY_NODE *X509_policy_level_get0_node(const X509_POLICY_LEVEL *level,
    int i);
""",
    """/**
 * @brief Return a policy node at index @p i within a policy-tree level.
 * @param level Policy level from X509_policy_tree_get0_level().
 * @param i Node index from 0 to X509_policy_level_node_count(@p level) - 1.
 * @return Internal X509_POLICY_NODE pointer (do not free), or NULL if out of range.
 */
X509_POLICY_NODE *X509_policy_level_get0_node(const X509_POLICY_LEVEL *level,
    int i);
""",
    "X509_policy_level_get0_node",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(POLICYQUALINFO)
*X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node);
""",
    """/**
 * @brief Return the policy qualifiers associated with a policy-tree node.
 * @param node Policy node to query.
 * @return Internal STACK_OF(POLICYQUALINFO) (do not free), or NULL if none.
 */
STACK_OF(POLICYQUALINFO)
*X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node);
""",
    "X509_policy_node_get0_qualifiers",
)

patch_both(
    "x509_vfy.h",
    """const X509_POLICY_NODE *X509_policy_node_get0_parent(const X509_POLICY_NODE *node);
""",
    """/**
 * @brief Return the parent policy-tree node of @p node, if any.
 * @param node Policy node to query.
 * @return Internal parent X509_POLICY_NODE pointer (do not free), or NULL for a root node.
 */
const X509_POLICY_NODE *X509_policy_node_get0_parent(const X509_POLICY_NODE *node);
""",
    "X509_policy_node_get0_parent",
)

# =============================================================================
# x509v3.h
# =============================================================================

patch_both(
    "x509v3.h",
    """#define X509V3_CTX_REPLACE 0x2
    int flags;
    /** Issuer certificate used when constructing context-dependent extensions. */
""",
    """#define X509V3_CTX_REPLACE 0x2
    /** Context flags such as X509V3_CTX_TEST or X509V3_CTX_REPLACE. */
    int flags;
    /** Issuer certificate used when constructing context-dependent extensions. */
""",
    "v3_ext_ctx.flags",
)

patch_both(
    "x509v3.h",
    """PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a, const unsigned char **in, long len);
""",
    """/**
 * @brief Decode a PROXY_CERT_INFO_EXTENSION structure from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded PROXY_CERT_INFO_EXTENSION, or NULL on error.
 */
PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a, const unsigned char **in, long len);
""",
    "d2i_PROXY_CERT_INFO_EXTENSION",
)

patch_both(
    "x509v3.h",
    """void *X509V3_EXT_d2i(X509_EXTENSION *ext);
""",
    """/**
 * @brief Decode the ASN.1 value of an X509_EXTENSION into its extension-specific C structure.
 * @param ext Extension whose octet string is decoded according to its OID.
 * @return Newly allocated extension-specific object, or NULL if unsupported / malformed; free with the matching free function.
 */
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
""",
    "X509V3_EXT_d2i",
)

patch_both(
    "x509v3.h",
    """int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);
""",
    """/**
 * @brief Check whether a certificate's subjectAltName contains an IP address in binary form.
 * @param x Certificate to match.
 * @param chk IPv4 (4 bytes) or IPv6 (16 bytes) address in network byte order.
 * @param chklen Length of @p chk in bytes (4 or 16).
 * @param flags X509_CHECK_FLAG_* controlling comparison behaviour (currently unused for IP).
 * @return 1 on match, 0 on no match, or -1 on malformed input / error.
 */
int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);
""",
    "X509_check_ip",
)

patch_both(
    "x509v3.h",
    """void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa);
""",
    """/**
 * @brief Set the admission authority GENERAL_NAME on an ADMISSIONS entry, transferring ownership.
 * @param a Admissions entry to update; any previous authority is freed.
 * @param aa New admission authority, or NULL to clear; ownership transfers to @p a.
 */
void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa);
""",
    "ADMISSIONS_set0_admissionAuthority",
)

patch_both(
    "x509v3.h",
    """void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi);
""",
    """/**
 * @brief Set the profession-info stack on an ADMISSIONS entry, transferring ownership.
 * @param a Admissions entry to update; any previous stack is freed.
 * @param pi New PROFESSION_INFOS stack, or NULL to clear; ownership transfers to @p a.
 */
void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi);
""",
    "ADMISSIONS_set0_professionInfos",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
