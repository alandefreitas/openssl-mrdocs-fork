#!/usr/bin/env python3
"""Documentation repair batch 11d: ssl.h + x509.h."""
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


print("=== batch 11d: ssl.h + x509.h ===")


# ----- ssl.h -----
patch_both(
    "ssl.h",
    """typedef int (*custom_ext_add_cb)(SSL *s, unsigned int ext_type,
    const unsigned char **out, size_t *outlen,
    int *al, void *add_arg);
""",
    """/**
 * @brief Callback that supplies payload bytes for a legacy custom TLS extension being sent.
 * @param s SSL connection constructing the extension.
 * @param ext_type TLS extension type code being added.
 * @param out Set to point at the extension payload bytes to send.
 * @param outlen Receives the length of *@p out.
 * @param al Set to a TLS alert description if the callback fails.
 * @param add_arg Application argument registered with the extension.
 * @return 1 to include the extension, 0 to omit it, or a negative value to abort with *@p al.
 */
typedef int (*custom_ext_add_cb)(SSL *s, unsigned int ext_type,
    const unsigned char **out, size_t *outlen,
    int *al, void *add_arg);
""",
    "custom_ext_add_cb",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_3_0 int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
""",
    """/**
 * @brief Free SRP parameters stored on an SSL_CTX (deprecated).
 * @param ctx SSL context whose SRP BIGNUMs and strings are released.
 * @return 1 on success (including when @p ctx is NULL).
 */
OSSL_DEPRECATEDIN_3_0 int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
""",
    "SSL_CTX_SRP_CTX_free",
)

patch_both(
    "ssl.h",
    """const char *SSL_get0_group_name(SSL *s);
""",
    """/**
 * @brief Return the name of the key-exchange group negotiated on @p s.
 * @param s SSL connection after a successful handshake (or once the group is known).
 * @return Internal NUL-terminated group name string, or NULL if none is available; do not free.
 */
const char *SSL_get0_group_name(SSL *s);
""",
    "SSL_get0_group_name",
)

patch_both(
    "ssl.h",
    """void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
""",
    """/**
 * @brief Attach read and write BIOs to an SSL connection, transferring ownership as appropriate.
 * @param s SSL connection whose I/O channels are replaced.
 * @param rbio BIO used for reading encrypted records; may equal @p wbio for a shared BIO.
 * @param wbio BIO used for writing encrypted records; freed with @p s subject to reference rules when shared.
 */
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
""",
    "SSL_set_bio",
)

patch_both(
    "ssl.h",
    """/* PEM type */
__owur int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
""",
    """/**
 * @brief Load a PEM certificate chain from @p file into @p ctx.
 * @param ctx SSL context that receives the end-entity certificate and any following CA certs.
 * @param file Path to a PEM file containing the leaf certificate followed by optional intermediates.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
""",
    "SSL_CTX_use_certificate_chain_file",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
""",
    """/**
 * @brief Set peer certificate verification mode and optional callback for an SSL context.
 * @param ctx SSL context whose default verify settings are updated (inherited by SSL_new).
 * @param mode Bitmask of SSL_VERIFY_* flags controlling whether and how peers are verified.
 * @param callback Optional verify callback invoked during certificate checking, or NULL for the default.
 */
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
""",
    "SSL_CTX_set_verify",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx,
    const unsigned char *d, long len);
""",
    """/**
 * @brief Install a private key of type @p pk from a DER buffer on an SSL context.
 * @param pk Private-key ASN.1 type such as EVP_PKEY_RSA or EVP_PKEY_EC.
 * @param ctx SSL context that receives the key; it must match any certificate already set.
 * @param d Buffer containing a DER-encoded private key of type @p pk.
 * @param len Length of @p d in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx,
    const unsigned char *d, long len);
""",
    "SSL_CTX_use_PrivateKey_ASN1",
)

patch_both(
    "ssl.h",
    """__owur int SSL_get_async_status(SSL *s, int *status);
""",
    """/**
 * @brief Query the current asynchronous operation status for an SSL connection.
 * @param s SSL connection used with SSL_MODE_ASYNC.
 * @param status Receives an ASYNC_* status code describing wait or completion state.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_get_async_status(SSL *s, int *status);
""",
    "SSL_get_async_status",
)

patch_both(
    "ssl.h",
    """int SSL_renegotiate(SSL *s);
""",
    """/**
 * @brief Schedule a full renegotiation of the current TLS ≤ 1.2 connection.
 * @param s SSL connection that has negotiated TLSv1.2 or earlier.
 * @return 1 on success, or 0 on error.
 */
int SSL_renegotiate(SSL *s);
""",
    "SSL_renegotiate",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
""",
    """/**
 * @brief Set the list of CA names sent to clients when requesting a client certificate.
 * @param ctx SSL context (typically a server) that owns @p name_list after this call.
 * @param name_list Stack of X509_NAME objects identifying acceptable CAs; ownership transfers to @p ctx.
 */
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
""",
    "SSL_CTX_set_client_CA_list",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_not_resumable_session_callback(SSL_CTX *ctx,
    int (*cb)(SSL *ssl,
        int
            is_forward_secure));
""",
    """/**
 * @brief Register a context-wide callback that decides whether new sessions may be resumed.
 * @param ctx SSL context whose sessions inherit this policy (copied to new SSL objects by SSL_new).
 * @param cb Callback returning non-zero to mark the session non-resumable; @p is_forward_secure indicates forward secrecy.
 */
void SSL_CTX_set_not_resumable_session_callback(SSL_CTX *ctx,
    int (*cb)(SSL *ssl,
        int
            is_forward_secure));
""",
    "SSL_CTX_set_not_resumable_session_callback",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg);
""",
    """/**
 * @brief Set the opaque argument passed to the context's TLS 1.3 record-padding callback.
 * @param ctx SSL context whose padding callback argument is set (inherited by SSL_new).
 * @param arg Pointer forwarded as the callback's @c arg parameter, or NULL.
 */
void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg);
""",
    "SSL_CTX_set_record_padding_callback_arg",
)


# ----- x509.h -----
patch_both(
    "x509.h",
    """typedef struct X509_extension_st X509_EXTENSION;
""",
    """/**
 * @brief Opaque X.509 extension object (OID, criticality, and octet-string value).
 */
typedef struct X509_extension_st X509_EXTENSION;
""",
    "X509_EXTENSION",
)

patch_both(
    "x509.h",
    """int X509_self_signed(X509 *cert, int verify_signature);
""",
    """/**
 * @brief Test whether @p cert is self-issued, optionally verifying its signature.
 * @param cert Certificate to examine.
 * @param verify_signature Non-zero to verify the signature with the certificate's own public key; 0 to compare names only.
 * @return 1 if self-signed (and verified when requested), 0 if not, or -1 on error.
 */
int X509_self_signed(X509 *cert, int verify_signature);
""",
    "X509_self_signed",
)

patch_both(
    "x509.h",
    """int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);
""",
    """/**
 * @brief Print a human-readable representation of a Netscape signed public key and challenge.
 * @param out BIO that receives the textual dump.
 * @param spki SPKI structure to print.
 * @return 1 on success, or 0 on failure.
 */
int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);
""",
    "NETSCAPE_SPKI_print",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey_fp(FILE *fp, const DSA *dsa);
""",
    """/**
 * @brief Write a DER-encoded DSA private key to a FILE stream (deprecated).
 * @param fp Output file stream.
 * @param dsa DSA key whose private key encoding is written.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey_fp(FILE *fp, const DSA *dsa);
""",
    "i2d_DSAPrivateKey_fp",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
""",
    """/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo EC public key from a BIO (deprecated).
 * @param bp BIO positioned at a SubjectPublicKeyInfo encoding for an EC key.
 * @param eckey Optional destination pointer updated to the result, or NULL.
 * @return Newly allocated EC_KEY, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
""",
    "d2i_EC_PUBKEY_bio",
)

patch_both(
    "x509.h",
    """X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey);
""",
    """/**
 * @brief Build a self-signed X.509 certificate from a certificate request.
 * @param r Certificate request supplying subject name and public key.
 * @param days Validity period in days from the current time.
 * @param pkey Private key used to sign the resulting certificate (must match the request key).
 * @return New X509 certificate, or NULL on error.
 */
X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey);
""",
    "X509_REQ_to_X509",
)

patch_both(
    "x509.h",
    """unsigned char *X509_alias_get0(X509 *x, int *len);
""",
    """/**
 * @brief Return the friendly-name alias attached to a certificate, if any.
 * @param x Certificate whose auxiliary alias is queried.
 * @param len Optional out-parameter receiving the alias length in bytes; may be NULL.
 * @return Internal pointer to alias bytes, or NULL if none; do not free.
 */
unsigned char *X509_alias_get0(X509 *x, int *len);
""",
    "X509_alias_get0",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0
int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2,
    ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey,
    const EVP_MD *type);
""",
    """/**
 * @brief Sign ASN.1 data described by an i2d encoder using @p pkey (deprecated).
 * @param i2d Encoder that serializes @p data into DER for hashing.
 * @param algor1 Optional AlgorithmIdentifier updated with the signature algorithm, or NULL.
 * @param algor2 Optional second AlgorithmIdentifier updated similarly, or NULL.
 * @param signature Output BIT STRING that receives the signature bits.
 * @param data Structure passed to @p i2d.
 * @param pkey Private key used for signing.
 * @param type Digest algorithm used to hash the DER encoding.
 * @return Signature length in bytes on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2,
    ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey,
    const EVP_MD *type);
""",
    "ASN1_sign",
)

patch_both(
    "x509.h",
    """int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *type, void *data,
    unsigned char *md, unsigned int *len);
""",
    """/**
 * @brief Digest the ASN.1 encoding of @p data as described by @p it.
 * @param it ASN.1 item describing the type of @p data.
 * @param type Digest algorithm used to hash the DER encoding.
 * @param data Structure to encode and digest.
 * @param md Buffer that receives the digest bytes (at least EVP_MD_size(@p type)).
 * @param len Receives the digest length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *type, void *data,
    unsigned char *md, unsigned int *len);
""",
    "ASN1_item_digest",
)

patch_both(
    "x509.h",
    """long X509_get_version(const X509 *x);
""",
    """/**
 * @brief Return the X.509 version field of a certificate.
 * @param x Certificate to query.
 * @return Version constant such as X509_VERSION_1, X509_VERSION_2, or X509_VERSION_3.
 */
long X509_get_version(const X509 *x);
""",
    "X509_get_version",
)

patch_both(
    "x509.h",
    """int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp);
""",
    """/**
 * @brief Re-encode the TBS (to-be-signed) portion of a certificate request to DER.
 * @param req Certificate request whose certificationRequestInfo is encoded; cached encoding may be refreshed.
 * @param pp Optional out-pointer receiving the allocated DER (or advanced if non-NULL as for i2d_*); may be NULL to measure length.
 * @return Length of the DER encoding, or a negative value on error.
 */
int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp);
""",
    "i2d_re_X509_REQ_tbs",
)

patch_both(
    "x509.h",
    """EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req);
""",
    """/**
 * @brief Return a new EVP_PKEY copy of the public key from a certificate request.
 * @param req Certificate request to query.
 * @return Newly referenced EVP_PKEY, or NULL on error; free with EVP_PKEY_free.
 */
EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req);
""",
    "X509_REQ_get_pubkey",
)

patch_both(
    "x509.h",
    """void X509_REQ_set_extension_nids(int *nids);
""",
    """/**
 * @brief Set the global list of NIDs recognized as certificate-request extension attributes.
 * @param nids NID array terminated by NID_undef that replaces the built-in extension NID list, or NULL to restore defaults.
 */
void X509_REQ_set_extension_nids(int *nids);
""",
    "X509_REQ_set_extension_nids",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int X509_certificate_type(const X509 *x,
    const EVP_PKEY *pubkey);
""",
    """/**
 * @brief Classify the key usage / type bits implied by a certificate and key (deprecated).
 * @param x Certificate whose extensions and key type are examined; may be NULL to use @p pubkey alone.
 * @param pubkey Public key to classify; if NULL, taken from @p x.
 * @return Bitmask of EV_PK_* / EV_PKT_* style type flags, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int X509_certificate_type(const X509 *x,
    const EVP_PKEY *pubkey);
""",
    "X509_certificate_type",
)

patch_both(
    "x509.h",
    """int X509_get_ext_count(const X509 *x);
""",
    """/**
 * @brief Return the number of extensions present on a certificate.
 * @param x Certificate to query.
 * @return Count of X509_EXTENSION entries in the certificate's extension stack.
 */
int X509_get_ext_count(const X509 *x);
""",
    "X509_get_ext_count",
)

patch_both(
    "x509.h",
    """STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
    X509_ATTRIBUTE *attr);
""",
    """/**
 * @brief Append a duplicate of @p attr to an X509_ATTRIBUTE stack, creating the stack if needed.
 * @param x Address of a STACK_OF(X509_ATTRIBUTE) pointer; allocated if *@p x is NULL.
 * @param attr Attribute to duplicate and append.
 * @return The attribute stack on success, or NULL on failure.
 */
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
    X509_ATTRIBUTE *attr);
""",
    "X509at_add1_attr",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, const ASN1_OBJECT *obj,
    int lastpos);
""",
    """/**
 * @brief Find the next attribute on an EVP_PKEY matching object identifier @p obj.
 * @param key Key whose attribute stack is searched.
 * @param obj Attribute type OID to match.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Attribute index, or -1 if not found.
 */
int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, const ASN1_OBJECT *obj,
    int lastpos);
""",
    "EVP_PKEY_get_attr_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_PUBKEY_eq(const X509_PUBKEY *a, const X509_PUBKEY *b);
""",
    """/**
 * @brief Compare two X509_PUBKEY structures for equality.
 * @param a First public key encoding.
 * @param b Second public key encoding.
 * @return 1 if equal, 0 if not equal, or -1 on error.
 */
int X509_PUBKEY_eq(const X509_PUBKEY *a, const X509_PUBKEY *b);
""",
    "X509_PUBKEY_eq",
)


print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(" ", m)
    raise SystemExit(1)
