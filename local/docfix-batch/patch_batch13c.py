#!/usr/bin/env python3
"""Documentation repair batch 13c: http..ui (+ types, ssl, rsa, sha, srtp)."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
DOCS = ROOT / "docs"
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


print("=== batch 13c ===")

# Exclude LHASH helper typedefs (same class as sk_*_compfunc)
yml = DOCS / "mrdocs.yml"
yt = yml.read_text(encoding="utf-8")
needle = "  - 'sk_*_freefunc'\n"
insert = (
    "  - 'sk_*_freefunc'\n"
    "  - 'lh_*_compfunc'\n"
    "  - 'lh_*_hashfunc'\n"
    "  - 'lh_*_doallfunc'\n"
)
if "lh_*_doallfunc" not in yt:
    if needle not in yt:
        print("  MISS: mrdocs.yml :: lh_*_doallfunc exclude")
        missing.append("mrdocs.yml:lh_exclude")
    else:
        yml.write_text(yt.replace(needle, insert, 1), encoding="utf-8")
        print("  OK: mrdocs.yml :: lh_*_{comp,hash,doall}func exclude")
        ok.append("mrdocs.yml:lh_exclude")
else:
    print("  SKIP: mrdocs.yml already has lh_*_doallfunc")

patch_one(
    "http.h",
    """int OSSL_HTTP_REQ_CTX_nbio_d2i(OSSL_HTTP_REQ_CTX *rctx,
    ASN1_VALUE **pval, const ASN1_ITEM *it);
""",
    """/**
 * @brief Exchange an HTTP request non-blockingly and decode the response body as ASN.1.
 * @param rctx Request context prepared with headers/body; may need multiple calls when BIOs would block.
 * @param pval Destination for the decoded ASN.1 value (type described by @p it).
 * @param it ASN.1 item descriptor used to decode the HTTP response body.
 * @return 1 on completion with success, 0 on failure, or -1 if the I/O would block (retry later).
 */
int OSSL_HTTP_REQ_CTX_nbio_d2i(OSSL_HTTP_REQ_CTX *rctx,
    ASN1_VALUE **pval, const ASN1_ITEM *it);
""",
    "OSSL_HTTP_REQ_CTX_nbio_d2i",
)

patch_one(
    "http.h",
    """int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
    const char *proxyuser, const char *proxypass,
    int timeout, BIO *bio_err, const char *prog);
""",
    """/**
 * @brief Perform an HTTP CONNECT through a proxy on an already-connected BIO.
 * @param bio BIO connected to the HTTP proxy; on success becomes a tunnel to @p server:@p port.
 * @param server Target hostname to CONNECT to.
 * @param port Target port (decimal string) or service name.
 * @param proxyuser Optional proxy username for Basic auth, or NULL.
 * @param proxypass Optional proxy password for Basic auth, or NULL.
 * @param timeout Overall timeout in seconds (0 for none / BIO default).
 * @param bio_err Optional BIO for diagnostic output, or NULL.
 * @param prog Optional program name prefix for diagnostics, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
    const char *proxyuser, const char *proxypass,
    int timeout, BIO *bio_err, const char *prog);
""",
    "OSSL_HTTP_proxy_connect",
)

patch_one(
    "kdf.h",
    """int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *ctx,
    const unsigned char *key, int keylen);
""",
    """/**
 * @brief Set the HKDF input keying material (IKM) on a PKEY KDF context.
 * @param ctx Context configured for the HKDF KDF.
 * @param key Input keying material bytes (copied).
 * @param keylen Length of @p key in bytes.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *ctx,
    const unsigned char *key, int keylen);
""",
    "EVP_PKEY_CTX_set1_hkdf_key",
)

patch_one(
    "kdf.h",
    """int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *ctx, uint64_t r);
""",
    """/**
 * @brief Set the scrypt block-size parameter r on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param r Block-size parameter (must be > 0).
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *ctx, uint64_t r);
""",
    "EVP_PKEY_CTX_set_scrypt_r",
)

patch_both(
    "lhash.h",
    """typedef struct lhash_node_st OPENSSL_LH_NODE;
""",
    """/**
 * @brief Opaque hash-table node used internally by OPENSSL_LHASH.
 */
typedef struct lhash_node_st OPENSSL_LH_NODE;
""",
    "OPENSSL_LH_NODE",
)

patch_one(
    "objects.h",
    """int OBJ_sn2nid(const char *s);
""",
    """/**
 * @brief Look up the numeric object identifier (NID) for a short name string.
 * @param s Short name such as "SHA256" or "rsaEncryption".
 * @return Matching NID, or NID_undef if @p s is not recognised.
 */
int OBJ_sn2nid(const char *s);
""",
    "OBJ_sn2nid",
)

patch_both(
    "pkcs7.h",
    """    ASN1_INTEGER *version; /* version 1 */
""",
    """    /** PKCS#7 SignerInfo version (typically 1). */
    ASN1_INTEGER *version; /* version 1 */
""",
    "pkcs7_signer_info_st.version",
)

patch_both(
    "pkcs7.h",
    """    STACK_OF(X509_ATTRIBUTE) *auth_attr; /* [ 0 ] */
""",
    """    /** Authenticated (signed) attributes ([0]), or NULL if absent. */
    STACK_OF(X509_ATTRIBUTE) *auth_attr; /* [ 0 ] */
""",
    "pkcs7_signer_info_st.auth_attr",
)

patch_both(
    "pkcs7.h",
    """int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7);
""",
    """/**
 * @brief Write a DER-encoded PKCS#7 structure to a BIO.
 * @param bp Output BIO receiving the DER encoding.
 * @param p7 PKCS#7 object to serialise.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7);
""",
    "i2d_PKCS7_bio",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_add_certificate(PKCS7 *p7, X509 *cert);
""",
    """/**
 * @brief Add a certificate to a PKCS#7 SignedData or SignedAndEnvelopedData structure.
 * @param p7 PKCS#7 object that already has a signed content type.
 * @param cert Certificate to include; a reference is retained by @p p7.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_add_certificate(PKCS7 *p7, X509 *cert);
""",
    "PKCS7_add_certificate",
)

patch_one(
    "rsa.h",
    """int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
""",
    """/**
 * @brief Get the MGF1 digest algorithm name from an RSA EVP_PKEY_CTX.
 * @param ctx Context whose padding mode uses MGF1 (PSS or OAEP).
 * @param name Buffer receiving the NUL-terminated digest name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name,
    size_t namelen);
""",
    "EVP_PKEY_CTX_get_rsa_mgf1_md_name",
)

patch_one(
    "rsa.h",
    """int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
""",
    """/**
 * @brief Get the RSA-OAEP message-digest algorithm from an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param md Receives a pointer to the EVP_MD in use (do not free).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);
""",
    "EVP_PKEY_CTX_get_rsa_oaep_md",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_get0_multi_prime_factors(const RSA *r,
    const BIGNUM *primes[]);
""",
    """/**
 * @brief Fill @p primes with borrowed pointers to the extra multi-prime factors (deprecated).
 * @param r RSA key that may have more than two primes.
 * @param primes Array of size RSA_get_multi_prime_extra_count(@p r) receiving factor pointers (do not free).
 * @return 1 on success, or 0 if @p r is not multi-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get0_multi_prime_factors(const RSA *r,
    const BIGNUM *primes[]);
""",
    "RSA_get0_multi_prime_factors",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmp1(const RSA *r);
""",
    """/**
 * @brief Return CRT exponent d mod (p-1) without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for dmp1, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmp1(const RSA *r);
""",
    "RSA_get0_dmp1",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_iqmp(const RSA *r);
""",
    """/**
 * @brief Return CRT coefficient q^-1 mod p without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for iqmp, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_iqmp(const RSA *r);
""",
    "RSA_get0_iqmp",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
""",
    """/**
 * @brief Verify "no padding" by copying @p f into @p to when lengths match (deprecated).
 * @param to Destination buffer of capacity @p tlen.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block bytes to check/copy.
 * @param fl Length of @p f in bytes.
 * @param rsa_len RSA modulus size in bytes (expected encoded length).
 * @return Length of recovered data on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);
""",
    "RSA_padding_check_none",
)

patch_one(
    "rsa.h",
    """DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, RSA, RSAPrivateKey)
""",
    """/**
 * @brief Deep-copy an RSA private key (RSAPrivateKey_dup) (deprecated).
 * @param a Source RSA key to duplicate.
 * @return Newly allocated RSA copy, or NULL on failure; free with RSA_free().
 */
DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, RSA, RSAPrivateKey)
""",
    "RSAPrivateKey_dup",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_finish(RSA_METHOD *rsa, int (*finish)(RSA *rsa));
""",
    """/**
 * @brief Set the finish/cleanup callback on an RSA_METHOD (deprecated).
 * @param rsa Method table to update.
 * @param finish Callback invoked when an RSA object using this method is freed, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_finish(RSA_METHOD *rsa, int (*finish)(RSA *rsa));
""",
    "RSA_meth_set_finish",
)

patch_one(
    "sha.h",
    """typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
""",
    """typedef struct SHA256state_st {
    /** Working hash state H0..H7 (eight 32-bit words). */
    SHA_LONG h[8];
    /** Low and high 32-bit halves of the bit-length counter. */
    SHA_LONG Nl, Nh;
    /** Partial input block being accumulated (SHA_LBLOCK words). */
    SHA_LONG data[SHA_LBLOCK];
""",
    "SHA256_CTX fields",
)

patch_one(
    "srtp.h",
    """__owur STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *ssl);
""",
    """/**
 * @brief Return the stack of SRTP protection profiles configured on an SSL connection.
 * @param ssl SSL/DTLS connection whose use_srtp profile list is queried.
 * @return Internal STACK_OF(SRTP_PROTECTION_PROFILE) (do not free), or NULL if none are set.
 */
__owur STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *ssl);
""",
    "SSL_get_srtp_profiles",
)

# ----- ssl.h -----
patch_both(
    "ssl.h",
    """typedef int (*custom_ext_parse_cb)(SSL *s, unsigned int ext_type,
    const unsigned char *in, size_t inlen,
    int *al, void *parse_arg);
""",
    """/**
 * @brief Callback that parses a received custom TLS extension.
 * @param s SSL connection that received the extension.
 * @param ext_type TLS extension type code.
 * @param in Extension payload bytes.
 * @param inlen Length of @p in in bytes.
 * @param al On failure, set to a TLS alert description to send.
 * @param parse_arg Application argument registered with the extension.
 * @return 1 on success, or 0 to abort the handshake (after setting *@p al).
 */
typedef int (*custom_ext_parse_cb)(SSL *s, unsigned int ext_type,
    const unsigned char *in, size_t inlen,
    int *al, void *parse_arg);
""",
    "custom_ext_parse_cb",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_add_server_custom_ext(SSL_CTX *ctx,
    unsigned int ext_type,
    custom_ext_add_cb add_cb,
    custom_ext_free_cb free_cb,
    void *add_arg,
    custom_ext_parse_cb parse_cb,
    void *parse_arg);
""",
    """/**
 * @brief Register a custom TLS extension handler for the server role on an SSL context.
 * @param ctx Server SSL context that sends or receives the extension.
 * @param ext_type Extension type code (must not collide with built-in handlers).
 * @param add_cb Callback that constructs extension data to send, or NULL.
 * @param free_cb Callback that frees data produced by @p add_cb, or NULL.
 * @param add_arg Opaque pointer passed to @p add_cb / @p free_cb.
 * @param parse_cb Callback that parses a received extension, or NULL.
 * @param parse_arg Opaque pointer passed to @p parse_cb.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_add_server_custom_ext(SSL_CTX *ctx,
    unsigned int ext_type,
    custom_ext_add_cb add_cb,
    custom_ext_free_cb free_cb,
    void *add_arg,
    custom_ext_parse_cb parse_cb,
    void *parse_arg);
""",
    "SSL_CTX_add_server_custom_ext",
)

patch_both(
    "ssl.h",
    """size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);
""",
    """/**
 * @brief Copy the peer's Finished handshake message hash into @p buf.
 * @param s SSL connection that has completed the Finished exchange.
 * @param buf Destination buffer, or NULL to query the Finished length only.
 * @param count Capacity of @p buf in bytes.
 * @return Number of Finished bytes available (may exceed @p count if truncated).
 */
size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);
""",
    "SSL_get_peer_finished",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_free(SSL_CTX *);
""",
    """/**
 * @brief Decrement the reference count of an SSL_CTX and free it when it reaches zero.
 * @param ctx SSL context to release, or NULL (no-op).
 */
void SSL_CTX_free(SSL_CTX *ctx);
""",
    "SSL_CTX_free",
)

patch_both(
    "ssl.h",
    """typedef int (*SSL_client_hello_cb_fn)(SSL *s, int *al, void *arg);
""",
    """/**
 * @brief Server callback invoked after a ClientHello is received and parsed.
 * @param s Server SSL connection processing the ClientHello.
 * @param al On failure, set to a TLS alert description to send.
 * @param arg Application pointer from SSL_CTX_set_client_hello_cb().
 * @return SSL_CLIENT_HELLO_SUCCESS, SSL_CLIENT_HELLO_ERROR, or SSL_CLIENT_HELLO_RETRY.
 */
typedef int (*SSL_client_hello_cb_fn)(SSL *s, int *al, void *arg);
""",
    "SSL_client_hello_cb_fn",
)

patch_both(
    "ssl.h",
    """long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
""",
    """/**
 * @brief Perform a low-level control operation on an SSL context.
 * @param ctx SSL context to manipulate.
 * @param cmd Control command (SSL_CTRL_*); prefer typed SSL_CTX_* helpers.
 * @param larg Integer argument whose meaning depends on @p cmd.
 * @param parg Pointer argument whose meaning depends on @p cmd.
 * @return Command-specific long result.
 */
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
""",
    "SSL_CTX_ctrl",
)

patch_both(
    "ssl.h",
    """__owur int SSL_is_server(const SSL *s);
""",
    """/**
 * @brief Report whether an SSL object was created as a server endpoint.
 * @param s SSL connection to query.
 * @return 1 if @p s is a server, or 0 if it is a client.
 */
__owur int SSL_is_server(const SSL *s);
""",
    "SSL_is_server",
)

patch_both(
    "ssl.h",
    """typedef int (*SSL_allow_early_data_cb_fn)(SSL *s, void *arg);
""",
    """/**
 * @brief Server callback that decides whether to accept TLSv1.3 early data for a connection.
 * @param s Server SSL connection that received early data / a 0-RTT ClientHello.
 * @param arg Application pointer from SSL_CTX_set_allow_early_data_cb() / SSL_set_allow_early_data_cb().
 * @return 1 to allow early data, or 0 to reject it.
 */
typedef int (*SSL_allow_early_data_cb_fn)(SSL *s, void *arg);
""",
    "SSL_allow_early_data_cb_fn",
)

# ----- types.h -----
patch_one(
    "types.h",
    """typedef struct asn1_object_st ASN1_OBJECT;
""",
    """/**
 * @brief Opaque ASN.1 OBJECT IDENTIFIER (OID) value.
 */
typedef struct asn1_object_st ASN1_OBJECT;
""",
    "ASN1_OBJECT",
)

patch_one(
    "types.h",
    """typedef struct x509_object_st X509_OBJECT;
""",
    """/**
 * @brief Opaque X509_STORE cache entry holding a certificate or CRL.
 */
typedef struct x509_object_st X509_OBJECT;
""",
    "X509_OBJECT",
)

patch_one(
    "types.h",
    """typedef struct x509_lookup_st X509_LOOKUP;
""",
    """/**
 * @brief Opaque certificate/CRL lookup method instance attached to an X509_STORE.
 */
typedef struct x509_lookup_st X509_LOOKUP;
""",
    "X509_LOOKUP",
)

patch_one(
    "types.h",
    """typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
""",
    """/**
 * @brief Opaque cache of processed certificate policy data used during path validation.
 */
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
""",
    "X509_POLICY_CACHE",
)

patch_one(
    "types.h",
    """typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
""",
    """/**
 * @brief Opaque Name Constraints extension value (permitted/excluded subtrees).
 */
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
""",
    "NAME_CONSTRAINTS",
)

patch_one(
    "types.h",
    """typedef struct ossl_encoder_ctx_st OSSL_ENCODER_CTX;
""",
    """/**
 * @brief Opaque encoder context that drives OSSL_ENCODER output of keys and related objects.
 */
typedef struct ossl_encoder_ctx_st OSSL_ENCODER_CTX;
""",
    "OSSL_ENCODER_CTX",
)

# ----- ui.h -----
patch_both(
    "ui.h",
    """int UI_dup_input_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize);
""",
    """/**
 * @brief Add a string prompt, duplicating @p prompt into UI-owned storage.
 * @param ui UI object collecting prompts.
 * @param prompt Text shown to the user (copied).
 * @param flags UI_INPUT_FLAG_* behaviour bits.
 * @param result_buf Buffer receiving the user input (size at least @p maxsize+1).
 * @param minsize Minimum accepted result length.
 * @param maxsize Maximum accepted result length (excluding the trailing NUL).
 * @return Index of the added string on success, or a negative value on error.
 */
int UI_dup_input_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize);
""",
    "UI_dup_input_string",
)

patch_both(
    "ui.h",
    """int UI_dup_error_string(UI *ui, const char *text);
""",
    """/**
 * @brief Add an error/info string, duplicating @p text into UI-owned storage.
 * @param ui UI object collecting prompts and messages.
 * @param text Message shown to the user (copied).
 * @return Index of the added string on success, or a negative value on error.
 */
int UI_dup_error_string(UI *ui, const char *text);
""",
    "UI_dup_error_string",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print(" ", m)
