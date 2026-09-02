#!/usr/bin/env python3
"""Documentation repair batch 16: http, params, objects, cms, engine, rsa, pkcs7, evp, sha."""
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


print("=== batch 16: misc headers ===")

# ----- http.h -----

patch_both(
    "http.h",
    """OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int buf_size);
""",
    """/**
 * @brief Allocate a low-level HTTP request context bound to write and read BIOs.
 * @param wbio BIO used to send the request (may equal @p rbio).
 * @param rbio BIO used to receive the response (may equal @p wbio).
 * @param buf_size Max response header line length and read chunk size; <= 0 uses OSSL_HTTP_DEFAULT_MAX_LINE_LEN.
 * @return New request context including an internal memory BIO for headers, or NULL on failure.
 */
OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int buf_size);
""",
    "OSSL_HTTP_REQ_CTX_new",
)

patch_both(
    "http.h",
    """int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX *rctx, int method_POST,
    const char *server, const char *port,
    const char *path);
""",
    """/**
 * @brief Set the first HTTP request line (method and request-target) on @p rctx.
 * @param rctx Request context to update.
 * @param method_POST Nonzero for POST; zero for GET.
 * @param server Optional origin host an HTTP proxy should forward to, or NULL.
 * @param port Optional origin port for proxy forwarding, or NULL.
 * @param path Request path (NULL means "/"); may be an absolute http:// URI for proxy use (then @p server/@p port must be NULL).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX *rctx, int method_POST,
    const char *server, const char *port,
    const char *path);
""",
    "OSSL_HTTP_REQ_CTX_set_request_line",
)

patch_both(
    "http.h",
    """int OSSL_HTTP_REQ_CTX_set_expected(OSSL_HTTP_REQ_CTX *rctx,
    const char *content_type, int asn1,
    int timeout, int keep_alive);
""",
    """/**
 * @brief Configure response Content-Type, ASN.1, timeout, and keep-alive expectations on @p rctx.
 * @param rctx Request context; call before OSSL_HTTP_REQ_CTX_set1_req() when @p keep_alive is nonzero.
 * @param content_type Required response Content-Type (exact or prefix before ';'), or NULL to accept any.
 * @param asn1 Nonzero if the body must be ASN.1 DER (disables streaming; use the memory BIO).
 * @param timeout Soft transfer timeout in seconds (>0 limited; 0 wait forever; <0 keep prior/open default).
 * @param keep_alive 0 close after response; 1 request persistence; 2 require persistence or fail.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set_expected(OSSL_HTTP_REQ_CTX *rctx,
    const char *content_type, int asn1,
    int timeout, int keep_alive);
""",
    "OSSL_HTTP_REQ_CTX_set_expected",
)

patch_both(
    "http.h",
    """int OSSL_HTTP_REQ_CTX_set1_req(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
    const ASN1_ITEM *it, const ASN1_VALUE *req);
""",
    """/**
 * @brief Finalize the request by attaching an ASN.1 DER body and Content-Type/Length headers.
 * @param rctx Request context prepared with OSSL_HTTP_REQ_CTX_set_request_line() (and keep-alive expectations if needed).
 * @param content_type Content-Type header value; must be NULL when @p req is NULL.
 * @param it ASN.1 item template used to encode @p req (DER; not streaming).
 * @param req ASN.1 value to send as the body, or NULL for a body-less (for example GET) request when keep-alive still needs finalization.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set1_req(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
    const ASN1_ITEM *it, const ASN1_VALUE *req);
""",
    "OSSL_HTTP_REQ_CTX_set1_req",
)

patch_both(
    "http.h",
    """BIO *OSSL_HTTP_REQ_CTX_exchange(OSSL_HTTP_REQ_CTX *rctx);
""",
    """/**
 * @brief Exchange the prepared HTTP request and response, retrying non-blocking I/O until done or timeout.
 * @param rctx Request context with BIOs and headers/body configured.
 * @return BIO positioned at the response body (memory BIO for expected ASN.1, else @p rbio); do not free; NULL on failure.
 */
BIO *OSSL_HTTP_REQ_CTX_exchange(OSSL_HTTP_REQ_CTX *rctx);
""",
    "OSSL_HTTP_REQ_CTX_exchange",
)

patch_both(
    "http.h",
    """BIO *OSSL_HTTP_transfer(OSSL_HTTP_REQ_CTX **prctx,
    const char *server, const char *port,
    const char *path, int use_ssl,
    const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *content_type, BIO *req,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout, int keep_alive);
""",
    """/**
 * @brief Open (or reuse), send one HTTP request, receive the response, and optionally keep the connection.
 * @param prctx Optional address of an OSSL_HTTP_REQ_CTX*; reuses *@p prctx when non-NULL, else opens; may be set to NULL when closed.
 * @param server Hostname or address to contact when opening a new connection.
 * @param port Service port, or NULL for the default (80/443).
 * @param path Request path (or absolute URI for a proxy).
 * @param use_ssl Nonzero to use HTTPS (requires @p bio_update_fn when opening via sockets).
 * @param proxy Optional HTTP(S) proxy, or NULL to consult environment defaults.
 * @param no_proxy Optional comma/whitespace host exclusion list, or NULL for environment defaults.
 * @param bio Optional write BIO; NULL builds an internal connect BIO from @p server/@p port.
 * @param rbio Optional read BIO used with @p bio when both are non-NULL (no auto-connect).
 * @param bio_update_fn Optional connect/disconnect BIO callback (required for TLS when @p bio is NULL).
 * @param arg Callback argument for @p bio_update_fn (not consumed).
 * @param buf_size Max header line length / read chunk; <= 0 uses the default.
 * @param headers Optional additional request headers, or NULL.
 * @param content_type Content-Type for @p req, or NULL.
 * @param req Optional request-body BIO, or NULL for a GET-style exchange.
 * @param expected_content_type Expected response Content-Type, or NULL.
 * @param expect_asn1 Nonzero if the response body should be treated as ASN.1 DER.
 * @param max_resp_len Maximum accepted response length in bytes.
 * @param timeout Soft overall timeout in seconds for this exchange.
 * @param keep_alive Keep-alive preference (0/1/2 as for OSSL_HTTP_set1_request()).
 * @return Response-body BIO owned by the caller (free with BIO_free*), or NULL on failure.
 */
BIO *OSSL_HTTP_transfer(OSSL_HTTP_REQ_CTX **prctx,
    const char *server, const char *port,
    const char *path, int use_ssl,
    const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *content_type, BIO *req,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout, int keep_alive);
""",
    "OSSL_HTTP_transfer",
)

patch_both(
    "http.h",
    """int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX *rctx, int ok);
""",
    """/**
 * @brief Close the HTTP connection and free the request context.
 * @param rctx Context from OSSL_HTTP_open()/OSSL_HTTP_transfer(); may be NULL.
 * @param ok 1 if the transfer succeeded (passed to any BIO update callback), or 0 on error.
 * @return 1 if disconnect completed cleanly, or 0 if anything went wrong while closing.
 */
int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX *rctx, int ok);
""",
    "OSSL_HTTP_close",
)

patch_both(
    "http.h",
    """int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
""",
    """/**
 * @brief Parse an http or https URL into allocated component strings.
 * @param url URL of the form [http[s]://][userinfo@]host[:port][/path][?query][#fragment].
 * @param pssl Optional; set to 1 if the scheme is https, else 0.
 * @param puser Optional out for userinfo (empty string if absent); free with OPENSSL_free.
 * @param phost Optional out for host (IPv6 enclosed in brackets); free with OPENSSL_free.
 * @param pport Optional out for port string (defaults "80"/"443"); free with OPENSSL_free.
 * @param pport_num Optional out for the numeric port.
 * @param ppath Optional out for path (always begins with '/'); free with OPENSSL_free.
 * @param pquery Optional out for query (empty if absent); free with OPENSSL_free.
 * @param pfrag Optional out for fragment (empty if absent); free with OPENSSL_free.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
""",
    "OSSL_HTTP_parse_url",
)

patch_both(
    "http.h",
    """const char *OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
    const char *server, int use_ssl);
""",
    """/**
 * @brief Choose an HTTP(S) proxy string, applying no_proxy exclusions and environment defaults.
 * @param proxy Explicit proxy hostname, or NULL to use http_proxy/HTTP_PROXY (or https variants when @p use_ssl).
 * @param no_proxy Exclusion list (comma/whitespace), or NULL to use no_proxy/NO_PROXY.
 * @param server Destination host; if listed in the exclusion set, no proxy is used.
 * @param use_ssl Nonzero selects HTTPS proxy environment variables when @p proxy is NULL.
 * @return Constant proxy hostname string to use, or NULL when no proxy should be used.
 */
const char *OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
    const char *server, int use_ssl);
""",
    "OSSL_HTTP_adapt_proxy",
)

# ----- params.h -----

patch_both(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
    size_t bsize);
""",
    """/**
 * @brief Construct an OSSL_PARAM describing a UTF-8 string buffer.
 * @param key Parameter name.
 * @param buf Storage for the UTF-8 string (writable buffer owned by the caller).
 * @param bsize Capacity of @p buf in bytes; 0 means use strlen(@p buf).
 * @return Populated OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
    size_t bsize);
""",
    "OSSL_PARAM_construct_utf8_string",
)

patch_both(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
    size_t bsize);
""",
    """/**
 * @brief Construct an OSSL_PARAM describing an octet-string buffer.
 * @param key Parameter name.
 * @param buf Storage for the octet string.
 * @param bsize Size of @p buf in bytes.
 * @return Populated OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
    size_t bsize);
""",
    "OSSL_PARAM_construct_octet_string",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val);
""",
    """/**
 * @brief Read an OSSL_PARAM value as a uint64_t (with allowed integer type coercion).
 * @param p Parameter locating the value.
 * @param val Receives the converted integer on success.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val);
""",
    "OSSL_PARAM_get_uint64",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val);
""",
    """/**
 * @brief Store an int32_t value into an integer OSSL_PARAM.
 * @param p Parameter descriptor whose buffer receives @p val (or whose return_size is filled if data is NULL).
 * @param val Value to write.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val);
""",
    "OSSL_PARAM_set_int32",
)

# ----- objects.h -----

patch_both(
    "objects.h",
    """int OBJ_create_objects(BIO *in);
""",
    """/**
 * @brief Load OID definitions from text lines read from @p in into the internal object table.
 * @param in BIO supplying lines of the form "oid [shortName [longName]]".
 * @return Number of objects successfully created before EOF or the first failure/invalid line.
 */
int OBJ_create_objects(BIO *in);
""",
    "OBJ_create_objects",
)

# ----- cms.h / cms.h.in -----

patch_both(
    "cms.h",
    """int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr);
""",
    """/**
 * @brief Add a CMS signed receipt request to a SignerInfo.
 * @param si SignerInfo that receives the receipt request attribute.
 * @param rr Receipt request to add (caller retains ownership of @p rr).
 * @return 1 on success, or 0 on error.
 */
int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr);
""",
    "CMS_add1_ReceiptRequest",
)

# ----- engine.h -----

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_asn1_meths(ENGINE *e);
""",
    """/**
 * @brief Unregister the EVP_PKEY ASN.1 methods previously registered from @p e (deprecated).
 * @param e ENGINE whose pkey ASN.1 methods should be removed from the global table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_asn1_meths(ENGINE *e);
""",
    "ENGINE_unregister_pkey_asn1_meths",
)

# ----- rsa.h -----

patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
""",
    """/**
 * @brief Set the RSA padding mode on an EVP_PKEY_CTX.
 * @param ctx Context used for RSA encrypt, decrypt, sign, or verify.
 * @param pad_mode Padding mode such as RSA_PKCS1_PADDING, RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_X931_PADDING, RSA_PKCS1_PSS_PADDING, or RSA_PKCS1_WITH_TLS_PADDING.
 * @return Positive value on success, or 0 / negative on failure (-2 if unsupported).
 */
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
""",
    "EVP_PKEY_CTX_set_rsa_padding",
)

# ----- pkcs7.h / pkcs7.h.in -----

patch_both(
    "pkcs7.h",
    """int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si,
    const unsigned char *md, int mdlen);
""",
    """/**
 * @brief Add a PKCS#9 messageDigest authenticated attribute to a SignerInfo.
 * @param si SignerInfo to update.
 * @param md Digest octets to embed (copied into a new ASN1_OCTET_STRING).
 * @param mdlen Length of @p md in bytes.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si,
    const unsigned char *md, int mdlen);
""",
    "PKCS7_add1_attrib_digest",
)

# ----- evp.h -----

patch_both(
    "evp.h",
    """EVP_MD *EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx);
""",
    """/**
 * @brief Return the digest method associated with @p ctx, transferring a reference to the caller.
 * @param ctx Digest context to query.
 * @return EVP_MD with an incremented reference count (free with EVP_MD_free), or NULL if unset.
 */
EVP_MD *EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx);
""",
    "EVP_MD_CTX_get1_md",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_256_cfb1(void);
""",
    """/**
 * @brief Return the AES-256 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aes-256-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_256_cfb1(void);
""",
    "EVP_aes_256_cfb1",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_256_xts(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for AES-256 in XTS mode (IEEE 1619 / NIST SP 800-38E).
 * @return Pointer to the cipher method (expects a 512-bit key), or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_xts(void);
""",
    "EVP_aes_256_xts",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_digestsign_supports_digest(EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *name, const char *propq);
""",
    """/**
 * @brief Query whether digest @p name can be used for DigestSign/Verify with @p pkey.
 * @param pkey Public key whose signature algorithm is checked.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param name Digest algorithm name (for example "SHA256").
 * @param propq Property query for provider selection, or NULL.
 * @return 1 if supported, 0 if not, or a negative value on failure.
 */
int EVP_PKEY_digestsign_supports_digest(EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *name, const char *propq);
""",
    "EVP_PKEY_digestsign_supports_digest",
)

patch_both(
    "evp.h",
    """void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
""",
    """/**
 * @brief Free an EVP_PKEY_ASN1_METHOD allocated with EVP_PKEY_asn1_new().
 * @param ameth Method object to free; NULL is ignored.
 */
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
""",
    "EVP_PKEY_asn1_free",
)

patch_both(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Return the peer key previously set on a derive context.
 * @param ctx Key context that may hold a peer key from EVP_PKEY_derive_set_peer().
 * @return Peer EVP_PKEY owned by @p ctx (do not free), or NULL if unset.
 */
EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_CTX_get0_peerkey",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
""",
    """/**
 * @brief Set the public-component check callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param check Callback invoked by EVP_PKEY_public_check(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
""",
    "EVP_PKEY_meth_set_public_check",
)

# ----- sha.h -----

patch_one(
    "sha.h",
    """typedef struct SHAstate_st {
    /** Chaining variables H0..H4 of the SHA-1 compression function. */
    SHA_LONG h0, h1, h2, h3, h4;
""",
    """/**
 * @brief Incremental SHA-1 digest state (also typedef'd as SHA_CTX); deprecated low-level API.
 */
typedef struct SHAstate_st {
    /** Chaining variables H0..H4 of the SHA-1 compression function. */
    SHA_LONG h0, h1, h2, h3, h4;
""",
    "SHAstate_st/SHA_CTX",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA1_Init(SHA_CTX *c);
OSSL_DEPRECATEDIN_3_0 int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
OSSL_DEPRECATEDIN_3_0 int SHA1_Final(unsigned char *md, SHA_CTX *c);
""",
    """/**
 * @brief Initialize a low-level SHA-1 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Init(SHA_CTX *c);
/**
 * @brief Absorb @p len bytes at @p data into a SHA-1 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA1_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
/**
 * @brief Finalize a SHA-1 digest into @p md and clear @p c (deprecated; prefer EVP_DigestFinal_ex).
 * @param md Output buffer of at least SHA_DIGEST_LENGTH (20) bytes.
 * @param c Context previously updated with SHA1_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA1_Final(unsigned char *md, SHA_CTX *c);
""",
    "SHA1_Init/Update/Final",
)

patch_one(
    "sha.h",
    """typedef struct SHA256state_st {
    /** Working hash state H0..H7 (eight 32-bit words). */
    SHA_LONG h[8];
""",
    """/**
 * @brief Incremental SHA-224 / SHA-256 digest state (also typedef'd as SHA256_CTX); deprecated low-level API.
 */
typedef struct SHA256state_st {
    /** Working hash state H0..H7 (eight 32-bit words). */
    SHA_LONG h[8];
""",
    "SHA256state_st/SHA256_CTX",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA224_Update(SHA256_CTX *c,
    const void *data, size_t len);
""",
    """/**
 * @brief Absorb message bytes into a SHA-224 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA224_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Update(SHA256_CTX *c,
    const void *data, size_t len);
""",
    "SHA224_Update",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA256_Update(SHA256_CTX *c,
    const void *data, size_t len);
""",
    """/**
 * @brief Absorb message bytes into a SHA-256 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA256_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA256_Update(SHA256_CTX *c,
    const void *data, size_t len);
""",
    "SHA256_Update",
)

patch_one(
    "sha.h",
    """unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
""",
    """/**
 * @brief Compute the SHA-256 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA256_DIGEST_LENGTH bytes, or NULL for a static buffer (not thread-safe).
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
""",
    "SHA256",
)

patch_one(
    "sha.h",
    """typedef struct SHA512state_st {
    SHA_LONG64 h[8];
""",
    """typedef struct SHA512state_st {
    /** Working hash state H0..H7 (eight 64-bit words). */
    SHA_LONG64 h[8];
""",
    "SHA512state_st.h",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA384_Update(SHA512_CTX *c,
    const void *data, size_t len);
""",
    """/**
 * @brief Absorb message bytes into a SHA-384 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA384_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA384_Update(SHA512_CTX *c,
    const void *data, size_t len);
""",
    "SHA384_Update",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA512_Update(SHA512_CTX *c,
    const void *data, size_t len);
""",
    """/**
 * @brief Absorb message bytes into a SHA-512 context (deprecated; prefer EVP_DigestUpdate).
 * @param c Context previously initialized with SHA512_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Update(SHA512_CTX *c,
    const void *data, size_t len);
""",
    "SHA512_Update",
)

patch_one(
    "sha.h",
    """unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
""",
    """/**
 * @brief Compute the SHA-512 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA512_DIGEST_LENGTH bytes, or NULL for a static buffer (not thread-safe).
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
""",
    "SHA512",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
