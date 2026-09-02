#!/usr/bin/env python3
"""Documentation repair batch 18d: hmac, http, kdf, lhash, params, pkcs7, rsa, sha."""
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


print("=== batch 18d: hmac/http/kdf/lhash/params/pkcs7/rsa/sha ===")

# ----- hmac.h -----

patch_one(
    "hmac.h",
    """OSSL_DEPRECATEDIN_3_0 int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
""",
    """/**
 * @brief (Re)initialize an HMAC_CTX with key and digest (deprecated; prefer EVP_MAC).
 * @param ctx HMAC context to initialize.
 * @param key HMAC key bytes, or NULL to reuse the previous key when only @p md changes.
 * @param len Length of @p key in bytes (ignored when @p key is NULL).
 * @param md Message digest used as the HMAC hash, or NULL to keep the previous digest.
 * @param impl Optional ENGINE implementing @p md, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
""",
    "HMAC_Init_ex",
)

# ----- http.h -----

patch_one(
    "http.h",
    """void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
""",
    """/**
 * @brief Free an HTTP request context and its owned BIO/state.
 * @param rctx Context to free, or NULL.
 */
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
""",
    "OSSL_HTTP_REQ_CTX_free",
)

patch_one(
    "http.h",
    """int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
""",
    """/**
 * @brief Continue a non-blocking HTTP request/response exchange on @p rctx.
 * @param rctx Request context previously prepared with headers/body.
 * @return 1 when the exchange completed, -1 when more I/O is needed, or 0 on error.
 */
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
""",
    "OSSL_HTTP_REQ_CTX_nbio",
)

patch_one(
    "http.h",
    """typedef BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail);
""",
    """/**
 * @brief Optional callback that updates or replaces the HTTP connection BIO around connect/TLS.
 * @param bio Current connection BIO (may be NULL before connect).
 * @param arg User pointer supplied to OSSL_HTTP_open().
 * @param connect Non-zero when establishing the connection; zero when disconnecting.
 * @param detail Non-zero to request detailed error reporting from the callback.
 * @return BIO to use for subsequent HTTP I/O, or NULL on failure.
 */
typedef BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail);
""",
    "OSSL_HTTP_bio_cb_t",
)

patch_one(
    "http.h",
    """OSSL_HTTP_REQ_CTX *OSSL_HTTP_open(const char *server, const char *port,
    const char *proxy, const char *no_proxy,
    int use_ssl, BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, int overall_timeout);
""",
    """/**
 * @brief Open an HTTP (or HTTPS) connection and allocate a request context.
 * @param server Hostname or address of the HTTP server.
 * @param port Port string, or NULL for the default (80/443).
 * @param proxy Optional HTTP proxy host, or NULL.
 * @param no_proxy Optional comma-separated bypass list, or NULL.
 * @param use_ssl Non-zero to use TLS (HTTPS).
 * @param bio Optional pre-existing write BIO, or NULL to create one.
 * @param rbio Optional separate read BIO, or NULL to use @p bio for both.
 * @param bio_update_fn Optional connect/disconnect BIO callback, or NULL.
 * @param arg User pointer passed to @p bio_update_fn.
 * @param buf_size I/O buffer size hint (0 for default).
 * @param overall_timeout Overall transfer timeout in seconds (0 for default/none).
 * @return New OSSL_HTTP_REQ_CTX, or NULL on failure; free with OSSL_HTTP_REQ_CTX_free().
 */
OSSL_HTTP_REQ_CTX *OSSL_HTTP_open(const char *server, const char *port,
    const char *proxy, const char *no_proxy,
    int use_ssl, BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, int overall_timeout);
""",
    "OSSL_HTTP_open",
)

patch_one(
    "http.h",
    """BIO *OSSL_HTTP_exchange(OSSL_HTTP_REQ_CTX *rctx, char **redirection_url);
""",
    """/**
 * @brief Perform the HTTP exchange and return a BIO of the response body.
 * @param rctx Request context prepared with method, headers, and optional request body.
 * @param redirection_url Optional receiver for an allocated redirect URL on 3xx, or NULL.
 * @return Memory BIO containing the response body, or NULL on failure; free with BIO_free().
 */
BIO *OSSL_HTTP_exchange(OSSL_HTTP_REQ_CTX *rctx, char **redirection_url);
""",
    "OSSL_HTTP_exchange",
)

patch_one(
    "http.h",
    """int OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
""",
    """/**
 * @brief Parse @p url into allocated scheme/user/host/port/path/query/fragment components.
 * @param url URL string to parse.
 * @param pscheme Receives allocated scheme (for example \"https\"), or NULL to skip.
 * @param puser Receives allocated userinfo, or NULL to skip.
 * @param phost Receives allocated host, or NULL to skip.
 * @param pport Receives allocated port string, or NULL to skip.
 * @param pport_num Receives numeric port, or NULL to skip.
 * @param ppath Receives allocated path (at least \"/\"), or NULL to skip.
 * @param pquery Receives allocated query without leading '?', or NULL to skip.
 * @param pfrag Receives allocated fragment without leading '#', or NULL to skip.
 * @return 1 on success, or 0 on failure; free each returned string with OPENSSL_free().
 */
int OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
""",
    "OSSL_parse_url",
)

# ----- kdf.h -----

patch_one(
    "kdf.h",
    """const char *EVP_KDF_get0_description(const EVP_KDF *kdf);
""",
    """/**
 * @brief Return a human-readable description of a KDF algorithm.
 * @param kdf KDF method to query.
 * @return Internal description string, or NULL; do not free.
 */
const char *EVP_KDF_get0_description(const EVP_KDF *kdf);
""",
    "EVP_KDF_get0_description",
)

patch_one(
    "kdf.h",
    """const char *EVP_KDF_get0_name(const EVP_KDF *kdf);
""",
    """/**
 * @brief Return the algorithm name of a KDF method.
 * @param kdf KDF method to query.
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KDF_get0_name(const EVP_KDF *kdf);
""",
    "EVP_KDF_get0_name",
)

patch_one(
    "kdf.h",
    """size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *ctx);
""",
    """/**
 * @brief Return the output size produced by @p ctx, or SIZE_MAX if variable-length.
 * @param ctx KDF context to query.
 * @return Fixed output length in bytes, 0 on error, or SIZE_MAX when unbounded.
 */
size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *ctx);
""",
    "EVP_KDF_CTX_get_kdf_size",
)

patch_one(
    "kdf.h",
    """int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX *ctx, const char *pass,
    int passlen);
""",
    """/**
 * @brief Set the password for a PBE-based EVP_PKEY_CTX derivation (PKCS#5 style).
 * @param ctx Key-derivation context.
 * @param pass Password bytes (may contain embedded NULs).
 * @param passlen Length of @p pass in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX *ctx, const char *pass,
    int passlen);
""",
    "EVP_PKEY_CTX_set1_pbe_pass",
)

# ----- lhash.h -----

patch_both(
    "lhash.h",
    """typedef unsigned long (*OPENSSL_LH_HASHFUNCTHUNK)(const void *, OPENSSL_LH_HASHFUNC hfn);
typedef void (*OPENSSL_LH_DOALL_FUNC)(void *);
""",
    """/**
 * @brief Adapter that invokes a typed OPENSSL_LH_HASHFUNC on a void* element.
 */
typedef unsigned long (*OPENSSL_LH_HASHFUNCTHUNK)(const void *, OPENSSL_LH_HASHFUNC hfn);
/**
 * @brief Callback applied to each element by OPENSSL_LH_doall().
 */
typedef void (*OPENSSL_LH_DOALL_FUNC)(void *);
""",
    "LH hash/doall typedefs",
)

patch_both(
    "lhash.h",
    """typedef void (*OPENSSL_LH_DOALL_FUNCARG_THUNK)(void *, void *, OPENSSL_LH_DOALL_FUNCARG doall);
typedef struct lhash_st OPENSSL_LHASH;
""",
    """/**
 * @brief Adapter that invokes a typed OPENSSL_LH_DOALL_FUNCARG on void* element/arg.
 */
typedef void (*OPENSSL_LH_DOALL_FUNCARG_THUNK)(void *, void *, OPENSSL_LH_DOALL_FUNCARG doall);
/**
 * @brief Opaque dynamic hash table (LHASH) of void* elements.
 */
typedef struct lhash_st OPENSSL_LHASH;
""",
    "LH doall_arg_thunk + OPENSSL_LHASH",
)

# Also document the record lhash_st - the diagnostic said both record and typedef.
# Adding a forward brief on the struct tag via documenting typedef should cover OPENSSL_LHASH;
# for lhash_st record, we may need:
patch_both(
    "lhash.h",
    """/**
 * @brief Opaque dynamic hash table (LHASH) of void* elements.
 */
typedef struct lhash_st OPENSSL_LHASH;
""",
    """/**
 * @brief Opaque dynamic hash table (LHASH) of void* elements.
 */
struct lhash_st;
/**
 * @brief Opaque dynamic hash table (LHASH) of void* elements.
 */
typedef struct lhash_st OPENSSL_LHASH;
""",
    "struct lhash_st forward",
)

patch_both(
    "lhash.h",
    """void OPENSSL_LH_flush(OPENSSL_LHASH *lh);
""",
    """/**
 * @brief Remove and free all entries from an LHASH without freeing the table itself.
 * @param lh Hash table to empty.
 */
void OPENSSL_LH_flush(OPENSSL_LHASH *lh);
""",
    "OPENSSL_LH_flush",
)

patch_both(
    "lhash.h",
    """void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data);
""",
    """/**
 * @brief Delete the entry matching @p data from an LHASH.
 * @param lh Hash table.
 * @param data Key/element used for lookup (compared via the table's compare function).
 * @return The removed element pointer, or NULL if not found.
 */
void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data);
""",
    "OPENSSL_LH_delete",
)

patch_both(
    "lhash.h",
    """unsigned long OPENSSL_LH_strhash(const char *c);
""",
    """/**
 * @brief Hash a NUL-terminated C string for use as an LHASH hash function.
 * @param c String to hash; NULL is treated as empty.
 * @return Hash value.
 */
unsigned long OPENSSL_LH_strhash(const char *c);
""",
    "OPENSSL_LH_strhash",
)

patch_both(
    "lhash.h",
    """OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    """/**
 * @brief Print per-bucket node counts for an LHASH to @p fp (deprecated).
 * @param lh Hash table to describe.
 * @param fp Output stream.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    "OPENSSL_LH_node_stats",
)

# ----- params.h -----

patch_one(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf);
""",
    """/**
 * @brief Construct an OSSL_PARAM that locates an unsigned long value.
 * @param key Parameter name.
 * @param buf Address of the unsigned long to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf);
""",
    "OSSL_PARAM_construct_ulong",
)

patch_one(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf);
""",
    """/**
 * @brief Construct an OSSL_PARAM that locates a size_t value.
 * @param key Parameter name.
 * @param buf Address of the size_t to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf);
""",
    "OSSL_PARAM_construct_size_t",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val);
""",
    """/**
 * @brief Read an integer parameter value from @p p into *@p val.
 * @param p Parameter locator describing an integer-typed value.
 * @param val Receives the converted int.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val);
""",
    "OSSL_PARAM_get_int",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);
""",
    """/**
 * @brief Read a long integer parameter value from @p p into *@p val.
 * @param p Parameter locator describing an integer-typed value.
 * @param val Receives the converted long.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);
""",
    "OSSL_PARAM_get_long",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val);
""",
    """/**
 * @brief Write an unsigned int into the storage located by @p p.
 * @param p Parameter locator describing an unsigned integer-typed destination.
 * @param val Value to store.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val);
""",
    "OSSL_PARAM_set_uint",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_double(OSSL_PARAM *p, double val);
""",
    """/**
 * @brief Write a double into the storage located by @p p.
 * @param p Parameter locator describing a floating-point destination.
 * @param val Value to store.
 * @return 1 on success, or 0 on type failure.
 */
int OSSL_PARAM_set_double(OSSL_PARAM *p, double val);
""",
    "OSSL_PARAM_set_double",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val);
""",
    """/**
 * @brief Set a UTF-8 pointer parameter to refer to @p val (no copy).
 * @param p Parameter locator with type OSSL_PARAM_UTF8_PTR.
 * @param val Pointer to a NUL-terminated string retained by the caller.
 * @return 1 on success, or 0 on type failure.
 */
int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val);
""",
    "OSSL_PARAM_set_utf8_ptr",
)

# ----- pkcs7.h -----

patch_both(
    "pkcs7.h",
    """DECLARE_ASN1_DUP_FUNCTION(PKCS7)
""",
    """/**
 * @brief Deep-copy a PKCS#7 structure (PKCS7_dup).
 * @param a Source PKCS7 to duplicate.
 * @return Newly allocated PKCS7 copy, or NULL on failure; free with PKCS7_free().
 */
DECLARE_ASN1_DUP_FUNCTION(PKCS7)
""",
    "PKCS7_dup",
)

patch_both(
    "pkcs7.h",
    """ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk);
""",
    """/**
 * @brief Extract the message-digest OCTET STRING from a set of authenticatedAttributes.
 * @param sk Attribute stack from a PKCS7_SIGNER_INFO.
 * @return Pointer to the digest octets within @p sk, or NULL if absent; do not free.
 */
ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk);
""",
    "PKCS7_digest_from_attributes",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,
    STACK_OF(X509_ATTRIBUTE) *sk);
""",
    """/**
 * @brief Replace the authenticatedAttributes of a signer info with a copy of @p sk.
 * @param p7si Signer info to update.
 * @param sk Attributes to install (copied); may be empty.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,
    STACK_OF(X509_ATTRIBUTE) *sk);
""",
    "PKCS7_set_signed_attributes",
)

# ----- rsa.h -----

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_check_key(const RSA *);
""",
    """/**
 * @brief Validate consistency of an RSA key's public/private components (deprecated).
 * @param rsa RSA key to check.
 * @return 1 if the key looks consistent, or 0 on failure (error queue may explain).
 */
OSSL_DEPRECATEDIN_3_0 int RSA_check_key(const RSA *);
""",
    "RSA_check_key",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_print_fp(FILE *fp, const RSA *r, int offset);
""",
    """/**
 * @brief Print RSA key components to a FILE with indentation (deprecated).
 * @param fp Output stream.
 * @param r RSA key to print.
 * @param offset Indentation in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_print_fp(FILE *fp, const RSA *r, int offset);
""",
    "RSA_print_fp",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_print(BIO *bp, const RSA *r, int offset);
""",
    """/**
 * @brief Print RSA key components to a BIO with indentation (deprecated).
 * @param bp Output BIO.
 * @param r RSA key to print.
 * @param offset Indentation in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_print(BIO *bp, const RSA *r, int offset);
""",
    "RSA_print",
)

# ----- sha.h -----

patch_one(
    "sha.h",
    """    SHA_LONG data[SHA_LBLOCK];
""",
    """    /** Current message block buffer (16 SHA_LONG words). */
    SHA_LONG data[SHA_LBLOCK];
""",
    "SHA_CTX.data",
)

patch_one(
    "sha.h",
    """    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
""",
    """    union {
        /** Current message block as 64-bit words for the compression function. */
        SHA_LONG64 d[SHA_LBLOCK];
        /** Current message block as bytes for partial-block buffering. */
        unsigned char p[SHA512_CBLOCK];
    } u;
""",
    "SHA512 u.d/u.p",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA512_Init(SHA512_CTX *c);
""",
    """/**
 * @brief Initialize a SHA-512 digest context (deprecated; prefer EVP_DigestInit).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Init(SHA512_CTX *c);
""",
    "SHA512_Init",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA512_Final(unsigned char *md, SHA512_CTX *c);
""",
    """/**
 * @brief Finalize a SHA-512 digest and write SHA512_DIGEST_LENGTH bytes to @p md (deprecated).
 * @param md Destination buffer for the digest.
 * @param c Context previously updated with SHA512_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA512_Final(unsigned char *md, SHA512_CTX *c);
""",
    "SHA512_Final",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
