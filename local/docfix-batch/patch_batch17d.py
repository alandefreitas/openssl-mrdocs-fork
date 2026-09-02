#!/usr/bin/env python3
"""Documentation repair batch 17d: params, evp, http, kdf, lhash, objects."""
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


print("=== batch 17d: params/evp/http/kdf/lhash/objects ===")

# ----- params.h -----

patch_both(
    "params.h",
    """/* Search an OSSL_PARAM array for a matching name */
OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);
""",
    """/**
 * @brief Find the first OSSL_PARAM in @p p whose key matches @p key.
 * @param p Parameter array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param key Parameter name to search for.
 * @return Pointer to the matching element, or NULL if not found.
 */
OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);
""",
    "OSSL_PARAM_locate",
)

patch_both(
    "params.h",
    """/* Basic parameter type run-time construction */
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
""",
    """/* Basic parameter type run-time construction */
/**
 * @brief Construct an OSSL_PARAM that locates a signed int value.
 * @param key Parameter name.
 * @param buf Address of the int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
""",
    "OSSL_PARAM_construct_int",
)

patch_both(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf);
""",
    """/**
 * @brief Construct an OSSL_PARAM that locates a signed long int value.
 * @param key Parameter name.
 * @param buf Address of the long int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf);
""",
    "OSSL_PARAM_construct_long",
)

patch_both(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf);
OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf);
""",
    """/**
 * @brief Construct an OSSL_PARAM describing an unsigned 32-bit integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the uint32_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_UNSIGNED_INTEGER sized for uint32_t.
 */
OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing a signed 64-bit integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the int64_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_INTEGER sized for int64_t.
 */
OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf);
""",
    "OSSL_PARAM_construct_uint32+int64",
)

patch_both(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
    size_t bsize);
""",
    """/**
 * @brief Construct an OSSL_PARAM that references an existing octet buffer via pointer.
 * @param key Parameter name.
 * @param buf Address of a void* that points at (or receives) the octet data.
 * @param bsize Size of the buffer addressed by *@p buf when writing, or 0 when only reading.
 * @return OSSL_PARAM of type OSSL_PARAM_OCTET_PTR.
 */
OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
    size_t bsize);
""",
    "OSSL_PARAM_construct_octet_ptr",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_allocate_from_text(OSSL_PARAM *to,
    const OSSL_PARAM *paramdefs,
    const char *key, const char *value,
    size_t value_n, int *found);
""",
    """/**
 * @brief Allocate and fill an OSSL_PARAM from a textual key/value using a param definition list.
 * @param to Destination parameter; on success owns freshly allocated @c data that the caller must free.
 * @param paramdefs Array of parameter definitions describing allowed keys and types.
 * @param key Parameter name to look up in @p paramdefs.
 * @param value Textual representation of the value (encoding depends on the matched type).
 * @param value_n Length of @p value in bytes (not necessarily NUL-terminated).
 * @param found Optional; set to 1 if @p key was found in @p paramdefs, else 0.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_allocate_from_text(OSSL_PARAM *to,
    const OSSL_PARAM *paramdefs,
    const char *key, const char *value,
    size_t value_n, int *found);
""",
    "OSSL_PARAM_allocate_from_text",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val);
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val);
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val);
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);
""",
    """/**
 * @brief Read an unsigned long integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val);
/**
 * @brief Read a signed 32-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val);
/**
 * @brief Read an unsigned 32-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val);
/**
 * @brief Read a signed 64-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);
""",
    "OSSL_PARAM_get_ulong+int32+uint32+int64",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_time_t(const OSSL_PARAM *p, time_t *val);

int OSSL_PARAM_set_int(OSSL_PARAM *p, int val);
""",
    """/**
 * @brief Read a time_t value from an integer OSSL_PARAM.
 * @param p Parameter whose contents convert to time_t.
 * @param val Receives the time value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_time_t(const OSSL_PARAM *p, time_t *val);

/**
 * @brief Store a signed int into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 if the buffer is too small or of the wrong type.
 */
int OSSL_PARAM_set_int(OSSL_PARAM *p, int val);
""",
    "OSSL_PARAM_get_time_t+set_int",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val);
int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val);
int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val);
""",
    """/**
 * @brief Store a uint32_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val);
/**
 * @brief Store an int64_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val);
/**
 * @brief Store a uint64_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val);
""",
    "OSSL_PARAM_set_uint32+int64+uint64",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_set_time_t(OSSL_PARAM *p, time_t val);
""",
    """/**
 * @brief Store a time_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Time value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_time_t(OSSL_PARAM *p, time_t val);
""",
    "OSSL_PARAM_set_time_t",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val);
""",
    """/**
 * @brief Decode an unsigned integer OSSL_PARAM into a newly allocated BIGNUM.
 * @param p Parameter holding an unsigned big-endian integer.
 * @param val In/out BIGNUM pointer; allocates when *@p val is NULL, else reuses it.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val);
""",
    "OSSL_PARAM_get_BN",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
""",
    """/**
 * @brief Copy a UTF-8 string OSSL_PARAM into a caller-provided or allocated buffer.
 * @param p Parameter of type OSSL_PARAM_UTF8_STRING.
 * @param val When *@p val is NULL, receives a newly allocated copy; otherwise writes into the buffer of size @p max_len.
 * @param max_len Capacity of *@p val when non-NULL (including space for the NUL); ignored when allocating.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
""",
    "OSSL_PARAM_get_utf8_string",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);
""",
    """/**
 * @brief Return a pointer to the octet data referenced by an OSSL_PARAM_OCTET_PTR parameter.
 * @param p Parameter of type OSSL_PARAM_OCTET_PTR.
 * @param val Receives the address of the referenced octet data (not a copy).
 * @param used_len Optional; receives the number of meaningful bytes.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);
""",
    "OSSL_PARAM_get_octet_ptr",
)

patch_both(
    "params.h",
    """int OSSL_PARAM_get_utf8_string_ptr(const OSSL_PARAM *p, const char **val);
int OSSL_PARAM_get_octet_string_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);

int OSSL_PARAM_modified(const OSSL_PARAM *p);
void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *p);

OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *p);
""",
    """/**
 * @brief Return a pointer to the UTF-8 contents of an OSSL_PARAM without copying.
 * @param p Parameter of type OSSL_PARAM_UTF8_STRING or OSSL_PARAM_UTF8_PTR.
 * @param val Receives a pointer to the internal string data (do not free).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_utf8_string_ptr(const OSSL_PARAM *p, const char **val);
/**
 * @brief Return a pointer to the octet-string contents of an OSSL_PARAM without copying.
 * @param p Parameter of type OSSL_PARAM_OCTET_STRING.
 * @param val Receives a pointer to the internal octets (do not free).
 * @param used_len Optional; receives the number of bytes at *@p val.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_octet_string_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);

/**
 * @brief Test whether an OSSL_PARAM was written (modified) by a set/get operation.
 * @param p Parameter to query, or NULL.
 * @return 1 if the modified flag is set, or 0 otherwise.
 */
int OSSL_PARAM_modified(const OSSL_PARAM *p);
/**
 * @brief Clear the modified flag on every element of an OSSL_PARAM array.
 * @param p Parameter array terminated by an end sentinel; may be NULL.
 */
void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *p);

/**
 * @brief Deep-copy an OSSL_PARAM array, including owned string/octet buffers.
 * @param p Source array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @return Newly allocated copy freed with OSSL_PARAM_free(), or NULL on failure.
 */
OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *p);
""",
    "OSSL_PARAM_get_*_ptr+modified+dup",
)

# ----- evp.h -----

patch_both(
    "evp.h",
    """const EVP_MD *EVP_sha512_224(void);
""",
    """/**
 * @brief Return the EVP_MD for SHA-512/224 (truncated SHA-512).
 * @return Built-in message digest method (do not free).
 */
const EVP_MD *EVP_sha512_224(void);
""",
    "EVP_sha512_224",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_rc4_hmac_md5(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for the RC4-HMAC-MD5 AEAD suite (TLS legacy).
 * @return Built-in cipher method (do not free), or NULL if the algorithm is unavailable.
 */
const EVP_CIPHER *EVP_rc4_hmac_md5(void);
""",
    "EVP_rc4_hmac_md5",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
    int *ppkey_flags, const char **pinfo,
    const char **ppem_str,
    const EVP_PKEY_ASN1_METHOD *ameth);
""",
    """/**
 * @brief Extract identifying metadata from an EVP_PKEY_ASN1_METHOD.
 * @param ppkey_id Optional; receives the method's EVP_PKEY type NID.
 * @param pkey_base_id Optional; receives the base key type NID.
 * @param ppkey_flags Optional; receives ASN1 method flags (ASN1_PKEY_*).
 * @param pinfo Optional; receives the human-readable info string, or NULL.
 * @param ppem_str Optional; receives the PEM string name used for this key type.
 * @param ameth ASN.1 method to query; must not be NULL.
 * @return 1 on success, or 0 if @p ameth is NULL.
 */
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
    int *ppkey_flags, const char **pinfo,
    const char **ppem_str,
    const EVP_PKEY_ASN1_METHOD *ameth);
""",
    "EVP_PKEY_asn1_get0_info",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key,
    int keylen);
""",
    """/**
 * @brief Set the MAC key bytes on a keygen/paramgen EVP_PKEY_CTX (for example HMAC or Poly1305).
 * @param ctx Key generation context for a MAC algorithm.
 * @param key MAC key octets; may be NULL when @p keylen is 0.
 * @param keylen Length of @p key in bytes.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key,
    int keylen);
""",
    "EVP_PKEY_CTX_set_mac_key",
)

patch_both(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub,
    size_t len);
""",
    """/**
 * @brief Create an EVP_PKEY from raw public key octets for algorithms that support that form.
 * @param type Key type NID (for example EVP_PKEY_X25519, EVP_PKEY_ED25519, EVP_PKEY_EC).
 * @param e Deprecated ENGINE parameter; pass NULL.
 * @param pub Public key bytes in the algorithm's raw format.
 * @param len Length of @p pub in bytes.
 * @return New EVP_PKEY on success, or NULL on failure.
 */
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub,
    size_t len);
""",
    "EVP_PKEY_new_raw_public_key",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
""",
    """/**
 * @brief Set the peer public key used by EVP_PKEY_derive() on a derivation context.
 * @param ctx Initialized derive context from EVP_PKEY_derive_init().
 * @param peer Peer public key; ownership is not transferred.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
""",
    "EVP_PKEY_derive_set_peer",
)

# ----- http.h -----

patch_both(
    "http.h",
    """BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout);
""",
    """/**
 * @brief Perform an HTTP GET and return a memory BIO holding the response body.
 * @param url Absolute http:// or https:// URL to fetch.
 * @param proxy Optional HTTP(S) proxy URL/host, or NULL to use environment defaults.
 * @param no_proxy Optional host exclusion list, or NULL for environment defaults.
 * @param bio Optional write BIO; NULL builds an internal connect BIO from @p url.
 * @param rbio Optional read BIO paired with @p bio when both are non-NULL.
 * @param bio_update_fn Optional connect/TLS BIO callback (needed for https when @p bio is NULL).
 * @param arg Opaque argument forwarded to @p bio_update_fn.
 * @param buf_size Max header line length / read chunk; <= 0 uses the default.
 * @param headers Optional additional request headers, or NULL.
 * @param expected_content_type Required Content-Type (exact or prefix), or NULL for any.
 * @param expect_asn1 Nonzero if the body must be ASN.1 DER.
 * @param max_resp_len Maximum accepted response body length in bytes; 0 means unlimited.
 * @param timeout Soft transfer timeout in seconds (<= 0 waits indefinitely where supported).
 * @return Memory BIO with the response body on success (caller frees), or NULL on failure.
 */
BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout);
""",
    "OSSL_HTTP_get",
)

patch_both(
    "http.h",
    """void OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(OSSL_HTTP_REQ_CTX *rctx,
    size_t count);
""",
    """/**
 * @brief Limit how many HTTP response header lines @p rctx will accept.
 * @param rctx Request context to update.
 * @param count Maximum header lines (0 means unlimited / implementation default).
 */
void OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(OSSL_HTTP_REQ_CTX *rctx,
    size_t count);
""",
    "OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines",
)

# ----- kdf.h -----

patch_both(
    "kdf.h",
    """const OSSL_PARAM *EVP_KDF_CTX_gettable_params(EVP_KDF_CTX *ctx);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors that can be retrieved from a KDF context.
 * @param ctx KDF context whose gettable parameters are queried.
 * @return Array of OSSL_PARAM descriptors terminated by an end sentinel, or NULL.
 */
const OSSL_PARAM *EVP_KDF_CTX_gettable_params(EVP_KDF_CTX *ctx);
""",
    "EVP_KDF_CTX_gettable_params",
)

patch_both(
    "kdf.h",
    """int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
""",
    """/**
 * @brief Select the digest used by a TLS1-PRF EVP_PKEY_CTX.
 * @param ctx Context for EVP_PKEY_TLS1_PRF key derivation.
 * @param md Message digest (for example EVP_sha256()) used by the PRF.
 * @return 1 on success, or a negative value / 0 on failure.
 */
int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
""",
    "EVP_PKEY_CTX_set_tls1_prf_md",
)

# ----- lhash.h -----

patch_both(
    "lhash.h",
    """OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
""",
    """/**
 * @brief Print per-bucket node counts for a hash table to a BIO (deprecated).
 * @param lh Hash table to describe.
 * @param out BIO that receives the human-readable report.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
""",
    "OPENSSL_LH_node_stats_bio",
)

# ----- objects.h -----

patch_both(
    "objects.h",
    """size_t OBJ_length(const ASN1_OBJECT *obj);
""",
    """/**
 * @brief Return the length in bytes of an ASN.1 object's encoded OID content.
 * @param obj Object identifier to query; NULL yields 0.
 * @return Number of content octets in the OID, or 0 if @p obj is NULL or has no data.
 */
size_t OBJ_length(const ASN1_OBJECT *obj);
""",
    "OBJ_length",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
for m in missing:
    print(" ", m)
