#!/usr/bin/env python3
"""Documentation repair batch 7a: asn1, async, bio, bn, cms, conf, conftypes, crypto."""
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


# ----- asn1.h -----
patch_both("asn1.h",
"""typedef struct ASN1_ENCODING_st {
    unsigned char *enc; /* DER encoding */
    long len; /* Length of encoding */
    int modified; /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;""",
"""typedef struct ASN1_ENCODING_st {
    /** Saved DER encoding of an ASN.1 value (may be invalid). */
    unsigned char *enc;
    /** Length in bytes of the buffer at @c enc. */
    long len;
    /** Non-zero when @c enc is invalid and must not be reused for signatures. */
    int modified;
} ASN1_ENCODING;""",
"ASN1_ENCODING::len")

patch_both("asn1.h",
"DECLARE_ASN1_ALLOC_FUNCTIONS_name(ASN1_TYPE, ASN1_TYPE)",
"""/**
 * @brief Allocate an empty ASN.1 ANY / ASN1_TYPE container.
 * @return New ASN1_TYPE, or NULL on allocation failure.
 */
ASN1_TYPE *ASN1_TYPE_new(void);
/**
 * @brief Free an ASN.1 ANY / ASN1_TYPE value and its contents.
 * @param a Value to free, or NULL.
 */
void ASN1_TYPE_free(ASN1_TYPE *a);""",
"ASN1_TYPE_alloc")

patch_both("asn1.h",
"DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)",
asn1_funcs("ASN1_T61STRING", "ASN.1 TeletexString (T61String)"),
"ASN1_T61STRING_funcs")

patch_both("asn1.h",
"long ASN1_INTEGER_get(const ASN1_INTEGER *a);",
"""/**
 * @brief Return the value of an ASN.1 INTEGER as a C long.
 * @param a INTEGER to read.
 * @return The integer value, or 0xffffffffL if @p a is NULL or out of long range.
 */
long ASN1_INTEGER_get(const ASN1_INTEGER *a);""",
"ASN1_INTEGER_get")

patch_both("asn1.h",
"""void *ASN1_item_d2i_fp_ex(const ASN1_ITEM *it, FILE *in, void *x,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"""/**
 * @brief Decode an ASN.1 value described by @p it from a FILE, with library context.
 * @param it ASN.1 item describing the type to decode.
 * @param in Open FILE positioned at DER input.
 * @param x Optional existing object to reuse, or NULL to allocate.
 * @param libctx Library context for algorithm fetches during decode, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_item_d2i_fp_ex(const ASN1_ITEM *it, FILE *in, void *x,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"ASN1_item_d2i_fp_ex")

patch_both("asn1.h",
"int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);",
"""/**
 * @brief Print a byte buffer as colon-separated hex to a BIO with indentation.
 * @param bp BIO that receives the formatted output.
 * @param buf Bytes to print.
 * @param buflen Number of bytes at @p buf.
 * @param off Indentation depth in spaces.
 * @return 1 on success, or 0 on error.
 */
int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);""",
"ASN1_buf_print")

patch_both("asn1.h",
"void ASN1_add_stable_module(void);",
"""/**
 * @brief Register the built-in ASN.1 string-table (STABLE) configuration module.
 *
 * Enables the \"asn1_string_table\" CONF module used to override default string
 * type masks and size limits for OIDs.
 */
void ASN1_add_stable_module(void);""",
"ASN1_add_stable_module")

patch_both("asn1.h",
"ASN1_PCTX *ASN1_PCTX_new(void);",
"""/**
 * @brief Allocate a new ASN.1 print context with default formatting flags.
 * @return New ASN1_PCTX, or NULL on allocation failure.
 */
ASN1_PCTX *ASN1_PCTX_new(void);""",
"ASN1_PCTX_new")

# ----- async.h -----
patch_both("async.h",
"""int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
    OSSL_ASYNC_FD *fd, void **custom_data);""",
"""/**
 * @brief Look up the wait file descriptor registered under @p key.
 * @param ctx Wait context to query.
 * @param key Unique key previously passed to ASYNC_WAIT_CTX_set_wait_fd.
 * @param fd Receives the registered OSSL_ASYNC_FD on success.
 * @param custom_data Receives the custom_data pointer registered with the fd, or NULL.
 * @return 1 if a matching fd was found, or 0 otherwise.
 */
int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
    OSSL_ASYNC_FD *fd, void **custom_data);""",
"ASYNC_WAIT_CTX_get_fd")

patch_both("async.h",
"int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status);",
"""/**
 * @brief Set the engine-reported status of an asynchronous wait context.
 * @param ctx Wait context to update.
 * @param status One of the ASYNC_STATUS_* values describing progress or readiness.
 * @return 1 on success, or 0 on error.
 */
int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status);""",
"ASYNC_WAIT_CTX_set_status")

patch_both("async.h",
"""void ASYNC_get_mem_functions(ASYNC_stack_alloc_fn *alloc_fn,
    ASYNC_stack_free_fn *free_fn);""",
"""/**
 * @brief Retrieve the current custom ASYNC stack allocator callbacks.
 * @param alloc_fn Receives the installed allocator, or NULL if the default is in use.
 * @param free_fn Receives the installed free callback, or NULL if the default is in use.
 */
void ASYNC_get_mem_functions(ASYNC_stack_alloc_fn *alloc_fn,
    ASYNC_stack_free_fn *free_fn);""",
"ASYNC_get_mem_functions")

patch_both("async.h",
"""ASYNC_JOB *ASYNC_get_current_job(void);
ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job);
void ASYNC_block_pause(void);""",
"""/**
 * @brief Return the ASYNC_JOB currently executing on this thread, if any.
 * @return The current job, or NULL when called outside an ASYNC job.
 */
ASYNC_JOB *ASYNC_get_current_job(void);
/**
 * @brief Return the wait context associated with an asynchronous job.
 * @param job Job whose wait context is requested.
 * @return The job's ASYNC_WAIT_CTX, or NULL if @p job is NULL.
 */
ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job);
/**
 * @brief Temporarily ignore ASYNC_pause_job() on the current thread.
 *
 * Nested calls nest; each block must be matched by ASYNC_unblock_pause().
 * Use around code that must not yield (for example while holding locks).
 */
void ASYNC_block_pause(void);""",
"ASYNC_get_wait_ctx_block_pause")

# ----- bio.h -----
patch_both("bio.h",
"""typedef struct bio_poll_descriptor_st {
    uint32_t type;
    union {
        int fd;
        void *custom;
        uintptr_t custom_ui;
        SSL *ssl;
    } value;
} BIO_POLL_DESCRIPTOR;""",
"""/**
 * @brief Pollable I/O target returned by BIO_get_rpoll_descriptor / BIO_get_wpoll_descriptor.
 */
typedef struct bio_poll_descriptor_st {
    /** Discriminator: BIO_POLL_DESCRIPTOR_TYPE_* (NONE, SOCK_FD, SSL, or custom). */
    uint32_t type;
    union {
        /** Socket or file descriptor when @c type is BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD. */
        int fd;
        /** Application-defined pointer for custom poll descriptor types. */
        void *custom;
        /** Application-defined integer for custom poll descriptor types. */
        uintptr_t custom_ui;
        /** SSL object when @c type is BIO_POLL_DESCRIPTOR_TYPE_SSL. */
        SSL *ssl;
    } value;
} BIO_POLL_DESCRIPTOR;""",
"bio_poll_descriptor_st")

patch_both("bio.h",
"uint64_t BIO_number_written(BIO *bio);",
"""/**
 * @brief Return the cumulative number of bytes successfully written through a BIO.
 * @param bio BIO whose write counter is queried.
 * @return Total bytes written since the BIO was created.
 */
uint64_t BIO_number_written(BIO *bio);""",
"BIO_number_written")

patch_both("bio.h",
"void BIO_set_next(BIO *b, BIO *next);",
"""/**
 * @brief Set the next BIO in a filter chain after @p b.
 * @param b BIO whose successor is replaced.
 * @param next BIO to become the next filter, or NULL to clear the link.
 */
void BIO_set_next(BIO *b, BIO *next);""",
"BIO_set_next")

patch_both("bio.h",
"const BIO_METHOD *BIO_s_secmem(void);",
"""/**
 * @brief Return the BIO_METHOD for a secure-heap memory BIO.
 * @return Pointer to the static secure-memory BIO method.
 *
 * Like BIO_s_mem(), but buffers are allocated from the OpenSSL secure heap.
 */
const BIO_METHOD *BIO_s_secmem(void);""",
"BIO_s_secmem")

patch_both("bio.h",
"enum BIO_lookup_type {",
"""/**
 * @brief Whether BIO_lookup resolves addresses for a client connect or server bind.
 */
enum BIO_lookup_type {""",
"BIO_lookup_type")

patch_both("bio.h",
"""long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *);
int BIO_meth_set_ctrl(BIO_METHOD *biom,
    long (*ctrl)(BIO *, int, long, void *));""",
"""/**
 * @brief Return the ctrl function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Ctrl callback pointer, or NULL if unset.
 */
long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *);
int BIO_meth_set_ctrl(BIO_METHOD *biom,
    long (*ctrl)(BIO *, int, long, void *));""",
"BIO_meth_get_ctrl")

patch_both("bio.h",
"int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));",
"""/**
 * @brief Install the destroy callback invoked when a BIO of this method is freed.
 * @param biom Method being configured.
 * @param destroy Callback that releases method-specific state for a BIO; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));""",
"BIO_meth_set_destroy")

# ----- bn.h -----
patch_both("bn.h",
"void BN_CTX_start(BN_CTX *ctx);",
"""/**
 * @brief Begin a temporary BIGNUM frame on a BN_CTX.
 * @param ctx Context whose allocation frame is pushed.
 *
 * Pair with BN_CTX_end(). BIGNUMs obtained via BN_CTX_get() after start are
 * released (not freed) when the matching end is called.
 */
void BN_CTX_start(BN_CTX *ctx);""",
"BN_CTX_start")

patch_both("bn.h",
"""int BN_rand_range_ex(BIGNUM *r, const BIGNUM *range, unsigned int strength,
    BN_CTX *ctx);""",
"""/**
 * @brief Generate a cryptographically strong uniform random BIGNUM in [0, range).
 * @param r Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @param strength Desired security strength in bits for the RNG draw.
 * @param ctx BN_CTX for temporary storage, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_rand_range_ex(BIGNUM *r, const BIGNUM *range, unsigned int strength,
    BN_CTX *ctx);""",
"BN_rand_range_ex")

patch_both("bn.h",
"int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);",
"""/**
 * @brief Encode a BIGNUM as a fixed-length big-endian unsigned byte string.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes; leading zeros are written as needed.
 * @param tolen Exact output length in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);""",
"BN_bn2binpad")

patch_both("bn.h",
"""int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);""",
"""/**
 * @brief Compute r = (a * b) mod m.
 * @param r Destination for the product modulo @p m.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param m Modulus; must be non-zero.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);""",
"BN_mod_mul")

patch_both("bn.h",
"""int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
    BN_CTX *ctx);""",
"""/**
 * @brief Compute r = (a << n) mod m (left-shift then reduce).
 * @param r Destination for the result.
 * @param a Value to shift.
 * @param n Number of bits to shift left; must be non-negative.
 * @param m Modulus; must be non-zero.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
    BN_CTX *ctx);""",
"BN_mod_lshift")

patch_both("bn.h",
"int BN_asc2bn(BIGNUM **a, const char *str);",
"""/**
 * @brief Parse an ASCII decimal or hexadecimal integer into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Decimal digits, or a hex string with a leading \"0x\" / \"0X\".
 * @return 1 on success, or 0 on parse error.
 *
 * A leading '-' sets the negative flag. Trailing non-digit characters are ignored
 * after a successful parse of a number prefix.
 */
int BN_asc2bn(BIGNUM **a, const char *str);""",
"BN_asc2bn")

patch_both("bn.h",
"""int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);""",
"""/**
 * @brief Convert @p a into the Montgomery domain for modulus @p mont.
 * @param r Destination for aR mod m.
 * @param a Value to convert (typically reduced modulo m).
 * @param mont Montgomery context initialized for modulus m.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);""",
"BN_to_montgomery")

patch_both("bn.h",
"int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);",
"""/**
 * @brief Initialize a Montgomery context for modulus @p mod.
 * @param mont Context to configure.
 * @param mod Odd modulus m.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);""",
"BN_MONT_CTX_set")

patch_both("bn.h",
"void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);",
"""/**
 * @brief Set behavioural flags on a BN_BLINDING object.
 * @param b Blinding object to update.
 * @param flags Bitmask of BN_BLINDING_* flags (for example BN_BLINDING_NO_UPDATE).
 */
void BN_BLINDING_set_flags(BN_BLINDING *b, unsigned long flags);""",
"BN_BLINDING_set_flags")

patch_both("bn.h",
"""int (*BN_nist_mod_func(const BIGNUM *p))(BIGNUM *r, const BIGNUM *a,
    const BIGNUM *field, BN_CTX *ctx);""",
"""/**
 * @brief Return a fast modular-reduction function for a known NIST prime.
 * @param p Prime to look up (for example a BN_get0_nist_prime_* value).
 * @return Specialized mod function for @p p, or NULL if @p p is not a built-in NIST prime.
 */
int (*BN_nist_mod_func(const BIGNUM *p))(BIGNUM *r, const BIGNUM *a,
    const BIGNUM *field, BN_CTX *ctx);""",
"BN_nist_mod_func")

# ----- cms.h -----
patch_both("cms.h",
"""int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in,
    int flags);""",
"""/**
 * @brief Write a CMS ContentInfo as a PEM CMS message, optionally streaming content from @p in.
 * @param out BIO that receives the PEM-encoded CMS.
 * @param cms CMS structure to encode.
 * @param in BIO supplying detached or streaming content when required by @p flags, or NULL.
 * @param flags CMS_* flags controlling streaming and encoding behaviour.
 * @return 1 on success, or 0 on error.
 */
int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in,
    int flags);""",
"PEM_write_bio_CMS_stream")

patch_both("cms.h",
"CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms);",
"""/**
 * @brief Append an empty CertificateChoices slot to a CMS SignedData certificates set.
 * @param cms ContentInfo of type signed-data (or similar) that holds certificates.
 * @return Newly added CMS_CertificateChoices, or NULL on error; ownership stays with @p cms.
 */
CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms);""",
"CMS_add0_CertificateChoices")

patch_both("cms.h",
"""int CMS_SharedInfo_encode(unsigned char **pder, X509_ALGOR *kekalg,
    ASN1_OCTET_STRING *ukm, int keylen);""",
"""/**
 * @brief DER-encode a CMS SharedInfo structure used in key-encryption key derivation.
 * @param pder Receives a newly allocated DER encoding on success; free with OPENSSL_free.
 * @param kekalg Key-encryption algorithm identifier placed in SharedInfo.
 * @param ukm Optional user keying material OCTET STRING, or NULL.
 * @param keylen Length in bytes of the KEK being derived (encoded as a 4-byte INTEGER).
 * @return Length of the DER encoding, or a negative value on error.
 */
int CMS_SharedInfo_encode(unsigned char **pder, X509_ALGOR *kekalg,
    ASN1_OCTET_STRING *ukm, int keylen);""",
"CMS_SharedInfo_encode")

# ----- conf.h -----
patch_both("conf.h",
"typedef struct conf_imodule_st CONF_IMODULE;",
"""/**
 * @brief Opaque instance of a loaded CONF module (per-section module state).
 */
typedef struct conf_imodule_st CONF_IMODULE;""",
"CONF_IMODULE")

patch_both("conf.h",
"int CONF_set_default_method(CONF_METHOD *meth);",
"""/**
 * @brief Set the default CONF_METHOD used by the legacy CONF_load family.
 * @param meth Method implementation to install as the process default.
 * @return 1 on success, or 0 on error.
 */
int CONF_set_default_method(CONF_METHOD *meth);""",
"CONF_set_default_method")

patch_both("conf.h",
"int NCONF_dump_bio(const CONF *conf, BIO *out);",
"""/**
 * @brief Dump a CONF structure's sections and name/value pairs to a BIO.
 * @param conf Configuration to print.
 * @param out BIO that receives the textual dump.
 * @return 1 on success, or 0 on error.
 */
int NCONF_dump_bio(const CONF *conf, BIO *out);""",
"NCONF_dump_bio")

# ----- conftypes.h -----
patch_both("conftypes.h",
"    int (*destroy_data)(CONF *conf);",
"""    /** Release configuration data held by @p conf without destroying the object. */
    int (*destroy_data)(CONF *conf);""",
"destroy_data")

patch_both("conftypes.h",
"    LHASH_OF(CONF_VALUE) *data;",
"""    /** Hash table of CONF_VALUE entries (section/name/value triples). */
    LHASH_OF(CONF_VALUE) *data;""",
"conf_st::data")

patch_both("conftypes.h",
"    int flag_abspath;",
"""    /** Non-zero when .include paths are treated as absolute rather than relative. */
    int flag_abspath;""",
"flag_abspath")

# ----- crypto.h -----
patch_both("crypto.h",
"int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);",
"""/**
 * @brief Release a previously acquired read or write lock on a CRYPTO_RWLOCK.
 * @param lock Lock to unlock.
 * @return 1 on success, or 0 on error.
 */
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);""",
"CRYPTO_THREAD_unlock")

patch_both("crypto.h",
"size_t OPENSSL_strlcpy(char *dst, const char *src, size_t siz);",
"""/**
 * @brief Copy @p src into @p dst with BSD strlcpy semantics.
 * @param dst Destination buffer of @p siz bytes.
 * @param src NUL-terminated source string.
 * @param siz Capacity of @p dst including space for the NUL terminator.
 * @return Length of @p src (as if there were no truncation).
 */
size_t OPENSSL_strlcpy(char *dst, const char *src, size_t siz);""",
"OPENSSL_strlcpy")

patch_both("crypto.h",
"char *OPENSSL_buf2hexstr(const unsigned char *buf, long buflen);",
"""/**
 * @brief Convert a byte buffer to a newly allocated colon-separated hex string.
 * @param buf Bytes to convert.
 * @param buflen Number of bytes at @p buf; negative treats the buffer as unsigned.
 * @return Newly allocated string such as \"AB:CD\", or NULL on error; free with OPENSSL_free.
 */
char *OPENSSL_buf2hexstr(const unsigned char *buf, long buflen);""",
"OPENSSL_buf2hexstr")

patch_both("crypto.h",
"int OPENSSL_strcasecmp(const char *s1, const char *s2);",
"""/**
 * @brief Case-insensitive comparison of two NUL-terminated C strings.
 * @param s1 First string.
 * @param s2 Second string.
 * @return Less than, equal to, or greater than zero as with strcasecmp(3).
 */
int OPENSSL_strcasecmp(const char *s1, const char *s2);""",
"OPENSSL_strcasecmp")

# ----- cryptoerr_legacy.h -----
patch_both("cryptoerr_legacy.h",
"OSSL_DEPRECATEDIN_3_0 int ERR_load_DH_strings(void);",
"""/**
 * @brief Load Diffie-Hellman library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_DH_strings(void);""",
"ERR_load_DH_strings")

patch_both("cryptoerr_legacy.h",
"OSSL_DEPRECATEDIN_3_0 int ERR_load_ERR_strings(void);",
"""/**
 * @brief Load core ERR library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_ERR_strings(void);""",
"ERR_load_ERR_strings")

print(f"\nDone 7a: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print(" ", m)
