#!/usr/bin/env python3
"""Documentation repair batch 14a: asn1, bio, bn, cms, conf, core, crypto*."""
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


print("=== batch 14a ===")

# ----- asn1.h -----
patch_both(
    "asn1.h",
    """int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
""",
    """/**
 * @brief Compare two ASN.1 INTEGER values numerically (including sign).
 * @param x First INTEGER.
 * @param y Second INTEGER.
 * @return Negative, zero, or positive if @p x is less than, equal to, or greater than @p y.
 */
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
""",
    "ASN1_INTEGER_cmp",
)

patch_both(
    "asn1.h",
    """ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
    int offset_day, long offset_sec);
""",
    """/**
 * @brief Set an ASN.1 Time to @p t plus a day/second offset (UTCTime or GeneralizedTime).
 * @param s Existing ASN1_TIME to reuse, or NULL to allocate.
 * @param t Base POSIX time before applying offsets.
 * @param offset_day Days to add (may be negative).
 * @param offset_sec Seconds to add after @p offset_day (may be negative).
 * @return The resulting ASN1_TIME (possibly newly allocated), or NULL on error.
 */
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
    int offset_day, long offset_sec);
""",
    "ASN1_TIME_adj",
)

patch_both(
    "asn1.h",
    """int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size);
""",
    """/**
 * @brief Read a colon-separated hex INTEGER from @p bp into @p bs (PEM helper).
 * @param bp Input BIO supplying ASCII hex digits (and optional colon separators).
 * @param bs Destination INTEGER updated with the parsed value.
 * @param buf Scratch buffer of length @p size used while reading lines.
 * @param size Capacity of @p buf in bytes.
 * @return 1 on success, or 0 on parse/I/O error.
 */
int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size);
""",
    "a2i_ASN1_INTEGER",
)

patch_both(
    "asn1.h",
    """int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a);
""",
    """/**
 * @brief Convert an ASN.1 INTEGER to a host int64_t.
 * @param pr Receives the signed value on success.
 * @param a INTEGER to convert; must fit in int64_t.
 * @return 1 on success, or 0 if @p a is NULL or out of int64_t range.
 */
int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a);
""",
    "ASN1_INTEGER_get_int64",
)

patch_both(
    "asn1.h",
    """ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
""",
    """/**
 * @brief Convert a BIGNUM to an ASN.1 INTEGER (allocating or reusing @p ai).
 * @param bn Source big integer (may be negative).
 * @param ai Existing ASN1_INTEGER to reuse, or NULL to allocate.
 * @return Pointer to the INTEGER result (possibly newly allocated), or NULL on error.
 */
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
""",
    "BN_to_ASN1_INTEGER",
)

patch_both(
    "asn1.h",
    """BIGNUM *ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED *ai, BIGNUM *bn);
""",
    """/**
 * @brief Convert an ASN.1 ENUMERATED value to a BIGNUM.
 * @param ai Source ENUMERATED.
 * @param bn Existing BIGNUM to reuse, or NULL to allocate.
 * @return Pointer to the BIGNUM result (possibly newly allocated), or NULL on error.
 */
BIGNUM *ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED *ai, BIGNUM *bn);
""",
    "ASN1_ENUMERATED_to_BN",
)

patch_both(
    "asn1.h",
    """int ASN1_TIME_print_ex(BIO *bp, const ASN1_TIME *tm, unsigned long flags);
""",
    """/**
 * @brief Print an ASN.1 Time to a BIO with ASN1_DTFLGS_* formatting flags.
 * @param bp Output BIO.
 * @param tm Time value (UTCTime or GeneralizedTime).
 * @param flags Combination of ASN1_DTFLGS_* (for example ASN1_DTFLGS_ISO8601).
 * @return 1 on success, or 0 on error.
 */
int ASN1_TIME_print_ex(BIO *bp, const ASN1_TIME *tm, unsigned long flags);
""",
    "ASN1_TIME_print_ex",
)

patch_both(
    "asn1.h",
    """int ASN1_item_i2d(const ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
""",
    """/**
 * @brief Encode an ASN.1 value described by @p it to DER.
 * @param val Value to encode (typed according to @p it).
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @param it ASN.1 item descriptor for the type of @p val.
 * @return Number of bytes encoded, or a negative value on error.
 */
int ASN1_item_i2d(const ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
""",
    "ASN1_item_i2d",
)

patch_both(
    "asn1.h",
    """int ASN1_item_print(BIO *out, const ASN1_VALUE *ifld, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
""",
    """/**
 * @brief Pretty-print an ASN.1 value described by @p it to a BIO.
 * @param out Output BIO.
 * @param ifld Value to print (typed according to @p it).
 * @param indent Initial indentation depth in spaces.
 * @param it ASN.1 item descriptor for the type of @p ifld.
 * @param pctx Print context with ASN1_PCTX_FLAGS_*, or NULL for defaults.
 * @return 1 on success, or 0 on error.
 */
int ASN1_item_print(BIO *out, const ASN1_VALUE *ifld, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
""",
    "ASN1_item_print",
)

# ----- bio.h -----
patch_both(
    "bio.h",
    """    uint32_t type;
    union {
        /** Socket or file descriptor when @c type is BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD. */
        int fd;
""",
    """    uint32_t type;
    /**
     * @brief Active poll target; which arm is valid depends on @c type.
     */
    union {
        /** Socket or file descriptor when @c type is BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD. */
        int fd;
""",
    "BIO_POLL_DESCRIPTOR::value union",
)

patch_both(
    "bio.h",
    """long BIO_debug_callback_ex(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed);
""",
    """/**
 * @brief Default BIO info callback that logs operations to the BIO's callback argument BIO.
 * @param bio BIO whose operation is being reported.
 * @param oper BIO_CB_* operation code (read, write, ctrl, …).
 * @param argp Pointer argument for the operation (buffer or ctrl pointer), or NULL.
 * @param len Byte count associated with the operation when applicable.
 * @param argi Integer argument for ctrl-style operations.
 * @param argl Long argument for ctrl-style operations.
 * @param ret Return value being reported for the operation.
 * @param processed Optional in/out processed-byte count for extended callbacks.
 * @return @p ret unchanged (pass-through debug callback).
 */
long BIO_debug_callback_ex(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed);
""",
    "BIO_debug_callback_ex",
)

patch_both(
    "bio.h",
    """int BIO_read(BIO *b, void *data, int dlen);
""",
    """/**
 * @brief Read up to @p dlen bytes from BIO @p b into @p data.
 * @param b Source BIO.
 * @param data Destination buffer.
 * @param dlen Maximum number of bytes to read (must be non-negative and fit in int).
 * @return Number of bytes read, 0 on EOF/no data, or a negative value on error (see BIO_should_retry).
 */
int BIO_read(BIO *b, void *data, int dlen);
""",
    "BIO_read",
)

patch_both(
    "bio.h",
    """int BIO_puts(BIO *bp, const char *buf);
""",
    """/**
 * @brief Write the NUL-terminated string @p buf to BIO @p bp.
 * @param bp Destination BIO.
 * @param buf C string to write (excluding the terminating NUL).
 * @return Number of bytes written, or a negative value on error.
 */
int BIO_puts(BIO *bp, const char *buf);
""",
    "BIO_puts",
)

patch_both(
    "bio.h",
    """long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
""",
    """/**
 * @brief Invoke a BIO ctrl that takes a BIO_info_cb callback pointer.
 * @param b BIO to control.
 * @param cmd Control command (for example BIO_CTRL_SET_CALLBACK).
 * @param fp Callback function pointer passed as the ctrl argument.
 * @return Command-specific long result, or <=0 on error depending on @p cmd.
 */
long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
""",
    "BIO_callback_ctrl",
)

patch_both(
    "bio.h",
    """int BIO_nread(BIO *bio, char **buf, int num);
""",
    """/**
 * @brief Consume up to @p num bytes from a memory BIO, returning an internal pointer.
 * @param bio Memory BIO to read from.
 * @param buf Receives a pointer into the BIO's internal buffer (valid until the next modify).
 * @param num Maximum number of bytes to consume.
 * @return Number of bytes made available at *@p buf, or a negative value on error.
 */
int BIO_nread(BIO *bio, char **buf, int num);
""",
    "BIO_nread",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_mem_buf(const void *buf, int len);
""",
    """/**
 * @brief Create a read-only memory BIO that reads from an existing buffer.
 * @param buf Pointer to @p len bytes of data (not copied; must remain valid for the BIO's life).
 * @param len Length of @p buf in bytes, or -1 to use strlen(@p buf).
 * @return New memory BIO, or NULL on error; free with BIO_free().
 */
BIO *BIO_new_mem_buf(const void *buf, int len);
""",
    "BIO_new_mem_buf",
)

patch_both(
    "bio.h",
    """int BIO_sock_should_retry(int i);
""",
    """/**
 * @brief Decide whether a socket BIO operation should be retried after return value @p i.
 * @param i Result from a socket read/write (negative on error, or zero in some cases).
 * @return 1 if the failure is retryable (EAGAIN/EINTR-style), or 0 otherwise.
 */
int BIO_sock_should_retry(int i);
""",
    "BIO_sock_should_retry",
)

patch_both(
    "bio.h",
    """int BIO_dump_fp(FILE *fp, const void *s, int len);
""",
    """/**
 * @brief Hex-dump @p len bytes at @p s to a stdio FILE.
 * @param fp Output FILE.
 * @param s Bytes to dump.
 * @param len Number of bytes at @p s.
 * @return 1 on success, or 0 on error.
 */
int BIO_dump_fp(FILE *fp, const void *s, int len);
""",
    "BIO_dump_fp",
)

patch_both(
    "bio.h",
    """int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai);
""",
    """/**
 * @brief Return the protocol number from an address-info element (for example IPPROTO_TCP).
 * @param bai Address-info node from BIO_lookup_ex() / BIO_ADDRINFO_next().
 * @return Protocol constant suitable for socket(), or 0 if unspecified.
 */
int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai);
""",
    "BIO_ADDRINFO_protocol",
)

# ----- bn.h -----
patch_one(
    "bn.h",
    """void BN_set_flags(BIGNUM *b, int n);
""",
    """/**
 * @brief Set selected BIGNUM flag bits on @p b (bitwise OR with @p n).
 * @param b Big number whose flags are updated.
 * @param n Combination of BN_FLG_* bits to set (for example BN_FLG_CONSTTIME).
 */
void BN_set_flags(BIGNUM *b, int n);
""",
    "BN_set_flags",
)

patch_one(
    "bn.h",
    """/*
 * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
 * has not been otherwise initialised or used.
 */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);
""",
    """/**
 * @brief Make @p dest a temporary read-only clone of @p b with flags replaced by @p flags.
 *
 * For temporary use only: @p dest and @p b must not be used concurrently, and
 * @p dest should be a freshly BN_new()'d BIGNUM that has not been initialised otherwise.
 *
 * @param dest Destination BIGNUM receiving the aliased limbs and new flags.
 * @param b Source BIGNUM whose limbs are shared.
 * @param flags Replacement BN_FLG_* flag word for @p dest.
 */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);
""",
    "BN_with_flags",
)

patch_one(
    "bn.h",
    """BN_CTX *BN_CTX_new(void);
""",
    """/**
 * @brief Allocate a BN_CTX using the default library context.
 * @return New BN_CTX, or NULL on allocation failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_new(void);
""",
    "BN_CTX_new",
)

patch_one(
    "bn.h",
    """int BN_priv_rand_range_ex(BIGNUM *r, const BIGNUM *range,
    unsigned int strength, BN_CTX *ctx);
""",
    """/**
 * @brief Generate a private random BIGNUM uniformly in [0, @p range) with strength bits.
 * @param r Destination for the random value.
 * @param range Exclusive upper bound (must be positive).
 * @param strength Requested security strength in bits for the DRBG draw.
 * @param ctx BN_CTX scratch, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_priv_rand_range_ex(BIGNUM *r, const BIGNUM *range,
    unsigned int strength, BN_CTX *ctx);
""",
    "BN_priv_rand_range_ex",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    """/**
 * @brief Convert @p len big-endian unsigned bytes at @p s into a BIGNUM.
 * @param s Input byte string (most significant byte first).
 * @param len Number of bytes at @p s.
 * @param ret Existing BIGNUM to reuse, or NULL to allocate.
 * @return Result BIGNUM (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    "BN_bin2bn",
)

patch_one(
    "bn.h",
    """int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
""",
    """/**
 * @brief Encode @p a in MPI format (4-byte length prefix plus big-endian content).
 * @param a Value to encode.
 * @param to Output buffer, or NULL to return only the required length.
 * @return Number of bytes written (or required), including the length prefix.
 */
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
""",
    "BN_bn2mpi",
)

patch_one(
    "bn.h",
    """int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
""",
    """/**
 * @brief Compute @p r = (@p a - @p b) mod @p m assuming 0 <= @p a,@p b < @p m.
 * @param r Destination (may alias @p a or @p b).
 * @param a Minuend already reduced modulo @p m.
 * @param b Subtrahend already reduced modulo @p m.
 * @param m Modulus (must be positive).
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
""",
    "BN_mod_sub_quick",
)

patch_one(
    "bn.h",
    """int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
""",
    """/**
 * @brief Compute @p r = (@p a * @p a) mod @p m.
 * @param r Destination square.
 * @param a Value to square.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
""",
    "BN_mod_sqr",
)

patch_one(
    "bn.h",
    """BN_ULONG BN_get_word(const BIGNUM *a);
""",
    """/**
 * @brief Return @p a as a BN_ULONG when it fits in a single word.
 * @param a Big number to convert.
 * @return The low word value, or (BN_ULONG)-1 if @p a cannot be represented as one word.
 */
BN_ULONG BN_get_word(const BIGNUM *a);
""",
    "BN_get_word",
)

patch_one(
    "bn.h",
    """int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    """/**
 * @brief Test whether @p a and @p b are coprime (gcd == 1), possibly mutating @p a.
 * @param a First value; may be overwritten as a scratch during the gcd.
 * @param b Second value (not modified).
 * @param ctx BN_CTX scratch space.
 * @return 1 if gcd(|@p a|,|@p b|) == 1, 0 if not coprime, or a negative value on error.
 */
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    "BN_are_coprime",
)

patch_one(
    "bn.h",
    """int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx);
""",
    """/**
 * @brief Montgomery multiply @p a and @p b modulo @p mont's modulus into @p r.
 * @param r Destination product in the Montgomery domain (or ordinary form depending on inputs).
 * @param a First factor (typically already in Montgomery form).
 * @param b Second factor (typically already in Montgomery form).
 * @param mont Montgomery context from BN_MONT_CTX_set().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx);
""",
    "BN_mod_mul_montgomery",
)

patch_one(
    "bn.h",
    """int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
""",
    """/**
 * @brief Compute @p r = (@p a / @p b) in GF(2^m) with reduction polynomial @p p[].
 * @param r Destination quotient.
 * @param a Dividend.
 * @param b Divisor (must be nonzero in the field).
 * @param p Irreducible polynomial as a descending exponent array terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
""",
    "BN_GF2m_mod_div_arr",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn);
""",
    """/**
 * @brief Return the 768-bit MODP group prime from RFC 2409.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn);
""",
    "BN_get_rfc2409_prime_768",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn);
""",
    """/**
 * @brief Return the 4096-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn);
""",
    "BN_get_rfc3526_prime_4096",
)

# ----- cms.h -----
patch_both(
    "cms.h",
    """CMS_ContentInfo *CMS_data_create_ex(BIO *in, unsigned int flags,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Create a CMS Data contentInfo wrapping the octets read from @p in.
 * @param in BIO supplying the content bytes to embed.
 * @param flags CMS_* flags (for example CMS_STREAM / CMS_PARTIAL).
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider algorithms, or NULL.
 * @return New CMS_ContentInfo, or NULL on error; free with CMS_ContentInfo_free().
 */
CMS_ContentInfo *CMS_data_create_ex(BIO *in, unsigned int flags,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "CMS_data_create_ex",
)

patch_both(
    "cms.h",
    """int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
    int lastpos);
""",
    """/**
 * @brief Find a signed attribute in @p si by NID, searching after @p lastpos.
 * @param si SignerInfo whose signedAttrs are searched.
 * @param nid NID of the attribute OID to locate.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Attribute index on success, or -1 if not found / on error.
 */
int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
    int lastpos);
""",
    "CMS_signed_get_attr_by_NID",
)

# ----- conf.h -----
patch_both(
    "conf.h",
    """typedef struct conf_module_st CONF_MODULE;
""",
    """/**
 * @brief Opaque registration record for a CONF DSO module implementation.
 */
typedef struct conf_module_st CONF_MODULE;
""",
    "CONF_MODULE",
)

patch_both(
    "conf.h",
    """STACK_OF(CONF_IMODULE);
""",
    """/**
 * @brief Opaque STACK_OF(CONF_IMODULE) container type for per-section module instances.
 */
STACK_OF(CONF_IMODULE);
""",
    "stack_st_CONF_IMODULE",
)

patch_both(
    "conf.h",
    """LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file,
    long *eline);
""",
    """/**
 * @brief Load a CONF file into an LHASH of CONF_VALUE (legacy CONF API).
 * @param conf Existing hash to extend, or NULL to allocate a new one.
 * @param file Path of the configuration file to parse.
 * @param eline Receives the error line number on parse failure, or unchanged on success.
 * @return The configuration hash (possibly newly allocated), or NULL on error.
 */
LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file,
    long *eline);
""",
    "CONF_load",
)

patch_both(
    "conf.h",
    """CONF_METHOD *NCONF_default(void);
""",
    """/**
 * @brief Return the default NCONF_METHOD used by NCONF_new(NULL).
 * @return Pointer to the static default configuration method.
 */
CONF_METHOD *NCONF_default(void);
""",
    "NCONF_default",
)

patch_both(
    "conf.h",
    """void NCONF_free(CONF *conf);
""",
    """/**
 * @brief Free a CONF object and its contained values.
 * @param conf Configuration to free, or NULL.
 */
void NCONF_free(CONF *conf);
""",
    "NCONF_free",
)

patch_both(
    "conf.h",
    """void *CONF_module_get_usr_data(CONF_MODULE *pmod);
""",
    """/**
 * @brief Return the application pointer previously stored on a CONF_MODULE.
 * @param pmod Module whose user data is queried.
 * @return Pointer set with CONF_module_set_usr_data(), or NULL if unset.
 */
void *CONF_module_get_usr_data(CONF_MODULE *pmod);
""",
    "CONF_module_get_usr_data",
)

# ----- core.h -----
patch_one(
    "core.h",
    """typedef struct openssl_core_ctx_st OPENSSL_CORE_CTX;
""",
    """/**
 * @brief Opaque core-side library context handle passed across the provider boundary.
 */
typedef struct openssl_core_ctx_st OPENSSL_CORE_CTX;
""",
    "OPENSSL_CORE_CTX",
)

patch_one(
    "core.h",
    """    unsigned int data_type; /* declare what kind of content is in buffer */
""",
    """    /** OSSL_PARAM_* type tag describing how @c data should be interpreted. */
    unsigned int data_type; /* declare what kind of content is in buffer */
""",
    "ossl_param_st::data_type",
)

# ----- crypto.h -----
patch_both(
    "crypto.h",
    """struct crypto_ex_data_st {
    OSSL_LIB_CTX *ctx;
    STACK_OF(void) *sk;
};
""",
    """/**
 * @brief Per-object extensible data bag keyed by CRYPTO_EX_INDEX_* class.
 */
struct crypto_ex_data_st {
    /** Library context associated with this ex_data instance. */
    OSSL_LIB_CTX *ctx;
    /** Stack of class-specific ex_data pointers indexed by ex_data index. */
    STACK_OF(void) *sk;
};
""",
    "crypto_ex_data_st",
)

patch_both(
    "crypto.h",
    """int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
""",
    """/**
 * @brief Initialise @p ad for object @p obj of CRYPTO_EX_INDEX class @p class_index.
 * @param class_index CRYPTO_EX_INDEX_* identifying the owning object type.
 * @param obj Owning object pointer passed to new-index callbacks.
 * @param ad Ex-data structure embedded in (or associated with) @p obj.
 * @return 1 on success, or 0 on error.
 */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
""",
    "CRYPTO_new_ex_data",
)

patch_both(
    "crypto.h",
    """void CRYPTO_get_mem_functions(CRYPTO_malloc_fn *malloc_fn,
    CRYPTO_realloc_fn *realloc_fn,
    CRYPTO_free_fn *free_fn);
""",
    """/**
 * @brief Retrieve the process-wide CRYPTO memory allocator callbacks currently installed.
 * @param malloc_fn Receives the malloc callback, or may be NULL.
 * @param realloc_fn Receives the realloc callback, or may be NULL.
 * @param free_fn Receives the free callback, or may be NULL.
 */
void CRYPTO_get_mem_functions(CRYPTO_malloc_fn *malloc_fn,
    CRYPTO_realloc_fn *realloc_fn,
    CRYPTO_free_fn *free_fn);
""",
    "CRYPTO_get_mem_functions",
)

patch_both(
    "crypto.h",
    """OSSL_CRYPTO_ALLOC void *CRYPTO_secure_zalloc(size_t num, const char *file, int line);
""",
    """/**
 * @brief Allocate @p num bytes from the secure heap and zero them.
 * @param num Number of bytes to allocate.
 * @param file Source file name for allocation tracking (usually OPENSSL_FILE).
 * @param line Source line for allocation tracking (usually OPENSSL_LINE).
 * @return Pointer to zeroed secure memory, or NULL on failure.
 */
OSSL_CRYPTO_ALLOC void *CRYPTO_secure_zalloc(size_t num, const char *file, int line);
""",
    "CRYPTO_secure_zalloc",
)

patch_both(
    "crypto.h",
    """size_t CRYPTO_secure_used(void);
""",
    """/**
 * @brief Return how many bytes are currently allocated from the secure heap.
 * @return Total secure-heap bytes in use, or 0 if the secure heap is not initialised.
 */
size_t CRYPTO_secure_used(void);
""",
    "CRYPTO_secure_used",
)

patch_both(
    "crypto.h",
    """void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings);
""",
    """/**
 * @brief Free an OPENSSL_INIT_SETTINGS object allocated with OPENSSL_INIT_new().
 * @param settings Settings object to free, or NULL.
 */
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings);
""",
    "OPENSSL_INIT_free",
)

patch_both(
    "crypto.h",
    """OSSL_LIB_CTX *OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX *libctx);
""",
    """/**
 * @brief Set the thread-local default OSSL_LIB_CTX used when NULL is passed for libctx.
 * @param libctx Library context to install as the default, or NULL to restore the global default.
 * @return The previous default library context.
 */
OSSL_LIB_CTX *OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX *libctx);
""",
    "OSSL_LIB_CTX_set0_default",
)

# ----- cryptoerr_legacy.h -----
patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_DSA_strings(void);
""",
    """/**
 * @brief Load legacy DSA error reason strings (deprecated no-op in OpenSSL 3).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_DSA_strings(void);
""",
    "ERR_load_DSA_strings",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
