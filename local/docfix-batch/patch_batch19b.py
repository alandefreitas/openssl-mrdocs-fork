#!/usr/bin/env python3
"""Documentation repair batch 19b: bn, cms, conf, conf_api, conftypes, core."""
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


print("=== batch 19b: bn/cms/conf/conf_api/conftypes/core ===")

# ----- bn.h (plain .h only) -----

patch_one(
    "bn.h",
    """void BN_GENCB_free(BN_GENCB *cb);
""",
    """/**
 * @brief Free a BN_GENCB allocated by BN_GENCB_new().
 * @param cb Callback object to free, or NULL (no-op).
 */
void BN_GENCB_free(BN_GENCB *cb);
""",
    "BN_GENCB_free",
)

patch_one(
    "bn.h",
    """int BN_is_one(const BIGNUM *a);
""",
    """/**
 * @brief Test whether a BIGNUM equals one.
 * @param a BIGNUM to test.
 * @return 1 if @p a has the value 1, or 0 otherwise.
 */
int BN_is_one(const BIGNUM *a);
""",
    "BN_is_one",
)

patch_one(
    "bn.h",
    """const BIGNUM *BN_value_one(void);
""",
    """/**
 * @brief Return a shared BIGNUM constant equal to 1.
 * @return Pointer to a static BIGNUM holding the value 1; do not free or modify.
 */
const BIGNUM *BN_value_one(void);
""",
    "BN_value_one",
)

patch_one(
    "bn.h",
    """int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    """/**
 * @brief Generate a cryptographically strong public random BIGNUM of @p bits bits.
 * @param rnd Destination BIGNUM (allocated/resized as needed).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling whether the least-significant bit must be set.
 * @return 1 on success, or 0 on failure.
 */
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    "BN_rand",
)

patch_one(
    "bn.h",
    """int BN_num_bits(const BIGNUM *a);
""",
    """/**
 * @brief Return the size of @p a in bits (index of the highest set bit plus one).
 * @param a BIGNUM to measure; zero yields 0.
 * @return Number of significant bits in the absolute value of @p a.
 */
int BN_num_bits(const BIGNUM *a);
""",
    "BN_num_bits",
)

patch_one(
    "bn.h",
    """int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
""",
    """/**
 * @brief Encode a BIGNUM as a fixed-length native-endian unsigned byte string.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes; leading zeros are written as needed.
 * @param tolen Exact output length in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
""",
    "BN_bn2nativepad",
)

patch_one(
    "bn.h",
    """int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    """/**
 * @brief Subtract unsigned BIGNUMs: @p r = @p a - @p b (requires @p a >= @p b).
 * @param r Destination difference (non-negative).
 * @param a Minuend.
 * @param b Subtrahend; must not exceed @p a.
 * @return 1 on success, or 0 if @p a < @p b or on error.
 */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    "BN_usub",
)

patch_one(
    "bn.h",
    """int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
""",
    """/**
 * @brief Compute r = (a << 1) mod m, assuming 0 <= a < m.
 * @param r Destination for the result (may alias @p a).
 * @param a Value to double then reduce; must already be reduced modulo @p m.
 * @param m Modulus; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
""",
    "BN_mod_lshift1_quick",
)

patch_one(
    "bn.h",
    """int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *in_mont);
""",
    """/**
 * @brief Compute modular exponentiation in constant time: @p rr = (@p a ^ @p p) mod @p m.
 * @param rr Destination for the result.
 * @param a Base.
 * @param p Exponent (treated as secret for timing purposes).
 * @param m Odd modulus.
 * @param ctx BN_CTX for temporary storage.
 * @param in_mont Optional precomputed Montgomery context for @p m, or NULL to build one.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *in_mont);
""",
    "BN_mod_exp_mont_consttime",
)

patch_one(
    "bn.h",
    """int BN_mod_exp_mont_consttime_x2(BIGNUM *rr1, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *m1, BN_MONT_CTX *in_mont1,
    BIGNUM *rr2, const BIGNUM *a2, const BIGNUM *p2,
    const BIGNUM *m2, BN_MONT_CTX *in_mont2,
    BN_CTX *ctx);
""",
    """/**
 * @brief Compute two constant-time Montgomery modular exponentiations together.
 * @param rr1 Destination for (a1 ^ p1) mod m1.
 * @param a1 First base.
 * @param p1 First exponent.
 * @param m1 First odd modulus.
 * @param in_mont1 Optional Montgomery context for @p m1, or NULL.
 * @param rr2 Destination for (a2 ^ p2) mod m2.
 * @param a2 Second base.
 * @param p2 Second exponent.
 * @param m2 Second odd modulus.
 * @param in_mont2 Optional Montgomery context for @p m2, or NULL.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_mont_consttime_x2(BIGNUM *rr1, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *m1, BN_MONT_CTX *in_mont1,
    BIGNUM *rr2, const BIGNUM *a2, const BIGNUM *p2,
    const BIGNUM *m2, BN_MONT_CTX *in_mont2,
    BN_CTX *ctx);
""",
    "BN_mod_exp_mont_consttime_x2",
)

patch_one(
    "bn.h",
    """int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
""",
    """/**
 * @brief Compute r = a >> n (right shift by @p n bits).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param n Number of bits to shift (non-negative).
 * @return 1 on success, or 0 on failure.
 */
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
""",
    "BN_rshift",
)

patch_one(
    "bn.h",
    """int BN_hex2bn(BIGNUM **a, const char *str);
""",
    """/**
 * @brief Parse a hexadecimal ASCII string into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Hex digit string; a leading '-' sets the negative flag.
 * @return Number of characters consumed from @p str on success, or 0 on parse error.
 */
int BN_hex2bn(BIGNUM **a, const char *str);
""",
    "BN_hex2bn",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_mod_inverse(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
""",
    """/**
 * @brief Compute the modular inverse of @p a modulo @p n.
 * @param ret Existing BIGNUM to receive the result, or NULL to allocate.
 * @param a Value to invert.
 * @param n Modulus; must be non-zero.
 * @param ctx BN_CTX scratch space.
 * @return Result BIGNUM (possibly newly allocated) on success, or NULL if no inverse exists / on error.
 */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
""",
    "BN_mod_inverse",
)

patch_one(
    "bn.h",
    """BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
""",
    """/**
 * @brief Allocate a BN_BLINDING object from blinding factors A and A^-1 mod @p mod.
 * @param A Blinding multiplier (may be freshly generated by the caller).
 * @param Ai Modular inverse of @p A modulo @p mod.
 * @param mod Modulus copied into the new blinding object.
 * @return New BN_BLINDING, or NULL on error; free with BN_BLINDING_free().
 */
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
""",
    "BN_BLINDING_new",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
""",
    """/**
 * @brief Unblind @p n after a private modular operation using @p b (BN_BLINDING_invert_ex with no saved r).
 * @param n Blinded value to multiply by the inverse blinding factor modulo the modulus.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
""",
    "BN_BLINDING_invert",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
    BN_CTX *);
""",
    """/**
 * @brief Unblind @p n using @p b, optionally multiplying by a caller-supplied inverse factor @p r.
 * @param n Blinded value updated in place.
 * @param r Optional precomputed inverse blinding factor, or NULL to use the factor stored in @p b.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space (unnamed parameter in the prototype).
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
    BN_CTX *);
""",
    "BN_BLINDING_invert_ex",
)

patch_one(
    "bn.h",
    """int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
    BN_RECP_CTX *recp, BN_CTX *ctx);
""",
    """/**
 * @brief Multiply then reduce using a reciprocal context: r = (x * y) mod m (m from @p recp).
 * @param r Destination for the product modulo the reciprocal modulus.
 * @param x First multiplicand.
 * @param y Second multiplicand.
 * @param recp Reciprocal context previously set with BN_RECP_CTX_set().
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
    BN_RECP_CTX *recp, BN_CTX *ctx);
""",
    "BN_mod_mul_reciprocal",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn);
""",
    """/**
 * @brief Return the 1024-bit MODP group prime from RFC 2409.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn);
""",
    "BN_get_rfc2409_prime_1024",
)

# ----- cms.h / cms.h.in -----

patch_both(
    "cms.h",
    """int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
    unsigned int flags);
""",
    """/**
 * @brief Decompress a CMS CompressedData ContentInfo to @p out.
 * @param cms CompressedData ContentInfo to expand.
 * @param dcont Optional BIO supplying detached content, or NULL when content is embedded.
 * @param out BIO that receives the uncompressed content octets.
 * @param flags Optional CMS flags such as CMS_TEXT.
 * @return 1 on success, or 0 on failure.
 */
int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
    unsigned int flags);
""",
    "CMS_uncompress",
)

# ----- conf.h / conf.h.in -----

patch_both(
    "conf.h",
    """LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp,
    long *eline);
""",
    """/**
 * @brief Load a CONF file from an open FILE into an LHASH of CONF_VALUE (legacy API).
 * @param conf Existing hash to extend, or NULL to allocate a new one.
 * @param fp Input stream positioned at the start of the configuration text.
 * @param eline Receives the error line number on parse failure, or unchanged on success.
 * @return The configuration hash (possibly newly allocated), or NULL on error.
 */
LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp,
    long *eline);
""",
    "CONF_load_fp",
)

patch_both(
    "conf.h",
    """long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
    const char *name);
""",
    """/**
 * @brief Look up a numeric value in a legacy CONF LHASH.
 * @param conf Configuration hash from CONF_load*().
 * @param group Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Parsed long integer, or 0 if missing / not a number (errors are not distinguished).
 */
long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
    const char *name);
""",
    "CONF_get_number",
)

patch_both(
    "conf.h",
    """OSSL_LIB_CTX *NCONF_get0_libctx(const CONF *conf);
""",
    """/**
 * @brief Return the library context associated with a CONF object.
 * @param conf Configuration created with NCONF_new_ex() or equivalent.
 * @return The OSSL_LIB_CTX stored on @p conf, or NULL for the default context.
 */
OSSL_LIB_CTX *NCONF_get0_libctx(const CONF *conf);
""",
    "NCONF_get0_libctx",
)

patch_both(
    "conf.h",
    """STACK_OF(OPENSSL_CSTRING) *NCONF_get_section_names(const CONF *conf);
""",
    """/**
 * @brief Return the names of all sections present in a CONF object.
 * @param conf Configuration to query.
 * @return Newly allocated stack of section name strings (free the stack with OPENSSL_sk_free(); do not free the strings), or NULL on error.
 */
STACK_OF(OPENSSL_CSTRING) *NCONF_get_section_names(const CONF *conf);
""",
    "NCONF_get_section_names",
)

# ----- conf_api.h -----

patch_one(
    "conf_api.h",
    """CONF_VALUE *_CONF_new_section(CONF *conf, const char *section);
""",
    """/**
 * @brief Create a new named section in the internal CONF data store.
 * @param conf Configuration object to update.
 * @param section Section name to create.
 * @return CONF_VALUE representing the new section, or NULL on error.
 */
CONF_VALUE *_CONF_new_section(CONF *conf, const char *section);
""",
    "_CONF_new_section",
)

patch_one(
    "conf_api.h",
    """CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section);
""",
    """/**
 * @brief Look up a section CONF_VALUE in the internal CONF data store.
 * @param conf Configuration object.
 * @param section Section name to find.
 * @return Internal section CONF_VALUE, or NULL if absent; do not free.
 */
CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section);
""",
    "_CONF_get_section",
)

patch_one(
    "conf_api.h",
    """long _CONF_get_number(const CONF *conf, const char *section,
    const char *name);
""",
    """/**
 * @brief Look up a numeric value in the internal CONF data store (legacy helper).
 * @param conf Configuration object.
 * @param section Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Parsed long integer, or 0 if missing / not a number.
 */
long _CONF_get_number(const CONF *conf, const char *section,
    const char *name);
""",
    "_CONF_get_number",
)

patch_one(
    "conf_api.h",
    """void _CONF_free_data(CONF *conf);
""",
    """/**
 * @brief Free the internal LHASH and CONF_VALUE entries stored in @p conf.
 * @param conf Configuration object whose data table is released; NULL is ignored.
 */
void _CONF_free_data(CONF *conf);
""",
    "_CONF_free_data",
)

# ----- conftypes.h -----

patch_one(
    "conftypes.h",
    """    void *meth_data;
""",
    """    /** Opaque method-specific data for @c meth (CONF_METHOD private state). */
    void *meth_data;
""",
    "meth_data",
)

# ----- core.h -----

patch_one(
    "core.h",
    """    const char *algorithm_names; /* key */
""",
    """    /** Colon-separated algorithm name synonyms; NULL terminates an OSSL_ALGORITHM array. */
    const char *algorithm_names; /* key */
""",
    "algorithm_names",
)

print()
print(f"OK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
