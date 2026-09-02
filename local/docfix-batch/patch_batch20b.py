#!/usr/bin/env python3
"""Documentation repair batch 20b: bn.h."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


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


print("=== batch 20b: bn ===")

patch_one(
    "bn.h",
    """BN_GENCB *BN_GENCB_new(void);
""",
    """/**
 * @brief Allocate a BN_GENCB used to report progress from prime generation.
 * @return New callback object, or NULL on failure; free with BN_GENCB_free().
 */
BN_GENCB *BN_GENCB_new(void);
""",
    "BN_GENCB_new",
)

patch_one(
    "bn.h",
    """/* Populate a BN_GENCB structure with an "old"-style callback */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback)(int, int, void *),
    void *cb_arg);
""",
    """/**
 * @brief Populate a BN_GENCB with a legacy void-returning progress callback.
 * @param gencb Callback object from BN_GENCB_new() (or a stack instance).
 * @param callback Old-style callback receiving (event, progress, @p cb_arg).
 * @param cb_arg Opaque pointer passed through to @p callback.
 */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback)(int, int, void *),
    void *cb_arg);
""",
    "BN_GENCB_set_old",
)

patch_one(
    "bn.h",
    """int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
""",
    """/**
 * @brief Test whether the absolute value of @p a equals word @p w.
 * @param a BIGNUM to test (sign is ignored).
 * @param w Single-word value to compare against.
 * @return 1 if |@p a| equals @p w, or 0 otherwise.
 */
int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
""",
    "BN_abs_is_word",
)

patch_one(
    "bn.h",
    """BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *ctx);
""",
    """/**
 * @brief Allocate a BN_CTX associated with library context @p ctx.
 * @param ctx Library context for provider-aware temporaries, or NULL for the default.
 * @return New BN_CTX, or NULL on allocation failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *ctx);
""",
    "BN_CTX_new_ex",
)

patch_one(
    "bn.h",
    """BN_CTX *BN_CTX_secure_new(void);
""",
    """/**
 * @brief Allocate a BN_CTX whose temporary BIGNUMs use the secure heap.
 * @return New secure BN_CTX, or NULL on failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_secure_new(void);
""",
    "BN_CTX_secure_new",
)

patch_one(
    "bn.h",
    """void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
""",
    """void BN_CTX_start(BN_CTX *ctx);
/**
 * @brief Obtain a temporary BIGNUM from the current BN_CTX frame started by BN_CTX_start().
 * @param ctx Context with an active BN_CTX_start() frame.
 * @return Temporary BIGNUM owned by @p ctx (do not free), or NULL on error / after a prior failure.
 */
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
/**
 * @brief Generate a cryptographically strong public random BIGNUM with explicit strength.
 * @param rnd Destination BIGNUM (allocated/resized as needed).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling the least-significant bit.
 * @param strength Requested security strength in bits for the DRBG draw.
 * @param ctx BN_CTX scratch, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int BN_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
""",
    "BN_CTX_get/BN_rand_ex",
)

patch_one(
    "bn.h",
    """int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    """/**
 * @brief Generate a cryptographically strong private random BIGNUM of @p bits bits.
 * @param rnd Destination BIGNUM (allocated/resized as needed).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    "BN_priv_rand",
)

patch_one(
    "bn.h",
    """int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    """/**
 * @brief Generate a cryptographically strong uniform public random BIGNUM in [0, @p range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    "BN_rand_range",
)

patch_one(
    "bn.h",
    """int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    """/**
 * @brief Generate a cryptographically strong uniform private random BIGNUM in [0, @p range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    "BN_priv_rand_range",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    """/**
 * @brief Generate a pseudo-random BIGNUM in [0, @p range) (deprecated; prefer BN_rand_range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
""",
    "BN_pseudo_rand_range",
)

patch_one(
    "bn.h",
    """int BN_num_bits_word(BN_ULONG l);
""",
    """/**
 * @brief Return the number of significant bits in a single BN_ULONG word.
 * @param l Word value to measure; zero yields 0.
 * @return Bit length of @p l (floor(log2(@p l))+1 when @p l != 0).
 */
int BN_num_bits_word(BN_ULONG l);
""",
    "BN_num_bits_word",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_new(void);
""",
    """/**
 * @brief Allocate a new BIGNUM initialized to zero.
 * @return New BIGNUM, or NULL on failure; free with BN_free() / BN_clear_free().
 */
BIGNUM *BN_new(void);
""",
    "BN_new",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
""",
    """/**
 * @brief Convert a big-endian two's-complement byte array to a signed BIGNUM.
 * @param s Input octets in big-endian two's-complement form.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Encode the absolute value of @p a as a minimal big-endian unsigned byte string.
 * @param a Value to encode (sign is ignored).
 * @param to Destination buffer of at least BN_num_bytes(@p a) bytes.
 * @return Number of bytes written.
 */
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
""",
    "BN_signed_bin2bn/BN_bn2bin",
)

patch_one(
    "bn.h",
    """int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
""",
    """/**
 * @brief Encode a signed BIGNUM as big-endian two's-complement of fixed width.
 * @param a Value to encode (may be negative).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Fixed output width in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
""",
    "BN_signed_bn2bin",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    """/**
 * @brief Convert a little-endian two's-complement byte array to a signed BIGNUM.
 * @param s Little-endian two's-complement input octets.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    "BN_signed_lebin2bn",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    """/**
 * @brief Convert a native-endian two's-complement byte array to a signed BIGNUM.
 * @param s Native-endian two's-complement input octets.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    "BN_signed_native2bn",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    """/**
 * @brief Decode an MPI-format integer (4-byte length prefix plus big-endian content).
 * @param s MPI-encoded input buffer.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    "BN_mpi2bn",
)

patch_one(
    "bn.h",
    """int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    """/**
 * @brief Subtract signed BIGNUMs: @p r = @p a - @p b.
 * @param r Destination difference.
 * @param a Minuend.
 * @param b Subtrahend.
 * @return 1 on success, or 0 on error.
 */
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    "BN_sub",
)

patch_one(
    "bn.h",
    """int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    """/**
 * @brief Add unsigned BIGNUMs: @p r = @p a + @p b (ignores signs; result non-negative).
 * @param r Destination sum.
 * @param a First addend.
 * @param b Second addend.
 * @return 1 on success, or 0 on error.
 */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
/**
 * @brief Add signed BIGNUMs: @p r = @p a + @p b.
 * @param r Destination sum.
 * @param a First addend.
 * @param b Second addend.
 * @return 1 on success, or 0 on error.
 */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
""",
    "BN_uadd/BN_add",
)

patch_one(
    "bn.h",
    """int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
""",
    """/**
 * @brief Square a BIGNUM: @p r = @p a * @p a.
 * @param r Destination square.
 * @param a Value to square.
 * @param ctx BN_CTX scratch space, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
""",
    "BN_sqr",
)

patch_one(
    "bn.h",
    """int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
""",
    """/**
 * @brief Compute @p r = (@p a + @p b) mod @p m assuming 0 <= @p a,@p b < @p m.
 * @param r Destination (may alias @p a or @p b).
 * @param a First addend already reduced modulo @p m.
 * @param b Second addend already reduced modulo @p m.
 * @param m Modulus.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
""",
    "BN_mod_add_quick",
)

patch_one(
    "bn.h",
    """BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_set_word(BIGNUM *a, BN_ULONG w);
""",
    """/**
 * @brief Divide @p a by word @p w in place and return the remainder.
 * @param a Dividend updated to the quotient (sign preserved).
 * @param w Non-zero divisor word.
 * @return Remainder, or (BN_ULONG)-1 on error (for example @p w is 0).
 */
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Add word @p w to BIGNUM @p a in place.
 * @param a Destination/addend updated in place.
 * @param w Word value added to @p a.
 * @return 1 on success, or 0 on error.
 */
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Set BIGNUM @p a to the single-word value @p w.
 * @param a Destination BIGNUM.
 * @param w Word value to assign (non-negative).
 * @return 1 on success, or 0 on error.
 */
int BN_set_word(BIGNUM *a, BN_ULONG w);
""",
    "BN_div/add/set_word",
)

patch_one(
    "bn.h",
    """int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
""",
    """/**
 * @brief Compute modular exponentiation using Montgomery reduction: r = (a ^ p) mod m.
 * @param r Destination for the result.
 * @param a Base.
 * @param p Exponent.
 * @param m Modulus (must be odd).
 * @param ctx BN_CTX scratch space.
 * @param m_ctx Montgomery context for @p m, or NULL to build one temporarily.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
""",
    "BN_mod_exp_mont",
)

patch_one(
    "bn.h",
    """int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
""",
    """/**
 * @brief Montgomery modular exponentiation with a single-word base: r = (a ^ p) mod m.
 * @param r Destination for the result.
 * @param a Word-sized base.
 * @param p Exponent.
 * @param m Odd modulus.
 * @param ctx BN_CTX scratch space.
 * @param m_ctx Montgomery context for @p m, or NULL to build one temporarily.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
/**
 * @brief Compute modular exponentiation with a simple sliding-window algorithm: r = (a ^ p) mod m.
 * @param r Destination for the result.
 * @param a Base.
 * @param p Exponent.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
""",
    "BN_mod_exp_mont_word/simple",
)

patch_one(
    "bn.h",
    """void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
""",
    """/**
 * @brief Set a BIGNUM to zero and scrub its limb storage.
 * @param a BIGNUM to clear; may be NULL (no-op).
 */
void BN_clear(BIGNUM *a);
/**
 * @brief Allocate a new BIGNUM that is a deep copy of @p a.
 * @param a Source value to duplicate.
 * @return New BIGNUM equal to @p a, or NULL on failure; free with BN_free().
 */
BIGNUM *BN_dup(const BIGNUM *a);
/**
 * @brief Compare absolute values of two BIGNUMs (ignores signs).
 * @param a First operand.
 * @param b Second operand.
 * @return Negative, zero, or positive as |@p a| is less than, equal to, or greater than |@p b|.
 */
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
/**
 * @brief Set bit @p n of BIGNUM @p a (expanding the value if needed).
 * @param a BIGNUM to modify.
 * @param n Zero-based bit index to set.
 * @return 1 on success, or 0 on error.
 */
int BN_set_bit(BIGNUM *a, int n);
/**
 * @brief Clear bit @p n of BIGNUM @p a.
 * @param a BIGNUM to modify.
 * @param n Zero-based bit index to clear.
 * @return 1 on success, or 0 on error.
 */
int BN_clear_bit(BIGNUM *a, int n);
/**
 * @brief Convert a BIGNUM to a newly allocated hexadecimal string.
 * @param a Value to convert.
 * @return Heap string (free with OPENSSL_free()), or NULL on failure.
 */
char *BN_bn2hex(const BIGNUM *a);
""",
    "BN_clear/dup/ucmp/bits/hex",
)

patch_one(
    "bn.h",
    """int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
""",
    """/**
 * @brief Compute the Kronecker symbol (a/b), a generalization of the Jacobi symbol.
 * @param a Numerator.
 * @param b Denominator.
 * @param ctx BN_CTX scratch space.
 * @return -1, 0, or 1 for a valid symbol, or -2 on error.
 */
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
""",
    "BN_kronecker",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_mod_sqrt(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
""",
    """/**
 * @brief Compute a modular square root: ret^2 ≡ a (mod n) when a quadratic residue.
 * @param ret Destination for the root, or NULL to allocate.
 * @param a Value whose square root modulo @p n is requested.
 * @param n Odd prime modulus (Tonelli–Shanks style algorithms).
 * @param ctx BN_CTX scratch space.
 * @return Result BIGNUM (possibly @p ret), or NULL if no root exists / on error.
 */
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
""",
    "BN_mod_sqrt",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb);
""",
    """/**
 * @brief Probable-primality test with optional trial division (deprecated; prefer BN_check_prime).
 * @param p Candidate integer.
 * @param nchecks Number of Miller–Rabin rounds, or 0 for a size-based default.
 * @param ctx BN_CTX scratch, or NULL.
 * @param do_trial_division Non-zero to trial-divide by small primes first.
 * @param cb Optional progress callback, or NULL.
 * @return 1 if @p p is probably prime, 0 if composite, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0
int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb);
""",
    "BN_is_prime_fasttest_ex",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1,
    BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *e,
    BN_CTX *ctx, BN_GENCB *cb);
""",
    """/**
 * @brief Generate an X9.31-style probable prime derived from parameters @p Xp/@p e (deprecated).
 * @param p Destination for the generated prime.
 * @param p1 Optional destination for auxiliary prime p1, or NULL.
 * @param p2 Optional destination for auxiliary prime p2, or NULL.
 * @param Xp1 Optional random seed for p1, or NULL to generate internally.
 * @param Xp2 Optional random seed for p2, or NULL to generate internally.
 * @param Xp Random parameter that constrains p.
 * @param e Public exponent that must be coprime to (p-1).
 * @param ctx BN_CTX scratch space.
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1,
    BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *e,
    BN_CTX *ctx, BN_GENCB *cb);
""",
    "BN_X931_generate_prime_ex",
)

patch_one(
    "bn.h",
    """int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
""",
    """/**
 * @brief Convert @p a from Montgomery representation to a normal residue modulo mont->N.
 * @param r Destination for the converted value.
 * @param a Value in Montgomery form.
 * @param mont Montgomery context from BN_MONT_CTX_set().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);
/**
 * @brief Free a BN_MONT_CTX allocated by BN_MONT_CTX_new().
 * @param mont Montgomery context to free, or NULL (no-op).
 */
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
""",
    "BN_from_montgomery/MONT_CTX_free",
)

patch_one(
    "bn.h",
    """BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
""",
    """/**
 * @brief Copy Montgomery context @p from into @p to.
 * @param to Destination context (must already be allocated).
 * @param from Source context to duplicate.
 * @return @p to on success, or NULL on error.
 */
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
""",
    "BN_MONT_CTX_copy",
)

patch_one(
    "bn.h",
    """void BN_BLINDING_free(BN_BLINDING *b);
""",
    """/**
 * @brief Free a BN_BLINDING object and its associated factors.
 * @param b Blinding object to free, or NULL (no-op).
 */
void BN_BLINDING_free(BN_BLINDING *b);
""",
    "BN_BLINDING_free",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
""",
    """/**
 * @brief Blind @p n using @p b, optionally storing the inverse factor in @p r.
 * @param n Value updated in place to its blinded form.
 * @param r Optional destination for the inverse blinding factor, or NULL.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx);
""",
    "BN_BLINDING_convert_ex",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_unlock(BN_BLINDING *b);

unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
""",
    """/**
 * @brief Release the mutex associated with a BN_BLINDING object.
 * @param b Blinding object whose lock is released.
 * @return 1 on success, or 0 on failure.
 */
int BN_BLINDING_unlock(BN_BLINDING *b);

/**
 * @brief Return the behavioural flag mask stored on a BN_BLINDING object.
 * @param b Blinding object to query.
 * @return Bitmask of BN_BLINDING_* flags.
 */
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *b);
""",
    "BN_BLINDING_unlock/get_flags",
)

patch_one(
    "bn.h",
    """BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
""",
    """/**
 * @brief Allocate a BN_RECP_CTX used to accelerate repeated modular reduction.
 * @return New reciprocal context, or NULL on failure; free with BN_RECP_CTX_free().
 */
BN_RECP_CTX *BN_RECP_CTX_new(void);
/**
 * @brief Free a BN_RECP_CTX allocated by BN_RECP_CTX_new().
 * @param recp Reciprocal context to free, or NULL (no-op).
 */
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
/**
 * @brief Configure a reciprocal context for repeated division by modulus @p rdiv.
 * @param recp Context to initialize.
 * @param rdiv Modulus / divisor used for subsequent reciprocal operations.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
""",
    "BN_RECP_CTX_*",
)

patch_one(
    "bn.h",
    """int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
""",
    """/**
 * @brief Compute modular exponentiation using reciprocal reduction: r = (a ^ p) mod m.
 * @param r Destination for the result.
 * @param a Base.
 * @param p Exponent.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
""",
    "BN_mod_exp_recp",
)

# GF(2^m) family — convert adjacent // comments into proper docs
patch_one(
    "bn.h",
    """/* r=a mod p
 */
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
/* r = (a * b) mod p */
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
/* r = (a * a) mod p */
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/* r = (1 / b) mod p */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
""",
    """/**
 * @brief Reduce @p a modulo irreducible polynomial @p p in GF(2^m): r = a mod p.
 * @param r Destination residue.
 * @param a Polynomial to reduce.
 * @param p Irreducible modulus polynomial.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
/**
 * @brief Multiply then reduce in GF(2^m): r = (a * b) mod p.
 * @param r Destination product.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Square then reduce in GF(2^m): r = (a * a) mod p.
 * @param r Destination square.
 * @param a Value to square.
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Compute the multiplicative inverse in GF(2^m): r = (1 / b) mod p.
 * @param r Destination inverse.
 * @param b Value to invert (must be non-zero modulo @p p).
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
""",
    "BN_GF2m_mod/mul/sqr/inv",
)

patch_one(
    "bn.h",
    """/* r^2 + r = a mod p */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    BN_CTX *ctx);
""",
    """/**
 * @brief Solve the quadratic r^2 + r = a mod p over GF(2^m).
 * @param r Destination for one solution when it exists.
 * @param a Right-hand side.
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 if no solution / on error.
 */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    BN_CTX *ctx);
""",
    "BN_GF2m_mod_solve_quad",
)

patch_one(
    "bn.h",
    """/* r = (a * b) mod p */
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/* r = (a * a) mod p */
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
    BN_CTX *ctx);
""",
    """/**
 * @brief Multiply then reduce in GF(2^m) with the modulus given as an int array: r = (a * b) mod p.
 * @param r Destination product.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param p Descending exponent list of the irreducible, terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/**
 * @brief Square then reduce in GF(2^m) with the modulus given as an int array: r = (a * a) mod p.
 * @param r Destination square.
 * @param a Value to square.
 * @param p Descending exponent list of the irreducible, terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
    BN_CTX *ctx);
""",
    "BN_GF2m_mod_mul/sqr_arr",
)

patch_one(
    "bn.h",
    """/* r = (a ^ b) mod p */
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/* r = sqrt(a) mod p */
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
    const int p[], BN_CTX *ctx);
""",
    """/**
 * @brief Exponentiate in GF(2^m) with the modulus given as an int array: r = (a ^ b) mod p.
 * @param r Destination for the power.
 * @param a Base.
 * @param b Exponent.
 * @param p Descending exponent list of the irreducible, terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/**
 * @brief Compute a square root in GF(2^m) with the modulus given as an int array: r = sqrt(a) mod p.
 * @param r Destination for the root.
 * @param a Value whose square root is requested.
 * @param p Descending exponent list of the irreducible, terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
    const int p[], BN_CTX *ctx);
""",
    "BN_GF2m_mod_exp/sqrt_arr",
)

patch_one(
    "bn.h",
    """int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
""",
    """/**
 * @brief Convert a GF(2^m) polynomial BIGNUM into a descending exponent index array.
 * @param a Polynomial whose set bits become exponents.
 * @param p Destination array of size at least @p max; filled then terminated with -1.
 * @param max Capacity of @p p including room for the -1 terminator.
 * @return Number of exponents written (excluding -1), or 0 if @p max is too small / on error.
 */
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
""",
    "BN_GF2m_poly2arr",
)

patch_one(
    "bn.h",
    """int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
""",
    """/**
 * @brief Fast reduction of @p a modulo the NIST P-192 prime (0 <= a < p^2).
 * @param r Destination residue.
 * @param a Value to reduce (typically less than p^2).
 * @param p Must be the NIST P-192 prime (often ignored when specialized).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Fast reduction of @p a modulo the NIST P-224 prime (0 <= a < p^2).
 * @param r Destination residue.
 * @param a Value to reduce (typically less than p^2).
 * @param p Must be the NIST P-224 prime (often ignored when specialized).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Fast reduction of @p a modulo the NIST P-256 prime (0 <= a < p^2).
 * @param r Destination residue.
 * @param a Value to reduce (typically less than p^2).
 * @param p Must be the NIST P-256 prime (often ignored when specialized).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Fast reduction of @p a modulo the NIST P-384 prime (0 <= a < p^2).
 * @param r Destination residue.
 * @param a Value to reduce (typically less than p^2).
 * @param p Must be the NIST P-384 prime (often ignored when specialized).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

/**
 * @brief Return the NIST P-192 prime as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_192(void);
/**
 * @brief Return the NIST P-224 prime as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_224(void);
/**
 * @brief Return the NIST P-256 prime as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
""",
    "BN_nist_mod/get0_192-256",
)

patch_one(
    "bn.h",
    """/* Primes from RFC 3526 */
BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_3072(BIGNUM *bn);
""",
    """/* Primes from RFC 3526 */
/**
 * @brief Return the 1536-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *bn);
/**
 * @brief Return the 2048-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_2048(BIGNUM *bn);
/**
 * @brief Return the 3072-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_3072(BIGNUM *bn);
""",
    "BN_get_rfc3526_1536/2048/3072",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_8192(BIGNUM *bn);
""",
    """/**
 * @brief Return the 6144-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_6144(BIGNUM *bn);
/**
 * @brief Return the 8192-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_8192(BIGNUM *bn);
""",
    "BN_get_rfc3526_6144/8192",
)

patch_one(
    "bn.h",
    """int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    """/**
 * @brief Generate a non-cryptographic test random BIGNUM for BN self-tests.
 * @param rnd Destination BIGNUM.
 * @param bits Desired bit length.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    "BN_bntest_rand",
)

print(f"\nOK {len(ok)}, MISS {len(missing)}")
for m in missing:
    print(" ", m)
