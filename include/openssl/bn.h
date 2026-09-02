/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_BN_H
#define OPENSSL_BN_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_BN_H
#endif

#include <openssl/e_os2.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#include <openssl/opensslconf.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/bnerr.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULONG unsigned long
#define BN_BYTES 8
#endif

/*
 * 64-bit processor other than LP64 ABI
 */
#ifdef SIXTY_FOUR_BIT
#define BN_ULONG unsigned long long
#define BN_BYTES 8
#endif

#ifdef THIRTY_TWO_BIT
#define BN_ULONG unsigned int
#define BN_BYTES 4
#endif

#define BN_BITS2 (BN_BYTES * 8)
#define BN_BITS (BN_BITS2 * 2)
#define BN_TBIT ((BN_ULONG)1 << (BN_BITS2 - 1))

#define BN_FLG_MALLOCED 0x01
#define BN_FLG_STATIC_DATA 0x02

/*
 * avoid leaking exponent information through timing,
 * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
 * BN_div() will call BN_div_no_branch,
 * BN_mod_inverse() will call bn_mod_inverse_no_branch.
 */
#define BN_FLG_CONSTTIME 0x04
#define BN_FLG_SECURE 0x08

#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/* deprecated name for the flag */
#define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME
#define BN_FLG_FREE 0x8000 /* used for debugging */
#endif

/**
 * @brief Set selected BIGNUM flag bits on @p b (bitwise OR with @p n).
 * @param b Big number whose flags are updated.
 * @param n Combination of BN_FLG_* bits to set (for example BN_FLG_CONSTTIME).
 */
void BN_set_flags(BIGNUM *b, int n);
/**
 * @brief Test whether the given BN_FLG_* bits are set on a BIGNUM.
 * @param b BIGNUM to query.
 * @param n Flag mask (for example BN_FLG_CONSTTIME).
 * @return @p n bits that are set on @p b (0 if none).
 */
int BN_get_flags(const BIGNUM *b, int n);

/* Values for |top| in BN_rand() */
#define BN_RAND_TOP_ANY -1
#define BN_RAND_TOP_ONE 0
#define BN_RAND_TOP_TWO 1

/* Values for |bottom| in BN_rand() */
#define BN_RAND_BOTTOM_ANY 0
#define BN_RAND_BOTTOM_ODD 1

/**
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

/* Wrapper function to make using BN_GENCB easier */
/**
 * @brief Invoke a BN_GENCB progress callback with event codes @p a and @p b.
 * @param cb Callback object populated with BN_GENCB_set() or BN_GENCB_set_old(); NULL is ignored.
 * @param a Primary event / stage code passed to the callback.
 * @param b Secondary progress value passed to the callback.
 * @return 1 to continue, or 0 if the callback requested cancellation.
 */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);

/**
 * @brief Allocate a BN_GENCB used to report progress from prime generation.
 * @return New callback object, or NULL on failure; free with BN_GENCB_free().
 */
BN_GENCB *BN_GENCB_new(void);
/**
 * @brief Free a BN_GENCB allocated by BN_GENCB_new().
 * @param cb Callback object to free, or NULL (no-op).
 */
void BN_GENCB_free(BN_GENCB *cb);

/**
 * @brief Populate a BN_GENCB with a legacy void-returning progress callback.
 * @param gencb Callback object from BN_GENCB_new() (or a stack instance).
 * @param callback Old-style callback receiving (event, progress, @p cb_arg).
 * @param cb_arg Opaque pointer passed through to @p callback.
 */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback)(int, int, void *),
    void *cb_arg);

/**
 * @brief Populate a BN_GENCB with a new-style progress callback that returns success/failure.
 * @param gencb Callback object from BN_GENCB_new() (or a stack instance where supported).
 * @param callback Callback receiving (event, progress, @p gencb); should return 1 on success or 0 on error.
 * @param cb_arg Opaque pointer stored in @p gencb and retrievable via BN_GENCB_get_arg().
 */
void BN_GENCB_set(BN_GENCB *gencb, int (*callback)(int, int, BN_GENCB *),
    void *cb_arg);

/**
 * @brief Return the user argument previously associated with a BN_GENCB.
 * @param cb Callback object set via BN_GENCB_set() or BN_GENCB_set_old().
 * @return The @c cb_arg pointer stored in @p cb.
 */
void *BN_GENCB_get_arg(BN_GENCB *cb);

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define BN_prime_checks 0 /* default: select number of iterations based \
                           * on the size of the number */

/*
 * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
 * that will be done for checking that a random number is probably prime. The
 * error rate for accepting a composite number as prime depends on the size of
 * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
 * and so the level is what you would expect for a key of double the size of the
 * prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level we want to
 * reach.
 *
 * prime length | RSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 |         64 bit
 *  (b) >=    6 |     >=    12 |         34 |         64 bit
 */

#define BN_prime_checks_for_size(b) ((b) >= 3747 ? 3 : (b) >= 1345 ? 4  \
        : (b) >= 476                                               ? 5  \
        : (b) >= 400                                               ? 6  \
        : (b) >= 347                                               ? 7  \
        : (b) >= 308                                               ? 8  \
        : (b) >= 55                                                ? 27 \
                                                                   : /* b >= 6 */ 34)
#endif

#define BN_num_bytes(a) ((BN_num_bits(a) + 7) / 8)

/**
 * @brief Test whether the absolute value of @p a equals word @p w.
 * @param a BIGNUM to test (sign is ignored).
 * @param w Single-word value to compare against.
 * @return 1 if |@p a| equals @p w, or 0 otherwise.
 */
int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
/**
 * @brief Test whether a BIGNUM is zero.
 * @param a Value to test.
 * @return 1 if @p a is zero, or 0 otherwise.
 */
int BN_is_zero(const BIGNUM *a);
/**
 * @brief Test whether a BIGNUM equals one.
 * @param a BIGNUM to test.
 * @return 1 if @p a has the value 1, or 0 otherwise.
 */
int BN_is_one(const BIGNUM *a);
/**
 * @brief Test whether a BIGNUM equals the single word @p w (including sign of zero).
 * @param a Value to test.
 * @param w Word value to compare against.
 * @return 1 if @p a equals @p w, or 0 otherwise.
 */
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
/**
 * @brief Test whether a BIGNUM is odd.
 * @param a Value to test.
 * @return 1 if the least-significant bit of @p a is set, or 0 otherwise.
 */
int BN_is_odd(const BIGNUM *a);

#define BN_one(a) (BN_set_word((a), 1))

/**
 * @brief Set a BIGNUM to zero without allocating or freeing limbs.
 * @param a Integer cleared in place; must already be a valid BIGNUM.
 */
void BN_zero_ex(BIGNUM *a);

#if OPENSSL_API_LEVEL > 908
#define BN_zero(a) BN_zero_ex(a)
#else
#define BN_zero(a) (BN_set_word((a), 0))
#endif

/**
 * @brief Return a shared BIGNUM constant equal to 1.
 * @return Pointer to a static BIGNUM holding the value 1; do not free or modify.
 */
const BIGNUM *BN_value_one(void);
/**
 * @brief Return a short string describing compiled BIGNUM word size / options.
 * @return Static NUL-terminated options string (for example "bn(64,64)").
 */
char *BN_options(void);
/**
 * @brief Allocate a BN_CTX associated with library context @p ctx.
 * @param ctx Library context for provider-aware temporaries, or NULL for the default.
 * @return New BN_CTX, or NULL on allocation failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *ctx);
/**
 * @brief Allocate a BN_CTX using the default library context.
 * @return New BN_CTX, or NULL on allocation failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_new(void);
/**
 * @brief Allocate a BN_CTX whose temporary BIGNUMs use secure heap storage.
 * @param ctx Library context for allocation, or NULL for the default.
 * @return New BN_CTX with BN_FLG_SECURE set, or NULL on failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *ctx);
/**
 * @brief Allocate a BN_CTX whose temporary BIGNUMs use the secure heap.
 * @return New secure BN_CTX, or NULL on failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_secure_new(void);
/**
 * @brief Free a BN_CTX and any BIGNUMs still owned by its stack frames.
 * @param c Context to free, or NULL (no-op).
 */
void BN_CTX_free(BN_CTX *c);
/**
 * @brief Begin a temporary BIGNUM frame on a BN_CTX.
 * @param ctx Context whose allocation frame is pushed.
 *
 * Pair with BN_CTX_end(). BIGNUMs obtained via BN_CTX_get() after start are
 * released (not freed) when the matching end is called.
 */
void BN_CTX_start(BN_CTX *ctx);
/**
 * @brief Obtain a temporary BIGNUM from the current BN_CTX frame started by BN_CTX_start().
 * @param ctx Context with an active BN_CTX_start() frame.
 * @return Temporary BIGNUM owned by @p ctx (do not free), or NULL on error / after a prior failure.
 */
BIGNUM *BN_CTX_get(BN_CTX *ctx);
/**
 * @brief End a BN_CTX temporary frame started with BN_CTX_start(), releasing its BN_CTX_get() values.
 * @param ctx Context whose current frame is popped.
 */
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
/**
 * @brief Generate a cryptographically strong public random BIGNUM of @p bits bits.
 * @param rnd Destination BIGNUM (allocated/resized as needed).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling whether the least-significant bit must be set.
 * @return 1 on success, or 0 on failure.
 */
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
/**
 * @brief Generate a cryptographically strong private random BIGNUM with strength.
 * @param rnd Destination BIGNUM (allocated if needed by the implementation).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling whether the number must be odd.
 * @param strength Requested security strength in bits for the RNG.
 * @param ctx BN_CTX for temporary allocations, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int BN_priv_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
/**
 * @brief Generate a cryptographically strong private random BIGNUM of @p bits bits.
 * @param rnd Destination BIGNUM (allocated/resized as needed).
 * @param bits Desired bit length of the result.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
/**
 * @brief Generate a cryptographically strong uniform random BIGNUM in [0, range).
 * @param r Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @param strength Desired security strength in bits for the RNG draw.
 * @param ctx BN_CTX for temporary storage, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_rand_range_ex(BIGNUM *r, const BIGNUM *range, unsigned int strength,
    BN_CTX *ctx);
/**
 * @brief Generate a cryptographically strong uniform public random BIGNUM in [0, @p range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
/**
 * @brief Generate a private random BIGNUM uniformly in [0, @p range) with strength bits.
 * @param r Destination for the random value.
 * @param range Exclusive upper bound (must be positive).
 * @param strength Requested security strength in bits for the DRBG draw.
 * @param ctx BN_CTX scratch, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_priv_rand_range_ex(BIGNUM *r, const BIGNUM *range,
    unsigned int strength, BN_CTX *ctx);
/**
 * @brief Generate a cryptographically strong uniform private random BIGNUM in [0, @p range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Generate a pseudo-random BIGNUM (deprecated; prefer BN_rand / BN_priv_rand).
 * @param rnd Destination BIGNUM.
 * @param bits Desired bit length.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling parity of the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
/**
 * @brief Generate a pseudo-random BIGNUM in [0, @p range) (deprecated; prefer BN_rand_range).
 * @param rnd Destination for the random value.
 * @param range Exclusive upper bound; must be positive.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
#endif
/**
 * @brief Return the size of @p a in bits (index of the highest set bit plus one).
 * @param a BIGNUM to measure; zero yields 0.
 * @return Number of significant bits in the absolute value of @p a.
 */
int BN_num_bits(const BIGNUM *a);
/**
 * @brief Return the number of significant bits in a single BN_ULONG word.
 * @param l Word value to measure; zero yields 0.
 * @return Bit length of @p l (floor(log2(@p l))+1 when @p l != 0).
 */
int BN_num_bits_word(BN_ULONG l);
/**
 * @brief Estimate the security strength in bits for asymmetric parameters of sizes @p L and @p N.
 * @param L Public-key / modulus size in bits (for example RSA modulus length).
 * @param N Private-value size in bits (for example subgroup order); may be 0 when unused.
 * @return Estimated security strength in bits (NIST SP 800-57 style).
 */
int BN_security_bits(int L, int N);
/**
 * @brief Allocate a new BIGNUM initialized to zero.
 * @return New BIGNUM, or NULL on failure; free with BN_free() / BN_clear_free().
 */
BIGNUM *BN_new(void);
/**
 * @brief Allocate a BIGNUM whose limb storage is allocated from the secure heap.
 * @return New BIGNUM with BN_FLG_SECURE set, or NULL on failure; free with BN_clear_free().
 */
BIGNUM *BN_secure_new(void);
/**
 * @brief Clear sensitive digits of a BIGNUM and free it.
 * @param a BIGNUM to wipe and free, or NULL.
 */
void BN_clear_free(BIGNUM *a);
/**
 * @brief Copy BIGNUM @p b into @p a, resizing @p a as needed.
 * @param a Destination (must be non-NULL).
 * @param b Source value.
 * @return @p a on success, or NULL on allocation failure.
 */
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
/**
 * @brief Exchange the values of two BIGNUMs in constant time relative to their limb counts.
 * @param a First value.
 * @param b Second value.
 */
void BN_swap(BIGNUM *a, BIGNUM *b);
/**
 * @brief Convert @p len big-endian unsigned bytes at @p s into a BIGNUM.
 * @param s Input byte string (most significant byte first).
 * @param len Number of bytes at @p s.
 * @param ret Existing BIGNUM to reuse, or NULL to allocate.
 * @return Result BIGNUM (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
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
/**
 * @brief Encode a BIGNUM as a fixed-length big-endian unsigned byte string.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes; leading zeros are written as needed.
 * @param tolen Exact output length in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Encode a signed BIGNUM as big-endian two's-complement of fixed width.
 * @param a Value to encode (may be negative).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Fixed output width in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Convert a little-endian unsigned byte array to a BIGNUM.
 * @param s Little-endian input octets (least significant byte first).
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Convert a little-endian two's-complement byte array to a signed BIGNUM.
 * @param s Little-endian two's-complement input octets.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Encode a BIGNUM as fixed-length little-endian unsigned bytes with zero padding.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Required output length; must be large enough for @p a.
 * @return @p tolen on success, or -1 if @p tolen is too small or on error.
 */
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Encode a signed BIGNUM as little-endian two's-complement of fixed width.
 * @param a Value to encode (may be negative).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Fixed output width in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit.
 */
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Decode a native-endian unsigned byte string into a BIGNUM.
 * @param s Input bytes in host endianness.
 * @param len Number of bytes at @p s.
 * @param ret Optional existing BIGNUM to reuse, or NULL to allocate.
 * @return Result BIGNUM (same as @p ret when non-NULL), or NULL on error.
 */
BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Convert a native-endian two's-complement byte array to a signed BIGNUM.
 * @param s Native-endian two's-complement input octets.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Encode a BIGNUM as a fixed-length native-endian unsigned byte string.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes; leading zeros are written as needed.
 * @param tolen Exact output length in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Encode a BIGNUM as a fixed-length native-endian two's-complement byte string.
 * @param a Value to encode (sign is preserved via two's complement).
 * @param to Destination buffer of @p tolen bytes; sign-extended as needed.
 * @param tolen Exact output length in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit in @p tolen bytes.
 */
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
/**
 * @brief Decode an MPI-format integer (4-byte length prefix plus big-endian content).
 * @param s MPI-encoded input buffer.
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
/**
 * @brief Encode @p a in MPI format (4-byte length prefix plus big-endian content).
 * @param a Value to encode.
 * @param to Output buffer, or NULL to return only the required length.
 * @return Number of bytes written (or required), including the length prefix.
 */
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
/**
 * @brief Subtract signed BIGNUMs: @p r = @p a - @p b.
 * @param r Destination difference.
 * @param a Minuend.
 * @param b Subtrahend.
 * @return 1 on success, or 0 on error.
 */
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
/**
 * @brief Subtract unsigned BIGNUMs: @p r = @p a - @p b (requires @p a >= @p b).
 * @param r Destination difference (non-negative).
 * @param a Minuend.
 * @param b Subtrahend; must not exceed @p a.
 * @return 1 on success, or 0 if @p a < @p b or on error.
 */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
/**
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
/**
 * @brief Multiply two BIGNUMs: @p r = @p a * @p b.
 * @param r Destination product.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param ctx BN_CTX scratch space, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
/**
 * @brief Square a BIGNUM: @p r = @p a * @p a.
 * @param r Destination square.
 * @param a Value to square.
 * @param ctx BN_CTX scratch space, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  b  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
int BN_is_negative(const BIGNUM *b);

/**
 * @brief Divide @p m by @p d, writing quotient and/or remainder.
 * @param dv Receives the quotient, or NULL if not required.
 * @param rem Receives the remainder, or NULL if not required.
 * @param m Dividend.
 * @param d Divisor (must be non-zero).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
    BN_CTX *ctx);
#define BN_mod(rem, m, d, ctx) BN_div(NULL, (rem), (m), (d), (ctx))
/**
 * @brief Compute a non-negative remainder @p r = @p m mod @p d (0 <= r < |d|).
 * @param r Destination remainder.
 * @param m Dividend.
 * @param d Modulus (must be non-zero).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
/**
 * @brief Modular addition: @p r = (@p a + @p b) mod @p m with non-negative result.
 * @param r Destination.
 * @param a First addend.
 * @param b Second addend.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
/**
 * @brief Compute @p r = (@p a + @p b) mod @p m assuming 0 <= @p a,@p b < @p m.
 * @param r Destination (may alias @p a or @p b).
 * @param a First addend already reduced modulo @p m.
 * @param b Second addend already reduced modulo @p m.
 * @param m Modulus.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
/**
 * @brief Compute @p r = (@p a - @p b) mod @p m.
 * @param r Destination BIGNUM.
 * @param a Minuend.
 * @param b Subtrahend.
 * @param m Modulus (must be positive).
 * @param ctx Optional BN_CTX for temporaries, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
/**
 * @brief Compute @p r = (@p a - @p b) mod @p m assuming 0 <= @p a,@p b < @p m.
 * @param r Destination (may alias @p a or @p b).
 * @param a Minuend already reduced modulo @p m.
 * @param b Subtrahend already reduced modulo @p m.
 * @param m Modulus (must be positive).
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
/**
 * @brief Compute r = (a * b) mod m.
 * @param r Destination for the product modulo @p m.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param m Modulus; must be non-zero.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
/**
 * @brief Compute @p r = (@p a * @p a) mod @p m.
 * @param r Destination square.
 * @param a Value to square.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
/**
 * @brief Compute r = (a << 1) mod m.
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param m Modulus.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
/**
 * @brief Compute r = (a << 1) mod m, assuming 0 <= a < m.
 * @param r Destination for the result (may alias @p a).
 * @param a Value to double then reduce; must already be reduced modulo @p m.
 * @param m Modulus; must be positive.
 * @return 1 on success, or 0 on failure.
 */
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
/**
 * @brief Compute r = (a << n) mod m (left-shift then reduce).
 * @param r Destination for the result.
 * @param a Value to shift.
 * @param n Number of bits to shift left; must be non-negative.
 * @param m Modulus; must be non-zero.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
    BN_CTX *ctx);
/**
 * @brief Left-shift then reduce quickly: @p r = (@p a << @p n) mod @p m (assumes 0 <= a < m).
 * @param r Destination.
 * @param a Value already reduced modulo @p m.
 * @param n Number of bits to shift left (non-negative).
 * @param m Modulus.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

/**
 * @brief Return @p a modulo word @p w.
 * @param a Dividend.
 * @param w Modulus word (must be non-zero).
 * @return Remainder in [0, w), or (BN_ULONG)-1 on error.
 */
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
/**
 * @brief Divide @p a by word @p w in place and return the remainder.
 * @param a Dividend updated to the quotient (sign preserved).
 * @param w Non-zero divisor word.
 * @return Remainder, or (BN_ULONG)-1 on error (for example @p w is 0).
 */
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Multiply BIGNUM @p a by word @p w in place: a := a * w.
 * @param a Value to scale (updated in place).
 * @param w Multiplier word.
 * @return 1 on success, or 0 on error.
 */
int BN_mul_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Add word @p w to BIGNUM @p a in place.
 * @param a Destination/addend updated in place.
 * @param w Word value added to @p a.
 * @return 1 on success, or 0 on error.
 */
int BN_add_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Subtract word @p w from BIGNUM @p a in place: a := a - w.
 * @param a Value to update.
 * @param w Word to subtract.
 * @return 1 on success, or 0 on error.
 */
int BN_sub_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Set BIGNUM @p a to the single-word value @p w.
 * @param a Destination BIGNUM.
 * @param w Word value to assign (non-negative).
 * @return 1 on success, or 0 on error.
 */
int BN_set_word(BIGNUM *a, BN_ULONG w);
/**
 * @brief Return @p a as a BN_ULONG when it fits in a single word.
 * @param a Big number to convert.
 * @return The low word value, or (BN_ULONG)-1 if @p a cannot be represented as one word.
 */
BN_ULONG BN_get_word(const BIGNUM *a);

/**
 * @brief Compare two BIGNUMs considering sign.
 * @param a First value (NULL treated as zero).
 * @param b Second value (NULL treated as zero).
 * @return -1 if a < b, 0 if equal, or 1 if a > b.
 */
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
/**
 * @brief Free a BIGNUM and its limbs (no-op for static BIGNUMs flagged BN_FLG_STATIC_DATA).
 * @param a BIGNUM to free, or NULL (no-op).
 */
void BN_free(BIGNUM *a);
/**
 * @brief Test whether bit @p n of a BIGNUM is set.
 * @param a Value to test.
 * @param n Bit index (0 is the least-significant bit).
 * @return 1 if the bit is set, or 0 otherwise.
 */
int BN_is_bit_set(const BIGNUM *a, int n);
/**
 * @brief Compute r = a << n (left shift by @p n bits).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param n Number of bits to shift (non-negative).
 * @return 1 on success, or 0 on failure.
 */
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
/**
 * @brief Compute r = a << 1 (left shift by one bit), i.e. r = 2 * a.
 * @param r Result BIGNUM (may alias @p a).
 * @param a Value to shift.
 * @return 1 on success, or 0 on failure.
 */
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
/**
 * @brief Compute r = a^p (non-modular exponentiation).
 * @param r Result BIGNUM.
 * @param a Base.
 * @param p Non-negative exponent.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

/**
 * @brief Compute modular exponentiation: @p r = (@p a ^ @p p) mod @p m.
 * @param r Destination for the result.
 * @param a Base.
 * @param p Exponent.
 * @param m Modulus; must be non-zero.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
/**
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
/**
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
/**
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
/**
 * @brief Montgomery modular dual exponentiation: r = a1^p1 * a2^p2 mod m.
 * @param r Destination.
 * @param a1 First base.
 * @param p1 First exponent.
 * @param a2 Second base.
 * @param p2 Second exponent.
 * @param m Odd modulus matching @p m_ctx.
 * @param ctx BN_CTX scratch space.
 * @param m_ctx Montgomery context for @p m.
 * @return 1 on success, or 0 on error.
 */
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
/**
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

/**
 * @brief Truncate @p a in place so that only the least-significant @p n bits remain.
 * @param a BIGNUM to mask (modified).
 * @param n Number of low bits to keep.
 * @return 1 on success, or 0 if @p a has fewer than @p n bits / on error.
 */
int BN_mask_bits(BIGNUM *a, int n);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Write the hexadecimal encoding of a BIGNUM to a FILE stream.
 * @param fp Output FILE (for example stdout).
 * @param a Value to print; a leading '-' is written for negative numbers.
 * @return 1 on success, or 0 on write error.
 */
int BN_print_fp(FILE *fp, const BIGNUM *a);
#endif
/**
 * @brief Write the hexadecimal encoding of a BIGNUM to a BIO.
 * @param bio Destination BIO.
 * @param a Value to print; a leading '-' is written for negative numbers.
 * @return 1 on success, or 0 on write error.
 */
int BN_print(BIO *bio, const BIGNUM *a);
/**
 * @brief Compute a reciprocal @p r = 2^@p len / @p m for BN_div-style quotient estimation.
 * @param r Destination reciprocal.
 * @param m Divisor.
 * @param len Bit precision of the reciprocal.
 * @param ctx BN_CTX scratch space.
 * @return @p len on success, or -1 on error.
 */
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
/**
 * @brief Compute r = a >> n (right shift by @p n bits).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param n Number of bits to shift (non-negative).
 * @return 1 on success, or 0 on failure.
 */
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
/**
 * @brief Compute r = a >> 1 (right shift by one bit).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @return 1 on success, or 0 on failure.
 */
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
/**
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
/**
 * @brief Convert a BIGNUM to a newly allocated decimal string.
 * @param a Value to convert.
 * @return Heap string (free with OPENSSL_free()), or NULL on failure.
 */
char *BN_bn2dec(const BIGNUM *a);
/**
 * @brief Parse a hexadecimal ASCII string into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Hex digit string; a leading '-' sets the negative flag.
 * @return Number of characters consumed from @p str on success, or 0 on parse error.
 */
int BN_hex2bn(BIGNUM **a, const char *str);
/**
 * @brief Parse a decimal ASCII string into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Decimal digit string; a leading '-' sets the negative flag.
 * @return Number of characters consumed from @p str on success, or 0 on parse error.
 */
int BN_dec2bn(BIGNUM **a, const char *str);
/**
 * @brief Parse an ASCII decimal or hexadecimal integer into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Decimal digits, or a hex string with a leading "0x" / "0X".
 * @return 1 on success, or 0 on parse error.
 *
 * A leading '-' sets the negative flag. Trailing non-digit characters are ignored
 * after a successful parse of a number prefix.
 */
int BN_asc2bn(BIGNUM **a, const char *str);
/**
 * @brief Compute the greatest common divisor of @p a and @p b.
 * @param r Destination for gcd(|a|, |b|).
 * @param a First value.
 * @param b Second value.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
/**
 * @brief Compute the Kronecker symbol (a/b), a generalization of the Jacobi symbol.
 * @param a Numerator.
 * @param b Denominator.
 * @param ctx BN_CTX scratch space.
 * @return -1, 0, or 1 for a valid symbol, or -2 on error.
 */
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
/**
 * @brief Test whether @p a and @p b are coprime (gcd == 1), possibly mutating @p a.
 * @param a First value; may be overwritten as a scratch during the gcd.
 * @param b Second value (not modified).
 * @param ctx BN_CTX scratch space.
 * @return 1 if gcd(|@p a|,|@p b|) == 1, 0 if not coprime, or a negative value on error.
 */
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
/**
 * @brief Compute the modular inverse of @p a modulo @p n.
 * @param ret Existing BIGNUM to receive the result, or NULL to allocate.
 * @param a Value to invert.
 * @param n Modulus; must be non-zero.
 * @param ctx BN_CTX scratch space.
 * @return Result BIGNUM (possibly newly allocated) on success, or NULL if no inverse exists / on error.
 */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
/**
 * @brief Compute a modular square root: ret^2 ≡ a (mod n) when a quadratic residue.
 * @param ret Destination for the root, or NULL to allocate.
 * @param a Value whose square root modulo @p n is requested.
 * @param n Odd prime modulus (Tonelli–Shanks style algorithms).
 * @param ctx BN_CTX scratch space.
 * @return Result BIGNUM (possibly @p ret), or NULL if no root exists / on error.
 */
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

/**
 * @brief Conditionally swap the top @p nwords limbs (and top/neg) of two BIGNUMs in constant time.
 * @param swap Non-zero to swap, or zero to leave @p a and @p b unchanged (must be 0 or 1).
 * @param a First BIGNUM (must have at least @p nwords usable limbs).
 * @param b Second BIGNUM (same size requirement as @p a).
 * @param nwords Number of limbs to exchange.
 */
void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);

/* Deprecated versions */
#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/**
 * @brief Generate a prime of approximately @p bits (deprecated; prefer BN_generate_prime_ex).
 * @param ret Destination BIGNUM, or NULL to allocate a new one.
 * @param bits Desired bit length of the prime.
 * @param safe Nonzero to require a safe prime ((p-1)/2 also prime).
 * @param add Optional congruence modulus constraint, or NULL.
 * @param rem Optional remainder for the @p add constraint, or NULL.
 * @param callback Progress callback, or NULL.
 * @param cb_arg User argument passed to @p callback.
 * @return Generated prime BIGNUM, or NULL on error.
 */
OSSL_DEPRECATEDIN_0_9_8
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem,
    void (*callback)(int, int, void *),
    void *cb_arg);
/**
 * @brief Probable-primality test without trial division (deprecated; prefer BN_check_prime()).
 * @param p Candidate integer.
 * @param nchecks Number of Miller-Rabin rounds (or BN_prime_checks for a size-based default).
 * @param callback Optional old-style progress callback, or NULL.
 * @param ctx BN_CTX for temporaries, or NULL.
 * @param cb_arg User pointer passed to @p callback.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
OSSL_DEPRECATEDIN_0_9_8
int BN_is_prime(const BIGNUM *p, int nchecks,
    void (*callback)(int, int, void *),
    BN_CTX *ctx, void *cb_arg);
/**
 * @brief Probable-primality test with optional trial division (deprecated).
 * @param p Candidate integer.
 * @param nchecks Number of Miller-Rabin rounds (or BN_prime_checks for default).
 * @param callback Optional progress callback, or NULL.
 * @param ctx BN_CTX for temporaries, or NULL.
 * @param cb_arg User pointer passed to @p callback.
 * @param do_trial_division Non-zero to run small-prime trial division first.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
OSSL_DEPRECATEDIN_0_9_8
int BN_is_prime_fasttest(const BIGNUM *p, int nchecks,
    void (*callback)(int, int, void *),
    BN_CTX *ctx, void *cb_arg,
    int do_trial_division);
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Test whether @p p is prime using Miller-Rabin (deprecated; prefer BN_check_prime).
 * @param p Candidate integer.
 * @param nchecks Number of Miller-Rabin rounds, or BN_prime_checks for a default.
 * @param ctx Optional BN_CTX, or NULL to allocate internally.
 * @param cb Optional progress callback, or NULL.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
/**
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
#endif
/* Newer versions */
/**
 * @brief Generate a probable prime into @p ret using caller-supplied BN_CTX scratch space.
 * @param ret Destination BIGNUM that receives the prime.
 * @param bits Desired bit length of the prime.
 * @param safe Nonzero to require a safe prime ((p-1)/2 also prime).
 * @param add Optional congruence modulus for p = rem (mod add), or NULL.
 * @param rem Optional remainder used with @p add, or NULL.
 * @param cb Progress callback, or NULL.
 * @param ctx BN_CTX used for generation (must be non-NULL).
 * @return 1 if a suitable prime was found, or 0 on error.
 */
int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb,
    BN_CTX *ctx);
/**
 * @brief Generate a probable prime of the requested size and congruence constraints.
 * @param ret Destination BIGNUM for the prime.
 * @param bits Desired bit length.
 * @param safe Non-zero to require a safe prime ((p-1)/2 also prime).
 * @param add Optional modulus for the constraint ret ≡ rem (mod add), or NULL.
 * @param rem Optional residue for that constraint, or NULL (defaults to 1).
 * @param cb Optional generation callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add,
    const BIGNUM *rem, BN_GENCB *cb);
/**
 * @brief Test whether @p p is prime using the library's default primality checks.
 * @param p Candidate integer.
 * @param ctx Optional BN_CTX, or NULL to allocate internally.
 * @param cb Optional progress callback, or NULL.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Generate random X9.31 parameters Xp and Xq of half the requested RSA bit length (deprecated).
 * @param Xp Destination for the first random parameter (top bits set for the X9.31 range).
 * @param Xq Destination for the second random parameter; |Xp - Xq| is forced above 2^(nbits/2 - 100).
 * @param nbits Total RSA modulus bit length (at least 1024 and a multiple of 256).
 * @param ctx BN_CTX for temporaries and private RNG.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);

/**
 * @brief Derive an X9.31 prime p from Xp/Xp1/Xp2 parameters (deprecated).
 * @param p Destination for the derived prime.
 * @param p1 Optional destination for the first auxiliary prime, or NULL.
 * @param p2 Optional destination for the second auxiliary prime, or NULL.
 * @param Xp Random parameter used to construct p.
 * @param Xp1 Random parameter used to construct p1.
 * @param Xp2 Random parameter used to construct p2.
 * @param e Public exponent that must be coprime to p-1.
 * @param ctx BN_CTX for temporaries.
 * @param cb Optional generation callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb);
/**
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
#endif

/**
 * @brief Allocate an empty Montgomery multiplication context.
 * @return New BN_MONT_CTX, or NULL on failure; free with BN_MONT_CTX_free().
 */
BN_MONT_CTX *BN_MONT_CTX_new(void);
/**
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
/**
 * @brief Convert @p a into the Montgomery domain for modulus @p mont.
 * @param r Destination for aR mod m.
 * @param a Value to convert (typically reduced modulo m).
 * @param mont Montgomery context initialized for modulus m.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);
/**
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
/**
 * @brief Initialize a Montgomery context for modulus @p mod.
 * @param mont Context to configure.
 * @param mod Odd modulus m.
 * @param ctx BN_CTX for temporary storage.
 * @return 1 on success, or 0 on error.
 */
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
/**
 * @brief Copy Montgomery context @p from into @p to.
 * @param to Destination context (must already be allocated).
 * @param from Source context to duplicate.
 * @return @p to on success, or NULL on error.
 */
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
/**
 * @brief Lazily initialize a shared Montgomery context under a lock.
 * @param pmont Address of the Montgomery context pointer; allocated and set on first use.
 * @param lock Read/write lock serializing initialization of *@p pmont.
 * @param mod Modulus used to build the Montgomery context.
 * @param ctx BN_CTX scratch space for the initialization.
 * @return The initialized Montgomery context at *@p pmont, or NULL on error.
 */
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
    const BIGNUM *mod, BN_CTX *ctx);

/* BN_BLINDING flags */
#define BN_BLINDING_NO_UPDATE 0x00000001
#define BN_BLINDING_NO_RECREATE 0x00000002

/**
 * @brief Allocate a BN_BLINDING object from blinding factors A and A^-1 mod @p mod.
 * @param A Blinding multiplier (may be freshly generated by the caller).
 * @param Ai Modular inverse of @p A modulo @p mod.
 * @param mod Modulus copied into the new blinding object.
 * @return New BN_BLINDING, or NULL on error; free with BN_BLINDING_free().
 */
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
/**
 * @brief Free a BN_BLINDING object and its associated factors.
 * @param b Blinding object to free, or NULL (no-op).
 */
void BN_BLINDING_free(BN_BLINDING *b);
/**
 * @brief Refresh a BN_BLINDING object by squaring its blinding factors.
 * @param b Blinding state to update.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
/**
 * @brief Blind @p n for a private modular operation using @p b (equivalent to BN_BLINDING_convert_ex with no saved inverse).
 * @param n Value to blind in place (multiplied by the blinding factor modulo the modulus).
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
/**
 * @brief Unblind @p n after a private modular operation using @p b (BN_BLINDING_invert_ex with no saved r).
 * @param n Blinded value to multiply by the inverse blinding factor modulo the modulus.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
/**
 * @brief Blind @p n using @p b, optionally storing the inverse factor in @p r.
 * @param n Value updated in place to its blinded form.
 * @param r Optional destination for the inverse blinding factor, or NULL.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx);
/**
 * @brief Unblind @p n using @p b, optionally multiplying by a caller-supplied inverse factor @p r.
 * @param n Blinded value updated in place.
 * @param r Optional precomputed inverse blinding factor, or NULL to use the factor stored in @p b.
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
    BN_CTX *ctx);

/**
 * @brief Report whether @p b is marked as owned by the calling thread.
 * @param b Blinding state to query.
 * @return 1 if owned by this thread, or 0 otherwise.
 */
int BN_BLINDING_is_current_thread(BN_BLINDING *b);
/**
 * @brief Record the calling thread as the owner of blinding context @p b.
 * @param b Blinding object whose thread id is updated to the current thread.
 */
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
/**
 * @brief Acquire the mutex associated with a BN_BLINDING object.
 * @param b Blinding object whose lock is taken.
 * @return 1 on success, or 0 on failure.
 */
int BN_BLINDING_lock(BN_BLINDING *b);
/**
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
/**
 * @brief Set behavioural flags on a BN_BLINDING object.
 * @param b Blinding object to update.
 * @param flags Bitmask of BN_BLINDING_* flags (for example BN_BLINDING_NO_UPDATE).
 */
void BN_BLINDING_set_flags(BN_BLINDING *b, unsigned long flags);
/**
 * @brief Create or refresh RSA blinding factors A and A^-1 mod @p m.
 * @param b Existing BN_BLINDING to reuse, or NULL to allocate a new one.
 * @param e Public exponent used when generating fresh factors (may be NULL to keep the stored value).
 * @param m Modulus (copied into the blinding object when @p b is newly allocated).
 * @param ctx BN_CTX scratch space.
 * @param bn_mod_exp Modular exponentiation callback used internally, or NULL for BN_mod_exp_mont().
 * @param m_ctx Optional Montgomery context passed to @p bn_mod_exp, or NULL.
 * @return Blinding object on success, or NULL on error.
 */
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
    const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
    int (*bn_mod_exp)(BIGNUM *r,
        const BIGNUM *a,
        const BIGNUM *p,
        const BIGNUM *m,
        BN_CTX *ctx,
        BN_MONT_CTX *m_ctx),
    BN_MONT_CTX *m_ctx);
#ifndef OPENSSL_NO_DEPRECATED_0_9_8
/**
 * @brief Set legacy BIGNUM tuning parameters (deprecated no-op on modern builds).
 * @param mul Multiplication window / related tuning value.
 * @param high High-bit related tuning value.
 * @param low Low-bit related tuning value.
 * @param mont Montgomery-related tuning value.
 */
OSSL_DEPRECATEDIN_0_9_8
void BN_set_params(int mul, int high, int low, int mont);
/**
 * @brief Return a legacy BN library tuning parameter (deprecated no-op on modern OpenSSL).
 * @param which Selector historically meaning 0=mul, 1=high, 2=low, 3=mont.
 * @return Stored parameter value (typically 0 in current builds).
 */
OSSL_DEPRECATEDIN_0_9_8
int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
#endif

/**
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
/**
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
/**
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
/**
 * @brief Divide @p m by the reciprocal modulus in @p recp, producing quotient and remainder.
 * @param dv Destination for the quotient, or NULL if not required.
 * @param rem Destination for the remainder, or NULL if not required.
 * @param m Dividend.
 * @param recp Reciprocal context previously set up for the divisor.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
    BN_RECP_CTX *recp, BN_CTX *ctx);

#ifndef OPENSSL_NO_EC2M

/*
 * Functions for arithmetic over binary polynomials represented by BIGNUMs.
 * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
 * ignored. Note that input arguments are not const so that their bit arrays
 * can be expanded to the appropriate size if needed.
 */

/*
 * r = a + b
 */
/**
 * @brief Add binary polynomials over GF(2): r = a XOR b (addition without carry).
 * @param r Destination sum.
 * @param a First addend.
 * @param b Second addend.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
/**
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
/* r = (a / b) mod p */
/**
 * @brief Compute r = (a / b) mod p for binary polynomial-field (GF(2^m)) values.
 * @param r Result BIGNUM.
 * @param a Dividend.
 * @param b Divisor (must be invertible modulo @p p).
 * @param p Irreducible reduction polynomial.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
/* r = (a ^ b) mod p */
/**
 * @brief Compute r = (a ^ b) mod p for binary polynomial-field (GF(2^m)) values.
 * @param r Result BIGNUM.
 * @param a Base.
 * @param b Exponent.
 * @param p Irreducible field polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
/* r = sqrt(a) mod p */
/**
 * @brief Compute a square root in GF(2^m): r = sqrt(a) mod p.
 * @param r Destination for the root.
 * @param a Value whose square root is requested.
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    BN_CTX *ctx);
/**
 * @brief Solve the quadratic r^2 + r = a mod p over GF(2^m).
 * @param r Destination for one solution when it exists.
 * @param a Right-hand side.
 * @param p Irreducible modulus polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 if no solution / on error.
 */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    BN_CTX *ctx);
#define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
/**
 * @brief Reduce @p a modulo an irreducible GF(2^m) polynomial given as an int array: r = a mod p.
 * @param r Destination.
 * @param a Value to reduce.
 * @param p Descending exponent list of the irreducible, terminated by -1 (and ending in 0).
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
/**
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
/* r = (1 / b) mod p */
/**
 * @brief Compute the inverse of @p b modulo an irreducible GF(2^m) polynomial given as an int array.
 * @param r Result BIGNUM receiving (1 / b) mod p(x).
 * @param b Value to invert (must be non-zero modulo @p p).
 * @param p Irreducible polynomial as a descending list of set-bit indices terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
    BN_CTX *ctx);
/* r = (a / b) mod p */
/**
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
/**
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
/* r^2 + r = a mod p */
/**
 * @brief Solve the quadratic r^2 + r = a mod p over GF(2^m) with the modulus given as an int array.
 * @param r Destination for one solution when it exists.
 * @param a Right-hand side.
 * @param p Descending exponent list of the irreducible, terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 if no solution / on error.
 */
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a,
    const int p[], BN_CTX *ctx);
/**
 * @brief Convert a GF(2^m) polynomial BIGNUM into a descending exponent index array.
 * @param a Polynomial whose set bits become exponents.
 * @param p Destination array of size at least @p max; filled then terminated with -1.
 * @param max Capacity of @p p including room for the -1 terminator.
 * @return Number of exponents written (excluding -1), or 0 if @p max is too small / on error.
 */
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
/**
 * @brief Build a GF(2^m) irreducible polynomial BIGNUM from an exponent index array.
 * @param p Descending list of set-bit indices p[0] > p[1] > ... > p[k] == 0, terminated by -1.
 * @param a Destination BIGNUM cleared then filled with the polynomial representation.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_arr2poly(const int p[], BIGNUM *a);

#endif

/*
 * faster mod functions for the 'NIST primes' 0 <= a < p^2
 */
/**
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
/**
 * @brief Fast reduction of @p a modulo the NIST P-521 prime.
 * @param r Destination (may equal @p a).
 * @param a Value to reduce (non-negative).
 * @param p Must be the NIST P-521 prime (unused for the fast path but retained for API shape).
 * @param ctx BN_CTX scratch space (may be unused).
 * @return 1 on success, or 0 on error.
 */
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
/**
 * @brief Return the NIST P-384 prime as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_384(void);
/**
 * @brief Return the NIST P-521 prime (2^521 - 1) as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_521(void);

/**
 * @brief Return a fast modular-reduction function for a known NIST prime.
 * @param p Prime to look up (for example a BN_get0_nist_prime_* value).
 * @return Specialized mod function for @p p, or NULL if @p p is not a built-in NIST prime.
 */
int (*BN_nist_mod_func(const BIGNUM *p))(BIGNUM *r, const BIGNUM *a,
    const BIGNUM *field, BN_CTX *ctx);

/**
 * @brief Generate a DSA/ECDSA per-signature nonce in [0, @p range).
 * @param out Destination BIGNUM that receives the nonce k.
 * @param range Exclusive upper bound (typically the group order).
 * @param priv Private key value mixed into the nonce derivation.
 * @param message Message/digest octets mixed into the nonce derivation.
 * @param message_len Length of @p message in bytes.
 * @param ctx BN_CTX for temporary BIGNUMs, or NULL.
 * @return 1 on success, or 0 on failure.
 *
 * Mixes @p priv and @p message with fresh entropy so an RNG failure alone
 * cannot expose the private key the way a raw BN_rand_range() nonce would.
 */
int BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range,
    const BIGNUM *priv, const unsigned char *message,
    size_t message_len, BN_CTX *ctx);

/* Primes from RFC 2409 */
/**
 * @brief Return the 768-bit MODP group prime from RFC 2409.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn);
/**
 * @brief Return the 1024-bit MODP group prime from RFC 2409.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn);

/* Primes from RFC 3526 */
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
/**
 * @brief Return the 4096-bit MODP group prime from RFC 3526.
 * @param bn Existing BIGNUM to fill, or NULL to allocate.
 * @return The prime (possibly newly allocated), or NULL on error.
 */
BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn);
/**
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

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define get_rfc2409_prime_768 BN_get_rfc2409_prime_768
#define get_rfc2409_prime_1024 BN_get_rfc2409_prime_1024
#define get_rfc3526_prime_1536 BN_get_rfc3526_prime_1536
#define get_rfc3526_prime_2048 BN_get_rfc3526_prime_2048
#define get_rfc3526_prime_3072 BN_get_rfc3526_prime_3072
#define get_rfc3526_prime_4096 BN_get_rfc3526_prime_4096
#define get_rfc3526_prime_6144 BN_get_rfc3526_prime_6144
#define get_rfc3526_prime_8192 BN_get_rfc3526_prime_8192
#endif

/**
 * @brief Generate a non-cryptographic test random BIGNUM for BN self-tests.
 * @param rnd Destination BIGNUM.
 * @param bits Desired bit length.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);

#ifdef __cplusplus
}
#endif
#endif
