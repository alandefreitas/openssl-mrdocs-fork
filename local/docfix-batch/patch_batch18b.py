#!/usr/bin/env python3
"""Documentation repair batch 18b: blowfish, bn, cms, conf*."""
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


print("=== batch 18b: blowfish/bn/cms/conf ===")

# ----- blowfish.h -----

patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 void BF_encrypt(BF_LONG *data, const BF_KEY *key);
""",
    """/**
 * @brief Encrypt one Blowfish block in place (deprecated low-level primitive).
 * @param data Two BF_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded Blowfish key schedule from BF_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void BF_encrypt(BF_LONG *data, const BF_KEY *key);
""",
    "BF_encrypt",
)

patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 void BF_ofb64_encrypt(const unsigned char *in,
    unsigned char *out,
    long length, const BF_KEY *schedule,
    unsigned char *ivec, int *num);
""",
    """/**
 * @brief Encrypt or decrypt with Blowfish in 64-bit OFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from BF_set_key().
 * @param ivec 8-byte initialization vector, updated in place.
 * @param num Offset into the OFB keystream (0..7), updated in place.
 */
OSSL_DEPRECATEDIN_3_0 void BF_ofb64_encrypt(const unsigned char *in,
    unsigned char *out,
    long length, const BF_KEY *schedule,
    unsigned char *ivec, int *num);
""",
    "BF_ofb64_encrypt",
)

# ----- bn.h -----

patch_one(
    "bn.h",
    """char *BN_options(void);
""",
    """/**
 * @brief Return a short string describing compiled BIGNUM word size / options.
 * @return Static NUL-terminated options string (for example \"bn(64,64)\").
 */
char *BN_options(void);
""",
    "BN_options",
)

patch_one(
    "bn.h",
    """int BN_priv_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
""",
    """/**
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
""",
    "BN_priv_rand_ex",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    """/**
 * @brief Generate a pseudo-random BIGNUM (deprecated; prefer BN_rand / BN_priv_rand).
 * @param rnd Destination BIGNUM.
 * @param bits Desired bit length.
 * @param top BN_RAND_TOP_* controlling the most-significant bits.
 * @param bottom BN_RAND_BOTTOM_* controlling parity of the least-significant bit.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
""",
    "BN_pseudo_rand",
)

patch_one(
    "bn.h",
    """int BN_security_bits(int L, int N);
""",
    """/**
 * @brief Estimate the security strength in bits for asymmetric parameters of sizes @p L and @p N.
 * @param L Public-key / modulus size in bits (for example RSA modulus length).
 * @param N Private-value size in bits (for example subgroup order); may be 0 when unused.
 * @return Estimated security strength in bits (NIST SP 800-57 style).
 */
int BN_security_bits(int L, int N);
""",
    "BN_security_bits",
)

patch_one(
    "bn.h",
    """int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
""",
    """/**
 * @brief Encode a signed BIGNUM as little-endian two's-complement of fixed width.
 * @param a Value to encode (may be negative).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Fixed output width in bytes.
 * @return @p tolen on success, or -1 if @p a does not fit.
 */
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
""",
    "BN_signed_bn2lebin",
)

patch_one(
    "bn.h",
    """int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
""",
    """/**
 * @brief Compute r = (a << 1) mod m.
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param m Modulus.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
""",
    "BN_mod_lshift1",
)

patch_one(
    "bn.h",
    """int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
""",
    """/**
 * @brief Compute r = a << n (left shift by @p n bits).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @param n Number of bits to shift (non-negative).
 * @return 1 on success, or 0 on failure.
 */
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
""",
    "BN_lshift",
)

patch_one(
    "bn.h",
    """int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
""",
    """/**
 * @brief Compute r = a^p (non-modular exponentiation).
 * @param r Result BIGNUM.
 * @param a Base.
 * @param p Non-negative exponent.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
""",
    "BN_exp",
)

patch_one(
    "bn.h",
    """int BN_mask_bits(BIGNUM *a, int n);
""",
    """/**
 * @brief Truncate @p a in place so that only the least-significant @p n bits remain.
 * @param a BIGNUM to mask (modified).
 * @param n Number of low bits to keep.
 * @return 1 on success, or 0 if @p a has fewer than @p n bits / on error.
 */
int BN_mask_bits(BIGNUM *a, int n);
""",
    "BN_mask_bits",
)

patch_one(
    "bn.h",
    """int BN_rshift1(BIGNUM *r, const BIGNUM *a);
""",
    """/**
 * @brief Compute r = a >> 1 (right shift by one bit).
 * @param r Result BIGNUM.
 * @param a Value to shift.
 * @return 1 on success, or 0 on failure.
 */
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
""",
    "BN_rshift1",
)

patch_one(
    "bn.h",
    """char *BN_bn2dec(const BIGNUM *a);
""",
    """/**
 * @brief Convert a BIGNUM to a newly allocated decimal string.
 * @param a Value to convert.
 * @return Heap string (free with OPENSSL_free()), or NULL on failure.
 */
char *BN_bn2dec(const BIGNUM *a);
""",
    "BN_bn2dec",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_0_9_8
int BN_is_prime_fasttest(const BIGNUM *p, int nchecks,
    void (*callback)(int, int, void *),
    BN_CTX *ctx, void *cb_arg,
    int do_trial_division);
""",
    """/**
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
""",
    "BN_is_prime_fasttest",
)

patch_one(
    "bn.h",
    """int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add,
    const BIGNUM *rem, BN_GENCB *cb);
""",
    """/**
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
""",
    "BN_generate_prime_ex",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb);
""",
    """/**
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
""",
    "BN_X931_derive_prime_ex",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
""",
    """/**
 * @brief Refresh a BN_BLINDING object by squaring its blinding factors.
 * @param b Blinding state to update.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
""",
    "BN_BLINDING_update",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_lock(BN_BLINDING *b);
""",
    """/**
 * @brief Acquire the mutex associated with a BN_BLINDING object.
 * @param b Blinding object whose lock is taken.
 * @return 1 on success, or 0 on failure.
 */
int BN_BLINDING_lock(BN_BLINDING *b);
""",
    "BN_BLINDING_lock",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_0_9_8
void BN_set_params(int mul, int high, int low, int mont);
""",
    """/**
 * @brief Set legacy BIGNUM tuning parameters (deprecated no-op on modern builds).
 * @param mul Multiplication window / related tuning value.
 * @param high High-bit related tuning value.
 * @param low Low-bit related tuning value.
 * @param mont Montgomery-related tuning value.
 */
OSSL_DEPRECATEDIN_0_9_8
void BN_set_params(int mul, int high, int low, int mont);
""",
    "BN_set_params",
)

patch_one(
    "bn.h",
    """int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
    BN_RECP_CTX *recp, BN_CTX *ctx);
""",
    """/**
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
""",
    "BN_div_recp",
)

patch_one(
    "bn.h",
    """const BIGNUM *BN_get0_nist_prime_521(void);
""",
    """/**
 * @brief Return the NIST P-521 prime (2^521 - 1) as a shared BIGNUM.
 * @return Pointer to the static prime; do not free.
 */
const BIGNUM *BN_get0_nist_prime_521(void);
""",
    "BN_get0_nist_prime_521",
)

# ----- cms.h -----

patch_both(
    "cms.h",
    """int CMS_RecipientEncryptedKey_get0_id(CMS_RecipientEncryptedKey *rek,
    ASN1_OCTET_STRING **keyid,
    ASN1_GENERALIZEDTIME **tm,
    CMS_OtherKeyAttribute **other,
    X509_NAME **issuer, ASN1_INTEGER **sno);
""",
    """/**
 * @brief Extract KeyAgreeRecipientIdentifier fields from a RecipientEncryptedKey.
 * @param rek RecipientEncryptedKey to query.
 * @param keyid Receives subjectKeyIdentifier when that form is used, or NULL to skip.
 * @param tm Receives date when present with subjectKeyIdentifier, or NULL to skip.
 * @param other Receives otherKeyAttribute when present, or NULL to skip.
 * @param issuer Receives issuer name when IssuerAndSerialNumber is used, or NULL to skip.
 * @param sno Receives serial number when IssuerAndSerialNumber is used, or NULL to skip.
 * @return 1 on success, or 0 on failure.
 */
int CMS_RecipientEncryptedKey_get0_id(CMS_RecipientEncryptedKey *rek,
    ASN1_OCTET_STRING **keyid,
    ASN1_GENERALIZEDTIME **tm,
    CMS_OtherKeyAttribute **other,
    X509_NAME **issuer, ASN1_INTEGER **sno);
""",
    "CMS_RecipientEncryptedKey_get0_id",
)

# ----- conf.h -----

patch_both(
    "conf.h",
    """typedef struct {
    char *section;
    char *name;
    char *value;
} CONF_VALUE;
""",
    """/**
 * @brief One configuration entry: section, name, and string value.
 */
typedef struct {
    /** Section name owning this entry (for example \"default\"). */
    char *section;
    /** Key name within the section. */
    char *name;
    /** String value associated with @c name. */
    char *value;
} CONF_VALUE;
""",
    "CONF_VALUE",
)

patch_both(
    "conf.h",
    """void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
""",
    """/**
 * @brief Attach a legacy LHASH of CONF_VALUE entries as the data store of a CONF object.
 * @param conf CONF object whose data pointer is replaced.
 * @param hash Hash table of configuration values; ownership transfers to @p conf.
 */
void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
""",
    "CONF_set_nconf",
)

patch_both(
    "conf.h",
    """LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
    long *eline);
""",
    """/**
 * @brief Load configuration name/value pairs from a BIO into an LHASH (legacy API).
 * @param conf Existing hash to extend, or NULL to allocate a new one.
 * @param bp BIO supplying OpenSSL CONF syntax.
 * @param eline Optional receiver for the error line number on failure, or NULL.
 * @return The configuration hash, or NULL on error.
 */
LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
    long *eline);
""",
    "CONF_load_bio",
)

patch_both(
    "conf.h",
    """STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
    const char *section);
""",
    """/**
 * @brief Return all CONF_VALUE entries belonging to @p section (legacy API).
 * @param conf Configuration hash from CONF_load*().
 * @param section Section name to look up.
 * @return Internal stack of values for that section, or NULL if absent; do not free.
 */
STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
    const char *section);
""",
    "CONF_get_section",
)

patch_both(
    "conf.h",
    """void CONF_free(LHASH_OF(CONF_VALUE) *conf);
""",
    """/**
 * @brief Free a legacy CONF LHASH and all contained CONF_VALUE entries.
 * @param conf Hash to free, or NULL.
 */
void CONF_free(LHASH_OF(CONF_VALUE) *conf);
""",
    "CONF_free",
)

patch_both(
    "conf.h",
    """int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
""",
    """/**
 * @brief Dump a legacy CONF LHASH to a FILE in a human-readable form.
 * @param conf Configuration hash to print.
 * @param out Output stream.
 * @return 1 on success, or 0 on failure.
 */
int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out);
""",
    "CONF_dump_fp",
)

patch_both(
    "conf.h",
    """OSSL_DEPRECATEDIN_1_1_0 void OPENSSL_config(const char *config_name);
""",
    """/**
 * @brief Load the named OpenSSL configuration file (deprecated; prefer CONF_modules_load_file).
 * @param config_name Configuration file name/section hint, or NULL for the default openssl.cnf.
 */
OSSL_DEPRECATEDIN_1_1_0 void OPENSSL_config(const char *config_name);
""",
    "OPENSSL_config",
)

patch_both(
    "conf.h",
    """int NCONF_load_bio(CONF *conf, BIO *bp, long *eline);
""",
    """/**
 * @brief Load configuration data from a BIO into a CONF object.
 * @param conf Destination CONF (typically from NCONF_new()).
 * @param bp BIO supplying OpenSSL CONF syntax.
 * @param eline Optional receiver for the error line number on failure, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int NCONF_load_bio(CONF *conf, BIO *bp, long *eline);
""",
    "NCONF_load_bio",
)

patch_both(
    "conf.h",
    """char *NCONF_get_string(const CONF *conf, const char *group, const char *name);
""",
    """/**
 * @brief Look up a string value in a CONF object.
 * @param conf Configuration to query.
 * @param group Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Pointer to the internal value string, or NULL if not found; do not free.
 */
char *NCONF_get_string(const CONF *conf, const char *group, const char *name);
""",
    "NCONF_get_string",
)

patch_both(
    "conf.h",
    """int NCONF_get_number_e(const CONF *conf, const char *group, const char *name,
    long *result);
""",
    """/**
 * @brief Look up a numeric value in a CONF object, reporting errors via the error stack.
 * @param conf Configuration to query.
 * @param group Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @param result Receives the parsed long integer on success.
 * @return 1 on success, or 0 on failure.
 */
int NCONF_get_number_e(const CONF *conf, const char *group, const char *name,
    long *result);
""",
    "NCONF_get_number_e",
)

patch_both(
    "conf.h",
    """int CONF_modules_load(const CONF *cnf, const char *appname,
    unsigned long flags);
""",
    """/**
 * @brief Initialize configured OpenSSL modules listed in @p cnf for @p appname.
 * @param cnf Configuration object containing module sections.
 * @param appname Application section name (for example \"openssl_conf\"), or NULL for default.
 * @param flags CONF_MFLAGS_* controlling missing-file and error behavior.
 * @return 1 on success, or 0 / negative on failure depending on flags.
 */
int CONF_modules_load(const CONF *cnf, const char *appname,
    unsigned long flags);
""",
    "CONF_modules_load",
)

patch_both(
    "conf.h",
    """int CONF_module_add(const char *name, conf_init_func *ifunc,
    conf_finish_func *ffunc);
""",
    """/**
 * @brief Register a built-in configuration module under @p name.
 * @param name Module name as referenced from openssl.cnf.
 * @param ifunc Initialization callback invoked when the module is loaded.
 * @param ffunc Finish/cleanup callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CONF_module_add(const char *name, conf_init_func *ifunc,
    conf_finish_func *ffunc);
""",
    "CONF_module_add",
)

patch_both(
    "conf.h",
    """const char *CONF_imodule_get_value(const CONF_IMODULE *md);
""",
    """/**
 * @brief Return the value string associated with an initialized CONF module instance.
 * @param md Module instance from a conf_init_func callback.
 * @return Internal value string (often a section name); do not free.
 */
const char *CONF_imodule_get_value(const CONF_IMODULE *md);
""",
    "CONF_imodule_get_value",
)

patch_both(
    "conf.h",
    """CONF_MODULE *CONF_imodule_get_module(const CONF_IMODULE *md);
""",
    """/**
 * @brief Return the CONF_MODULE registration object for an initialized module instance.
 * @param md Module instance from a conf_init_func callback.
 * @return Owning CONF_MODULE, or NULL.
 */
CONF_MODULE *CONF_imodule_get_module(const CONF_IMODULE *md);
""",
    "CONF_imodule_get_module",
)

patch_both(
    "conf.h",
    """int CONF_parse_list(const char *list, int sep, int nospc,
    int (*list_cb)(const char *elem, int len, void *usr),
    void *arg);
""",
    """/**
 * @brief Split @p list on separator @p sep and invoke @p list_cb for each element.
 * @param list NUL-terminated list string.
 * @param sep Separator character.
 * @param nospc Non-zero to reject surrounding spaces around elements.
 * @param list_cb Callback receiving each element pointer, length, and @p arg; return 0 to abort.
 * @param arg User pointer passed to @p list_cb.
 * @return 1 on success, or 0 if a callback aborts / on parse failure.
 */
int CONF_parse_list(const char *list, int sep, int nospc,
    int (*list_cb)(const char *elem, int len, void *usr),
    void *arg);
""",
    "CONF_parse_list",
)

patch_both(
    "conf.h",
    """void OPENSSL_load_builtin_modules(void);
""",
    """/**
 * @brief Register OpenSSL's built-in CONF modules (engines, providers, SSL, etc.).
 */
void OPENSSL_load_builtin_modules(void);
""",
    "OPENSSL_load_builtin_modules",
)

# ----- conf_api.h -----

patch_one(
    "conf_api.h",
    """STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
    const char *section);
""",
    """/**
 * @brief Return the CONF_VALUE stack for @p section from the internal CONF data store.
 * @param conf Configuration object.
 * @param section Section name to look up.
 * @return Internal stack of values, or NULL if absent; do not free.
 */
STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
    const char *section);
""",
    "_CONF_get_section_values",
)

patch_one(
    "conf_api.h",
    """char *_CONF_get_string(const CONF *conf, const char *section,
    const char *name);
""",
    """/**
 * @brief Look up a string in the internal CONF data store (legacy helper).
 * @param conf Configuration object.
 * @param section Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Internal value string, or NULL if not found; do not free.
 */
char *_CONF_get_string(const CONF *conf, const char *section,
    const char *name);
""",
    "_CONF_get_string",
)

# ----- conftypes.h -----

patch_one(
    "conftypes.h",
    """    int (*destroy_data)(CONF *conf);
    int (*load_bio)(CONF *conf, BIO *bp, long *eline);
    int (*dump)(const CONF *conf, BIO *bp);
    int (*is_number)(const CONF *conf, char c);
    int (*to_int)(const CONF *conf, char c);
    int (*load)(CONF *conf, const char *name, long *eline);
};

struct conf_st {
    CONF_METHOD *meth;
""",
    """    int (*destroy_data)(CONF *conf);
    /** Load configuration syntax from a BIO into @p conf; @p eline receives error line. */
    int (*load_bio)(CONF *conf, BIO *bp, long *eline);
    /** Dump the configuration contents of @p conf to @p bp. */
    int (*dump)(const CONF *conf, BIO *bp);
    /** Return non-zero if @p c is a digit in this CONF method's number syntax. */
    int (*is_number)(const CONF *conf, char c);
    /** Convert digit character @p c to its integer value for this CONF method. */
    int (*to_int)(const CONF *conf, char c);
    /** Load configuration from a named file into @p conf; @p eline receives error line. */
    int (*load)(CONF *conf, const char *name, long *eline);
};

struct conf_st {
    /** Active CONF_METHOD vtable for this configuration object. */
    CONF_METHOD *meth;
""",
    "conftypes method+meth",
)

patch_one(
    "conftypes.h",
    """    int flag_dollarid;
    /** Non-zero when .include paths are treated as absolute rather than relative. */
    int flag_abspath;
    char *includedir;
    OSSL_LIB_CTX *libctx;
};
""",
    """    /** Non-zero when dollar-prefixed identifiers (\"$var\") are enabled in CONF syntax. */
    int flag_dollarid;
    /** Non-zero when .include paths are treated as absolute rather than relative. */
    int flag_abspath;
    /** Directory prepended to relative .include paths, or NULL. */
    char *includedir;
    /** Library context associated with this CONF, or NULL for the default. */
    OSSL_LIB_CTX *libctx;
};
""",
    "conftypes flags/paths",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
