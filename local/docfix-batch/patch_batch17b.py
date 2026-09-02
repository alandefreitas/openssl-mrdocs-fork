#!/usr/bin/env python3
"""Documentation repair batch 17b: bn, cms, conf, conftypes, core, crypto, dh, dsa, ec."""
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


print("=== batch 17b: bn, cms, conf, core, crypto, dh, dsa, ec ===")

# ----- bn.h -----

patch_both(
    "bn.h",
    """BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *ctx);
""",
    """/**
 * @brief Allocate a BN_CTX whose temporary BIGNUMs use secure heap storage.
 * @param ctx Library context for allocation, or NULL for the default.
 * @return New BN_CTX with BN_FLG_SECURE set, or NULL on failure; free with BN_CTX_free().
 */
BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *ctx);
""",
    "BN_CTX_secure_new_ex",
)

patch_both(
    "bn.h",
    """BIGNUM *BN_secure_new(void);
""",
    """/**
 * @brief Allocate a BIGNUM whose limb storage is allocated from the secure heap.
 * @return New BIGNUM with BN_FLG_SECURE set, or NULL on failure; free with BN_clear_free().
 */
BIGNUM *BN_secure_new(void);
""",
    "BN_secure_new",
)

patch_both(
    "bn.h",
    """int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    """/**
 * @brief Multiply two BIGNUMs: @p r = @p a * @p b.
 * @param r Destination product.
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param ctx BN_CTX scratch space, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    "BN_mul",
)

patch_both(
    "bn.h",
    """int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
""",
    """/**
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
""",
    "BN_mod_exp",
)

patch_both(
    "bn.h",
    """int BN_dec2bn(BIGNUM **a, const char *str);
""",
    """/**
 * @brief Parse a decimal ASCII string into a BIGNUM.
 * @param a Location of the BIGNUM pointer; allocated if *@p a is NULL.
 * @param str Decimal digit string; a leading '-' sets the negative flag.
 * @return Number of characters consumed from @p str on success, or 0 on parse error.
 */
int BN_dec2bn(BIGNUM **a, const char *str);
""",
    "BN_dec2bn",
)

patch_both(
    "bn.h",
    """int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb,
    BN_CTX *ctx);
""",
    """/**
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
""",
    "BN_generate_prime_ex2",
)

patch_both(
    "bn.h",
    """int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
""",
    """/**
 * @brief Blind @p n for a private modular operation using @p b (equivalent to BN_BLINDING_convert_ex with no saved inverse).
 * @param n Value to blind in place (multiplied by the blinding factor modulo the modulus).
 * @param b Blinding parameters from BN_BLINDING_new() or BN_BLINDING_create_param().
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
""",
    "BN_BLINDING_convert",
)

patch_both(
    "bn.h",
    """void BN_BLINDING_set_current_thread(BN_BLINDING *b);
""",
    """/**
 * @brief Record the calling thread as the owner of blinding context @p b.
 * @param b Blinding object whose thread id is updated to the current thread.
 */
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
""",
    "BN_BLINDING_set_current_thread",
)

patch_both(
    "bn.h",
    """BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
    const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
    int (*bn_mod_exp)(BIGNUM *r,
        const BIGNUM *a,
        const BIGNUM *p,
        const BIGNUM *m,
        BN_CTX *ctx,
        BN_MONT_CTX *m_ctx),
    BN_MONT_CTX *m_ctx);
""",
    """/**
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
""",
    "BN_BLINDING_create_param",
)

patch_both(
    "bn.h",
    """int BN_GF2m_arr2poly(const int p[], BIGNUM *a);
""",
    """/**
 * @brief Build a GF(2^m) irreducible polynomial BIGNUM from an exponent index array.
 * @param p Descending list of set-bit indices p[0] > p[1] > ... > p[k] == 0, terminated by -1.
 * @param a Destination BIGNUM cleared then filled with the polynomial representation.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_arr2poly(const int p[], BIGNUM *a);
""",
    "BN_GF2m_arr2poly",
)

# ----- cms.h / cms.h.in -----

patch_both(
    "cms.h",
    """BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
""",
    """/**
 * @brief Wrap a CMS ContentInfo in a filter BIO that writes indefinite-length BER to @p out.
 * @param out Underlying BIO that receives the encoded CMS structure.
 * @param cms CMS ContentInfo to encode through the filter.
 * @return New filter BIO, or NULL on failure; free with BIO_free_all().
 */
BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
""",
    "BIO_new_CMS",
)

patch_both(
    "cms.h",
    """int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap);
""",
    """/**
 * @brief Populate @p smcap with a standard set of S/MIME capability AlgorithmIdentifiers.
 * @param smcap Address of the stack to create or extend (may point to NULL).
 * @return 1 on success, or 0 if any capability could not be added.
 */
int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap);
""",
    "CMS_add_standard_smimecap",
)

# ----- conf.h / conf.h.in -----

patch_both(
    "conf.h",
    """struct conf_st;
struct conf_method_st;
typedef struct conf_method_st CONF_METHOD;
""",
    """struct conf_st;
struct conf_method_st;
/**
 * @brief Legacy CONF vtable type (see struct conf_method_st in conftypes.h).
 */
typedef struct conf_method_st CONF_METHOD;
""",
    "CONF_METHOD",
)

patch_both(
    "conf.h",
    """int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
""",
    """/**
 * @brief Dump a legacy CONF hash table to a BIO in name=value form.
 * @param conf LHASH of CONF_VALUE entries to print.
 * @param out Destination BIO.
 * @return 1 on success, or 0 on failure.
 */
int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
""",
    "CONF_dump_bio",
)

patch_both(
    "conf.h",
    """unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md);
""",
    """/**
 * @brief Return the CONF_MFLAGS_* control flags stored on a loaded module instance.
 * @param md Module instance whose flags are queried.
 * @return Bitmask of CONF_MFLAGS_* values.
 */
unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md);
""",
    "CONF_imodule_get_flags",
)

patch_both(
    "conf.h",
    """void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data);
""",
    """/**
 * @brief Store an opaque application pointer on a registered CONF DSO module.
 * @param pmod Module registration record to update.
 * @param usr_data Caller-owned pointer retrieved later with CONF_module_get_usr_data().
 */
void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data);
""",
    "CONF_module_set_usr_data",
)

# ----- conftypes.h (no .in) -----

patch_one(
    "conftypes.h",
    """struct conf_method_st {
    const char *name;
    /** Allocate a new CONF object for this method (may be NULL). */
    CONF *(*create)(CONF_METHOD *meth);
    int (*init)(CONF *conf);
""",
    """/**
 * @brief Legacy CONF method vtable (deprecated; contents will become opaque).
 */
struct conf_method_st {
    const char *name;
    /** Allocate a new CONF object for this method (may be NULL). */
    CONF *(*create)(CONF_METHOD *meth);
    /** Initialize a CONF object after allocation (may be NULL). */
    int (*init)(CONF *conf);
""",
    "conf_method_st/init",
)

# ----- core.h -----

patch_both(
    "core.h",
    """typedef struct openssl_core_ctx_st OPENSSL_CORE_CTX;
typedef struct ossl_core_bio_st OSSL_CORE_BIO;
""",
    """typedef struct openssl_core_ctx_st OPENSSL_CORE_CTX;
/**
 * @brief Opaque core-side BIO handle passed across the provider boundary for upcalls.
 */
typedef struct ossl_core_bio_st OSSL_CORE_BIO;
""",
    "OSSL_CORE_BIO",
)

# ----- crypto.h / crypto.h.in -----

patch_both(
    "crypto.h",
    """unsigned int OPENSSL_version_patch(void);
""",
    """/**
 * @brief Return the OpenSSL library patch level (OPENSSL_VERSION_PATCH).
 * @return Patch version number from the build-time OPENSSL_VERSION_* macros.
 */
unsigned int OPENSSL_version_patch(void);
""",
    "OPENSSL_version_patch",
)

patch_both(
    "crypto.h",
    """const char *OpenSSL_version(int type);
""",
    """/**
 * @brief Return a descriptive string about the running OpenSSL build.
 * @param type Selector such as OPENSSL_VERSION, OPENSSL_VERSION_STRING, OPENSSL_BUILT_ON, OPENSSL_PLATFORM, OPENSSL_DIR, OPENSSL_MODULES_DIR, or OPENSSL_CPU_INFO.
 * @return Constant string describing the requested aspect, or "not available" for unknown @p type values.
 */
const char *OpenSSL_version(int type);
""",
    "OpenSSL_version",
)

patch_both(
    "crypto.h",
    """void OPENSSL_thread_stop(void);
""",
    """/**
 * @brief Run per-thread OpenSSL cleanup handlers for the calling thread in the default library context.
 *
 * Invoked automatically from OPENSSL_cleanup() and on thread exit when thread-local destructors are active.
 */
void OPENSSL_thread_stop(void);
""",
    "OPENSSL_thread_stop",
)

patch_both(
    "crypto.h",
    """/* application has to include <windows.h> in order to use this */
typedef DWORD CRYPTO_THREAD_LOCAL;
typedef DWORD CRYPTO_THREAD_ID;
""",
    """/* application has to include <windows.h> in order to use this */
/**
 * @brief Platform thread-local storage key used by CRYPTO_THREAD_*_local() on Windows.
 *
 * On Windows builds this is DWORD (TlsAlloc index); POSIX builds use pthread_key_t; no-thread fallbacks use unsigned int.
 */
typedef DWORD CRYPTO_THREAD_LOCAL;
typedef DWORD CRYPTO_THREAD_ID;
""",
    "CRYPTO_THREAD_LOCAL/win",
)

patch_both(
    "crypto.h",
    """typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
/**
 * @brief Platform thread identifier used by CRYPTO_THREAD_get_current_id() and friends.
 *
 * On POSIX builds this is pthread_t; Windows and no-thread fallbacks use other underlying types.
 */
typedef pthread_t CRYPTO_THREAD_ID;
""",
    """typedef pthread_once_t CRYPTO_ONCE;
/**
 * @brief Platform thread-local storage key used by CRYPTO_THREAD_*_local().
 *
 * On POSIX builds this is pthread_key_t; Windows builds use DWORD; no-thread fallbacks use unsigned int.
 */
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
/**
 * @brief Platform thread identifier used by CRYPTO_THREAD_get_current_id() and friends.
 *
 * On POSIX builds this is pthread_t; Windows and no-thread fallbacks use other underlying types.
 */
typedef pthread_t CRYPTO_THREAD_ID;
""",
    "CRYPTO_THREAD_LOCAL/pthread",
)

patch_both(
    "crypto.h",
    """typedef unsigned int CRYPTO_ONCE;
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
""",
    """typedef unsigned int CRYPTO_ONCE;
/**
 * @brief Stub thread-local key type when OpenSSL is built without thread support.
 *
 * On threaded builds this is pthread_key_t (POSIX) or DWORD (Windows).
 */
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
""",
    "CRYPTO_THREAD_LOCAL/fallback",
)

patch_both(
    "crypto.h",
    """int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
""",
    """/**
 * @brief Allocate a thread-local storage key for use with CRYPTO_THREAD_get/set_local().
 * @param key Receives the new key on success.
 * @param cleanup Optional destructor invoked on thread exit for non-NULL values, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
""",
    "CRYPTO_THREAD_init_local",
)

patch_both(
    "crypto.h",
    """OSSL_LIB_CTX *OSSL_LIB_CTX_new_from_dispatch(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in);
""",
    """/**
 * @brief Allocate an OSSL_LIB_CTX wired to core BIO upcalls from a provider dispatch table.
 * @param handle Core handle passed to the provider (reserved for future use; may be NULL).
 * @param in Provider-to-core OSSL_DISPATCH table containing BIO upcall function pointers.
 * @return New library context, or NULL on failure; free with OSSL_LIB_CTX_free().
 */
OSSL_LIB_CTX *OSSL_LIB_CTX_new_from_dispatch(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in);
""",
    "OSSL_LIB_CTX_new_from_dispatch",
)

# ----- cryptoerr_legacy.h -----

patch_both(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_TS_strings(void);
""",
    """/**
 * @brief Load legacy ERR reason strings for the TS library (deprecated no-op).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_TS_strings(void);
""",
    "ERR_load_TS_strings",
)

# ----- dh.h -----

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_new(const char *name, int flags);
""",
    """/**
 * @brief Allocate a custom DH_METHOD with a duplicated name (deprecated).
 * @param name Display name copied into the method object.
 * @param flags Initial DH_METHOD flag bits.
 * @return New DH_METHOD, or NULL on failure; free with DH_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_new(const char *name, int flags);
""",
    "DH_meth_new",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 const char *DH_meth_get0_name(const DH_METHOD *dhm);
""",
    """/**
 * @brief Return the display name stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return NUL-terminated name string owned by @p dhm.
 */
OSSL_DEPRECATEDIN_3_0 const char *DH_meth_get0_name(const DH_METHOD *dhm);
""",
    "DH_meth_get0_name",
)

# ----- dsa.h -----

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_test_flags(const DSA *d, int flags);
""",
    """/**
 * @brief Test whether all bits in @p flags are set on a DSA object (deprecated).
 * @param d DSA object whose flag word is queried.
 * @param flags Bitmask of DSA_FLAG_* values to test.
 * @return Non-zero if every bit in @p flags is set, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_test_flags(const DSA *d, int flags);
""",
    "DSA_test_flags",
)

# ----- ec.h -----

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
""",
    """/**
 * @brief Return the point-conversion form used when encoding an EC_KEY public point (deprecated).
 * @param key EC key whose conversion form is queried.
 * @return Form such as POINT_CONVERSION_UNCOMPRESSED or POINT_CONVERSION_COMPRESSED.
 */
OSSL_DEPRECATEDIN_3_0 point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
""",
    "EC_KEY_get_conv_form",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 int ECDH_compute_key(void *out, size_t outlen,
    const EC_POINT *pub_key,
    const EC_KEY *ecdh,
    void *(*KDF)(const void *in,
        size_t inlen, void *out,
        size_t *outlen));
""",
    """/**
 * @brief Perform ECDH and optionally apply a KDF to the shared secret (deprecated).
 * @param out Buffer that receives the derived key material (or KDF output).
 * @param outlen Size of @p out in bytes; also passed to @p KDF as initial output capacity.
 * @param pub_key Peer's public EC point.
 * @param ecdh Local private EC_KEY used for the agreement.
 * @param KDF Optional key-derivation callback; if NULL, copies min(@p outlen, secret length) raw shared secret bytes into @p out.
 * @return Number of bytes written to @p out on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ECDH_compute_key(void *out, size_t outlen,
    const EC_POINT *pub_key,
    const EC_KEY *ecdh,
    void *(*KDF)(const void *in,
        size_t inlen, void *out,
        size_t *outlen));
""",
    "ECDH_compute_key",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
