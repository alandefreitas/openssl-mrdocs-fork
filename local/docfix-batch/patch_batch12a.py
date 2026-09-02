#!/usr/bin/env python3
"""Documentation repair batch 12a: smaller headers + dh.h."""
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


print("=== batch 12a: smaller files + dh.h ===")

# ----- asn1.h (+ .in) -----
patch_both(
    "asn1.h",
    """/*
 * Declarations for template structures: for full definitions see asn1t.h
 */
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
""",
    """/*
 * Declarations for template structures: for full definitions see asn1t.h
 */
/**
 * @brief Opaque field descriptor used when building ASN.1 ITEM templates.
 *
 * Full layout lives in asn1t.h; callers typically obtain templates via
 * ASN1_ITEM macros rather than constructing ASN1_TEMPLATE values by hand.
 */
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
""",
    "ASN1_TEMPLATE",
)

# ----- bio.h (+ .in) -----
patch_both(
    "bio.h",
    """const char *BIO_method_name(const BIO *b);
""",
    """/**
 * @brief Return the human-readable name of the BIO_METHOD attached to @p b.
 * @param b BIO whose method table is queried.
 * @return Internal NUL-terminated method name string (do not free).
 */
const char *BIO_method_name(const BIO *b);
""",
    "BIO_method_name",
)

# ----- bn.h -----
patch_one(
    "bn.h",
    """int BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range,
    const BIGNUM *priv, const unsigned char *message,
    size_t message_len, BN_CTX *ctx);
""",
    """/**
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
""",
    "BN_generate_dsa_nonce",
)

# ----- conf.h (+ .in) -----
patch_both(
    "conf.h",
    """void NCONF_free_data(CONF *conf);
""",
    """/**
 * @brief Free configuration values stored in @p conf without freeing the CONF object itself.
 * @param conf Configuration object whose loaded name/value data is released; NULL is ignored.
 *
 * Unlike NCONF_free(), the CONF shell remains allocated and can be reloaded.
 */
void NCONF_free_data(CONF *conf);
""",
    "NCONF_free_data",
)

# ----- crypto.h (+ .in) -----
patch_both(
    "crypto.h",
    """void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
    unsigned long flags);
""",
    """/**
 * @brief Set CONF_modules_load_file() flags used when OPENSSL_init_crypto() loads config.
 * @param settings Initialization settings object from OPENSSL_INIT_new().
 * @param flags Bitmask such as CONF_MFLAGS_IGNORE_MISSING_FILE or CONF_MFLAGS_DEFAULT_SECTION.
 */
void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
    unsigned long flags);
""",
    "OPENSSL_INIT_set_config_file_flags",
)

patch_both(
    "crypto.h",
    """typedef pthread_t CRYPTO_THREAD_ID;
""",
    """/**
 * @brief Platform thread identifier used by CRYPTO_THREAD_get_current_id() and friends.
 *
 * On POSIX builds this is pthread_t; Windows and no-thread fallbacks use other underlying types.
 */
typedef pthread_t CRYPTO_THREAD_ID;
""",
    "CRYPTO_THREAD_ID",
)

# ----- types.h -----
patch_one(
    "types.h",
    """typedef struct comp_method_st COMP_METHOD;
""",
    """/**
 * @brief Opaque compression method table (zlib, brotli, zstd, and related COMP_* APIs).
 */
typedef struct comp_method_st COMP_METHOD;
""",
    "COMP_METHOD",
)

# ----- engine.h -----
patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_digests(ENGINE *e);
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_digests(void);
""",
    """/**
 * @brief Unregister @p e's digest implementations from the ENGINE digests table (deprecated).
 * @param e ENGINE whose digests should be removed from selection.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_digests(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides digest implementations (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_digests(void);
""",
    "ENGINE_unregister/register_all_digests",
)

# ----- rand.h -----
patch_one(
    "rand.h",
    """int RAND_set0_private(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);
""",
    """/**
 * @brief Install @p rand as the private DRBG for a library context, transferring ownership.
 * @param ctx Library context whose private RNG is replaced, or NULL for the default.
 * @param rand RAND context that becomes the private generator used by RAND_priv_bytes(); @p ctx takes ownership.
 * @return 1 on success, or 0 on failure.
 */
int RAND_set0_private(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);
""",
    "RAND_set0_private",
)

# ----- sha.h -----
patch_one(
    "sha.h",
    """typedef struct SHA512state_st {
""",
    """/**
 * @brief Incremental SHA-384 / SHA-512 digest state (also typedef'd as SHA512_CTX).
 */
typedef struct SHA512state_st {
""",
    "SHA512state_st",
)

# ----- tls1.h -----
patch_one(
    "tls1.h",
    """__owur int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain);
""",
    """/**
 * @brief Check whether certificate @p x, key @p pk, and @p chain suit the current TLS session.
 * @param s SSL object whose peer preferences and negotiated parameters constrain the check.
 * @param x End-entity certificate under consideration.
 * @param pk Private key matching @p x.
 * @param chain Intermediate CA certificates, or NULL / empty when none are offered.
 * @return Bitmask of CERT_PKEY_* flags (CERT_PKEY_VALID means the chain is usable for this session).
 */
__owur int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain);
""",
    "SSL_check_chain",
)

# ----- dsa.h -----
patch_one(
    "dsa.h",
    """int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits);
""",
    """/**
 * @brief Set the DSA subprime (q) length in bits for parameter generation.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param qbits Desired bit length of q (default 224 if unset); ignored when a digest size selects q.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits);
""",
    "EVP_PKEY_CTX_set_dsa_paramgen_q_bits",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_method(DSA *d);
""",
    """/**
 * @brief Return the DSA_METHOD currently bound to @p d (deprecated).
 * @param d DSA key whose method table is queried.
 * @return Pointer to the method implementation, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_method(DSA *d);
""",
    "DSA_get_method",
)

# ----- dh.h -----
patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);
""",
    """/**
 * @brief Set a fixed seed for DH parameter generation (testing / reproducible params).
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param seed Seed octets used instead of a random seed; must yield primes on the first iteration.
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or a non-positive value on error.
 *
 * Persist @p seed if later validation of p, q, and verifiable g is required; it is not part of a stored key.
 */
int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);
""",
    "EVP_PKEY_CTX_set_dh_paramgen_seed",
)

patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid);
int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen);
""",
    """/**
 * @brief Select named Diffie-Hellman parameters (RFC 7919 / RFC 3526) by NID.
 * @param ctx EVP_PKEY_CTX used for DH parameter or key generation.
 * @param nid Named group such as NID_ffdhe2048 or NID_modp_2048, or NID_undef to clear.
 * @return 1 on success, or a non-positive value on error.
 *
 * Mutually exclusive with EVP_PKEY_CTX_set_dh_rfc5114() / set_dhx_rfc5114().
 */
int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid);
/**
 * @brief Select RFC 5114 DH parameters (sections 2.1–2.3) on a DHX key context.
 * @param ctx EVP_PKEY_CTX with key type EVP_PKEY_DHX used for parameter generation.
 * @param gen 1, 2, or 3 for RFC 5114 §2.1/§2.2/§2.3, or 0 to clear.
 * @return 1 on success, or a non-positive value on error.
 *
 * Mutually exclusive with EVP_PKEY_CTX_set_dh_nid().
 */
int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen);
""",
    "EVP_PKEY_CTX_set_dh_nid/rfc5114",
)

patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Return the DH key-derivation function type configured on @p ctx.
 * @param ctx Key context for a DHX KDF / derive operation.
 * @return EVP_PKEY_DH_KDF_NONE, EVP_PKEY_DH_KDF_X9_42, or a negative value on error.
 */
int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_CTX_get_dh_kdf_type",
)

patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);
""",
    """/**
 * @brief Return the configured DH KDF output length in bytes.
 * @param ctx Key context configured for a DH KDF operation.
 * @param len Receives the current KDF output length.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);
""",
    "EVP_PKEY_CTX_get_dh_kdf_outlen",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
""",
    """/**
 * @brief Borrow the DH KDF User Keying Material pointer and return its length (deprecated).
 * @param ctx Key context configured for a DH KDF operation.
 * @param ukm Receives an internal pointer to the UKM bytes (do not free).
 * @return UKM length in bytes on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
""",
    "EVP_PKEY_CTX_get0_dh_kdf_ukm",
)

patch_one(
    "dh.h",
    """DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, DH, DHparams)
""",
    """/**
 * @brief Duplicate Diffie-Hellman domain parameters (DHparams_dup) (deprecated).
 * @param x Source DH object whose p, q, and g are copied.
 * @return Newly allocated DH with duplicated parameters, or NULL on failure.
 */
DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, DH, DHparams)
""",
    "DHparams_dup",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_OpenSSL(void);
""",
    """/**
 * @brief Return the built-in OpenSSL software DH_METHOD (deprecated).
 * @return Pointer to the default internal Diffie-Hellman method table.
 */
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_OpenSSL(void);
""",
    "DH_OpenSSL",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_set_method(DH *dh, const DH_METHOD *meth);
""",
    """/**
 * @brief Select the DH_METHOD used for operations on @p dh (deprecated).
 * @param dh DH object whose method is replaced.
 * @param meth Method implementation to attach; releases any prior ENGINE method.
 * @return Non-zero on success.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_method(DH *dh, const DH_METHOD *meth);
""",
    "DH_set_method",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 DH *DH_new(void);
""",
    """/**
 * @brief Allocate and initialize an empty DH object (deprecated).
 * @return New DH, or NULL on allocation failure.
 *
 * Prefer EVP_PKEY-based Diffie-Hellman APIs for new code.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_new(void);
""",
    "DH_new",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_bits(const DH *dh);
""",
    """/**
 * @brief Return the bit length of the Diffie-Hellman prime modulus p (deprecated).
 * @param dh DH object whose parameters are queried; @p dh and its p must be non-NULL.
 * @return Number of significant bits in p.
 */
OSSL_DEPRECATEDIN_3_0 int DH_bits(const DH *dh);
""",
    "DH_bits",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_check_params(const DH *dh, int *ret);
""",
    """/**
 * @brief Perform a lightweight check that DH parameters p and g look plausible (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @param ret Receives zero or DH_CHECK_* reason bits describing problems found.
 * @return 1 if the check routine ran successfully (inspect @p ret), or 0 on hard failure.
 *
 * Prefer DH_check() when a more thorough validation is required.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_params(const DH *dh, int *ret);
""",
    "DH_check_params",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 DH *DH_get_1024_160(void);
""",
    """/**
 * @brief Allocate a DH object with the RFC 5114 1024-bit MODP group using a 160-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_1024_160(void);
""",
    "DH_get_1024_160",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_256(void);
""",
    """/**
 * @brief Allocate a DH object with the RFC 5114 2048-bit MODP group using a 256-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_256(void);
""",
    "DH_get_2048_256",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
""",
    """/**
 * @brief Set the prime, optional subprime, and generator on a DH object, transferring ownership (deprecated).
 * @param dh DH object to update.
 * @param p New modulus p; ownership transfers to @p dh (must not be freed by the caller on success).
 * @param q Optional subprime q, or NULL; ownership transfers when non-NULL.
 * @param g New generator g; ownership transfers to @p dh.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
""",
    "DH_set0_pqg",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
""",
    """/**
 * @brief Set the public and/or private key BIGNUMs on a DH object, transferring ownership (deprecated).
 * @param dh DH object to update.
 * @param pub_key New public value, or NULL to leave the existing public key unchanged.
 * @param priv_key New private value, or NULL to leave the existing private key unchanged.
 * @return 1 on success, or 0 on failure.
 *
 * Non-NULL values are owned by @p dh after a successful call and must not be freed by the caller.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
""",
    "DH_set0_key",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_q(const DH *dh);
""",
    """/**
 * @brief Return the optional subprime q stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_q(const DH *dh);
""",
    "DH_get0_q",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_test_flags(const DH *dh, int flags);
""",
    """/**
 * @brief Return which of the requested flag bits are currently set on a DH object (deprecated).
 * @param dh DH object to query.
 * @param flags Bitmask of DH_FLAG_* values to test (may combine several bits).
 * @return Subset of @p flags that are set, or 0 if none match.
 */
OSSL_DEPRECATEDIN_3_0 int DH_test_flags(const DH *dh, int flags);
""",
    "DH_test_flags",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 ENGINE *DH_get0_engine(DH *d);
""",
    """/**
 * @brief Return the ENGINE bound to a DH object, if any (deprecated).
 * @param d DH object to query.
 * @return ENGINE handle, or NULL when no ENGINE is set.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *DH_get0_engine(DH *d);
""",
    "DH_get0_engine",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_dup(const DH_METHOD *dhm);
""",
    """/**
 * @brief Duplicate a DH_METHOD, copying its name and callbacks (deprecated).
 * @param dhm Method table to clone.
 * @return New DH_METHOD, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DH_METHOD *DH_meth_dup(const DH_METHOD *dhm);
""",
    "DH_meth_dup",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_meth_set1_name(DH_METHOD *dhm, const char *name);
""",
    """/**
 * @brief Replace the display name stored on a DH_METHOD (deprecated).
 * @param dhm Method object to update.
 * @param name NUL-terminated name that is duplicated into @p dhm; the caller retains @p name.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set1_name(DH_METHOD *dhm, const char *name);
""",
    "DH_meth_set1_name",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_meth_set_compute_key(DH_METHOD *dhm,
    int (*compute_key)(unsigned char *key,
        const BIGNUM *pub_key,
        DH *dh));
""",
    """/**
 * @brief Set the shared-secret compute_key callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param compute_key Callback invoked by DH_compute_key(), or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_compute_key(DH_METHOD *dhm,
    int (*compute_key)(unsigned char *key,
        const BIGNUM *pub_key,
        DH *dh));
""",
    "DH_meth_set_compute_key",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_meth_set_finish(DH_METHOD *dhm, int (*finish)(DH *));
""",
    """/**
 * @brief Set the DH object teardown callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param finish Callback invoked from DH_free() for method-specific cleanup (must not free the DH itself), or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_finish(DH_METHOD *dhm, int (*finish)(DH *));
""",
    "DH_meth_set_finish",
)

print()
print(f"OK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
