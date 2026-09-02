#!/usr/bin/env python3
"""Documentation repair batch 13b: dsa, ec, engine, err, first half of evp."""
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
        missing.append(f"{rel}:{label}:no-file")
        print(f"  MISS: {rel} :: {label}:no-file")
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(f"{path.name}:{label}")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {path.name} :: {label}")
    ok.append(f"{path.name}:{label}")


print("=== batch 13b ===")

# ----- dsa.h -----
patch_one(
    "dsa.h",
    """int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
""",
    """/**
 * @brief Set the DSA parameter-generation gindex (FIPS 186 verifiable g seed index).
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param gindex Non-negative gindex value passed to the DSA provider.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);
""",
    "EVP_PKEY_CTX_set_dsa_paramgen_gindex",
)

patch_one(
    "dsa.h",
    """void DSA_SIG_free(DSA_SIG *a);
""",
    """/**
 * @brief Free a DSA_SIG and its r and s BIGNUM components.
 * @param a Signature to free, or NULL (no-op).
 */
void DSA_SIG_free(DSA_SIG *a);
""",
    "DSA_SIG_free",
)

patch_one(
    "dsa.h",
    """int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
""",
    """/**
 * @brief Set the r and s components of a DSA signature, transferring ownership.
 * @param sig Signature object to update.
 * @param r New r value; ownership transferred to @p sig (must not be NULL).
 * @param s New s value; ownership transferred to @p sig (must not be NULL).
 * @return 1 on success, or 0 on failure.
 */
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
""",
    "DSA_SIG_set0",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 DSA *DSA_new_method(ENGINE *engine);
""",
    """/**
 * @brief Allocate a DSA object that uses methods from @p engine (deprecated).
 * @param engine ENGINE providing DSA implementation, or NULL for the default software method.
 * @return New DSA, or NULL on failure; free with DSA_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSA_new_method(ENGINE *engine);
""",
    "DSA_new_method",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_security_bits(const DSA *d);
""",
    """/**
 * @brief Estimate the security strength in bits of a DSA key from its parameters (deprecated).
 * @param d DSA key whose p/q sizes are examined.
 * @return Approximate security bits, or 0 if parameters are incomplete.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_security_bits(const DSA *d);
""",
    "DSA_security_bits",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_sign(int type, const unsigned char *dgst,
    int dlen, unsigned char *sig,
    unsigned int *siglen, DSA *dsa);
""",
    """/**
 * @brief Create a DER-encoded DSA signature over a message digest (deprecated).
 * @param type Historical digest NID; ignored by modern implementations.
 * @param dgst Digest octets to sign.
 * @param dlen Length of @p dgst in bytes.
 * @param sig Output buffer receiving the DER signature (at least DSA_size(@p dsa) bytes).
 * @param siglen Receives the number of signature bytes written.
 * @param dsa DSA key containing the private key used for signing.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_sign(int type, const unsigned char *dgst,
    int dlen, unsigned char *sig,
    unsigned int *siglen, DSA *dsa);
""",
    "DSA_sign",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 void *DSA_get_ex_data(const DSA *d, int idx);
""",
    """/**
 * @brief Retrieve application data previously stored on a DSA object (deprecated).
 * @param d DSA object to query.
 * @param idx Index obtained from DSA_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *DSA_get_ex_data(const DSA *d, int idx);
""",
    "DSA_get_ex_data",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_0_9_8
DSA *DSA_generate_parameters(int bits, unsigned char *seed, int seed_len,
    int *counter_ret, unsigned long *h_ret,
    void (*callback)(int, int, void *),
    void *cb_arg);
""",
    """/**
 * @brief Generate DSA domain parameters with a legacy progress callback (deprecated).
 * @param bits Desired length of the prime p in bits.
 * @param seed Optional seed bytes for reproducible generation, or NULL.
 * @param seed_len Length of @p seed in bytes.
 * @param counter_ret Optional out-parameter receiving the counter used, or NULL.
 * @param h_ret Optional out-parameter receiving the h value used, or NULL.
 * @param callback Optional progress callback, or NULL.
 * @param cb_arg Opaque pointer passed to @p callback.
 * @return Newly allocated DSA with generated parameters, or NULL on failure.
 */
OSSL_DEPRECATEDIN_0_9_8
DSA *DSA_generate_parameters(int bits, unsigned char *seed, int seed_len,
    int *counter_ret, unsigned long *h_ret,
    void (*callback)(int, int, void *),
    void *cb_arg);
""",
    "DSA_generate_parameters",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSAparams_print(BIO *bp, const DSA *x);
""",
    """/**
 * @brief Print DSA domain parameters (p, q, g) to a BIO in human-readable form (deprecated).
 * @param bp BIO that receives the textual dump.
 * @param x DSA object whose parameters are printed.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSAparams_print(BIO *bp, const DSA *x);
""",
    "DSAparams_print",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_print_fp(FILE *bp, const DSA *x, int off);
""",
    """/**
 * @brief Print a human-readable representation of a DSA key to a FILE (deprecated).
 * @param bp Output FILE stream.
 * @param x DSA key (parameters and/or key pair) to print.
 * @param off Indentation width in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_print_fp(FILE *bp, const DSA *x, int off);
""",
    "DSA_print_fp",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_set0_key(DSA *d, BIGNUM *pub_key,
    BIGNUM *priv_key);
""",
    """/**
 * @brief Set the public and optional private key components of a DSA object (deprecated).
 * @param d DSA object to update.
 * @param pub_key Public key y; ownership transferred (must not be NULL).
 * @param priv_key Private key x; ownership transferred, or NULL to leave/clear private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set0_key(DSA *d, BIGNUM *pub_key,
    BIGNUM *priv_key);
""",
    "DSA_set0_key",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_q(const DSA *d);
""",
    """/**
 * @brief Return the DSA subgroup order q without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for q, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_q(const DSA *d);
""",
    "DSA_get0_q",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_pub_key(const DSA *d);
""",
    """/**
 * @brief Return the public key component of a DSA object without duplicating it (deprecated).
 * @param d DSA key to query.
 * @return Internal BIGNUM pointer for the public key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_pub_key(const DSA *d);
""",
    "DSA_get0_pub_key",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set0_app_data(DSA_METHOD *dsam,
    void *app_data);
""",
    """/**
 * @brief Store an opaque application pointer on a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param app_data Caller-owned pointer retrieved later with DSA_meth_get0_app_data().
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set0_app_data(DSA_METHOD *dsam,
    void *app_data);
""",
    "DSA_meth_set0_app_data",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    BN_CTX *, BN_MONT_CTX *);
""",
    """/**
 * @brief Return the modular-exponentiation callback from a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Pointer to the bn_mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    BN_CTX *, BN_MONT_CTX *);
""",
    "DSA_meth_get_bn_mod_exp",
)

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_keygen(DSA_METHOD *dsam,
    int (*keygen)(DSA *));
""",
    """/**
 * @brief Set the key-generation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param keygen Callback that fills public/private key values on a DSA object, or NULL to clear.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_keygen(DSA_METHOD *dsam,
    int (*keygen)(DSA *));
""",
    "DSA_meth_set_keygen",
)

# ----- ec.h -----
patch_one(
    "ec.h",
    """int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Return the ECDH key-derivation function type configured on a key context.
 * @param ctx Derive context for an EC key.
 * @return KDF type such as EVP_PKEY_ECDH_KDF_NONE or EVP_PKEY_ECDH_KDF_X9_63, or 0 / negative on error.
 */
int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_CTX_get_ecdh_kdf_type",
)

patch_one(
    "ec.h",
    """typedef struct ecpk_parameters_st ECPKPARAMETERS;
""",
    """/**
 * @brief ASN.1 EC private-key parameters CHOICE (named curve OID or explicit ECParameters).
 */
typedef struct ecpk_parameters_st ECPKPARAMETERS;
""",
    "ECPKPARAMETERS",
)

patch_one(
    "ec.h",
    """void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
""",
    """/**
 * @brief Select whether an EC_GROUP encodes as a named curve or with explicit parameters.
 * @param group EC_GROUP whose ASN.1 encoding flag is set.
 * @param flag OPENSSL_EC_NAMED_CURVE or OPENSSL_EC_EXPLICIT_CURVE.
 */
void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
""",
    "EC_GROUP_set_asn1_flag",
)

patch_one(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void *EC_KEY_get_ex_data(const EC_KEY *key, int idx);
""",
    """/**
 * @brief Retrieve application data previously stored on an EC_KEY (deprecated).
 * @param key EC key to query.
 * @param idx Index obtained from EC_KEY_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *EC_KEY_get_ex_data(const EC_KEY *key, int idx);
""",
    "EC_KEY_get_ex_data",
)

patch_one(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_default_method(const EC_KEY_METHOD *meth);
""",
    """/**
 * @brief Set the process-wide default EC_KEY_METHOD used by newly created EC keys (deprecated).
 * @param meth Method table to install as the default, or NULL to restore the built-in OpenSSL method.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_default_method(const EC_KEY_METHOD *meth);
""",
    "EC_KEY_set_default_method",
)

# ----- engine.h -----
patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_RAND(ENGINE *e);
""",
    """/**
 * @brief Unregister an ENGINE as a RAND implementation (deprecated).
 * @param e ENGINE previously registered for RAND to remove from the RAND table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_RAND(ENGINE *e);
""",
    "ENGINE_unregister_RAND",
)

patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
""",
    """/**
 * @brief Return the RAND_METHOD implemented by an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return RAND method pointer, or NULL if @p e does not provide RAND.
 */
OSSL_DEPRECATEDIN_3_0 const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
""",
    "ENGINE_get_RAND",
)

patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_ciphers(ENGINE *e);
""",
    """/**
 * @brief Register @p e as the default ENGINE for all cipher NIDs it implements (deprecated).
 * @param e ENGINE whose cipher implementations should become defaults.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_ciphers(ENGINE *e);
""",
    "ENGINE_set_default_ciphers",
)

# ----- err.h -----
patch_both(
    "err.h",
    """    size_t err_data_size[ERR_NUM_ERRORS];
""",
    """    /** Allocated size in bytes of each @c err_data slot. */
    size_t err_data_size[ERR_NUM_ERRORS];
""",
    "err_state_st.err_data_size",
)

patch_both(
    "err.h",
    """unsigned long ERR_get_error(void);
""",
    """/**
 * @brief Pop the earliest error code from the current thread's error queue.
 * @return Packed error code, or 0 if the queue is empty.
 */
unsigned long ERR_get_error(void);
""",
    "ERR_get_error",
)

patch_both(
    "err.h",
    """const char *ERR_lib_error_string(unsigned long e);
""",
    """/**
 * @brief Return the human-readable library name for a packed error code.
 * @param e Error code as returned by ERR_get_error() (library field is used).
 * @return Internal library name string (do not free), or NULL if unknown.
 */
const char *ERR_lib_error_string(unsigned long e);
""",
    "ERR_lib_error_string",
)

patch_both(
    "err.h",
    """int ERR_get_next_error_library(void);
""",
    """/**
 * @brief Allocate a unique library number for a dynamically registered error library.
 * @return New ERR_LIB_* style library index for use with ERR_load_strings().
 */
int ERR_get_next_error_library(void);
""",
    "ERR_get_next_error_library",
)

# ----- evp.h (first half of batch symbols) -----
patch_one(
    "evp.h",
    """int EVP_MD_up_ref(EVP_MD *md);
""",
    """/**
 * @brief Increment the reference count on a fetched EVP_MD.
 * @param md Digest method whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_up_ref(EVP_MD *md);
""",
    "EVP_MD_up_ref",
)

patch_one(
    "evp.h",
    """__owur int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);
""",
    """/**
 * @brief Finish encryption and write any remaining padded ciphertext bytes.
 * @param ctx Cipher context previously used with EVP_EncryptUpdate().
 * @param out Buffer receiving the final ciphertext block(s).
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);
""",
    "EVP_EncryptFinal",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for AES-256-CBC with HMAC-SHA1 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
""",
    "EVP_aes_256_cbc_hmac_sha1",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_aria_192_cbc(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for ARIA-192 in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aria_192_cbc(void);
""",
    "EVP_aria_192_cbc",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_aria_256_cfb1(void);
""",
    """/**
 * @brief Return the ARIA-256 cipher in 1-bit CFB mode.
 * @return EVP_CIPHER for aria-256-cfb1, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_256_cfb1(void);
""",
    "EVP_aria_256_cfb1",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from a fetched EVP_MAC algorithm.
 * @param mac MAC algorithm whose gettable algorithm parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
""",
    "EVP_MAC_gettable_params",
)

patch_one(
    "evp.h",
    """EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent);
""",
    """/**
 * @brief Create a RAND context for @p rand, optionally chaining from a parent DRBG.
 * @param rand Fetched EVP_RAND implementation (reference count is incremented).
 * @param parent Optional parent EVP_RAND_CTX used as entropy source, or NULL.
 * @return New EVP_RAND_CTX, or NULL on failure; free with EVP_RAND_CTX_free().
 */
EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent);
""",
    "EVP_RAND_CTX_new",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);
""",
    """/**
 * @brief Associate an ENGINE with an EVP_PKEY for subsequent low-level operations (deprecated).
 * @param pkey Key whose ENGINE reference is set.
 * @param e ENGINE to attach, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);
""",
    "EVP_PKEY_set1_engine",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_KEYMGMT_settable_params(const EVP_KEYMGMT *keymgmt);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors settable on an existing key via this keymgmt.
 * @param keymgmt Key management implementation to query.
 * @return Constant OSSL_PARAM array, or NULL on error.
 */
const OSSL_PARAM *EVP_KEYMGMT_settable_params(const EVP_KEYMGMT *keymgmt);
""",
    "EVP_KEYMGMT_settable_params",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);
""",
    """/**
 * @brief Test whether a key context is for the named key type.
 * @param ctx Key context to query.
 * @param keytype Algorithm name such as "RSA" or "EC".
 * @return 1 if @p ctx matches @p keytype, or 0 otherwise.
 */
int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);
""",
    "EVP_PKEY_CTX_is_a",
)

patch_one(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
    const unsigned char *priv,
    size_t len);
""",
    """/**
 * @brief Create an EVP_PKEY from raw private-key octets (legacy NID/ENGINE form).
 * @param type Key type NID such as EVP_PKEY_X25519 or EVP_PKEY_ED25519.
 * @param e Optional ENGINE, or NULL (ignored for provider-only types).
 * @param priv Raw private-key bytes in the algorithm-native format.
 * @param len Length of @p priv in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free().
 */
EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
    const unsigned char *priv,
    size_t len);
""",
    "EVP_PKEY_new_raw_private_key",
)

patch_one(
    "evp.h",
    """void EVP_SIGNATURE_free(EVP_SIGNATURE *signature);
""",
    """/**
 * @brief Free a fetched EVP_SIGNATURE method and release its provider reference.
 * @param signature Signature algorithm object to free, or NULL (no-op).
 */
void EVP_SIGNATURE_free(EVP_SIGNATURE *signature);
""",
    "EVP_SIGNATURE_free",
)

patch_one(
    "evp.h",
    """OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher);
""",
    """/**
 * @brief Return the provider that implemented an asymmetric cipher algorithm.
 * @param cipher Asymmetric cipher method to query.
 * @return Provider pointer (do not free), or NULL if unavailable.
 */
OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher);
""",
    "EVP_ASYM_CIPHER_get0_provider",
)

patch_one(
    "evp.h",
    """EVP_ASYM_CIPHER *EVP_ASYM_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
""",
    """/**
 * @brief Fetch an asymmetric cipher (encrypt/decrypt) algorithm from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name (for example "RSA").
 * @param properties Optional property query string, or NULL.
 * @return Fetched EVP_ASYM_CIPHER (free with EVP_ASYM_CIPHER_free()), or NULL on failure.
 */
EVP_ASYM_CIPHER *EVP_ASYM_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
""",
    "EVP_ASYM_CIPHER_fetch",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_KEM_settable_ctx_params(const EVP_KEM *kem);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors settable on a KEM operation context.
 * @param kem KEM algorithm whose settable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEM_settable_ctx_params(const EVP_KEM *kem);
""",
    "EVP_KEM_settable_ctx_params",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Initialize a key context for signature recovery (typically RSA).
 * @param ctx Key context created for a verify-recover-capable algorithm.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_verify_recover_init",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
""",
    """/**
 * @brief Decrypt data using the private key bound to @p ctx.
 * @param ctx Context previously initialized with EVP_PKEY_decrypt_init().
 * @param out Buffer receiving plaintext, or NULL to query the required size.
 * @param outlen In/out length of @p out; on return holds bytes written or needed.
 * @param in Ciphertext bytes to decrypt.
 * @param inlen Length of @p in in bytes.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
""",
    "EVP_PKEY_decrypt",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_auth_encapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpriv,
    const OSSL_PARAM params[]);
""",
    """/**
 * @brief Initialize authenticated key encapsulation using a peer public key and auth private key.
 * @param ctx Context created for a KEM algorithm (recipient/public key already set as needed).
 * @param authpriv Private key used for authentication during encapsulation.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_auth_encapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpriv,
    const OSSL_PARAM params[]);
""",
    "EVP_PKEY_auth_encapsulate_init",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_set_utf8_string_param(EVP_PKEY *pkey, const char *key_name,
    const char *str);
""",
    """/**
 * @brief Set a UTF-8 string algorithm parameter on an EVP_PKEY by name.
 * @param pkey Key whose provider-side parameters are updated.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param str NUL-terminated UTF-8 value to assign (copied).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_utf8_string_param(EVP_PKEY *pkey, const char *key_name,
    const char *str);
""",
    "EVP_PKEY_set_utf8_string_param",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
""",
    """/**
 * @brief Generate parameters or a key pair into *@p ppkey (unified keygen/paramgen entry).
 * @param ctx Context prepared with EVP_PKEY_keygen_init() or EVP_PKEY_paramgen_init().
 * @param ppkey Address of an EVP_PKEY pointer that receives the new object (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
""",
    "EVP_PKEY_generate",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));
""",
    """/**
 * @brief Set digest-context signing callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param signctx_init Optional initialiser called before streaming sign, or NULL.
 * @param signctx Callback that produces @p sig from digest state in @p mctx, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));
""",
    "EVP_PKEY_meth_set_signctx",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digest_custom(const EVP_PKEY_METHOD *pmeth,
    int (**pdigest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
""",
    """/**
 * @brief Retrieve the custom digest callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pdigest_custom Receives the digest_custom callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digest_custom(const EVP_PKEY_METHOD *pmeth,
    int (**pdigest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
""",
    "EVP_PKEY_meth_get_digest_custom",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX *ctx, char *name, size_t namelen);
""",
    """/**
 * @brief Copy the elliptic-curve or DH group name from a key context into a caller buffer.
 * @param ctx Key context whose group / curve name is queried.
 * @param name Destination buffer for the NUL-terminated name.
 * @param namelen Capacity of @p name in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX *ctx, char *name, size_t namelen);
""",
    "EVP_PKEY_CTX_get_group_name",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print(" ", m)
