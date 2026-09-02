#!/usr/bin/env python3
"""Documentation repair batch 18c: core, crypto*, dh, dsa, ec, err, evp (part)."""
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


print("=== batch 18c: core/crypto/dh/dsa/ec/err/evp ===")

# ----- core.h -----

patch_one(
    "core.h",
    """    int function_id;
    void (*function)(void);
};
""",
    """    int function_id;
    /** Function pointer for this dispatch table entry (cast to the concrete OSSL_FUNC_* type). */
    void (*function)(void);
};
""",
    "ossl_dispatch.function",
)

patch_one(
    "core.h",
    """struct ossl_item_st {
    unsigned int id;
    void *ptr;
""",
    """struct ossl_item_st {
    /** Identifier selecting how @c ptr should be interpreted for this item. */
    unsigned int id;
    void *ptr;
""",
    "ossl_item.id",
)

patch_one(
    "core.h",
    """struct ossl_param_st {
    const char *key; /* the name of the parameter */
""",
    """struct ossl_param_st {
    /** Parameter name string (for example an OSSL_PKEY_PARAM_* key). */
    const char *key;
""",
    "ossl_param.key",
)

# ----- crypto.h -----

patch_both(
    "crypto.h",
    """int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t n);
""",
    """/**
 * @brief Case-insensitive comparison of at most @p n characters of two C strings.
 * @param s1 First string.
 * @param s2 Second string.
 * @param n Maximum number of characters to compare.
 * @return Negative, zero, or positive like strncasecmp().
 */
int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t n);
""",
    "OPENSSL_strncasecmp",
)

patch_both(
    "crypto.h",
    """void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
""",
    """/**
 * @brief Free all ex_data attached to @p ad for the given class, invoking free callbacks.
 * @param class_index CRYPTO_EX_INDEX_* identifying the object class.
 * @param obj Object that owns @p ad (passed to free callbacks).
 * @param ad Ex-data table to clear.
 */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
""",
    "CRYPTO_free_ex_data",
)

patch_both(
    "crypto.h",
    """int CRYPTO_secure_malloc_init(size_t sz, size_t minsize);
""",
    """/**
 * @brief Initialize the secure heap used by CRYPTO_secure_malloc().
 * @param sz Total size of the secure heap in bytes.
 * @param minsize Minimum allocation granularity / guard size.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_secure_malloc_init(size_t sz, size_t minsize);
""",
    "CRYPTO_secure_malloc_init",
)

patch_both(
    "crypto.h",
    """void CRYPTO_secure_free(void *ptr, const char *file, int line);
""",
    """/**
 * @brief Free memory previously allocated from the secure heap.
 * @param ptr Pointer returned by CRYPTO_secure_malloc(), or NULL.
 * @param file Source file name recorded for diagnostics (usually __FILE__).
 * @param line Source line recorded for diagnostics (usually __LINE__).
 */
void CRYPTO_secure_free(void *ptr, const char *file, int line);
""",
    "CRYPTO_secure_free",
)

patch_both(
    "crypto.h",
    """ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);
""",
    """/**
 * @brief Abort the process after printing an internal OpenSSL assertion failure.
 * @param assertion Text describing the failed condition.
 * @param file Source file where the failure was detected.
 * @param line Source line where the failure was detected.
 */
ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);
""",
    "OPENSSL_die",
)

patch_both(
    "crypto.h",
    """void OPENSSL_thread_stop_ex(OSSL_LIB_CTX *ctx);
""",
    """/**
 * @brief Release per-thread OpenSSL state associated with library context @p ctx.
 * @param ctx Library context whose thread-local resources are torn down for this thread.
 */
void OPENSSL_thread_stop_ex(OSSL_LIB_CTX *ctx);
""",
    "OPENSSL_thread_stop_ex",
)

patch_both(
    "crypto.h",
    """int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
""",
    """/**
 * @brief Store @p val in the thread-local slot identified by @p key.
 * @param key Thread-local key previously created with CRYPTO_THREAD_init_local().
 * @param val Pointer to store for the calling thread.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
""",
    "CRYPTO_THREAD_set_local",
)

patch_both(
    "crypto.h",
    """OSSL_LIB_CTX *OSSL_LIB_CTX_new(void);
""",
    """/**
 * @brief Allocate a new OpenSSL library context (provider / property scope).
 * @return Newly allocated OSSL_LIB_CTX, or NULL on failure; free with OSSL_LIB_CTX_free().
 */
OSSL_LIB_CTX *OSSL_LIB_CTX_new(void);
""",
    "OSSL_LIB_CTX_new",
)

patch_both(
    "crypto.h",
    """void OSSL_LIB_CTX_free(OSSL_LIB_CTX *);
""",
    """/**
 * @brief Free a library context and its associated provider/algorithm state.
 * @param ctx Context to free, or NULL.
 */
void OSSL_LIB_CTX_free(OSSL_LIB_CTX *ctx);
""",
    "OSSL_LIB_CTX_free",
)

# ----- cryptoerr_legacy.h -----

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_COMP_strings(void);
""",
    """/**
 * @brief Load legacy COMP library error strings (deprecated; no longer needed).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_COMP_strings(void);
""",
    "ERR_load_COMP_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_OBJ_strings(void);
""",
    """/**
 * @brief Load legacy OBJ library error strings (deprecated; no longer needed).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_OBJ_strings(void);
""",
    "ERR_load_OBJ_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_OCSP_strings(void);
""",
    """/**
 * @brief Load legacy OCSP library error strings (deprecated; no longer needed).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_OCSP_strings(void);
""",
    "ERR_load_OCSP_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_UI_strings(void);
""",
    """/**
 * @brief Load legacy UI library error strings (deprecated; no longer needed).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_UI_strings(void);
""",
    "ERR_load_UI_strings",
)

# ----- dh.h -----

patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen);
""",
    """/**
 * @brief Select an RFC 5114 DHX (X9.42 DH) named parameter set on a keygen/paramgen context.
 * @param ctx EVP_PKEY_CTX for a DHX operation.
 * @param gen RFC 5114 parameter-set index (1, 2, or 3).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen);
""",
    "EVP_PKEY_CTX_set_dhx_rfc5114",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_finish(const DH_METHOD *dhm))(DH *);
""",
    """/**
 * @brief Return the finish/cleanup callback installed on a custom DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_finish(const DH_METHOD *dhm))(DH *);
""",
    "DH_meth_get_finish",
)

# ----- dsa.h -----

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_dup(const DSA_METHOD *dsam);
""",
    """/**
 * @brief Duplicate a DSA_METHOD object (deprecated).
 * @param dsam Method to copy.
 * @return Newly allocated DSA_METHOD copy, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_dup(const DSA_METHOD *dsam);
""",
    "DSA_meth_dup",
)

# ----- ec.h -----

patch_one(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth,
    int (**pinit)(EC_KEY *key),
    void (**pfinish)(EC_KEY *key),
    int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
    int (**pset_group)(EC_KEY *key, const EC_GROUP *grp),
    int (**pset_private)(EC_KEY *key, const BIGNUM *priv_key),
    int (**pset_public)(EC_KEY *key, const EC_POINT *pub_key));
""",
    """/**
 * @brief Retrieve init/finish/copy/set_* callbacks from an EC_KEY_METHOD (deprecated).
 * @param meth Method object to query.
 * @param pinit Receives the init callback pointer, or NULL to skip.
 * @param pfinish Receives the finish callback pointer, or NULL to skip.
 * @param pcopy Receives the copy callback pointer, or NULL to skip.
 * @param pset_group Receives the set_group callback pointer, or NULL to skip.
 * @param pset_private Receives the set_private callback pointer, or NULL to skip.
 * @param pset_public Receives the set_public callback pointer, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth,
    int (**pinit)(EC_KEY *key),
    void (**pfinish)(EC_KEY *key),
    int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
    int (**pset_group)(EC_KEY *key, const EC_GROUP *grp),
    int (**pset_private)(EC_KEY *key, const BIGNUM *priv_key),
    int (**pset_public)(EC_KEY *key, const EC_POINT *pub_key));
""",
    "EC_KEY_METHOD_get_init",
)

# ----- err.h -----

patch_both(
    "err.h",
    """    char *err_func[ERR_NUM_ERRORS];
""",
    """    /** Function-name strings associated with each slot in the error ring buffer. */
    char *err_func[ERR_NUM_ERRORS];
""",
    "err_func",
)

patch_both(
    "err.h",
    """void ERR_vset_error(int lib, int reason, const char *fmt, va_list args);
""",
    """/**
 * @brief Push an error onto the thread's error queue with a printf-style detail (va_list form).
 * @param lib Library number (ERR_LIB_*).
 * @param reason Reason code within that library.
 * @param fmt Optional printf-style detail format, or NULL.
 * @param args Variadic arguments matching @p fmt.
 */
void ERR_vset_error(int lib, int reason, const char *fmt, va_list args);
""",
    "ERR_vset_error",
)

# ----- evp.h (partial) -----

patch_one(
    "evp.h",
    """int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
""",
    """/**
 * @brief Copy the original IV from a cipher context into @p buf.
 * @param ctx Cipher context previously initialized with an IV.
 * @param buf Destination buffer for the IV bytes.
 * @param len Capacity of @p buf in bytes (must be at least the IV length).
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
""",
    "EVP_CIPHER_CTX_get_original_iv",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);
""",
    """/**
 * @brief Squeeze additional output from an XOF digest context (for example SHAKE).
 * @param ctx Digest context after EVP_DigestFinalXOF() / absorb phase as required by the algorithm.
 * @param out Buffer that receives @p outlen bytes of XOF output.
 * @param outlen Number of bytes to squeeze.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);
""",
    "EVP_DigestSqueeze",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);
""",
    """/**
 * @brief Initialize a digest-verify operation with an explicit digest name and library context.
 * @param ctx Digest context to initialize for verification.
 * @param pctx Optional receiver for the internal EVP_PKEY_CTX, or NULL.
 * @param mdname Digest algorithm name (for example \"SHA256\"), or NULL to use the key default.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param props Property query string for fetches, or NULL.
 * @param pkey Public key used to verify the signature.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);
""",
    "EVP_DigestVerifyInit_ex",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *ctx);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors that may be set on an initialized cipher context.
 * @param ctx Cipher context to query.
 * @return Array of settable parameter descriptors terminated by OSSL_PARAM_construct_end(), or NULL.
 */
const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *ctx);
""",
    "EVP_CIPHER_CTX_settable_params",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_192_ecb(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for AES-192 in ECB mode.
 * @return EVP_CIPHER for AES-192-ECB, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_ecb(void);
""",
    "EVP_aes_192_ecb",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_sm4_ofb(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for SM4 in OFB mode.
 * @return EVP_CIPHER for SM4-OFB, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_sm4_ofb(void);
""",
    "EVP_sm4_ofb",
)

patch_one(
    "evp.h",
    """int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Apply an OSSL_PARAM array of parameters to a MAC context.
 * @param ctx MAC context to update.
 * @param params Parameter array terminated by OSSL_PARAM_construct_end().
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_MAC_CTX_set_params",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand);
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors that can be retrieved from an EVP_RAND algorithm.
 * @param rand RAND algorithm object.
 * @return Array of gettable parameter descriptors terminated by OSSL_PARAM_construct_end(), or NULL.
 */
const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand);
""",
    "EVP_RAND_gettable_params",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_get_base_id(const EVP_PKEY *pkey);
""",
    """/**
 * @brief Return the base EVP_PKEY type id for @p pkey (for example EVP_PKEY_RSA).
 * @param pkey Key to query.
 * @return EVP_PKEY_* type constant, or EVP_PKEY_NONE if unset.
 */
int EVP_PKEY_get_base_id(const EVP_PKEY *pkey);
""",
    "EVP_PKEY_get_base_id",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey);
""",
    """/**
 * @brief Return the ENGINE associated with @p pkey, if any (deprecated).
 * @param pkey Key to query.
 * @return ENGINE pointer, or NULL if the key is not engine-backed.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey);
""",
    "EVP_PKEY_get0_engine",
)

patch_one(
    "evp.h",
    """const OSSL_PROVIDER *EVP_PKEY_get0_provider(const EVP_PKEY *key);
""",
    """/**
 * @brief Return the provider that implements @p key, if provider-backed.
 * @param key Key to query.
 * @return OSSL_PROVIDER pointer, or NULL for legacy/engine keys.
 */
const OSSL_PROVIDER *EVP_PKEY_get0_provider(const EVP_PKEY *key);
""",
    "EVP_PKEY_get0_provider",
)

patch_one(
    "evp.h",
    """void EVP_PKEY_asn1_set_get_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*get_pub_key)(const EVP_PKEY *pk,
        unsigned char *pub,
        size_t *len));
""",
    """/**
 * @brief Install a callback that exports the raw public key encoding from an EVP_PKEY.
 * @param ameth ASN.1 method table to update.
 * @param get_pub_key Callback that writes the public key into @c pub / updates @c len.
 */
void EVP_PKEY_asn1_set_get_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*get_pub_key)(const EVP_PKEY *pk,
        unsigned char *pub,
        size_t *len));
""",
    "EVP_PKEY_asn1_set_get_pub_key",
)

patch_one(
    "evp.h",
    """int EVP_KEYMGMT_up_ref(EVP_KEYMGMT *keymgmt);
""",
    """/**
 * @brief Increment the reference count on a key management method.
 * @param keymgmt Method object to retain.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYMGMT_up_ref(EVP_KEYMGMT *keymgmt);
""",
    "EVP_KEYMGMT_up_ref",
)

patch_one(
    "evp.h",
    """const OSSL_PROVIDER *EVP_KEYMGMT_get0_provider(const EVP_KEYMGMT *keymgmt);
""",
    """/**
 * @brief Return the provider that implements a key management method.
 * @param keymgmt Method to query.
 * @return OSSL_PROVIDER pointer, or NULL.
 */
const OSSL_PROVIDER *EVP_KEYMGMT_get0_provider(const EVP_KEYMGMT *keymgmt);
""",
    "EVP_KEYMGMT_get0_provider",
)

patch_one(
    "evp.h",
    """const char *EVP_KEYMGMT_get0_name(const EVP_KEYMGMT *keymgmt);
""",
    """/**
 * @brief Return the algorithm name of a key management method.
 * @param keymgmt Method to query.
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEYMGMT_get0_name(const EVP_KEYMGMT *keymgmt);
""",
    "EVP_KEYMGMT_get0_name",
)

patch_one(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
    const char *type, ...);
""",
    """/**
 * @brief Quickly generate a key of algorithm @p type using varargs size/curve parameters.
 * @param libctx Library context for fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @param type Algorithm name (for example \"RSA\", \"EC\", \"ED25519\").
 * @return Newly allocated EVP_PKEY, or NULL on failure; free with EVP_PKEY_free().
 */
EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
    const char *type, ...);
""",
    "EVP_PKEY_Q_keygen",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, int (**pderive_init)(EVP_PKEY_CTX *ctx),
    int (**pderive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
""",
    """/**
 * @brief Retrieve derive_init / derive callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method object to query.
 * @param pderive_init Receives the derive_init callback, or NULL to skip.
 * @param pderive Receives the derive callback, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, int (**pderive_init)(EVP_PKEY_CTX *ctx),
    int (**pderive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
""",
    "EVP_PKEY_meth_get_derive",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
