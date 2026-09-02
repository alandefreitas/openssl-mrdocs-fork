#!/usr/bin/env python3
"""Documentation repair batch 14c: remaining evp.h + http, kdf, objects, params."""
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


print("=== batch 14c ===")

# ----- evp remaining -----
patch_one(
    "evp.h",
    """void EVP_MD_do_all_sorted(void (*fn)(const EVP_MD *ciph, const char *from,
                              const char *to, void *x),
    void *arg);
""",
    """/**
 * @brief Call @p fn for each built-in digest name, in sorted name order (legacy).
 * @param fn Callback receiving the digest method, canonical name, alias, and @p arg.
 * @param arg Opaque pointer forwarded to every @p fn invocation.
 */
void EVP_MD_do_all_sorted(void (*fn)(const EVP_MD *ciph, const char *from,
                              const char *to, void *x),
    void *arg);
""",
    "EVP_MD_do_all_sorted",
)

patch_one(
    "evp.h",
    """int EVP_MAC_up_ref(EVP_MAC *mac);
""",
    """/**
 * @brief Increment the reference count on a fetched EVP_MAC.
 * @param mac MAC algorithm from EVP_MAC_fetch().
 * @return 1 on success, or 0 on error.
 */
int EVP_MAC_up_ref(EVP_MAC *mac);
""",
    "EVP_MAC_up_ref",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);
""",
    """/**
 * @brief Describe OSSL_PARAM keys that may be set on MAC contexts for @p mac.
 * @param mac MAC algorithm to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);
""",
    "EVP_MAC_settable_ctx_params",
)

patch_one(
    "evp.h",
    """const char *EVP_RAND_get0_name(const EVP_RAND *rand);
""",
    """/**
 * @brief Return the primary algorithm name of a fetched EVP_RAND.
 * @param rand RAND algorithm object.
 * @return NUL-terminated name, or NULL on error.
 */
const char *EVP_RAND_get0_name(const EVP_RAND *rand);
""",
    "EVP_RAND_get0_name",
)

patch_one(
    "evp.h",
    """EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
""",
    """/**
 * @brief Return the EVP_RAND algorithm associated with RAND context @p ctx.
 * @param ctx RAND context.
 * @return Borrowed EVP_RAND pointer (do not free), or NULL if unset.
 */
EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
""",
    "EVP_RAND_CTX_get0_rand",
)

patch_one(
    "evp.h",
    """int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
    const unsigned char *ent, size_t ent_len,
    const unsigned char *addin, size_t addin_len);
""",
    """/**
 * @brief Reseed a DRBG/RAND context with optional entropy and additional input.
 * @param ctx RAND context to reseed.
 * @param prediction_resistance Nonzero to request prediction resistance when supported.
 * @param ent Optional entropy bytes, or NULL to let the implementation gather entropy.
 * @param ent_len Length of @p ent.
 * @param addin Optional additional input bytes, or NULL.
 * @param addin_len Length of @p addin.
 * @return 1 on success, or 0 on error.
 */
int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
    const unsigned char *ent, size_t ent_len,
    const unsigned char *addin, size_t addin_len);
""",
    "EVP_RAND_reseed",
)

patch_one(
    "evp.h",
    """__owur int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen);
""",
    """/**
 * @brief Generate a nonce of @p outlen bytes from RAND context @p ctx.
 * @param ctx Instantiated RAND context.
 * @param out Buffer receiving the nonce.
 * @param outlen Number of nonce bytes to produce.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen);
""",
    "EVP_RAND_nonce",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
""",
    """/**
 * @brief Assign the algorithm type of an empty EVP_PKEY by NID / EVP_PKEY_* id.
 * @param pkey Key object to type (typically freshly EVP_PKEY_new()'d).
 * @param type Key type identifier (for example EVP_PKEY_RSA).
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
""",
    "EVP_PKEY_set_type",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt);
""",
    """/**
 * @brief Assign the algorithm type of @p pkey from a fetched EVP_KEYMGMT.
 * @param pkey Key object to type.
 * @param keymgmt Key management implementation that defines the type.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *pkey, EVP_KEYMGMT *keymgmt);
""",
    "EVP_PKEY_set_type_by_keymgmt",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
const struct rsa_st *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
""",
    """/**
 * @brief Return the legacy RSA handle inside @p pkey without incrementing its refcount (deprecated).
 * @param pkey Key expected to contain an RSA key.
 * @return Borrowed RSA pointer, or NULL if @p pkey is not RSA / on error.
 */
OSSL_DEPRECATEDIN_3_0
const struct rsa_st *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
""",
    "EVP_PKEY_get0_RSA",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
""",
    """/**
 * @brief Print a private key (including private components) to a BIO.
 * @param out Output BIO.
 * @param pkey Key to print.
 * @param indent Indentation depth in spaces.
 * @param pctx ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
""",
    "EVP_PKEY_print_private",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_asn1_add_alias(int to, int from);
""",
    """/**
 * @brief Alias ASN.1 method NID @p from so it is treated as NID @p to.
 * @param to Destination algorithm NID that already has an ASN.1 method.
 * @param from Alias NID to map onto @p to.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_asn1_add_alias(int to, int from);
""",
    "EVP_PKEY_asn1_add_alias",
)

patch_one(
    "evp.h",
    """void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
    void (*pkey_free)(EVP_PKEY *pkey));
""",
    """/**
 * @brief Set the private-key free callback on a custom EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being constructed.
 * @param pkey_free Callback that releases algorithm-specific key material in @p pkey.
 */
void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
    void (*pkey_free)(EVP_PKEY *pkey));
""",
    "EVP_PKEY_asn1_set_free",
)

patch_one(
    "evp.h",
    """void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_security_bits)(const EVP_PKEY
            *pk));
""",
    """/**
 * @brief Set the security-bits callback on a custom EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being constructed.
 * @param pkey_security_bits Callback returning an estimate of security strength in bits.
 */
void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_security_bits)(const EVP_PKEY
            *pk));
""",
    "EVP_PKEY_asn1_set_security_bits",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX *ctx, void *id);
""",
    """/**
 * @brief Copy the algorithm-specific ID bytes from @p ctx into @p id.
 * @param ctx Key context that previously received an ID via EVP_PKEY_CTX_set1_id().
 * @param id Caller-allocated buffer of size reported by EVP_PKEY_CTX_get1_id_len().
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX *ctx, void *id);
""",
    "EVP_PKEY_CTX_get1_id",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Describe OSSL_PARAM keys that may be set on key context @p ctx.
 * @param ctx Key operation context.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_CTX_settable_params",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_ASYM_CIPHER_settable_ctx_params(const EVP_ASYM_CIPHER *ciph);
""",
    """/**
 * @brief Describe OSSL_PARAM keys settable on asymmetric-cipher contexts for @p ciph.
 * @param ciph Asymmetric cipher algorithm to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_ASYM_CIPHER_settable_ctx_params(const EVP_ASYM_CIPHER *ciph);
""",
    "EVP_ASYM_CIPHER_settable_ctx_params",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
    int (*init)(EVP_PKEY_CTX *ctx));
""",
    """/**
 * @brief Set the context-init callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed with EVP_PKEY_meth_new().
 * @param init Callback invoked when an EVP_PKEY_CTX using @p pmeth is created.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
    int (*init)(EVP_PKEY_CTX *ctx));
""",
    "EVP_PKEY_meth_set_init",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, int (*verify_recover_init)(EVP_PKEY_CTX *ctx),
    int (*verify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, const unsigned char *tbs,
        size_t tbslen));
""",
    """/**
 * @brief Set verify-recover init/operation callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed.
 * @param verify_recover_init Callback that prepares @p ctx for verify-recover.
 * @param verify_recover Callback that recovers the encoded digest from a signature.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, int (*verify_recover_init)(EVP_PKEY_CTX *ctx),
    int (*verify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,
        size_t *siglen, const unsigned char *tbs,
        size_t tbslen));
""",
    "EVP_PKEY_meth_set_verify_recover",
)

# ----- http.h -----
patch_one(
    "http.h",
    """void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
    unsigned long len);
""",
    """/**
 * @brief Cap the maximum HTTP response body length accepted by @p rctx.
 * @param rctx HTTP request context.
 * @param len Maximum response length in bytes (0 may restore the implementation default).
 */
void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
    unsigned long len);
""",
    "OSSL_HTTP_REQ_CTX_set_max_response_length",
)

# ----- kdf.h -----
patch_one(
    "kdf.h",
    """void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx);
""",
    """/**
 * @brief Reset a KDF context so it can be reconfigured and reused.
 * @param ctx KDF context to clear, or NULL.
 */
void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx);
""",
    "EVP_KDF_CTX_reset",
)

patch_one(
    "kdf.h",
    """int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Apply OSSL_PARAM values (salt, key, info, digest, …) to a KDF context.
 * @param ctx KDF context.
 * @param params NULL-terminated parameter array.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_KDF_CTX_set_params",
)

patch_one(
    "kdf.h",
    """int EVP_KDF_names_do_all(const EVP_KDF *kdf,
    void (*fn)(const char *name, void *data),
    void *data);
""",
    """/**
 * @brief Invoke @p fn for every name/alias of KDF algorithm @p kdf.
 * @param kdf Fetched KDF algorithm.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_names_do_all(const EVP_KDF *kdf,
    void (*fn)(const char *name, void *data),
    void *data);
""",
    "EVP_KDF_names_do_all",
)

# ----- objects.h -----
patch_one(
    "objects.h",
    """int OBJ_NAME_add(const char *name, int type, const char *data);
""",
    """/**
 * @brief Register a name-to-data mapping in the OBJ_NAME table (legacy aliases).
 * @param name Alias string to add.
 * @param type OBJ_NAME_TYPE_* class for the alias.
 * @param data Canonical name or payload associated with @p name.
 * @return 1 on success, or 0 on error.
 */
int OBJ_NAME_add(const char *name, int type, const char *data);
""",
    "OBJ_NAME_add",
)

patch_one(
    "objects.h",
    """int OBJ_add_object(const ASN1_OBJECT *obj);
""",
    """/**
 * @brief Add @p obj to the process-wide object database (NID/sn/ln tables).
 * @param obj Object identifier to register (copied internally as needed).
 * @return New NID on success, or NID_undef on error.
 */
int OBJ_add_object(const ASN1_OBJECT *obj);
""",
    "OBJ_add_object",
)

# ----- params.h -----
patch_one(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf);
""",
    """/**
 * @brief Construct an OSSL_PARAM describing an unsigned 64-bit integer at @p buf.
 * @param key Parameter name (for example OSSL_PKEY_PARAM_*).
 * @param buf Address of the uint64_t value to expose.
 * @return OSSL_PARAM value suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf);
""",
    "OSSL_PARAM_construct_uint64",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val);
""",
    """/**
 * @brief Write @p val into parameter @p as a signed long (with range checks).
 * @param p Destination parameter located by key in an OSSL_PARAM array.
 * @param val Value to store.
 * @return 1 on success, or 0 if @p is NULL, wrong type, or out of range.
 */
int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val);
""",
    "OSSL_PARAM_set_long",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val);
""",
    """/**
 * @brief Read a UTF-8 pointer parameter without copying the string.
 * @param p Source parameter of type OSSL_PARAM_UTF8_PTR.
 * @param val Receives the pointer stored in @p (borrowed; do not free).
 * @return 1 on success, or 0 on type/error mismatch.
 */
int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val);
""",
    "OSSL_PARAM_get_utf8_ptr",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
