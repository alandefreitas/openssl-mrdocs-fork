#!/usr/bin/env python3
"""Documentation repair batch 10a: async, dh, dsa, ec, engine."""
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


# ----- async.h -----
patch_both(
    "async.h",
    """int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
    size_t *numfds);""",
    """/**
 * @brief Collect every wait file descriptor currently registered on @p ctx.
 * @param ctx Wait context to query.
 * @param fd Optional array that receives up to *@p numfds descriptors; may be NULL to query the count only.
 * @param numfds On input, capacity of @p fd when non-NULL; on output, the number of registered fds.
 * @return 1 on success, or 0 on failure.
 */
int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
    size_t *numfds);""",
    "ASYNC_WAIT_CTX_get_all_fds",
)

# ----- dh.h -----
patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits);",
    """/**
 * @brief Set the DH parameter-generation prime (p) length in bits.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param pbits Desired bit length of the prime modulus p.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits);""",
    "EVP_PKEY_CTX_set_dh_paramgen_prime_len",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key);",
    """/**
 * @brief Validate a Diffie-Hellman public key and report problems via the error queue (deprecated).
 * @param dh DH object providing the domain parameters used for the check.
 * @param pub_key Public key value to validate against those parameters.
 * @return 1 if the public key looks suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key);""",
    "DH_check_pub_key_ex",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key,
    int *codes);""",
    """/**
 * @brief Validate a Diffie-Hellman public key and return a bitmask of problems (deprecated).
 * @param dh DH object providing the domain parameters used for the check.
 * @param pub_key Public key value to validate against those parameters.
 * @param codes Receives zero or a combination of DH_CHECK_PUBKEY_* reason bits.
 * @return 1 if the check routine ran successfully (inspect @p codes), or 0 on hard failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key,
    int *codes);""",
    "DH_check_pub_key",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 void DH_clear_flags(DH *dh, int flags);",
    """/**
 * @brief Clear selected flag bits on a DH object (deprecated).
 * @param dh DH object to update.
 * @param flags Bitmask of DH_FLAG_* values to clear.
 */
OSSL_DEPRECATEDIN_3_0 void DH_clear_flags(DH *dh, int flags);""",
    "DH_clear_flags",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 void *DH_meth_get0_app_data(const DH_METHOD *dhm);",
    """/**
 * @brief Return the opaque application data pointer stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Application data previously set with DH_meth_set0_app_data(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void *DH_meth_get0_app_data(const DH_METHOD *dhm);""",
    "DH_meth_get0_app_data",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *));",
    """/**
 * @brief Set the DH object-initialization callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param init Callback invoked when a DH object using this method is initialized, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_init(DH_METHOD *dhm, int (*init)(DH *));""",
    "DH_meth_set_init",
)

# ----- dsa.h -----
patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen,
    DSA *dsa);""",
    """/**
 * @brief Sign a digest with a DSA private key, returning a DSA_SIG structure (deprecated).
 * @param dgst Digest bytes to sign.
 * @param dlen Length of @p dgst in bytes.
 * @param dsa DSA key containing the private key used for signing.
 * @return Newly allocated DSA_SIG, or NULL on error; free with DSA_SIG_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen,
    DSA *dsa);""",
    "DSA_do_sign",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void DSA_free(DSA *r);",
    """/**
 * @brief Free a DSA object and its associated resources (deprecated).
 * @param r DSA object to free; NULL is ignored.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_free(DSA *r);""",
    "DSA_free",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int DSA_set_ex_data(DSA *d, int idx, void *arg);",
    """/**
 * @brief Store application-specific data on a DSA object at a CRYPTO ex_data index (deprecated).
 * @param d DSA object to update.
 * @param idx Index obtained from DSA_get_ex_new_index() / CRYPTO_get_ex_new_index().
 * @param arg Pointer to store (ownership rules follow CRYPTO_set_ex_data()).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set_ex_data(DSA *d, int idx, void *arg);""",
    "DSA_set_ex_data",
)

patch_both(
    "dsa.h",
    """DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(OSSL_DEPRECATEDIN_3_0,
    DSA, DSAPublicKey)""",
    """/**
 * @brief Decode a DSA public key from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA public key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPublicKey(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA public key to DER (deprecated).
 * @param a DSA key whose public components are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPublicKey(const DSA *a, unsigned char **out);""",
    "d2i/i2d_DSAPublicKey",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int DSA_print(BIO *bp, const DSA *x, int off);",
    """/**
 * @brief Print a human-readable representation of a DSA key to a BIO (deprecated).
 * @param bp BIO that receives the textual dump.
 * @param x DSA key (parameters and/or key pair) to print.
 * @param off Indentation width in spaces.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_print(BIO *bp, const DSA *x, int off);""",
    "DSA_print",
)

patch_both(
    "dsa.h",
    """#ifndef OPENSSL_NO_DH
/*
 * Convert DSA structure (key or just parameters) into DH structure (be
 * careful to avoid small subgroup attacks when using this!)
 */
OSSL_DEPRECATEDIN_3_0 DH *DSA_dup_DH(const DSA *r);
#endif""",
    """#ifndef OPENSSL_NO_DH
/**
 * @brief Duplicate DSA parameters (and key material when present) into a new DH object (deprecated).
 * @param r Source DSA object whose p/q/g (and optional keys) are copied.
 * @return New DH object, or NULL on error; free with DH_free().
 *
 * Be careful to avoid small-subgroup attacks when using the resulting DH key.
 */
OSSL_DEPRECATEDIN_3_0 DH *DSA_dup_DH(const DSA *r);
#endif""",
    "DSA_dup_DH",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 void DSA_get0_key(const DSA *d, const BIGNUM **pub_key,
    const BIGNUM **priv_key);""",
    """/**
 * @brief Return pointers to the DSA public and private key components without transferring ownership (deprecated).
 * @param d DSA object to query.
 * @param pub_key Optional destination for the public key, or NULL.
 * @param priv_key Optional destination for the private key, or NULL.
 *
 * Returned BIGNUMs must not be freed by the caller.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_get0_key(const DSA *d, const BIGNUM **pub_key,
    const BIGNUM **priv_key);""",
    "DSA_get0_key",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_g(const DSA *d);",
    """/**
 * @brief Return the DSA generator g without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for g, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_g(const DSA *d);""",
    "DSA_get0_g",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void DSA_clear_flags(DSA *d, int flags);",
    """/**
 * @brief Clear selected flag bits on a DSA object (deprecated).
 * @param d DSA object to update.
 * @param flags Bitmask of DSA_FLAG_* values to clear.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_clear_flags(DSA *d, int flags);""",
    "DSA_clear_flags",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void DSA_set_flags(DSA *d, int flags);",
    """/**
 * @brief Set flag bits on a DSA object without clearing existing flags (deprecated).
 * @param d DSA object to update.
 * @param flags Bitmask of DSA_FLAG_* values to set.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_set_flags(DSA *d, int flags);""",
    "DSA_set_flags",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void DSA_meth_free(DSA_METHOD *dsam);",
    """/**
 * @brief Free a DSA_METHOD structure and any associated memory (deprecated).
 * @param dsam Method to free; NULL is ignored.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_meth_free(DSA_METHOD *dsam);""",
    "DSA_meth_free",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 const char *DSA_meth_get0_name(const DSA_METHOD *dsam);",
    """/**
 * @brief Return the descriptive name stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Internal name string (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const char *DSA_meth_get0_name(const DSA_METHOD *dsam);""",
    "DSA_meth_get0_name",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void *DSA_meth_get0_app_data(const DSA_METHOD *dsam);",
    """/**
 * @brief Return the opaque application data pointer stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Application data previously set with DSA_meth_set0_app_data(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void *DSA_meth_get0_app_data(const DSA_METHOD *dsam);""",
    "DSA_meth_get0_app_data",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign_setup(DSA_METHOD *dsam,
    int (*sign_setup)(DSA *, BN_CTX *, BIGNUM **, BIGNUM **));""",
    """/**
 * @brief Set the signature precomputation callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param sign_setup Callback that prepares signing intermediates, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign_setup(DSA_METHOD *dsam,
    int (*sign_setup)(DSA *, BN_CTX *, BIGNUM **, BIGNUM **));""",
    "DSA_meth_set_sign_setup",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_mod_exp(DSA_METHOD *dsam,
    int (*mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
        BN_MONT_CTX *));""",
    """/**
 * @brief Set the modular-exponentiation callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param mod_exp Callback performing the DSA modular exponentiation, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_mod_exp(DSA_METHOD *dsam,
    int (*mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
        BN_MONT_CTX *));""",
    "DSA_meth_set_mod_exp",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_finish(const DSA_METHOD *dsam))(DSA *);",
    """/**
 * @brief Return the DSA object-finalization callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_finish(const DSA_METHOD *dsam))(DSA *);""",
    "DSA_meth_get_finish",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_finish(DSA_METHOD *dsam,
    int (*finish)(DSA *));""",
    """/**
 * @brief Set the DSA object-finalization callback on a DSA_METHOD (deprecated).
 * @param dsam Method table to update.
 * @param finish Callback invoked when a DSA object using this method is freed, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_finish(DSA_METHOD *dsam,
    int (*finish)(DSA *));""",
    "DSA_meth_set_finish",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_paramgen(const DSA_METHOD *dsam))(DSA *, int, const unsigned char *, int, int *, unsigned long *,
    BN_GENCB *);""",
    """/**
 * @brief Return the parameter-generation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the paramgen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_paramgen(const DSA_METHOD *dsam))(DSA *, int, const unsigned char *, int, int *, unsigned long *,
    BN_GENCB *);""",
    "DSA_meth_get_paramgen",
)

# ----- ec.h -----
patch_both(
    "ec.h",
    "int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int cofactor_mode);",
    """/**
 * @brief Set whether ECDH key agreement multiplies by the curve cofactor.
 * @param ctx Key context configured for ECDH.
 * @param cofactor_mode 1 to enable cofactor ECDH, 0 to disable, or -1 to reset to the default.
 * @return 1 on success, or a negative value on failure.
 */
int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int cofactor_mode);""",
    "EVP_PKEY_CTX_set_ecdh_cofactor_mode",
)

# ----- engine.h -----
patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DSA(ENGINE *e);",
    """/**
 * @brief Register @p e's DSA method with the ENGINE DSA implementation table (deprecated).
 * @param e ENGINE that provides a DSA_METHOD.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DSA(ENGINE *e);""",
    "ENGINE_register_DSA",
)

patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_pkey_asn1_meths(void);",
    """/**
 * @brief Register every loaded ENGINE that provides EVP_PKEY ASN.1 methods (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_pkey_asn1_meths(void);""",
    "ENGINE_register_all_pkey_asn1_meths",
)

patch_both(
    "engine.h",
    """/*
 * This allows an application to determine if the installed OpenSSL has
 * the same static data as it does. This is primarily for systems that use
 * dynamic libraries / shared libraries / DLLs that may be loaded and
 * unloaded. When an ENGINE is loaded onto a system that does not share
 * static data with it (for example when an application is loaded as a DLL
 * onto a Windows system), OPENSSL_Applink may be required to provide a
 * "glue" layer between the OPENSSL static data and ENGINE static data.
 * This function returns a pointer to the OPENSSL static data. The
 * application can then compare this with the ENGINE's idea of the OPENSSL
 * static data and let the loading application and loaded ENGINE compare
 * their respective values.
 */
void *ENGINE_get_static_state(void);""",
    """/**
 * @brief Return a pointer that identifies this process's OpenSSL static data for ENGINE loaders.
 * @return Opaque pointer comparing OPENSSL and ENGINE static-data instances across DLL boundaries.
 *
 * Used primarily when dynamic libraries do not share static data; loaders can compare this
 * value with an ENGINE's view of OpenSSL static state (see OPENSSL_Applink on Windows).
 */
void *ENGINE_get_static_state(void);""",
    "ENGINE_get_static_state",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  MISSING:", m)
