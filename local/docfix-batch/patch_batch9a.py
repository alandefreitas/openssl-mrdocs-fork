#!/usr/bin/env python3
"""Documentation repair batch 9a: dh, dsa, ec, engine."""
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


# ----- dh.h -----
patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);",
    """/**
 * @brief Set the FIPS 186-4 gindex used when generating DH parameters.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param gindex Canonical gindex selecting the generator construction.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex);""",
    "EVP_PKEY_CTX_set_dh_paramgen_gindex",
)

patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid);",
    """/**
 * @brief Return the X9.42 KDF OID currently configured on a DH key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param oid Receives an internal ASN1_OBJECT pointer (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid);""",
    "EVP_PKEY_CTX_get0_dh_kdf_oid",
)

patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
    """/**
 * @brief Set the message digest used for DH key-derivation (KDF) on a key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param md Digest method such as EVP_sha256(); ownership is not transferred.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
    "EVP_PKEY_CTX_set_dh_kdf_md",
)

patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int len);",
    """/**
 * @brief Set the output length in bytes of the DH key-derivation function.
 * @param ctx Key context configured for a DH KDF operation.
 * @param len Desired KDF output length in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int len);""",
    "EVP_PKEY_CTX_set_dh_kdf_outlen",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 void DH_set_default_method(const DH_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_get_default_method(void);""",
    """/**
 * @brief Set the process-wide default DH_METHOD (deprecated).
 * @param meth Method that new DH objects use unless overridden.
 */
OSSL_DEPRECATEDIN_3_0 void DH_set_default_method(const DH_METHOD *meth);
/**
 * @brief Return the process-wide default DH_METHOD (deprecated).
 * @return Pointer to the current default method.
 */
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *DH_get_default_method(void);""",
    "DH_set/get_default_method",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 void DH_free(DH *dh);",
    """/**
 * @brief Free a DH object and decrement its reference count (deprecated).
 * @param dh Object to free; NULL is ignored. The structure is released when the last reference drops.
 */
OSSL_DEPRECATEDIN_3_0 void DH_free(DH *dh);""",
    "DH_free",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_set_ex_data(DH *d, int idx, void *arg);",
    """/**
 * @brief Store application data on a DH object at a CRYPTO_EX index (deprecated).
 * @param d DH object to update.
 * @param idx Index from DH_get_ex_new_index().
 * @param arg Application pointer to store (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_ex_data(DH *d, int idx, void *arg);""",
    "DH_set_ex_data",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_generate_parameters_ex(DH *dh, int prime_len,
    int generator,
    BN_GENCB *cb);""",
    """/**
 * @brief Generate Diffie-Hellman domain parameters into @p dh (deprecated).
 * @param dh Destination DH object that receives p and g.
 * @param prime_len Desired bit length of the prime modulus p.
 * @param generator Generator g (commonly 2 or 5).
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_PKEY_paramgen for new code.
 */
OSSL_DEPRECATEDIN_3_0 int DH_generate_parameters_ex(DH *dh, int prime_len,
    int generator,
    BN_GENCB *cb);""",
    "DH_generate_parameters_ex",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_check_ex(const DH *dh);",
    """/**
 * @brief Validate Diffie-Hellman parameters and report problems via the error queue (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @return 1 if the parameters look suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_ex(const DH *dh);""",
    "DH_check_ex",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_check(const DH *dh, int *codes);",
    """/**
 * @brief Validate Diffie-Hellman parameters and return a bitmask of problems (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @param codes Receives zero or a combination of DH_CHECK_* reason bits.
 * @return 1 if the check routine ran successfully (inspect @p codes), or 0 on hard failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_check(const DH *dh, int *codes);""",
    "DH_check",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DHparams_print(BIO *bp, const DH *x);",
    """/**
 * @brief Print Diffie-Hellman parameters to a BIO in human-readable form (deprecated).
 * @param bp Output BIO.
 * @param x DH object whose parameters are printed.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DHparams_print(BIO *bp, const DH *x);""",
    "DHparams_print",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_get_nid(const DH *dh);",
    """/**
 * @brief Return the named-group NID for a DH object if its parameters match a known group (deprecated).
 * @param dh DH object to query.
 * @return Matching NID such as NID_ffdhe2048, or NID_undef if the parameters are not a named group.
 */
OSSL_DEPRECATEDIN_3_0 int DH_get_nid(const DH *dh);""",
    "DH_get_nid",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 void DH_get0_pqg(const DH *dh, const BIGNUM **p,
    const BIGNUM **q, const BIGNUM **g);""",
    """/**
 * @brief Borrow pointers to the prime, optional subprime, and generator of a DH object (deprecated).
 * @param dh DH object to query.
 * @param p Receives an internal pointer to p, or NULL to skip; do not free.
 * @param q Receives an internal pointer to q when present, or NULL to skip; do not free.
 * @param g Receives an internal pointer to g, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void DH_get0_pqg(const DH *dh, const BIGNUM **p,
    const BIGNUM **q, const BIGNUM **g);""",
    "DH_get0_pqg",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
    const BIGNUM **priv_key);""",
    """/**
 * @brief Borrow pointers to the public and private key BIGNUMs of a DH object (deprecated).
 * @param dh DH object to query.
 * @param pub_key Receives an internal pointer to the public value, or NULL to skip; do not free.
 * @param priv_key Receives an internal pointer to the private value, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
    const BIGNUM **priv_key);""",
    "DH_get0_key",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_p(const DH *dh);",
    """/**
 * @brief Return the prime modulus p stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_p(const DH *dh);""",
    "DH_get0_p",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_g(const DH *dh);",
    """/**
 * @brief Return the generator g stored in a DH object (deprecated).
 * @param dh DH object to query.
 * @return Internal BIGNUM pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_g(const DH *dh);""",
    "DH_get0_g",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 void DH_set_flags(DH *dh, int flags);",
    """/**
 * @brief Set flag bits on a DH object without clearing existing flags (deprecated).
 * @param dh DH object to update.
 * @param flags Bitmask of DH_FLAG_* values to set.
 */
OSSL_DEPRECATEDIN_3_0 void DH_set_flags(DH *dh, int flags);""",
    "DH_set_flags",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_meth_set_flags(DH_METHOD *dhm, int flags);",
    """/**
 * @brief Replace the flag mask stored on a DH_METHOD (deprecated).
 * @param dhm Method object to update.
 * @param flags New flag mask (for example DH_FLAG_CACHE_MONT_P).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_flags(DH_METHOD *dhm, int flags);""",
    "DH_meth_set_flags",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data);",
    """/**
 * @brief Attach opaque application data to a DH_METHOD, transferring ownership of the pointer (deprecated).
 * @param dhm Method object to update.
 * @param app_data Caller-owned pointer stored on the method (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data);""",
    "DH_meth_set0_app_data",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_init(const DH_METHOD *dhm))(DH *);",
    """/**
 * @brief Return the DH object-initialization callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_init(const DH_METHOD *dhm))(DH *);""",
    "DH_meth_get_init",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_params(const DH_METHOD *dhm))(DH *, int, int,
    BN_GENCB *);""",
    """/**
 * @brief Return the parameter-generation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the generate_params callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_params(const DH_METHOD *dhm))(DH *, int, int,
    BN_GENCB *);""",
    "DH_meth_get_generate_params",
)

# ----- dsa.h -----
patch_both(
    "dsa.h",
    "int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);",
    """/**
 * @brief Set the DSA prime modulus length in bits for parameter generation.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param nbits Desired bit length of p (for example 2048).
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);""",
    "EVP_PKEY_CTX_set_dsa_paramgen_bits",
)

patch_both(
    "dsa.h",
    """int EVP_PKEY_CTX_set_dsa_paramgen_md_props(EVP_PKEY_CTX *ctx,
    const char *md_name,
    const char *md_properties);""",
    """/**
 * @brief Select the digest for DSA parameter generation by name and property query.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param md_name Digest algorithm name such as "SHA256".
 * @param md_properties Optional property query string for fetching the digest, or NULL.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_md_props(EVP_PKEY_CTX *ctx,
    const char *md_name,
    const char *md_properties);""",
    "EVP_PKEY_CTX_set_dsa_paramgen_md_props",
)

patch_both(
    "dsa.h",
    "int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX *ctx, const char *name);",
    """/**
 * @brief Set the DSA parameter-generation algorithm type by name.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param name Generator type name understood by the DSA provider (for example "fips186_4").
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_type(EVP_PKEY_CTX *ctx, const char *name);""",
    "EVP_PKEY_CTX_set_dsa_paramgen_type",
)

patch_both(
    "dsa.h",
    """int EVP_PKEY_CTX_set_dsa_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);""",
    """/**
 * @brief Supply the seed used when generating FIPS 186-style DSA parameters.
 * @param ctx EVP_PKEY_CTX configured for DSA parameter generation.
 * @param seed Seed bytes consumed by the parameter generator.
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_seed(EVP_PKEY_CTX *ctx,
    const unsigned char *seed,
    size_t seedlen);""",
    "EVP_PKEY_CTX_set_dsa_paramgen_seed",
)

patch_both(
    "dsa.h",
    "DSA_SIG *DSA_SIG_new(void);",
    """/**
 * @brief Allocate an empty DSA signature structure holding r and s.
 * @return New DSA_SIG, or NULL on allocation failure; free with DSA_SIG_free().
 */
DSA_SIG *DSA_SIG_new(void);""",
    "DSA_SIG_new",
)

patch_both(
    "dsa.h",
    "DECLARE_ASN1_ENCODE_FUNCTIONS_only(DSA_SIG, DSA_SIG)",
    """/**
 * @brief Decode a DSA signature (r, s) from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA_SIG, or NULL on error.
 */
DSA_SIG *d2i_DSA_SIG(DSA_SIG **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA signature (r, s) to DER.
 * @param a Signature to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **out);""",
    "d2i/i2d_DSA_SIG",
)

patch_both(
    "dsa.h",
    "void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);",
    """/**
 * @brief Borrow pointers to the r and s components of a DSA signature.
 * @param sig Signature to query.
 * @param pr Receives an internal pointer to r, or NULL to skip; do not free.
 * @param ps Receives an internal pointer to s, or NULL to skip; do not free.
 */
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);""",
    "DSA_SIG_get0",
)

patch_both(
    "dsa.h",
    "DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, DSA, DSAparams)",
    """/**
 * @brief Deep-copy DSA domain parameters into a new DSA object (deprecated).
 * @param a Source DSA whose p, q, and g are duplicated.
 * @return New DSA with copied parameters, or NULL on error; free with DSA_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSAparams_dup(const DSA *a);""",
    "DSAparams_dup",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_do_verify(const unsigned char *dgst, int dgst_len,
    DSA_SIG *sig, DSA *dsa);""",
    """/**
 * @brief Verify a DSA signature against a digest using a DSA_SIG structure (deprecated).
 * @param dgst Digest bytes that were signed.
 * @param dgst_len Length of @p dgst in bytes.
 * @param sig Signature containing r and s.
 * @param dsa DSA public key (and parameters) used for verification.
 * @return 1 if the signature is valid, 0 if invalid, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_do_verify(const unsigned char *dgst, int dgst_len,
    DSA_SIG *sig, DSA *dsa);""",
    "DSA_do_verify",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_OpenSSL(void);",
    """/**
 * @brief Return the built-in OpenSSL software DSA_METHOD (deprecated).
 * @return Pointer to the default software DSA method implementation.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_OpenSSL(void);""",
    "DSA_OpenSSL",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 void DSA_set_default_method(const DSA_METHOD *);",
    """/**
 * @brief Set the process-wide default DSA_METHOD (deprecated).
 * @param meth Method that new DSA objects use unless overridden.
 */
OSSL_DEPRECATEDIN_3_0 void DSA_set_default_method(const DSA_METHOD *meth);""",
    "DSA_set_default_method",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int DSA_bits(const DSA *d);",
    """/**
 * @brief Return the bit length of the DSA prime modulus p (deprecated).
 * @param d DSA key whose parameters are queried.
 * @return Bit length of p, or -1 if parameters are unavailable.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_bits(const DSA *d);""",
    "DSA_bits",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_verify(const DSA_METHOD *dsam))(const unsigned char *, int, DSA_SIG *, DSA *);",
    """/**
 * @brief Return the signature-verification callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the verify callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_verify(const DSA_METHOD *dsam))(const unsigned char *, int, DSA_SIG *, DSA *);""",
    "DSA_meth_get_verify",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *);""",
    """/**
 * @brief Return the modular-exponentiation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the mod_exp callback used during signing/verification, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_mod_exp(const DSA_METHOD *dsam))(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *);""",
    "DSA_meth_get_mod_exp",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_init(const DSA_METHOD *dsam))(DSA *);",
    """/**
 * @brief Return the DSA object-initialization callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_init(const DSA_METHOD *dsam))(DSA *);""",
    "DSA_meth_get_init",
)

# ----- ec.h -----
patch_both(
    "ec.h",
    """int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);""",
    """/**
 * @brief Set the message digest used for the ECDH X9.63 KDF on a key context.
 * @param ctx Key-exchange context configured for ECDH with a KDF.
 * @param md Digest method such as EVP_sha256(); ownership is not transferred.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * @brief Get the message digest used for the ECDH X9.63 KDF on a key context.
 * @param ctx Key-exchange context configured for ECDH with a KDF.
 * @param md Receives a pointer to the digest method (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);""",
    "EVP_PKEY_CTX_set/get_ecdh_kdf_md",
)

patch_both(
    "ec.h",
    """void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
    point_conversion_form_t form);""",
    """/**
 * @brief Select how EC points in this group are encoded (compressed, uncompressed, or hybrid).
 * @param group Curve group whose default encoding form is updated.
 * @param form One of POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED, or POINT_CONVERSION_HYBRID.
 */
void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
    point_conversion_form_t form);""",
    "EC_GROUP_set_point_conversion_form",
)

patch_both(
    "ec.h",
    """int EC_GROUP_check_named_curve(const EC_GROUP *group, int nist_only,
    BN_CTX *ctx);""",
    """/**
 * @brief Identify whether @p group matches a built-in named curve and return its NID.
 * @param group Curve group to compare against known named curves.
 * @param nist_only When non-zero, only NIST curves are considered.
 * @param ctx Optional BN_CTX for temporary big-number work, or NULL.
 * @return Matching curve NID on success, or 0 / a negative value when no named curve matches or on error.
 */
int EC_GROUP_check_named_curve(const EC_GROUP *group, int nist_only,
    BN_CTX *ctx);""",
    "EC_GROUP_check_named_curve",
)

patch_both(
    "ec.h",
    "EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);",
    """/**
 * @brief Decode EC domain parameters (EcpkParameters) from DER into an EC_GROUP.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded EC_GROUP, or NULL on error.
 */
EC_GROUP *d2i_ECPKParameters(EC_GROUP **a, const unsigned char **in, long len);""",
    "d2i_ECPKParameters",
)

patch_both(
    "ec.h",
    "OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);",
    """/**
 * @brief Set encoding-control flags on an EC_KEY (deprecated).
 * @param eckey Key whose encoding behaviour is updated.
 * @param flags Bitmask such as EC_PKEY_NO_PARAMETERS or EC_PKEY_NO_PUBKEY affecting private-key encoding.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);""",
    "EC_KEY_set_enc_flags",
)

# ----- engine.h -----
patch_both(
    "engine.h",
    """typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **,
    const int **, int);""",
    """/**
 * @brief ENGINE public-key method handler: list supported NIDs or return an EVP_PKEY_METHOD.
 * @param e ENGINE being queried (first parameter of the callback).
 * @param pmeth When non-NULL, receives the EVP_PKEY_METHOD for the requested NID.
 * @param nids When @p pmeth is NULL, receives the array of supported NIDs.
 * @param nid NID to look up when @p pmeth is non-NULL.
 * @return Number of NIDs when listing, 1 when a method is returned, or 0 on failure.
 */
typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **,
    const int **, int);""",
    "ENGINE_PKEY_METHS_PTR",
)

patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_ciphers(ENGINE *e);",
    """/**
 * @brief Unregister all cipher implementations previously registered from @p e (deprecated).
 * @param e ENGINE whose cipher methods are removed from the global cipher table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_ciphers(ENGINE *e);""",
    "ENGINE_unregister_ciphers",
)

patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_asn1_meths(ENGINE *e);",
    """/**
 * @brief Register the ASN.1 public-key methods provided by @p e (deprecated).
 * @param e ENGINE that implements one or more EVP_PKEY_ASN1_METHOD handlers.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_asn1_meths(ENGINE *e);""",
    "ENGINE_register_pkey_asn1_meths",
)

patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 int ENGINE_set_EC(ENGINE *e, const EC_KEY_METHOD *ecdsa_meth);",
    """/**
 * @brief Attach an EC_KEY_METHOD implementation to an ENGINE (deprecated).
 * @param e ENGINE that will expose the method.
 * @param ecdsa_meth EC key method table for ECDSA/ECDH operations, or NULL to clear.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_EC(ENGINE *e, const EC_KEY_METHOD *ecdsa_meth);""",
    "ENGINE_set_EC",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  missing:", m)
