#!/usr/bin/env python3
"""Documentation repair batch 12b: ec.h + evp.h."""
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


print("=== batch 12b: ec.h + evp.h ===")

# ----- ec.h (EVP_PKEY_CTX EC helpers live in this header) -----

patch_both(
    "ec.h",
    """int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
""",
    """/**
 * @brief Set the named curve NID used when generating EC parameters or keys.
 * @param ctx EVP_PKEY context for EC parameter or key generation.
 * @param nid Curve NID such as NID_X9_62_prime256v1.
 * @return 1 on success, or a negative value on failure.
 */
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
""",
    "EVP_PKEY_CTX_set_ec_paramgen_curve_nid",
)

patch_both(
    "ec.h",
    """int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);

int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm,
    int len);
#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
#endif
""",
    """/**
 * @brief Get the ECDH key-derivation output length from a key-exchange context.
 * @param ctx EVP_PKEY context configured for ECDH with a KDF.
 * @param len Receives the derived-key length in bytes.
 * @return 1 on success, or a negative value on failure.
 */
int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *len);

/**
 * @brief Set the ECDH KDF user keying material, transferring ownership of @p ukm.
 * @param ctx Key-exchange context configured for ECDH with a KDF.
 * @param ukm Buffer of UKM bytes; ownership transfers to @p ctx (freed with the context).
 * @param len Length of @p ukm in bytes.
 * @return 1 on success, or a negative value on failure.
 */
int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm,
    int len);
#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
/**
 * @brief Get a pointer to the ECDH KDF user keying material on a key context (deprecated).
 * @param ctx Key-exchange context configured for ECDH with a KDF.
 * @param ukm Receives a pointer to the internal UKM bytes (do not free).
 * @return Length of the UKM in bytes, or a negative value on failure.
 */
int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
#endif
""",
    "EVP_PKEY_CTX_get/set0_ecdh_kdf_ukm+outlen",
)

patch_both(
    "ec.h",
    """size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
""",
    """/**
 * @brief Return the length of the optional seed associated with an EC_GROUP.
 * @param group Group to query.
 * @return Seed length in bytes, or 0 if no seed is set.
 */
size_t EC_GROUP_get_seed_len(const EC_GROUP *group);
/**
 * @brief Set the optional seed bytes associated with an EC_GROUP.
 * @param group Group whose seed is updated.
 * @param seed Seed octets to copy, or NULL to clear when @p len is 0.
 * @param len Number of bytes at @p seed.
 * @return The seed length stored on success, or 0 on failure.
 */
size_t EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *seed, size_t len);
""",
    "EC_GROUP_get/set_seed",
)

patch_both(
    "ec.h",
    """char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
    point_conversion_form_t form, BN_CTX *);
""",
    """/**
 * @brief Encode an EC point as a newly allocated hexadecimal octet string.
 * @param group Curve that defines the point encoding.
 * @param point Point to encode.
 * @param form Conversion form such as POINT_CONVERSION_UNCOMPRESSED.
 * @param ctx BN_CTX for temporary values, or NULL to allocate internally.
 * @return NUL-terminated hex string (caller must OPENSSL_free), or NULL on error.
 */
char *EC_POINT_point2hex(const EC_GROUP *group, const EC_POINT *point,
    point_conversion_form_t form, BN_CTX *ctx);
""",
    "EC_POINT_point2hex",
)

patch_both(
    "ec.h",
    """int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
    unsigned int *k2, unsigned int *k3);
""",
    """/**
 * @brief Return the pentanomial basis degrees k1, k2, k3 for a characteristic-2 curve group.
 * @param group EC_GROUP defined over GF(2^m) with a pentanomial field polynomial.
 * @param k1 Receives the lowest middle-term degree of x^m + x^k3 + x^k2 + x^k1 + 1.
 * @param k2 Receives the middle middle-term degree.
 * @param k3 Receives the highest middle-term degree.
 * @return 1 on success, or 0 if @p group does not use a pentanomial basis.
 */
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *group, unsigned int *k1,
    unsigned int *k2, unsigned int *k3);
""",
    "EC_GROUP_get_pentanomial_basis",
)

patch_both(
    "ec.h",
    """int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
""",
    """/**
 * @brief Encode EC domain parameters (EcpkParameters) from an EC_GROUP to DER.
 * @param group Group whose parameters are encoded.
 * @param out Destination pointer for DER output (advanced on success), or NULL to measure length.
 * @return Number of bytes written (or that would be written), or a negative value on error.
 */
int i2d_ECPKParameters(const EC_GROUP *group, unsigned char **out);
""",
    "i2d_ECPKParameters",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 int EC_KEY_get_flags(const EC_KEY *key);

/**
 * @brief Set the given flag bits on an EC_KEY (deprecated; OR'd with existing flags).
 * @param key Elliptic-curve key object to update.
 * @param flags Flag mask such as EC_FLAG_COFACTOR_ECDH or EC_FLAG_CHECK_NAMED_GROUP.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_flags(EC_KEY *key, int flags);

OSSL_DEPRECATEDIN_3_0 void EC_KEY_clear_flags(EC_KEY *key, int flags);
""",
    """/**
 * @brief Return the flag bits currently set on an EC_KEY (deprecated).
 * @param key Elliptic-curve key object to query.
 * @return Bitmask of EC_FLAG_* values, or 0 if none are set.
 */
OSSL_DEPRECATEDIN_3_0 int EC_KEY_get_flags(const EC_KEY *key);

/**
 * @brief Set the given flag bits on an EC_KEY (deprecated; OR'd with existing flags).
 * @param key Elliptic-curve key object to update.
 * @param flags Flag mask such as EC_FLAG_COFACTOR_ECDH or EC_FLAG_CHECK_NAMED_GROUP.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_flags(EC_KEY *key, int flags);

/**
 * @brief Clear the given flag bits on an EC_KEY (deprecated).
 * @param key Elliptic-curve key object to update.
 * @param flags Flag mask of bits to clear (for example EC_FLAG_COFACTOR_ECDH).
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_clear_flags(EC_KEY *key, int flags);
""",
    "EC_KEY_get/clear_flags",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
""",
    """/**
 * @brief Return encoding-control flags from an EC_KEY (deprecated).
 * @param key Elliptic-curve key whose encoding behaviour is queried.
 * @return Bitmask such as EC_PKEY_NO_PARAMETERS or EC_PKEY_NO_PUBKEY.
 */
OSSL_DEPRECATEDIN_3_0 unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
""",
    "EC_KEY_get_enc_flags",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
    int (*keygen)(EC_KEY *key));
""",
    """/**
 * @brief Set the key-generation callback on an EC_KEY_METHOD (deprecated).
 * @param meth Method table to update.
 * @param keygen Callback that generates a key into @p key, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
    int (*keygen)(EC_KEY *key));
""",
    "EC_KEY_METHOD_set_keygen",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth, int (**pkeygen)(EC_KEY *key));

OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth,
    int (**pck)(unsigned char **psec,
        size_t *pseclen,
        const EC_POINT *pub_key,
        const EC_KEY *ecdh));

OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth,
    int (**psign)(int type, const unsigned char *dgst,
        int dlen, unsigned char *sig,
        unsigned int *siglen,
        const BIGNUM *kinv, const BIGNUM *r,
        EC_KEY *eckey),
    int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
        BIGNUM **kinvp, BIGNUM **rp),
    ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
        int dgst_len,
        const BIGNUM *in_kinv,
        const BIGNUM *in_r,
        EC_KEY *eckey));

OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_verify(const EC_KEY_METHOD *meth,
    int (**pverify)(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf,
        int sig_len, EC_KEY *eckey),
    int (**pverify_sig)(const unsigned char *dgst,
        int dgst_len,
        const ECDSA_SIG *sig,
        EC_KEY *eckey));
""",
    """/**
 * @brief Retrieve the key-generation callback from an EC_KEY_METHOD (deprecated).
 * @param meth Method table to query.
 * @param pkeygen Receives the keygen callback pointer, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth, int (**pkeygen)(EC_KEY *key));

/**
 * @brief Retrieve the ECDH shared-secret callback from an EC_KEY_METHOD (deprecated).
 * @param meth Method table to query.
 * @param pck Receives the compute_key callback pointer, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth,
    int (**pck)(unsigned char **psec,
        size_t *pseclen,
        const EC_POINT *pub_key,
        const EC_KEY *ecdh));

/**
 * @brief Retrieve ECDSA signing callbacks from an EC_KEY_METHOD (deprecated).
 * @param meth Method table to query.
 * @param psign Receives the ECDSA_sign-style callback, or NULL to skip.
 * @param psign_setup Receives the optional sign_setup callback, or NULL to skip.
 * @param psign_sig Receives the callback that returns an ECDSA_SIG, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth,
    int (**psign)(int type, const unsigned char *dgst,
        int dlen, unsigned char *sig,
        unsigned int *siglen,
        const BIGNUM *kinv, const BIGNUM *r,
        EC_KEY *eckey),
    int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
        BIGNUM **kinvp, BIGNUM **rp),
    ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
        int dgst_len,
        const BIGNUM *in_kinv,
        const BIGNUM *in_r,
        EC_KEY *eckey));

/**
 * @brief Retrieve ECDSA verify callbacks from an EC_KEY_METHOD (deprecated).
 * @param meth Method table to query.
 * @param pverify Receives the buffer-based verify callback, or NULL to skip.
 * @param pverify_sig Receives the ECDSA_SIG-based verify callback, or NULL to skip.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_get_verify(const EC_KEY_METHOD *meth,
    int (**pverify)(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf,
        int sig_len, EC_KEY *eckey),
    int (**pverify_sig)(const unsigned char *dgst,
        int dgst_len,
        const ECDSA_SIG *sig,
        EC_KEY *eckey));
""",
    "EC_KEY_METHOD_get_keygen/compute_key/sign/verify",
)

# ----- evp.h -----

patch_both(
    "evp.h",
    """const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md);
""",
    """/**
 * @brief Return the provider that implements a message-digest algorithm.
 * @param md Digest method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL on error.
 */
const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md);
""",
    "EVP_MD_get0_provider",
)

patch_both(
    "evp.h",
    """__owur int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
""",
    """/**
 * @brief Copy digest context state from @p in into an already allocated @p out.
 * @param out Destination context (must be initialised); previous state is replaced.
 * @param in Source context to copy, including algorithm state and associated key material.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
""",
    "EVP_MD_CTX_copy_ex",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_idea_cfb64(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for IDEA in 64-bit CFB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_idea_cfb64(void);
""",
    "EVP_idea_cfb64",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_256_ecb(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for AES-256 in ECB mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_256_ecb(void);
""",
    "EVP_aes_256_ecb",
)

patch_both(
    "evp.h",
    """const EVP_CIPHER *EVP_camellia_256_cfb8(void);
""",
    """/**
 * @brief Return the Camellia-256 cipher in 8-bit CFB mode.
 * @return EVP_CIPHER for camellia-256-cfb8, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
""",
    "EVP_camellia_256_cfb8",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_get_size(const EVP_PKEY *pkey);
""",
    """/**
 * @brief Return the maximum signature or related output size for a key in bytes.
 * @param pkey Key to query (for example RSA or EC).
 * @return Maximum size in bytes suitable for allocating signature buffers, or 0 on error.
 */
int EVP_PKEY_get_size(const EVP_PKEY *pkey);
""",
    "EVP_PKEY_get_size",
)

patch_both(
    "evp.h",
    """int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);
""",
    """/**
 * @brief Return the PBE algorithm type and NID at index @p num in the registry.
 * @param ptype Optional destination for the PBE type (EVP_PBE_TYPE_*), or NULL.
 * @param ppbe_nid Optional destination for the PBE algorithm NID, or NULL.
 * @param num Zero-based index into the registered PBE table.
 * @return 1 if @p num is valid, or 0 if out of range.
 */
int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);
""",
    "EVP_PBE_get",
)

patch_both(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype,
    const char *propq,
    const unsigned char *priv, size_t len);
""",
    """/**
 * @brief Create an EVP_PKEY from raw private-key octets using a named algorithm and library context.
 * @param libctx Library context used to fetch the key type, or NULL for the default.
 * @param keytype Algorithm name such as "ED25519" or "X25519".
 * @param propq Property query string, or NULL.
 * @param priv Raw private-key bytes in the algorithm-native format.
 * @param len Length of @p priv in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free.
 */
EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype,
    const char *propq,
    const unsigned char *priv, size_t len);
""",
    "EVP_PKEY_new_raw_private_key_ex",
)

patch_both(
    "evp.h",
    """void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Return the opaque application pointer previously stored on a key context.
 * @param ctx Key context to query.
 * @return Pointer set with EVP_PKEY_CTX_set_app_data(), or NULL if unset.
 */
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_CTX_get_app_data",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Initialise a key context for KEM decapsulation.
 * @param ctx Key context holding the recipient private key.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_PKEY_decapsulate_init",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Initialise a key context for key-pair generation.
 * @param ctx Context created for the target algorithm (for example via EVP_PKEY_CTX_new_id).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_keygen_init",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Validate the key associated with a key context (public/private consistency checks).
 * @param ctx Context whose key is checked (from EVP_PKEY_CTX_new or similar).
 * @return 1 if the key is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_check",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Validate that the public and private components of a key form a consistent pair.
 * @param ctx Context holding the key to check (typically created with EVP_PKEY_CTX_new).
 * @return 1 if the key pair is consistent, 0 if not, or a negative value on error.
 */
int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_pairwise_check",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth, int (*copy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));
""",
    """/**
 * @brief Set the context-copy callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param copy Callback that copies operation state from @p src into @p dst, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth, int (*copy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));
""",
    "EVP_PKEY_meth_set_copy",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, int (*paramgen_init)(EVP_PKEY_CTX *ctx),
    int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
""",
    """/**
 * @brief Set parameter-generation callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param paramgen_init Optional initialiser called from EVP_PKEY_paramgen_init(), or NULL.
 * @param paramgen Callback that writes parameters into @p pkey, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, int (*paramgen_init)(EVP_PKEY_CTX *ctx),
    int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
""",
    "EVP_PKEY_meth_set_paramgen",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth, int (*decrypt_init)(EVP_PKEY_CTX *ctx),
    int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
""",
    """/**
 * @brief Set public-key decryption callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param decrypt_init Optional initialiser called from EVP_PKEY_decrypt_init(), or NULL.
 * @param decrypt Callback that decrypts @p in into @p out / *@p outlen, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth, int (*decrypt_init)(EVP_PKEY_CTX *ctx),
    int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
""",
    "EVP_PKEY_meth_set_decrypt",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth, int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value));
""",
    """/**
 * @brief Set the ctrl / ctrl_str callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param ctrl Integer control callback (EVP_PKEY_CTX_ctrl), or NULL.
 * @param ctrl_str String control callback (EVP_PKEY_CTX_ctrl_str), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth, int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value));
""",
    "EVP_PKEY_meth_set_ctrl",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD *pmeth,
    int (*digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
""",
    """/**
 * @brief Set the one-shot DigestSign callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digestsign Callback implementing EVP_DigestSign()-style signing, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD *pmeth,
    int (*digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));
""",
    "EVP_PKEY_meth_set_digestsign",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth, void (**pcleanup)(EVP_PKEY_CTX *ctx));
""",
    """/**
 * @brief Retrieve the context-cleanup callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pcleanup Receives the cleanup callback pointer (may be set to NULL if unset).
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth, void (**pcleanup)(EVP_PKEY_CTX *ctx));
""",
    "EVP_PKEY_meth_get_cleanup",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth, int (**pkeygen_init)(EVP_PKEY_CTX *ctx),
    int (**pkeygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
""",
    """/**
 * @brief Retrieve key-generation callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pkeygen_init Receives the keygen_init callback pointer, or NULL.
 * @param pkeygen Receives the keygen callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth, int (**pkeygen_init)(EVP_PKEY_CTX *ctx),
    int (**pkeygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
""",
    "EVP_PKEY_meth_get_keygen",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth, int (**pencrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pencryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
""",
    """/**
 * @brief Retrieve public-key encryption callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pencrypt_init Optional destination for the encrypt_init function pointer, or NULL.
 * @param pencryptfn Optional destination for the encrypt function pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth, int (**pencrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pencryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
""",
    "EVP_PKEY_meth_get_encrypt",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestverify(const EVP_PKEY_METHOD *pmeth,
    int (**digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));
""",
    """/**
 * @brief Retrieve the one-shot digestverify callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param digestverify Receives the digestverify callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestverify(const EVP_PKEY_METHOD *pmeth,
    int (**digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));
""",
    "EVP_PKEY_meth_get_digestverify",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));
""",
    """/**
 * @brief Retrieve the public-key check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the public_check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));
""",
    "EVP_PKEY_meth_get_public_check",
)

patch_both(
    "evp.h",
    """void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange);
""",
    """/**
 * @brief Free a fetched key-exchange algorithm object.
 * @param exchange Object from EVP_KEYEXCH_fetch(); may be NULL.
 */
void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange);
""",
    "EVP_KEYEXCH_free",
)

patch_both(
    "evp.h",
    """void EVP_KEYEXCH_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYEXCH *keyexch, void *data),
    void *data);
""",
    """/**
 * @brief Invoke a callback for every key-exchange algorithm available from providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each EVP_KEYEXCH and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 */
void EVP_KEYEXCH_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYEXCH *keyexch, void *data),
    void *data);
""",
    "EVP_KEYEXCH_do_all_provided",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_get_group_name(const EVP_PKEY *pkey, char *name, size_t name_sz,
    size_t *gname_len);
""",
    """/**
 * @brief Copy the elliptic-curve or DH group name from a key into a caller buffer.
 * @param pkey Key whose group / curve name is queried.
 * @param name Optional destination buffer for the NUL-terminated name, or NULL to query length only.
 * @param name_sz Size of @p name in bytes.
 * @param gname_len Optional destination for the name length excluding NUL, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_group_name(const EVP_PKEY *pkey, char *name, size_t name_sz,
    size_t *gname_len);
""",
    "EVP_PKEY_get_group_name",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(" ", m)
    raise SystemExit(1)
