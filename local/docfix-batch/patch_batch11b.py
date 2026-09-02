#!/usr/bin/env python3
"""Documentation repair batch 11b: evp.h part 1."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


def patch(rel, old, new, label):
    path = INC / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(label)
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {label}")
    ok.append(label)


print("=== batch 11b: evp.h (part 1) ===")

# --- EVP_CIPHER_meth_get_get_asn1_params ---
patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
    ASN1_TYPE *);
""",
    """/**
 * @brief Return the get_asn1_params callback previously set on a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Function that reads AlgorithmIdentifier parameters from an ASN1_TYPE into @c EVP_CIPHER_CTX, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
    ASN1_TYPE *);
""",
    "EVP_CIPHER_meth_get_get_asn1_params",
)

# --- EVP_Q_mac ---
patch(
    "evp.h",
    """unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
    const char *subalg, const OSSL_PARAM *params,
    const void *key, size_t keylen,
    const unsigned char *data, size_t datalen,
    unsigned char *out, size_t outsize, size_t *outlen);
""",
    """/**
 * @brief One-shot MAC computation: fetch the algorithm, process @p data, and write the tag.
 * @param libctx Library context used to fetch the MAC, or NULL for the default.
 * @param name MAC algorithm name (for example "HMAC" or "CMAC").
 * @param propq Property query for the MAC fetch, or NULL.
 * @param subalg Optional sub-algorithm name (for example the HMAC digest), or NULL.
 * @param params Optional OSSL_PARAM array for algorithm setup, or NULL.
 * @param key MAC key octets.
 * @param keylen Length of @p key in bytes.
 * @param data Message bytes to authenticate.
 * @param datalen Length of @p data in bytes.
 * @param out Buffer that receives the MAC, or NULL to query the required size via @p outlen.
 * @param outsize Size of @p out in bytes when @p out is non-NULL.
 * @param outlen On success, receives the number of MAC bytes written (or required if @p out is NULL).
 * @return Pointer to @p out on success, or NULL on failure.
 */
unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
    const char *subalg, const OSSL_PARAM *params,
    const void *key, size_t keylen,
    const unsigned char *data, size_t datalen,
    unsigned char *out, size_t outsize, size_t *outlen);
""",
    "EVP_Q_mac",
)

# --- EVP_MAC_CTX_settable_params ---
patch(
    "evp.h",
    """const OSSL_PARAM *EVP_MAC_CTX_settable_params(EVP_MAC_CTX *ctx);

/**
 * @brief Invoke a callback for every MAC implementation available from activated providers.
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors settable on a live MAC context.
 * @param ctx MAC context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_CTX_settable_params(EVP_MAC_CTX *ctx);

/**
 * @brief Invoke a callback for every MAC implementation available from activated providers.
""",
    "EVP_MAC_CTX_settable_params",
)

# --- EVP_MAC_names_do_all ---
patch(
    "evp.h",
    """int EVP_MAC_names_do_all(const EVP_MAC *mac,
    void (*fn)(const char *name, void *data),
    void *data);

/* RAND stuff */
""",
    """/**
 * @brief Invoke a callback for every name (including aliases) associated with a MAC implementation.
 * @param mac MAC algorithm whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_names_do_all(const EVP_MAC *mac,
    void (*fn)(const char *name, void *data),
    void *data);

/* RAND stuff */
""",
    "EVP_MAC_names_do_all",
)

# --- EVP_RAND_up_ref ---
patch(
    "evp.h",
    """int EVP_RAND_up_ref(EVP_RAND *rand);
/**
 * @brief Release a reference to an EVP_RAND obtained from EVP_RAND_fetch.
""",
    """/**
 * @brief Increment the reference count on a fetched EVP_RAND.
 * @param rand RAND method whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_up_ref(EVP_RAND *rand);
/**
 * @brief Release a reference to an EVP_RAND obtained from EVP_RAND_fetch.
""",
    "EVP_RAND_up_ref",
)

# --- EVP_RAND_CTX_up_ref / free / set_params ---
patch(
    "evp.h",
    """int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx);
void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx);
EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Increment the reference count on an EVP_RAND_CTX.
 * @param ctx RAND context whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx);
/**
 * @brief Free an EVP_RAND_CTX and release associated resources.
 * @param ctx RAND context to free, or NULL.
 */
void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx);
EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
/**
 * @brief Set parameters on a RAND context via an OSSL_PARAM array.
 * @param ctx RAND context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_RAND_CTX_up_ref+free+set_params",
)

# --- EVP_RAND_settable_ctx_params / EVP_RAND_CTX_gettable_params ---
patch(
    "evp.h",
    """const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand);
const OSSL_PARAM *EVP_RAND_CTX_gettable_params(EVP_RAND_CTX *ctx);
/**
 * @brief Return the parameters that may be set on a RAND context.
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on a RAND context.
 * @param rand RAND method whose settable context parameters are listed.
 * @return Constant OSSL_PARAM array for use with EVP_RAND_CTX_set_params(), or NULL if none.
 */
const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a live RAND context.
 * @param ctx RAND context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_RAND_CTX_gettable_params(EVP_RAND_CTX *ctx);
/**
 * @brief Return the parameters that may be set on a RAND context.
""",
    "EVP_RAND_settable_ctx_params+CTX_gettable_params",
)

# --- EVP_PKEY_decrypt_old ---
patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_decrypt_old(unsigned char *dec_key,
    const unsigned char *enc_key,
    int enc_key_len,
    EVP_PKEY *private_key);
""",
    """/**
 * @brief Decrypt a session key with a private key using the legacy EVP_PKEY path (deprecated).
 * @param dec_key Output buffer for the recovered plaintext key material.
 * @param enc_key Encrypted key bytes.
 * @param enc_key_len Length of @p enc_key in bytes.
 * @param private_key Private key used for decryption.
 * @return Length of decrypted key on success, or a negative value on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_decrypt_old(unsigned char *dec_key,
    const unsigned char *enc_key,
    int enc_key_len,
    EVP_PKEY *private_key);
""",
    "EVP_PKEY_decrypt_old",
)

# --- EVP_PKEY_type ---
patch(
    "evp.h",
    """int EVP_PKEY_type(int type);
/**
 * @brief Return the numeric type identifier of a public-key object.
""",
    """/**
 * @brief Map a public-key type NID to its base algorithm type NID.
 * @param type Key type NID (possibly an alias such as EVP_PKEY_RSA2).
 * @return Base type NID (for example EVP_PKEY_RSA), or NID_undef if unknown.
 */
int EVP_PKEY_type(int type);
/**
 * @brief Return the numeric type identifier of a public-key object.
""",
    "EVP_PKEY_type",
)

# --- EVP_PKEY_get_bits ---
patch(
    "evp.h",
    """int EVP_PKEY_get_bits(const EVP_PKEY *pkey);
#define EVP_PKEY_bits EVP_PKEY_get_bits
/**
 * @brief Return the estimated security strength of a key in bits.
""",
    """/**
 * @brief Return the cryptographic size of a key in bits (for example RSA modulus length).
 * @param pkey Key to query.
 * @return Key size in bits, or 0 if unavailable.
 */
int EVP_PKEY_get_bits(const EVP_PKEY *pkey);
#define EVP_PKEY_bits EVP_PKEY_get_bits
/**
 * @brief Return the estimated security strength of a key in bits.
""",
    "EVP_PKEY_get_bits",
)

# --- EVP_PKEY_can_sign ---
patch(
    "evp.h",
    """int EVP_PKEY_can_sign(const EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
""",
    """/**
 * @brief Test whether a key type supports signing operations.
 * @param pkey Key to query.
 * @return 1 if the key can be used for signing, or 0 otherwise.
 */
int EVP_PKEY_can_sign(const EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
""",
    "EVP_PKEY_can_sign",
)

# --- EVP_PKEY_get0 ---
patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);
""",
    """/**
 * @brief Return the legacy low-level key pointer stored in an EVP_PKEY (deprecated).
 * @param pkey Key wrapper to query.
 * @return Internal type-specific key pointer (for example RSA *), or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
/**
 * @brief Return a pointer to the HMAC key material inside an EVP_PKEY (deprecated).
 * @param pkey Key of type EVP_PKEY_HMAC.
 * @param len Receives the key length in bytes.
 * @return Pointer to the internal key bytes (do not free), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);
""",
    "EVP_PKEY_get0+get0_hmac",
)

# --- EVP_PKEY_get1_DH ---
patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
#endif

#ifndef OPENSSL_NO_EC
struct ec_key_st;
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
""",
    """/**
 * @brief Return a new reference to the DH key held by @p pkey (deprecated).
 * @param pkey Key that must hold a DH key.
 * @return DH with an incremented reference count, or NULL if not a DH key; free with DH_free().
 */
OSSL_DEPRECATEDIN_3_0 struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
#endif

#ifndef OPENSSL_NO_EC
struct ec_key_st;
/**
 * @brief Assign an EC_KEY to an EVP_PKEY, incrementing the EC_KEY reference count (deprecated).
 * @param pkey Destination key wrapper.
 * @param key EC_KEY to associate; its reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
""",
    "EVP_PKEY_get1_DH+set1_EC_KEY",
)

# --- d2i_PublicKey ---
patch(
    "evp.h",
    """EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Encode the public key from an EVP_PKEY to DER in the algorithm-native public-key format.
""",
    """/**
 * @brief Decode a public key of the given type from DER into an EVP_PKEY.
 * @param type Expected key type NID (for example EVP_PKEY_RSA).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
/**
 * @brief Encode the public key from an EVP_PKEY to DER in the algorithm-native public-key format.
""",
    "d2i_PublicKey",
)

# --- i2d_PrivateKey / i2d_KeyParams ---
patch(
    "evp.h",
    """int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);

int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp);
/**
 * @brief Decode algorithm parameters of the given key type from DER into an EVP_PKEY.
""",
    """/**
 * @brief Encode the private key from an EVP_PKEY to DER in the algorithm-native private-key format.
 * @param a Key whose private component is encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);

/**
 * @brief Encode algorithm parameters from an EVP_PKEY to DER.
 * @param a Key whose parameters are encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp);
/**
 * @brief Decode algorithm parameters of the given key type from DER into an EVP_PKEY.
""",
    "i2d_PrivateKey+i2d_KeyParams",
)

# --- i2d_KeyParams_bio ---
patch(
    "evp.h",
    """int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey);
/**
 * @brief Decode algorithm parameters from a BIO into an EVP_PKEY of the given type.
""",
    """/**
 * @brief Encode algorithm parameters from an EVP_PKEY to a BIO in DER form.
 * @param bp Output BIO that receives the encoded parameters.
 * @param pkey Key whose parameters are written.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey);
/**
 * @brief Decode algorithm parameters from a BIO into an EVP_PKEY of the given type.
""",
    "i2d_KeyParams_bio",
)

# --- EVP_PKEY_missing_parameters ---
patch(
    "evp.h",
    """int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
/**
 * @brief Control whether algorithm parameters are written when serializing @p pkey.
""",
    """/**
 * @brief Test whether an EVP_PKEY lacks required algorithm parameters.
 * @param pkey Key to inspect.
 * @return Non-zero if parameters are missing, or 0 if parameters are present (or not required).
 */
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
/**
 * @brief Control whether algorithm parameters are written when serializing @p pkey.
""",
    "EVP_PKEY_missing_parameters",
)

# --- EVP_PKEY_print_public ---
patch(
    "evp.h",
    """int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print a key's domain parameters to a BIO in human-readable form.
""",
    """/**
 * @brief Print the public components of @p pkey to a BIO in human-readable form.
 * @param out Output BIO.
 * @param pkey Key whose public material is printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print a key's domain parameters to a BIO in human-readable form.
""",
    "EVP_PKEY_print_public",
)

# --- EVP_PKEY_print_private_fp ---
patch(
    "evp.h",
    """int EVP_PKEY_print_private_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print the algorithm parameters of @p pkey to a FILE in human-readable form.
""",
    """/**
 * @brief Print the private components of @p pkey to a FILE in human-readable form.
 * @param fp Output stream.
 * @param pkey Key whose private material is printed.
 * @param indent Indentation depth for the printed text.
 * @param pctx Optional ASN.1 print options, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_private_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
/**
 * @brief Print the algorithm parameters of @p pkey to a FILE in human-readable form.
""",
    "EVP_PKEY_print_private_fp",
)

# --- EVP_PKEY_set1_encoded_public_key ---
patch(
    "evp.h",
    """int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey,
    const unsigned char *pub, size_t publen);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use EVP_PKEY_get1_encoded_public_key in
 * preference
 */
""",
    """/**
 * @brief Set the public key on @p pkey from an encoded public-key octet string.
 * @param pkey Key object that receives the public key (type must already be set).
 * @param pub Encoded public-key bytes (format is algorithm-specific, for example a TLS point).
 * @param publen Length of @p pub in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey,
    const unsigned char *pub, size_t publen);

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use EVP_PKEY_get1_encoded_public_key in
 * preference
 */
""",
    "EVP_PKEY_set1_encoded_public_key",
)

# --- EVP_PKEY_get1_encoded_public_key ---
patch(
    "evp.h",
    """size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);

/* calls methods */
""",
    """/**
 * @brief Allocate and return the encoded public-key octet string for @p pkey.
 * @param pkey Key whose public key is exported.
 * @param ppub On success, set to a newly allocated buffer holding the encoded public key; free with OPENSSL_free().
 * @return Length of the encoded public key in bytes, or 0 on failure.
 */
size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);

/* calls methods */
""",
    "EVP_PKEY_get1_encoded_public_key",
)

# --- EVP_CIPHER_asn1_to_param ---
patch(
    "evp.h",
    """int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* These are used by EVP_CIPHER methods */
""",
    """/**
 * @brief Decode cipher AlgorithmIdentifier parameters from @p type into cipher context @p c.
 * @param c Cipher context that receives parameters (typically including the IV).
 * @param type ASN.1 type holding the AlgorithmIdentifier parameters.
 * @return 1 on success, or 0/-1 on failure (for example if the cipher lacks ASN.1 support).
 */
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* These are used by EVP_CIPHER methods */
""",
    "EVP_CIPHER_asn1_to_param",
)

# --- EVP_CIPHER_get_asn1_iv ---
patch(
    "evp.h",
    """int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* PKCS5 password based encryption */
""",
    """/**
 * @brief Decode an IV from an ASN.1 OCTET STRING in @p type into cipher context @p c.
 * @param c Cipher context whose IV is updated.
 * @param type ASN1_TYPE expected to hold an OCTET STRING encoding of the IV.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* PKCS5 password based encryption */
""",
    "EVP_CIPHER_get_asn1_iv",
)

# --- PKCS5_PBE_keyivgen_ex / PKCS5_PBKDF2_HMAC_SHA1 ---
patch(
    "evp.h",
    """int PKCS5_PBE_keyivgen_ex(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx,
    const char *propq);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    int keylen, unsigned char *out);
""",
    """/**
 * @brief Derive a key and IV for password-based encryption and initialize @p cctx (library-context variant).
 * @param cctx Cipher context to initialize with the derived key and IV.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param param ASN.1 PBE parameters (salt, iteration count, and related fields).
 * @param cipher Cipher algorithm used for PBE.
 * @param md Digest used by the PBE key derivation.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for provider-aware derivation, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBE_keyivgen_ex(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Derive a key from a password with PBKDF2-HMAC-SHA1 (RFC 2898).
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes, or -1 to use strlen(@p pass).
 * @param salt Salt bytes, or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @param iter Iteration count (should be large; typically at least 1000).
 * @param keylen Desired derived key length in bytes.
 * @param out Buffer of at least @p keylen bytes that receives the derived key.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    int keylen, unsigned char *out);
""",
    "PKCS5_PBE_keyivgen_ex+PBKDF2_HMAC_SHA1",
)

# --- EVP_PBE_scrypt_ex ---
patch(
    "evp.h",
    """int EVP_PBE_scrypt_ex(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Initialize @p ctx for PBE using scrypt parameters from ASN.1 (PKCS#5 v2).
""",
    """/**
 * @brief Derive a key from a password using scrypt with an explicit library context.
 * @param pass Password bytes, or NULL.
 * @param passlen Length of @p pass in bytes.
 * @param salt Salt bytes, or NULL when @p saltlen is 0.
 * @param saltlen Length of @p salt in bytes.
 * @param N CPU/memory cost parameter (must be a power of two greater than 1).
 * @param r Block size parameter.
 * @param p Parallelization parameter.
 * @param maxmem Maximum memory in bytes the derivation may use, or 0 for the default limit.
 * @param key Buffer that receives the derived key.
 * @param keylen Desired derived key length in bytes.
 * @param ctx Library context for provider selection, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_scrypt_ex(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Initialize @p ctx for PBE using scrypt parameters from ASN.1 (PKCS#5 v2).
""",
    "EVP_PBE_scrypt_ex",
)

# --- EVP_PBE_alg_add ---
patch(
    "evp.h",
    """int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
    EVP_PBE_KEYGEN *keygen);
/**
 * @brief Look up a registered password-based encryption (PBE) algorithm by NID.
""",
    """/**
 * @brief Register a password-based encryption algorithm by NID with cipher, digest, and keygen.
 * @param nid NID of the PBE algorithm OID being registered.
 * @param cipher Cipher used by the algorithm, or NULL if none.
 * @param md Digest used by the algorithm, or NULL if none.
 * @param keygen Key/IV derivation callback invoked for this PBE algorithm.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
    EVP_PBE_KEYGEN *keygen);
/**
 * @brief Look up a registered password-based encryption (PBE) algorithm by NID.
""",
    "EVP_PBE_alg_add",
)

# --- EVP_PBE_find_ex ---
patch(
    "evp.h",
    """int EVP_PBE_find_ex(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen, EVP_PBE_KEYGEN_EX **pkeygen_ex);
/**
 * @brief Free the global password-based encryption (PBE) algorithm registry.
""",
    """/**
 * @brief Look up a registered PBE algorithm, returning both classic and extended keygen callbacks.
 * @param type PBE application type such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE AlgorithmIdentifier.
 * @param pcnid Optional destination for the cipher NID, or NULL.
 * @param pmnid Optional destination for the digest/PRF NID, or NULL.
 * @param pkeygen Optional destination for the classic keygen function pointer, or NULL.
 * @param pkeygen_ex Optional destination for the extended (libctx-aware) keygen, or NULL.
 * @return 1 if found, or 0 otherwise.
 */
int EVP_PBE_find_ex(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen, EVP_PBE_KEYGEN_EX **pkeygen_ex);
/**
 * @brief Free the global password-based encryption (PBE) algorithm registry.
""",
    "EVP_PBE_find_ex",
)

# --- EVP_PKEY_asn1_get0 ---
patch(
    "evp.h",
    """const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
/**
 * @brief Find the ASN.1 method implementing a public-key algorithm NID.
""",
    """/**
 * @brief Return the registered EVP_PKEY_ASN1_METHOD at index @p idx.
 * @param idx Zero-based index in the range [0, EVP_PKEY_asn1_get_count()).
 * @return Internal ASN.1 method pointer, or NULL if @p idx is out of range.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
/**
 * @brief Find the ASN.1 method implementing a public-key algorithm NID.
""",
    "EVP_PKEY_asn1_get0",
)

# --- EVP_PKEY_asn1_add0 ---
patch(
    "evp.h",
    """int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
""",
    """/**
 * @brief Register an EVP_PKEY_ASN1_METHOD in the global ASN.1 method table.
 * @param ameth ASN.1 method to add; ownership is transferred on success.
 * @return 1 on success, or 0 on failure (for example duplicate id).
 */
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
""",
    "EVP_PKEY_asn1_add0",
)

# --- EVP_PKEY_get0_asn1 ---
patch(
    "evp.h",
    """const EVP_PKEY_ASN1_METHOD *EVP_PKEY_get0_asn1(const EVP_PKEY *pkey);
/**
 * @brief Allocate a new custom EVP_PKEY_ASN1_METHOD for algorithm @p id.
""",
    """/**
 * @brief Return the EVP_PKEY_ASN1_METHOD associated with a key.
 * @param pkey Key whose ASN.1 method is queried.
 * @return Internal ASN.1 method pointer, or NULL if unavailable; do not free.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_get0_asn1(const EVP_PKEY *pkey);
/**
 * @brief Allocate a new custom EVP_PKEY_ASN1_METHOD for algorithm @p id.
""",
    "EVP_PKEY_get0_asn1",
)

# --- EVP_PKEY_asn1_set_public ---
patch(
    "evp.h",
    """void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pub_decode)(EVP_PKEY *pk,
        const X509_PUBKEY *pub),
    int (*pub_encode)(X509_PUBKEY *pub,
        const EVP_PKEY *pk),
    int (*pub_cmp)(const EVP_PKEY *a,
        const EVP_PKEY *b),
    int (*pub_print)(BIO *out,
        const EVP_PKEY *pkey,
        int indent, ASN1_PCTX *pctx),
    int (*pkey_size)(const EVP_PKEY *pk),
    int (*pkey_bits)(const EVP_PKEY *pk));
/**
 * @brief Install PKCS#8 private-key decode, encode, and print callbacks on an ASN.1 method.
""",
    """/**
 * @brief Install public-key decode, encode, compare, print, size, and bits callbacks on an ASN.1 method.
 * @param ameth ASN.1 method being customized.
 * @param pub_decode Decode an X509_PUBKEY into @p pk.
 * @param pub_encode Encode @p pk into an X509_PUBKEY.
 * @param pub_cmp Compare two public keys (1 match, 0 differ, negative on error).
 * @param pub_print Print the public key to a BIO.
 * @param pkey_size Return the maximum output size in bytes for operations with @p pk.
 * @param pkey_bits Return the key size in bits for @p pk.
 */
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pub_decode)(EVP_PKEY *pk,
        const X509_PUBKEY *pub),
    int (*pub_encode)(X509_PUBKEY *pub,
        const EVP_PKEY *pk),
    int (*pub_cmp)(const EVP_PKEY *a,
        const EVP_PKEY *b),
    int (*pub_print)(BIO *out,
        const EVP_PKEY *pkey,
        int indent, ASN1_PCTX *pctx),
    int (*pkey_size)(const EVP_PKEY *pk),
    int (*pkey_bits)(const EVP_PKEY *pk));
/**
 * @brief Install PKCS#8 private-key decode, encode, and print callbacks on an ASN.1 method.
""",
    "EVP_PKEY_asn1_set_public",
)

# --- EVP_PKEY_asn1_set_siginf ---
patch(
    "evp.h",
    """void EVP_PKEY_asn1_set_siginf(EVP_PKEY_ASN1_METHOD *ameth,
    int (*siginf_set)(X509_SIG_INFO *siginf,
        const X509_ALGOR *alg,
        const ASN1_STRING *sig));

void EVP_PKEY_asn1_set_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_check)(const EVP_PKEY *pk));
""",
    """/**
 * @brief Install the X509_SIG_INFO setup callback on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method being customized.
 * @param siginf_set Callback that fills signature metadata from @p alg and @p sig, or NULL to clear.
 */
void EVP_PKEY_asn1_set_siginf(EVP_PKEY_ASN1_METHOD *ameth,
    int (*siginf_set)(X509_SIG_INFO *siginf,
        const X509_ALGOR *alg,
        const ASN1_STRING *sig));

/**
 * @brief Install the full-key consistency check callback on an ASN.1 method.
 * @param ameth ASN.1 method being configured.
 * @param pkey_check Callback that returns 1 if @p pk is consistent, or NULL to clear.
 */
void EVP_PKEY_asn1_set_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_check)(const EVP_PKEY *pk));
""",
    "EVP_PKEY_asn1_set_siginf+set_check",
)

# --- EVP_PKEY_asn1_set_set_pub_key ---
patch(
    "evp.h",
    """void EVP_PKEY_asn1_set_set_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*set_pub_key)(EVP_PKEY *pk,
        const unsigned char *pub,
        size_t len));
/**
 * @brief Install the raw private-key export callback on an EVP_PKEY_ASN1_METHOD.
""",
    """/**
 * @brief Install a callback that sets raw public-key octets on an EVP_PKEY.
 * @param ameth ASN.1 method being customized.
 * @param set_pub_key Callback that imports @p len bytes of raw public key material into @p pk.
 */
void EVP_PKEY_asn1_set_set_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
    int (*set_pub_key)(EVP_PKEY *pk,
        const unsigned char *pub,
        size_t len));
/**
 * @brief Install the raw private-key export callback on an EVP_PKEY_ASN1_METHOD.
""",
    "EVP_PKEY_asn1_set_set_pub_key",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    raise SystemExit(1)
