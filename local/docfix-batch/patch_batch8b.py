#!/usr/bin/env python3
"""Documentation repair batch 8b: evp, http, objects, pem, pkcs7, rand, rsa."""
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


def asn1_funcs(typename, brief):
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {typename}, or NULL on allocation failure.
 */
{typename} *{typename}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {typename}_free({typename} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {typename}, or NULL on error.
 */
{typename} *d2i_{typename}({typename} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{typename}(const {typename} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {typename}.
 * @return Pointer to the static ASN1_ITEM for {typename}.
 */
const ASN1_ITEM *{typename}_it(void);"""


# ----- evp.h -----
patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);""",
"""/**
 * @brief Set the digest output size on a custom EVP_MD method (deprecated).
 * @param md Digest method under construction.
 * @param resultsize Digest length in bytes (for example 32 for SHA-256).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);""",
"EVP_MD_meth_set_result_size")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);",
"""/**
 * @brief Return the flag bits configured on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Flag mask such as EVP_MD_FLAG_ONESHOT / EVP_MD_FLAG_XOF.
 */
OSSL_DEPRECATEDIN_3_0 unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);""",
"EVP_MD_meth_get_flags")

patch_both("evp.h",
"EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx);",
"""/**
 * @brief Return a new reference to the EVP_CIPHER used by a cipher context.
 * @param ctx Cipher context to query.
 * @return Cipher with an incremented reference count, or NULL if unset; free with EVP_CIPHER_free.
 */
EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx);""",
"EVP_CIPHER_CTX_get1_cipher")

patch_both("evp.h",
"""__owur int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc, const OSSL_PARAM params[]);""",
"""/**
 * @brief Initialise a cipher context with optional OSSL_PARAM settings.
 * @param ctx Cipher context to initialise.
 * @param cipher Cipher algorithm, or NULL to reuse the one already in @p ctx.
 * @param key Key bytes, or NULL to set later.
 * @param iv IV/nonce bytes, or NULL when not yet available / not required.
 * @param enc 1 to encrypt, 0 to decrypt, or -1 to leave the prior direction.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc, const OSSL_PARAM params[]);""",
"EVP_CipherInit_ex2")

patch_both("evp.h",
"""__owur int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);""",
"""/**
 * @brief Initialise a digest-sign operation using a digest name and library context.
 * @param ctx Message-digest context that will accumulate data to sign.
 * @param pctx Optional address receiving the EVP_PKEY_CTX used for signing, or NULL.
 * @param mdname Digest algorithm name (for example "SHA256"), or NULL for the key default.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param props Property query for algorithm fetches, or NULL.
 * @param pkey Private key used to create the signature.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);""",
"EVP_DigestSignInit_ex")

patch_both("evp.h",
"const EVP_MD *EVP_sha3_256(void);",
"""/**
 * @brief Return the built-in SHA3-256 message-digest method.
 * @return Pointer to the SHA3-256 EVP_MD (do not free).
 */
const EVP_MD *EVP_sha3_256(void);""",
"EVP_sha3_256")

patch_both("evp.h",
"const EVP_CIPHER *EVP_des_ede3_cbc(void);",
"""/**
 * @brief Return the built-in Triple-DES (EDE3) CBC cipher method.
 * @return Pointer to the DES-EDE3-CBC EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_des_ede3_cbc(void);""",
"EVP_des_ede3_cbc")

patch_both("evp.h",
"const EVP_CIPHER *EVP_aes_192_ocb(void);",
"""/**
 * @brief Return the built-in AES-192 OCB authenticated-encryption cipher method.
 * @return Pointer to the AES-192-OCB EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_aes_192_ocb(void);""",
"EVP_aes_192_ocb")

patch_both("evp.h",
"const EVP_CIPHER *EVP_aria_128_cbc(void);",
"""/**
 * @brief Return the built-in ARIA-128 CBC cipher method.
 * @return Pointer to the ARIA-128-CBC EVP_CIPHER (do not free).
 */
const EVP_CIPHER *EVP_aria_128_cbc(void);""",
"EVP_aria_128_cbc")

patch_both("evp.h",
"int EVP_MAC_is_a(const EVP_MAC *mac, const char *name);",
"""/**
 * @brief Test whether a MAC implementation matches an algorithm name.
 * @param mac MAC method to query.
 * @param name Algorithm name (for example "HMAC" or "CMAC").
 * @return 1 if @p mac is known as @p name, or 0 otherwise.
 */
int EVP_MAC_is_a(const EVP_MAC *mac, const char *name);""",
"EVP_MAC_is_a")

patch_both("evp.h",
"int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);",
"""/**
 * @brief Feed more message bytes into a MAC computation.
 * @param ctx MAC context previously initialised with EVP_MAC_init().
 * @param data Message bytes to absorb.
 * @param datalen Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);""",
"EVP_MAC_update")

patch_both("evp.h",
"const OSSL_PARAM *EVP_RAND_CTX_settable_params(EVP_RAND_CTX *ctx);",
"""/**
 * @brief Return the parameters that may be set on a RAND context.
 * @param ctx RAND context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_RAND_CTX_settable_params(EVP_RAND_CTX *ctx);""",
"EVP_RAND_CTX_settable_params")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);""",
"""/**
 * @brief Assign a low-level key object of @p type to an EVP_PKEY (deprecated).
 * @param pkey Destination key wrapper; previous key material is freed.
 * @param type Key type NID such as EVP_PKEY_RSA or EVP_PKEY_EC.
 * @param key Type-specific key pointer (for example RSA *) that @p pkey will own.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);""",
"EVP_PKEY_assign")

patch_both("evp.h",
"""int EVP_PKEY_print_public_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);""",
"""/**
 * @brief Print the public components of @p pkey to a FILE.
 * @param fp Output stream.
 * @param pkey Key whose public material is printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_public_fp(FILE *fp, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);""",
"EVP_PKEY_print_public_fp")

patch_both("evp.h",
"void EVP_PBE_cleanup(void);",
"""/**
 * @brief Free the global password-based encryption (PBE) algorithm registry.
 *
 * Intended for process teardown; after this call, PBE algorithms must be
 * re-registered before use.
 */
void EVP_PBE_cleanup(void);""",
"EVP_PBE_cleanup")

patch_both("evp.h",
"""void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_ctrl)(EVP_PKEY *pkey, int op,
        long arg1, void *arg2));""",
"""/**
 * @brief Set the control callback on an EVP_PKEY_ASN1_METHOD.
 * @param ameth ASN.1 method table under construction.
 * @param pkey_ctrl Callback for ASN.1/method control ops (for example PKCS#7/CMS), or NULL to clear.
 */
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_ctrl)(EVP_PKEY *pkey, int op,
        long arg1, void *arg2));""",
"EVP_PKEY_asn1_set_ctrl")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
    size_t len, const EVP_CIPHER *cipher);""",
"""/**
 * @brief Create an EVP_PKEY wrapping a CMAC key (deprecated).
 * @param e Unused legacy ENGINE parameter; pass NULL.
 * @param priv CMAC key bytes.
 * @param len Length of @p priv in bytes.
 * @param cipher Block cipher underlying the CMAC (for example AES-128-CBC).
 * @return New EVP_PKEY of type EVP_PKEY_CMAC, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
    size_t len, const EVP_CIPHER *cipher);""",
"EVP_PKEY_new_CMAC_key")

patch_both("evp.h",
"EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Return the primary EVP_PKEY associated with a key context.
 * @param ctx Key context to query.
 * @return Key pointer owned by @p ctx (do not free), or NULL if unset.
 */
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_CTX_get0_pkey")

patch_both("evp.h",
"int EVP_SIGNATURE_is_a(const EVP_SIGNATURE *signature, const char *name);",
"""/**
 * @brief Test whether a signature algorithm implementation matches a name.
 * @param signature Signature algorithm object to query.
 * @param name Algorithm name (for example "RSA" or "ED25519").
 * @return 1 if @p signature is known as @p name, or 0 otherwise.
 */
int EVP_SIGNATURE_is_a(const EVP_SIGNATURE *signature, const char *name);""",
"EVP_SIGNATURE_is_a")

patch_both("evp.h",
"int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER *cipher, const char *name);",
"""/**
 * @brief Test whether an asymmetric cipher implementation matches a name.
 * @param cipher Asymmetric cipher algorithm object to query.
 * @param name Algorithm name (for example "RSA").
 * @return 1 if @p cipher is known as @p name, or 0 otherwise.
 */
int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER *cipher, const char *name);""",
"EVP_ASYM_CIPHER_is_a")

patch_both("evp.h",
"const char *EVP_ASYM_CIPHER_get0_description(const EVP_ASYM_CIPHER *cipher);",
"""/**
 * @brief Return a human-readable description of an asymmetric cipher algorithm.
 * @param cipher Asymmetric cipher to query.
 * @return Description string (do not free), or NULL if none is available.
 */
const char *EVP_ASYM_CIPHER_get0_description(const EVP_ASYM_CIPHER *cipher);""",
"EVP_ASYM_CIPHER_get0_description")

patch_both("evp.h",
"const OSSL_PARAM *EVP_KEM_gettable_ctx_params(const EVP_KEM *kem);",
"""/**
 * @brief Return the context parameters that can be read from a KEM algorithm.
 * @param kem KEM algorithm to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEM_gettable_ctx_params(const EVP_KEM *kem);""",
"EVP_KEM_gettable_ctx_params")

patch_both("evp.h",
"int EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);",
"""/**
 * @brief Initialise @p ctx for signature verification with optional parameters.
 * @param ctx Key context holding the public key (or key pair) used to verify.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);""",
"EVP_PKEY_verify_init_ex")

patch_both("evp.h",
"""int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);""",
"""/**
 * @brief Verify a signature over @p tbs using an initialised key context.
 * @param ctx Context previously prepared with EVP_PKEY_verify_init() or _ex().
 * @param sig Signature bytes to verify.
 * @param siglen Length of @p sig in bytes.
 * @param tbs Data that was signed (typically a digest or raw message).
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);""",
"EVP_PKEY_verify")

patch_both("evp.h",
"int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Initialise @p ctx for public-key encryption.
 * @param ctx Key context holding the public key (or key pair) used to encrypt.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_encrypt_init")

patch_both("evp.h",
"int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Initialise @p ctx for private-key decryption.
 * @param ctx Key context holding the private key used to decrypt.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_decrypt_init")

patch_both("evp.h",
"const OSSL_PARAM *EVP_PKEY_settable_params(const EVP_PKEY *pkey);",
"""/**
 * @brief Return the parameters that may be set on an EVP_PKEY.
 * @param pkey Key to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_settable_params(const EVP_PKEY *pkey);""",
"EVP_PKEY_settable_params")

patch_both("evp.h",
"""int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name,
    const BIGNUM *bn);""",
"""/**
 * @brief Set a named BIGNUM parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param bn Integer value to assign (copied; caller retains ownership of @p bn).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name,
    const BIGNUM *bn);""",
"EVP_PKEY_set_bn_param")

patch_both("evp.h",
"""int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key_name,
    const unsigned char *buf, size_t bsize);""",
"""/**
 * @brief Set a named octet-string parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param buf Octet string value to assign (copied).
 * @param bsize Length of @p buf in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key_name,
    const unsigned char *buf, size_t bsize);""",
"EVP_PKEY_set_octet_string_param")

patch_both("evp.h",
"int EVP_PKEY_get_field_type(const EVP_PKEY *pkey);",
"""/**
 * @brief Return the EC field type NID for an elliptic-curve EVP_PKEY.
 * @param pkey EC key to query.
 * @return NID_X9_62_prime_field or NID_X9_62_characteristic_two_field, or 0 on error / non-EC keys.
 */
int EVP_PKEY_get_field_type(const EVP_PKEY *pkey);""",
"EVP_PKEY_get_field_type")

patch_both("evp.h",
"int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);",
"""/**
 * @brief Generate a key pair into *@p ppkey using an initialised keygen context.
 * @param ctx Context prepared with EVP_PKEY_keygen_init() (and any controls).
 * @param ppkey Address of an EVP_PKEY pointer that receives the new key (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);""",
"EVP_PKEY_keygen")

patch_both("evp.h",
"int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Validate domain parameters associated with a key context.
 * @param ctx Context holding parameters (or a key that embeds them).
 * @return 1 if parameters are valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_param_check")

patch_both("evp.h",
"int EVP_PKEY_param_check_quick(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Perform a fast/lightweight validation of domain parameters on a key context.
 * @param ctx Context holding parameters (or a key that embeds them).
 * @return 1 if parameters pass the quick check, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_param_check_quick(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_param_check_quick")

patch_both("evp.h",
"void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);",
"""/**
 * @brief Install a progress callback for key/parameter generation on a context.
 * @param ctx Key context used for keygen/paramgen.
 * @param cb Generation callback, or NULL to clear.
 */
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);""",
"EVP_PKEY_CTX_set_cb")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth, int (*keygen_init)(EVP_PKEY_CTX *ctx),
    int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));""",
"""/**
 * @brief Set key-generation callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param keygen_init Optional initialiser called from EVP_PKEY_keygen_init(), or NULL.
 * @param keygen Callback that writes a new key into @p pkey, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth, int (*keygen_init)(EVP_PKEY_CTX *ctx),
    int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));""",
"EVP_PKEY_meth_set_keygen")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth, int (*encrypt_init)(EVP_PKEY_CTX *ctx),
    int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));""",
"""/**
 * @brief Set public-key encryption callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param encrypt_init Optional initialiser called from EVP_PKEY_encrypt_init(), or NULL.
 * @param encryptfn Callback that encrypts @p in into @p out / *@p outlen, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth, int (*encrypt_init)(EVP_PKEY_CTX *ctx),
    int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));""",
"EVP_PKEY_meth_set_encrypt")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth, int (**pparamgen_init)(EVP_PKEY_CTX *ctx),
    int (**pparamgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));""",
"""/**
 * @brief Retrieve parameter-generation callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pparamgen_init Receives the paramgen_init callback pointer, or NULL.
 * @param pparamgen Receives the paramgen callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth, int (**pparamgen_init)(EVP_PKEY_CTX *ctx),
    int (**pparamgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));""",
"EVP_PKEY_meth_get_paramgen")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth,
    int (**psignctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**psignctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));""",
"""/**
 * @brief Retrieve digest-context signing callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param psignctx_init Receives the signctx_init callback pointer, or NULL.
 * @param psignctx Receives the signctx callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth,
    int (**psignctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**psignctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx));""",
"EVP_PKEY_meth_get_signctx")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth,
    int (**pverifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**pverifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        int siglen, EVP_MD_CTX *mctx));""",
"""/**
 * @brief Retrieve digest-context verification callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pverifyctx_init Receives the verifyctx_init callback pointer, or NULL.
 * @param pverifyctx Receives the verifyctx callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth,
    int (**pverifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (**pverifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        int siglen, EVP_MD_CTX *mctx));""",
"EVP_PKEY_meth_get_verifyctx")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestsign(const EVP_PKEY_METHOD *pmeth,
    int (**digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));""",
"""/**
 * @brief Retrieve the one-shot digestsign callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param digestsign Receives the digestsign callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestsign(const EVP_PKEY_METHOD *pmeth,
    int (**digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));""",
"EVP_PKEY_meth_get_digestsign")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));",
"""/**
 * @brief Retrieve the full key-check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));""",
"EVP_PKEY_meth_get_check")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));",
"""/**
 * @brief Retrieve the parameter-check callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pcheck Receives the param_check callback pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth, int (**pcheck)(EVP_PKEY *pkey));""",
"EVP_PKEY_meth_get_param_check")

patch_both("evp.h",
"int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange);",
"""/**
 * @brief Increment the reference count on a key-exchange algorithm object.
 * @param exchange Key-exchange method to retain.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange);""",
"EVP_KEYEXCH_up_ref")

patch_both("evp.h",
"const char *EVP_KEYEXCH_get0_description(const EVP_KEYEXCH *keyexch);",
"""/**
 * @brief Return a human-readable description of a key-exchange algorithm.
 * @param keyexch Key-exchange method to query.
 * @return Description string (do not free), or NULL if none is available.
 */
const char *EVP_KEYEXCH_get0_description(const EVP_KEYEXCH *keyexch);""",
"EVP_KEYEXCH_get0_description")

patch_both("evp.h",
"const OSSL_PARAM *EVP_KEYEXCH_gettable_ctx_params(const EVP_KEYEXCH *keyexch);",
"""/**
 * @brief Return the context parameters that can be read from a key-exchange algorithm.
 * @param keyexch Key-exchange method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_KEYEXCH_gettable_ctx_params(const EVP_KEYEXCH *keyexch);""",
"EVP_KEYEXCH_gettable_ctx_params")

patch_both("evp.h",
"void EVP_add_alg_module(void);",
"""/**
 * @brief Register built-in algorithm modules with the EVP subsystem.
 *
 * Called during library initialisation so config-driven algorithm modules
 * are available; safe to ignore from application code.
 */
void EVP_add_alg_module(void);""",
"EVP_add_alg_module")

patch_both("evp.h",
"int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);",
"""/**
 * @brief Set the elliptic-curve / DH group name on a key or parameter context.
 * @param ctx Key context used for keygen/paramgen/derive.
 * @param name Group name (for example "P-256" or "ffdhe2048").
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);""",
"EVP_PKEY_CTX_set_group_name")

# ----- http.h -----
patch_both("http.h",
"size_t OSSL_HTTP_REQ_CTX_get_resp_len(const OSSL_HTTP_REQ_CTX *rctx);",
"""/**
 * @brief Return the number of response body bytes accumulated so far.
 * @param rctx HTTP request context that has been exchanging data.
 * @return Current response length in bytes.
 */
size_t OSSL_HTTP_REQ_CTX_get_resp_len(const OSSL_HTTP_REQ_CTX *rctx);""",
"OSSL_HTTP_REQ_CTX_get_resp_len")

# ----- objects.h -----
patch_both("objects.h",
"ASN1_OBJECT *OBJ_nid2obj(int n);",
"""/**
 * @brief Return the ASN1_OBJECT for a numeric identifier (NID).
 * @param n Object NID such as NID_sha256.
 * @return Internal ASN1_OBJECT pointer (do not free), or NULL if @p n is unknown.
 */
ASN1_OBJECT *OBJ_nid2obj(int n);""",
"OBJ_nid2obj")

# ----- pem.h -----
patch_both("pem.h",
"""int PEM_read_bio(BIO *bp, char **name, char **header,
    unsigned char **data, long *len);""",
"""/**
 * @brief Read one PEM object from a BIO, returning name, header, and decoded data.
 * @param bp BIO to read from.
 * @param name Receives a newly allocated PEM type name (caller frees with OPENSSL_free).
 * @param header Receives a newly allocated PEM header block, or an empty string.
 * @param data Receives newly allocated decoded payload bytes.
 * @param len Receives the length of *@p data in bytes.
 * @return 1 on success, or 0 on failure / end of input.
 */
int PEM_read_bio(BIO *bp, char **name, char **header,
    unsigned char **data, long *len);""",
"PEM_read_bio")

patch_both("pem.h",
"""int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
    const void *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);""",
"""/**
 * @brief Encode an ASN.1 object with @p i2d and write it as a PEM block to a BIO.
 * @param i2d Encoder such as i2d_X509.
 * @param name PEM type label written after "-----BEGIN ".
 * @param bp BIO that receives the PEM text.
 * @param x Object passed to @p i2d.
 * @param enc Optional cipher for encrypting the PEM, or NULL for cleartext.
 * @param kstr Optional encryption key bytes when @p enc is non-NULL, or NULL to use @p cb.
 * @param klen Length of @p kstr in bytes.
 * @param cb Password callback used when @p enc is set and @p kstr is NULL, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
    const void *x, const EVP_CIPHER *enc,
    const unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);""",
"PEM_ASN1_write_bio")

patch_both("pem.h",
"""STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
    pem_password_cb *cb, void *u);
STACK_OF(X509_INFO)
*PEM_X509_INFO_read_ex(FILE *fp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb,
    void *u, OSSL_LIB_CTX *libctx, const char *propq);""",
"""/**
 * @brief Read certificates, CRLs, and keys from a PEM FILE into X509_INFO objects.
 * @param fp FILE positioned at PEM input.
 * @param sk Existing stack to append to, or NULL to allocate a new one.
 * @param cb Password callback for encrypted PEM private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @return Stack of X509_INFO on success, or NULL on failure.
 */
STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
    pem_password_cb *cb, void *u);
/**
 * @brief Read certificates, CRLs, and keys from a PEM FILE with a library context.
 * @param fp FILE positioned at PEM input.
 * @param sk Existing stack to append to, or NULL to allocate a new one.
 * @param cb Password callback for encrypted PEM private keys, or NULL.
 * @param u Application data passed to @p cb.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Stack of X509_INFO on success, or NULL on failure.
 */
STACK_OF(X509_INFO)
*PEM_X509_INFO_read_ex(FILE *fp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb,
    void *u, OSSL_LIB_CTX *libctx, const char *propq);""",
"PEM_X509_INFO_read")

patch_both("pem.h",
"int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);",
"""/**
 * @brief Absorb more message bytes into a PEM signing digest context.
 * @param ctx Digest context initialised for PEM signing (for example via PEM_SignInit).
 * @param d Message bytes to hash.
 * @param cnt Number of bytes at @p d.
 * @return 1 on success, or 0 on failure.
 */
int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);""",
"PEM_SignUpdate")

patch_both("pem.h",
"DECLARE_PEM_rw(X509_REQ, X509_REQ)",
"""/**
 * @brief Read a certificate request from a PEM-encoded BIO.
 * @param bp BIO to read from.
 * @param x Optional address of an X509_REQ pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate request on success, or NULL on failure.
 */
X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a certificate request to a BIO in PEM form.
 * @param bp BIO to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_X509_REQ(BIO *bp, const X509_REQ *x);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Read a certificate request from a PEM-encoded FILE stream.
 * @param fp FILE to read from.
 * @param x Optional address of an X509_REQ pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Certificate request on success, or NULL on failure.
 */
X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb *cb, void *u);
/**
 * @brief Write a certificate request to a FILE stream in PEM form.
 * @param fp FILE to write to.
 * @param x Request to encode.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_X509_REQ(FILE *fp, const X509_REQ *x);
#endif""",
"DECLARE_PEM_rw_X509_REQ")

# ----- pkcs7.h -----
patch_both("pkcs7.h",
"int i2d_PKCS7_fp(FILE *fp, const PKCS7 *p7);",
"""/**
 * @brief Write a DER-encoded PKCS#7 structure to a FILE.
 * @param fp Output stream.
 * @param p7 PKCS#7 object to encode.
 * @return Number of bytes written, or a negative / zero value on error.
 */
int i2d_PKCS7_fp(FILE *fp, const PKCS7 *p7);""",
"i2d_PKCS7_fp")

patch_both("pkcs7.h",
"int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);",
"""/**
 * @brief Write a PKCS#7 structure as PEM, streaming content from @p in when required.
 * @param out BIO that receives the PEM-encoded PKCS#7.
 * @param p7 PKCS#7 object to serialise.
 * @param in Optional content BIO for streaming signed/enveloped data, or NULL.
 * @param flags SMIME_* / PKCS7_* streaming and encoding flags.
 * @return 1 on success, or 0 on failure.
 */
int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);""",
"PEM_write_bio_PKCS7_stream")

patch_both("pkcs7.h",
"BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);",
"""/**
 * @brief Create a BIO that decrypts/verifies PKCS#7 content for reading.
 * @param p7 PKCS#7 EnvelopedData / SignedAndEnvelopedData (or similar) to decode.
 * @param pkey Recipient private key for decryption, or NULL when not required.
 * @param in_bio Optional BIO supplying encrypted content when not embedded in @p p7, or NULL.
 * @param pcert Recipient certificate used to select the matching RecipientInfo, or NULL.
 * @return BIO that yields cleartext content, or NULL on error.
 */
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);""",
"PKCS7_dataDecode")

patch_both("pkcs7.h",
"int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);",
"""/**
 * @brief Write a PKCS#7 object in S/MIME (PEM/CMS) form to a BIO.
 * @param bio Output BIO for the S/MIME message.
 * @param p7 PKCS#7 structure to write.
 * @param data Optional content BIO for streaming, or NULL when content is already in @p p7.
 * @param flags SMIME_* writing flags (for example SMIME_DETACHED).
 * @return 1 on success, or 0 on failure.
 */
int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);""",
"SMIME_write_PKCS7")

# ----- rand.h -----
patch_both("rand.h",
"int RAND_set0_public(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);",
"""/**
 * @brief Install @p rand as the public DRBG for a library context, transferring ownership.
 * @param ctx Library context whose public RNG is replaced, or NULL for the default.
 * @param rand RAND context that becomes the public generator; @p ctx takes ownership.
 * @return 1 on success, or 0 on failure.
 */
int RAND_set0_public(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);""",
"RAND_set0_public")

# ----- rsa.h -----
patch_both("rsa.h",
"int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
"""/**
 * @brief Set the MGF1 digest used for RSA-PSS or RSA-OAEP on a key context.
 * @param ctx RSA key context.
 * @param md Message digest for MGF1 (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
"EVP_PKEY_CTX_set_rsa_mgf1_md")

patch_both("rsa.h",
"int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);",
"""/**
 * @brief Get the MGF1 digest configured for RSA-PSS or RSA-OAEP on a key context.
 * @param ctx RSA key context.
 * @param md Receives a pointer to the digest method (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);""",
"EVP_PKEY_CTX_get_rsa_mgf1_md")

patch_both("rsa.h",
"""int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
    const char *mdprops);""",
"""/**
 * @brief Set the OAEP message digest by name on an RSA key context.
 * @param ctx RSA key context used for encrypt/decrypt.
 * @param mdname Digest name (for example "SHA256").
 * @param mdprops Property query for fetching @p mdname, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
    const char *mdprops);""",
"EVP_PKEY_CTX_set_rsa_oaep_md_name")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_size(const RSA *rsa);",
"""/**
 * @brief Return the RSA modulus size in bytes (deprecated).
 * @param rsa RSA key whose modulus size is queried.
 * @return Byte length of the modulus (RSA_size), or 0 if unset.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_size(const RSA *rsa);""",
"RSA_size")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);",
"""/**
 * @brief Set the RSA modulus and exponents, transferring ownership of the BIGNUMs (deprecated).
 * @param r RSA key to update.
 * @param n Modulus; required on the first call, or NULL to leave unchanged.
 * @param e Public exponent; required on the first call, or NULL to leave unchanged.
 * @param d Private exponent, or NULL to leave unchanged / omit.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);""",
"RSA_set0_key")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_set0_multi_prime_params(RSA *r,
    BIGNUM *primes[],
    BIGNUM *exps[],
    BIGNUM *coeffs[],
    int pnum);""",
"""/**
 * @brief Set multi-prime RSA factors, exponents, and CRT coefficients (deprecated).
 * @param r RSA key to update.
 * @param primes Array of @p pnum prime factors that @p r will own.
 * @param exps Array of @p pnum CRT exponents that @p r will own.
 * @param coeffs Array of @p pnum CRT coefficients that @p r will own.
 * @param pnum Number of additional primes (beyond the classic two-prime case).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_multi_prime_params(RSA *r,
    BIGNUM *primes[],
    BIGNUM *exps[],
    BIGNUM *coeffs[],
    int pnum);""",
"RSA_set0_multi_prime_params")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 void RSA_get0_key(const RSA *r,
    const BIGNUM **n, const BIGNUM **e,
    const BIGNUM **d);""",
"""/**
 * @brief Get const pointers to the RSA modulus and exponents (deprecated).
 * @param r RSA key to query.
 * @param n Receives the modulus, or NULL if not requested.
 * @param e Receives the public exponent, or NULL if not requested.
 * @param d Receives the private exponent, or NULL if not requested.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_get0_key(const RSA *r,
    const BIGNUM **n, const BIGNUM **e,
    const BIGNUM **d);""",
"RSA_get0_key")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
    const BIGNUM *coeffs[]);""",
"""/**
 * @brief Get const pointers to multi-prime CRT exponents and coefficients (deprecated).
 * @param r Multi-prime RSA key to query.
 * @param exps Caller-provided array receiving exponent pointers (length RSA_get_multi_prime_extra_count).
 * @param coeffs Caller-provided array receiving coefficient pointers, or NULL.
 * @return 1 on success, or 0 if @p r is not multi-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
    const BIGNUM *coeffs[]);""",
"RSA_get0_multi_prime_crt_params")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_n(const RSA *d);",
"""/**
 * @brief Return the RSA modulus n (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal modulus BIGNUM (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_n(const RSA *d);""",
"RSA_get0_n")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_d(const RSA *d);",
"""/**
 * @brief Return the RSA private exponent d (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal private-exponent BIGNUM (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_d(const RSA *d);""",
"RSA_get0_d")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_check_key_ex(const RSA *, BN_GENCB *cb);",
"""/**
 * @brief Validate RSA key components with an optional progress callback (deprecated).
 * @param rsa RSA key to check.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 if the key is valid, or 0 if invalid / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_check_key_ex(const RSA *rsa, BN_GENCB *cb);""",
"RSA_check_key_ex")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);""",
"""/**
 * @brief RSA private-key encryption (raw primitive / signing-style) (deprecated).
 * @param flen Length of @p from in bytes.
 * @param from Input bytes to encrypt with the private key.
 * @param to Output buffer of at least RSA_size(@p rsa) bytes.
 * @param rsa RSA private key.
 * @param padding Padding mode such as RSA_PKCS1_PADDING or RSA_NO_PADDING.
 * @return Number of bytes written to @p to, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding);""",
"RSA_private_encrypt")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 void RSA_free(RSA *r);",
"""/**
 * @brief Free an RSA key and its BIGNUM components (deprecated).
 * @param r Key to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_free(RSA *r);""",
"RSA_free")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_default_method(void);",
"""/**
 * @brief Return the current default RSA_METHOD (deprecated).
 * @return Default method pointer (do not free).
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_default_method(void);""",
"RSA_get_default_method")

patch_both("rsa.h",
"""struct rsa_pss_params_st {
    X509_ALGOR *hashAlgorithm;
    X509_ALGOR *maskGenAlgorithm;
    ASN1_INTEGER *saltLength;
    ASN1_INTEGER *trailerField;
    /* Decoded hash algorithm from maskGenAlgorithm */
    X509_ALGOR *maskHash;
};""",
"""struct rsa_pss_params_st {
    /** Hash AlgorithmIdentifier used by RSA-PSS (for example SHA-256). */
    X509_ALGOR *hashAlgorithm;
    /** Mask generation AlgorithmIdentifier (typically MGF1 with a hash). */
    X509_ALGOR *maskGenAlgorithm;
    /** PSS salt length in octets; NULL means the ASN.1 default. */
    ASN1_INTEGER *saltLength;
    /** Trailer field value; NULL means the default trailerFieldBC (0xbc). */
    ASN1_INTEGER *trailerField;
    /** Hash AlgorithmIdentifier decoded from @c maskGenAlgorithm (MGF1). */
    X509_ALGOR *maskHash;
};""",
"rsa_pss_params_fields")

patch_both("rsa.h",
"DECLARE_ASN1_DUP_FUNCTION(RSA_PSS_PARAMS)",
"""/**
 * @brief Deep-copy RSA-PSS algorithm parameters.
 * @param a Parameters to duplicate.
 * @return Newly allocated copy, or NULL on error; free with RSA_PSS_PARAMS_free.
 */
RSA_PSS_PARAMS *RSA_PSS_PARAMS_dup(const RSA_PSS_PARAMS *a);""",
"RSA_PSS_PARAMS_dup")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_sign(int type, const unsigned char *m,
    unsigned int m_length, unsigned char *sigret,
    unsigned int *siglen, RSA *rsa);""",
"""/**
 * @brief Create an RSA signature with PKCS#1 DigestInfo wrapping (deprecated).
 * @param type Digest NID identifying the hash algorithm (for example NID_sha256).
 * @param m Digest bytes to sign.
 * @param m_length Length of @p m in bytes.
 * @param sigret Buffer of at least RSA_size(@p rsa) bytes receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param rsa RSA private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_sign(int type, const unsigned char *m,
    unsigned int m_length, unsigned char *sigret,
    unsigned int *siglen, RSA *rsa);""",
"RSA_sign")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_sign_ASN1_OCTET_STRING(int type,
    const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen,
    RSA *rsa);""",
"""/**
 * @brief Sign an ASN.1 OCTET STRING payload with RSA (deprecated).
 * @param type Unused legacy digest type argument.
 * @param m OCTET STRING contents to sign.
 * @param m_length Length of @p m in bytes.
 * @param sigret Buffer of at least RSA_size(@p rsa) bytes receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param rsa RSA private key.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_sign_ASN1_OCTET_STRING(int type,
    const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen,
    RSA *rsa);""",
"RSA_sign_ASN1_OCTET_STRING")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);",
"""/**
 * @brief Enable RSA blinding on @p rsa to mitigate timing attacks (deprecated).
 * @param rsa RSA key that will use blinding for private operations.
 * @param ctx Optional BN_CTX for blinding setup, or NULL to allocate internally.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);""",
"RSA_blinding_on")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);""",
"""/**
 * @brief Verify and remove PKCS#1 v1.5 type-1 (signing) padding (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block to check.
 * @param fl Length of @p f in bytes.
 * @param rsa_len Expected RSA modulus size in bytes.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);""",
"RSA_padding_check_PKCS1_type_1")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    const unsigned char *p, int pl);""",
"""/**
 * @brief Apply PKCS#1 OAEP padding using SHA-1 / MGF1-SHA-1 defaults (deprecated).
 * @param to Destination encoded block of length @p tlen.
 * @param tlen RSA modulus size in bytes.
 * @param f Message bytes to pad.
 * @param fl Length of @p f in bytes.
 * @param p Optional OAEP encoding parameter / label bytes, or NULL.
 * @param pl Length of @p p in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    const unsigned char *p, int pl);""",
"RSA_padding_add_PKCS1_OAEP")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    int num,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);""",
"""/**
 * @brief Verify PKCS#1 OAEP padding with explicit digests and recover the message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param from Encoded OAEP block.
 * @param flen Length of @p from in bytes.
 * @param num RSA modulus size in bytes.
 * @param param Optional OAEP label bytes, or NULL.
 * @param plen Length of @p param in bytes.
 * @param md Hash used by OAEP, or NULL for SHA-1.
 * @param mgf1md Hash used by MGF1, or NULL to use @p md.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    int num,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);""",
"RSA_padding_check_PKCS1_OAEP_mgf1")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
"""/**
 * @brief Copy @p f into @p to with no padding (lengths must match) (deprecated).
 * @param to Destination block of length @p tlen.
 * @param tlen RSA modulus size in bytes; must equal @p fl.
 * @param f Message bytes.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 if lengths differ / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_none(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
"RSA_padding_add_none")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
"""/**
 * @brief Apply ANSI X9.31 padding to a message block (deprecated).
 * @param to Destination encoded block of length @p tlen.
 * @param tlen RSA modulus size in bytes.
 * @param f Message / hash bytes to pad.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_add_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
"RSA_padding_add_X931")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);""",
"""/**
 * @brief Verify ANSI X9.31 padding and recover the message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded block to check.
 * @param fl Length of @p f in bytes.
 * @param rsa_len Expected RSA modulus size in bytes.
 * @return Length of the recovered message, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_padding_check_X931(unsigned char *to, int tlen,
    const unsigned char *f, int fl,
    int rsa_len);""",
"RSA_padding_check_X931")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
    const unsigned char *mHash, const EVP_MD *Hash,
    int sLen);""",
"""/**
 * @brief Encode an EMSA-PSS padded block for RSA signature (deprecated).
 * @param rsa RSA key providing the modulus length.
 * @param EM Destination encoded message of length RSA_size(@p rsa).
 * @param mHash Hash of the message being signed.
 * @param Hash Digest method that produced @p mHash (and used by MGF1 unless configured otherwise).
 * @param sLen Salt length in bytes, or RSA_PSS_SALTLEN_* special values.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
    const unsigned char *mHash, const EVP_MD *Hash,
    int sLen);""",
"RSA_padding_add_PKCS1_PSS")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_set_ex_data(RSA *r, int idx, void *arg);",
"""/**
 * @brief Store application data on an RSA key at CRYPTO_EX index @p idx (deprecated).
 * @param r RSA key receiving the data.
 * @param idx Index from CRYPTO_get_ex_new_index() for RSA.
 * @param arg Pointer to store; ownership rules follow CRYPTO_EX_DATA.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set_ex_data(RSA *r, int idx, void *arg);""",
"RSA_set_ex_data")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 void RSA_meth_free(RSA_METHOD *meth);",
"""/**
 * @brief Free an RSA_METHOD allocated with RSA_meth_new() (deprecated).
 * @param meth Method table to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_meth_free(RSA_METHOD *meth);""",
"RSA_meth_free")

patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0 int RSA_meth_set0_app_data(RSA_METHOD *meth,
    void *app_data);""",
"""/**
 * @brief Attach application data to an RSA_METHOD without copying (deprecated).
 * @param meth Method table to update.
 * @param app_data Opaque pointer stored on @p meth (not freed by RSA_meth_free).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_set0_app_data(RSA_METHOD *meth,
    void *app_data);""",
"RSA_meth_set0_app_data")

print(f"\nDone 8b: {len(ok)} ok, {len(missing)} missing")
if missing:
    print("MISSING:", *missing, sep="\n  ")
