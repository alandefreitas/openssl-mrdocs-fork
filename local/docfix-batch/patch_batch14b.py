#!/usr/bin/env python3
"""Documentation repair batch 14b: dh, ec, engine, err, and early/mid evp.h."""
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


def cipher_getter(name, brief):
    return (
        f"const EVP_CIPHER *{name}(void);\n",
        f"""/**
 * @brief Return the EVP_CIPHER for {brief}.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *{name}(void);
""",
        name,
    )


def md_getter(name, brief):
    return (
        f"const EVP_MD *{name}(void);\n",
        f"""/**
 * @brief Return the EVP_MD for {brief}.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
const EVP_MD *{name}(void);
""",
        name,
    )


print("=== batch 14b ===")

# ----- dh.h -----
patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
""",
    """/**
 * @brief Set the DH parameter-generation generator (g) on @p ctx.
 * @param ctx Keygen/paramgen context for a DH key type.
 * @param gen Generator value (commonly 2 or 5).
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
""",
    "EVP_PKEY_CTX_set_dh_paramgen_generator",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_KDF_X9_42(unsigned char *out, size_t outlen,
    const unsigned char *Z, size_t Zlen,
    ASN1_OBJECT *key_oid,
    const unsigned char *ukm,
    size_t ukmlen, const EVP_MD *md);
""",
    """/**
 * @brief Derive keying material with the ANSI X9.42 / RFC 2631 KDF (deprecated).
 * @param out Output buffer of @p outlen bytes receiving the derived key.
 * @param outlen Desired derived-key length.
 * @param Z Shared secret bytes.
 * @param Zlen Length of @p Z.
 * @param key_oid Algorithm OID embedded in the OtherInfo structure.
 * @param ukm Optional partyInfo/UKM bytes, or NULL.
 * @param ukmlen Length of @p ukm when non-NULL.
 * @param md Message digest used by the KDF.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_KDF_X9_42(unsigned char *out, size_t outlen,
    const unsigned char *Z, size_t Zlen,
    ASN1_OBJECT *key_oid,
    const unsigned char *ukm,
    size_t ukmlen, const EVP_MD *md);
""",
    "DH_KDF_X9_42",
)

# ----- ec.h -----
patch_one(
    "ec.h",
    """const char *OSSL_EC_curve_nid2name(int nid);
""",
    """/**
 * @brief Return the short name of a built-in elliptic curve given its NID.
 * @param nid Curve NID (for example NID_X9_62_prime256v1).
 * @return NUL-terminated curve name, or NULL if @p nid is not a known EC curve.
 */
const char *OSSL_EC_curve_nid2name(int nid);
""",
    "OSSL_EC_curve_nid2name",
)

# ----- engine.h -----
patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_load_builtin_engines(void);
""",
    """/**
 * @brief Register all compiled-in ENGINE implementations (deprecated in OpenSSL 3).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_load_builtin_engines(void);
""",
    "ENGINE_load_builtin_engines",
)

# ----- err.h -----
patch_both(
    "err.h",
    """unsigned long ERR_peek_last_error_func(const char **func);
""",
    """/**
 * @brief Peek at the newest error code and optionally its function name.
 * @param func Receives the function name string associated with the error, or may be NULL.
 * @return Newest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_last_error_func(const char **func);
""",
    "ERR_peek_last_error_func",
)

patch_both(
    "err.h",
    """OSSL_DEPRECATEDIN_3_0
unsigned long ERR_peek_last_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    """/**
 * @brief Peek at the newest error with file, line, data, and flags (deprecated).
 * @param file Receives the source file name, or may be NULL.
 * @param line Receives the source line number, or may be NULL.
 * @param data Receives optional error data string, or may be NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or may be NULL.
 * @return Newest error code, or 0 if the queue is empty (queue unchanged).
 */
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_peek_last_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    "ERR_peek_last_error_line_data",
)

patch_both(
    "err.h",
    """void ERR_print_errors(BIO *bp);
""",
    """/**
 * @brief Print and clear all queued OpenSSL errors to BIO @p bp.
 * @param bp Destination BIO for human-readable error lines.
 */
void ERR_print_errors(BIO *bp);
""",
    "ERR_print_errors",
)

patch_both(
    "err.h",
    """int ERR_pop_to_mark(void);
""",
    """/**
 * @brief Pop errors until (and including) the most recent mark set by ERR_set_mark().
 * @return 1 if a mark was found and cleared, or 0 if no mark was present.
 */
int ERR_pop_to_mark(void);
""",
    "ERR_pop_to_mark",
)

patch_both(
    "err.h",
    """void OSSL_ERR_STATE_save(ERR_STATE *es);
""",
    """/**
 * @brief Copy the current thread's error queue into @p es and clear the thread queue.
 * @param es Destination error-state object from OSSL_ERR_STATE_new().
 */
void OSSL_ERR_STATE_save(ERR_STATE *es);
""",
    "OSSL_ERR_STATE_save",
)

# ----- evp.h: deprecated meth setters / early API -----
patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx, unsigned char *md));
""",
    """/**
 * @brief Set the final callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed with EVP_MD_meth_new().
 * @param final Callback that writes the digest and finalises @p ctx.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx, unsigned char *md));
""",
    "EVP_MD_meth_set_final",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to, const EVP_MD_CTX *from));
""",
    """/**
 * @brief Set the context-copy callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed with EVP_MD_meth_new().
 * @param copy Callback that duplicates digest state from @p from into @p to.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to, const EVP_MD_CTX *from));
""",
    "EVP_MD_meth_set_copy",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);
""",
    """/**
 * @brief Free a custom EVP_CIPHER created with EVP_CIPHER_meth_new() (deprecated).
 * @param cipher Cipher method to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);
""",
    "EVP_CIPHER_meth_free",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
""",
    """/**
 * @brief Set EVP_CIPH_* capability flags on a custom EVP_CIPHER (deprecated).
 * @param cipher Cipher method being constructed.
 * @param flags Combination of EVP_CIPH_* flags (mode, variable length, AEAD, …).
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
""",
    "EVP_CIPHER_meth_set_flags",
)

patch_one(
    "evp.h",
    """int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name);
""",
    """/**
 * @brief Test whether @p cipher is known under algorithm name @p name.
 * @param cipher Cipher implementation to query.
 * @param name Algorithm name or alias (for example "AES-128-CBC").
 * @return 1 if @p name identifies @p cipher, or 0 otherwise.
 */
int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name);
""",
    "EVP_CIPHER_is_a",
)

patch_one(
    "evp.h",
    """int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
""",
    """/**
 * @brief Increment the reference count on a fetched EVP_CIPHER.
 * @param cipher Cipher object from EVP_CIPHER_fetch() / similar.
 * @return 1 on success, or 0 on error.
 */
int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
""",
    "EVP_CIPHER_up_ref",
)

patch_one(
    "evp.h",
    """int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
""",
    """/**
 * @brief Return the IV length in bytes for the cipher currently set on @p ctx.
 * @param ctx Initialised cipher context.
 * @return IV length in bytes, or 0 if the cipher uses no IV / on error.
 */
int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
""",
    "EVP_CIPHER_CTX_get_iv_length",
)

patch_one(
    "evp.h",
    """void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
""",
    """/**
 * @brief Store an application pointer on a cipher context.
 * @param ctx Cipher context.
 * @param data Opaque pointer retained until overwritten or the context is freed.
 */
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
""",
    "EVP_CIPHER_CTX_set_app_data",
)

patch_one(
    "evp.h",
    """void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
""",
    """/**
 * @brief Return the cipher-implementation private data pointer for @p ctx.
 * @param ctx Cipher context.
 * @return Implementation-specific data pointer, or NULL if unset.
 */
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
""",
    "EVP_CIPHER_CTX_get_cipher_data",
)

patch_one(
    "evp.h",
    """void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
""",
    """/**
 * @brief Replace the cipher-implementation private data pointer on @p ctx.
 * @param ctx Cipher context.
 * @param cipher_data New implementation data pointer (ownership remains with the caller/impl).
 * @return The previous cipher-data pointer.
 */
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
""",
    "EVP_CIPHER_CTX_set_cipher_data",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx);
""",
    """/**
 * @brief Describe OSSL_PARAM keys that can be retrieved from digest context @p ctx.
 * @param ctx Digest context whose gettable parameters are queried.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx);
""",
    "EVP_MD_CTX_gettable_params",
)

patch_one(
    "evp.h",
    """EVP_MD_CTX *EVP_MD_CTX_new(void);
""",
    """/**
 * @brief Allocate a new digest context.
 * @return New EVP_MD_CTX, or NULL on allocation failure; free with EVP_MD_CTX_free().
 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
""",
    "EVP_MD_CTX_new",
)

patch_one(
    "evp.h",
    """int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
""",
    """/**
 * @brief Reset @p ctx so it can be reused with EVP_DigestInit_ex() without freeing it.
 * @param ctx Digest context to clear.
 * @return 1 on success, or 0 on error.
 */
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
""",
    "EVP_MD_CTX_reset",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
    ENGINE *impl);
""",
    """/**
 * @brief Initialise digest context @p ctx for algorithm @p type.
 * @param ctx Digest context to initialise (from EVP_MD_CTX_new()).
 * @param type Digest algorithm (for example from EVP_sha256()), or NULL to reuse the previous type.
 * @param impl Legacy ENGINE implementing @p type, or NULL for the default implementation.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
    ENGINE *impl);
""",
    "EVP_DigestInit_ex",
)

patch_one(
    "evp.h",
    """void EVP_MD_free(EVP_MD *md);
""",
    """/**
 * @brief Free a fetched EVP_MD (decrement its reference count).
 * @param md Digest method from EVP_MD_fetch(), or NULL.
 */
void EVP_MD_free(EVP_MD *md);
""",
    "EVP_MD_free",
)

patch_one(
    "evp.h",
    """int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
""",
    """/**
 * @brief Prompt on the terminal for a password into @p buf.
 * @param buf Destination buffer receiving the password (NUL-terminated).
 * @param length Capacity of @p buf in bytes including the NUL terminator.
 * @param prompt Prompt string shown to the user, or NULL for the default.
 * @param verify Nonzero to ask twice and require matching input.
 * @return 0 on success, a negative value on mismatch/cancel, or a positive UI error code.
 */
int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
""",
    "EVP_read_pw_string",
)

patch_one(
    "evp.h",
    """char *EVP_get_pw_prompt(void);
""",
    """/**
 * @brief Return the process-wide default password prompt string.
 * @return Pointer to the current prompt (do not free), never NULL after library init.
 */
char *EVP_get_pw_prompt(void);
""",
    "EVP_get_pw_prompt",
)

patch_one(
    "evp.h",
    """__owur int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv, int enc);
""",
    """/**
 * @brief Initialise @p ctx for encryption or decryption with @p cipher.
 * @param ctx Cipher context to initialise.
 * @param cipher Cipher algorithm, or NULL to keep the current cipher and change key/IV/dir.
 * @param impl Legacy ENGINE, or NULL for the default implementation.
 * @param key Raw key bytes, or NULL to set later.
 * @param iv IV/nonce bytes, or NULL when not required / set later.
 * @param enc 1 to encrypt, 0 to decrypt, or -1 to leave the direction unchanged.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv, int enc);
""",
    "EVP_CipherInit_ex",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
""",
    """/**
 * @brief Initialise @p ctx for a one-shot or streaming DigestSign with key @p pkey.
 * @param ctx Digest/sign context to initialise.
 * @param pctx Optional out-parameter receiving the internal EVP_PKEY_CTX, or NULL.
 * @param type Digest to use, or NULL for algorithms that do not take a separate MD.
 * @param e Legacy ENGINE, or NULL.
 * @param pkey Private key used for signing.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
""",
    "EVP_DigestSignInit",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
""",
    """/**
 * @brief Initialise @p ctx for a DigestVerify operation with public key @p pkey.
 * @param ctx Digest/verify context to initialise.
 * @param pctx Optional out-parameter receiving the internal EVP_PKEY_CTX, or NULL.
 * @param type Digest to use, or NULL for algorithms that do not take a separate MD.
 * @param e Legacy ENGINE, or NULL.
 * @param pkey Public key used for verification.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
""",
    "EVP_DigestVerifyInit",
)

patch_one(
    "evp.h",
    """void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
""",
    """/**
 * @brief Initialise a Base64 encode context for EVP_EncodeUpdate/Final.
 * @param ctx Encode context (typically from EVP_ENCODE_CTX_new()).
 */
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
""",
    "EVP_EncodeInit",
)

patch_one(
    "evp.h",
    """int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
""",
    """/**
 * @brief Finish a Base64 decode, flushing any remaining decoded bytes.
 * @param ctx Decode context previously used with EVP_DecodeUpdate().
 * @param out Buffer receiving final decoded bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or a negative value on decode error.
 */
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
""",
    "EVP_DecodeFinal",
)

patch_one(
    "evp.h",
    """int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Set provider parameters on an initialised cipher context.
 * @param ctx Cipher context.
 * @param params NULL-terminated OSSL_PARAM array of values to apply.
 * @return 1 on success, or 0 on error.
 */
int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_CIPHER_CTX_set_params",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher);
""",
    """/**
 * @brief Describe OSSL_PARAM keys that may be set on contexts of @p cipher.
 * @param cipher Cipher implementation to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher);
""",
    "EVP_CIPHER_settable_ctx_params",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher);
""",
    """/**
 * @brief Describe OSSL_PARAM keys that may be retrieved from contexts of @p cipher.
 * @param cipher Cipher implementation to query.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher);
""",
    "EVP_CIPHER_gettable_ctx_params",
)

patch_one(
    "evp.h",
    """const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx);
""",
    """/**
 * @brief Describe OSSL_PARAM keys gettable from the cipher currently bound to @p ctx.
 * @param ctx Cipher context.
 * @return NULL-terminated OSSL_PARAM descriptor array, or NULL on error.
 */
const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx);
""",
    "EVP_CIPHER_CTX_gettable_params",
)

# digests / ciphers getters
for old, new, label in [
    md_getter("EVP_sha512_256", "SHA-512/256"),
    md_getter("EVP_sha3_224", "SHA3-224"),
    md_getter("EVP_sha3_384", "SHA3-384"),
    cipher_getter("EVP_des_ecb", "DES in ECB mode"),
    cipher_getter("EVP_des_ede3", "triple-DES EDE with three keys in ECB mode"),
    cipher_getter("EVP_des_cfb1", "DES in 1-bit CFB mode"),
    cipher_getter("EVP_des_ede3_cfb64", "triple-DES EDE in 64-bit CFB mode"),
    cipher_getter("EVP_des_cbc", "DES in CBC mode"),
    cipher_getter("EVP_rc4_40", "RC4 with a 40-bit effective key (legacy)"),
    cipher_getter("EVP_idea_ecb", "IDEA in ECB mode"),
    cipher_getter("EVP_rc2_ecb", "RC2 in ECB mode"),
    cipher_getter("EVP_rc2_64_cbc", "RC2-64 in CBC mode"),
    cipher_getter("EVP_cast5_cfb64", "CAST5 in 64-bit CFB mode"),
    cipher_getter("EVP_aes_128_cbc", "AES-128 in CBC mode"),
    cipher_getter("EVP_aes_128_wrap", "AES-128 key wrap (RFC 3394)"),
    cipher_getter("EVP_aes_256_ccm", "AES-256 in CCM mode"),
    cipher_getter("EVP_aes_256_ocb", "AES-256 in OCB mode"),
    cipher_getter("EVP_aria_128_cfb1", "ARIA-128 in 1-bit CFB mode"),
    cipher_getter("EVP_camellia_128_ecb", "Camellia-128 in ECB mode"),
    cipher_getter("EVP_camellia_128_cfb128", "Camellia-128 in 128-bit CFB mode"),
    cipher_getter("EVP_chacha20_poly1305", "ChaCha20-Poly1305 AEAD"),
    cipher_getter("EVP_sm4_ecb", "SM4 in ECB mode"),
]:
    patch_one("evp.h", old, new, label)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
