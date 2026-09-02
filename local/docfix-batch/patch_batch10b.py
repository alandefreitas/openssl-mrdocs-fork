#!/usr/bin/env python3
"""Documentation repair batch 10b: evp.h non-cipher-getter APIs."""
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


def cipher(name, mode_brief):
    decl = f"const EVP_CIPHER *{name}(void);"
    patch_both(
        "evp.h",
        decl,
        f"""/**
 * @brief Return the EVP_CIPHER for {mode_brief}.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
{decl}""",
        name,
    )


def digest(name, brief):
    decl = f"const EVP_MD *{name}(void);"
    patch_both(
        "evp.h",
        decl,
        f"""/**
 * @brief Return the EVP_MD for {brief}.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
{decl}""",
        name,
    )


# ----- cipher / digest getters -----
digest("EVP_md5_sha1", "the combined MD5-SHA-1 digest used by TLS 1.0/1.1")
digest("EVP_blake2b512", "BLAKE2b-512")
digest("EVP_sha384", "SHA-384")
digest("EVP_mdc2", "MDC2")
digest("EVP_ripemd160", "RIPEMD-160")
digest("EVP_sm3", "SM3")

cipher("EVP_enc_null", "the null (pass-through) cipher")
cipher("EVP_des_ede", "two-key triple-DES in CBC mode (alias of EVP_des_ede_cbc)")
cipher("EVP_des_ede_ecb", "two-key triple-DES in ECB mode")
cipher("EVP_des_ede3_ecb", "three-key triple-DES in ECB mode")
cipher("EVP_des_ede3_cfb1", "three-key triple-DES in 1-bit CFB mode")
cipher("EVP_des_ede3_cfb8", "three-key triple-DES in 8-bit CFB mode")
cipher("EVP_des_ede3_ofb", "three-key triple-DES in OFB mode")
cipher("EVP_idea_ofb", "IDEA in OFB mode")
cipher("EVP_bf_cfb64", "Blowfish in 64-bit CFB mode")
cipher("EVP_aes_128_cfb1", "AES-128 in 1-bit CFB mode")
cipher("EVP_aes_128_cfb128", "AES-128 in 128-bit CFB mode")
cipher("EVP_aes_128_ofb", "AES-128 in OFB mode")
cipher("EVP_aes_128_xts", "AES-128 in XTS mode")
cipher("EVP_aes_192_ofb", "AES-192 in OFB mode")
cipher("EVP_aes_192_ccm", "AES-192 in CCM mode")
cipher("EVP_aes_256_cbc", "AES-256 in CBC mode")
cipher("EVP_aes_256_ofb", "AES-256 in OFB mode")
cipher("EVP_aes_256_gcm", "AES-256 in GCM mode")
cipher("EVP_aes_256_wrap", "AES-256 key wrap (RFC 3394)")
cipher("EVP_aes_256_wrap_pad", "AES-256 key wrap with padding (RFC 5649)")
cipher("EVP_aes_128_cbc_hmac_sha256", "AES-128-CBC with HMAC-SHA256 (TLS AEAD)")
cipher("EVP_aes_256_cbc_hmac_sha256", "AES-256-CBC with HMAC-SHA256 (TLS AEAD)")
cipher("EVP_aria_128_ctr", "ARIA-128 in CTR mode")
cipher("EVP_aria_128_ccm", "ARIA-128 in CCM mode")
cipher("EVP_aria_192_ecb", "ARIA-192 in ECB mode")
cipher("EVP_aria_192_ofb", "ARIA-192 in OFB mode")
cipher("EVP_aria_192_ccm", "ARIA-192 in CCM mode")
cipher("EVP_aria_256_cbc", "ARIA-256 in CBC mode")
cipher("EVP_aria_256_cfb128", "ARIA-256 in 128-bit CFB mode")
cipher("EVP_aria_256_ofb", "ARIA-256 in OFB mode")
cipher("EVP_aria_256_gcm", "ARIA-256 in GCM mode")
cipher("EVP_camellia_192_ecb", "Camellia-192 in ECB mode")
cipher("EVP_camellia_192_cfb8", "Camellia-192 in 8-bit CFB mode")
cipher("EVP_camellia_192_ctr", "Camellia-192 in CTR mode")
cipher("EVP_camellia_256_ctr", "Camellia-256 in CTR mode")
cipher("EVP_seed_cfb128", "SEED in 128-bit CFB mode")
cipher("EVP_sm4_cbc", "SM4 in CBC mode")
cipher("EVP_sm4_cfb128", "SM4 in 128-bit CFB mode")
cipher("EVP_sm4_ctr", "SM4 in CTR mode")

# ----- EVP_CIPHER_meth / MD params / encrypt pipeline -----
patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);""",
    """/**
 * @brief Set the IV length advertised by a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method under construction.
 * @param iv_len IV length in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);""",
    "EVP_CIPHER_meth_set_iv_length",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_MD_gettable_ctx_params(const EVP_MD *md);",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_MD context.
 * @param md Digest algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MD_gettable_ctx_params(const EVP_MD *md);""",
    "EVP_MD_gettable_ctx_params",
)

patch_both(
    "evp.h",
    "void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);",
    """/**
 * @brief Set flag bits on a cipher context without clearing existing flags.
 * @param ctx Cipher context to update.
 * @param flags Bitmask of EVP_CIPH_* context flags to set.
 */
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);""",
    "EVP_CIPHER_CTX_set_flags",
)

patch_both(
    "evp.h",
    """__owur int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);""",
    """/**
 * @brief Initialize @p ctx for encryption with an optional ENGINE implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param impl Optional ENGINE providing the implementation, or NULL.
 * @param key Encryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);""",
    "EVP_EncryptInit_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);""",
    """/**
 * @brief Finalize encryption and write any remaining ciphertext (including padding).
 * @param ctx Cipher context previously used with EVP_EncryptUpdate().
 * @param out Buffer receiving final ciphertext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl);""",
    "EVP_EncryptFinal_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);""",
    """/**
 * @brief Initialize @p ctx for decryption with an optional ENGINE implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param impl Optional ENGINE providing the implementation, or NULL.
 * @param key Decryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key,
    const unsigned char *iv);""",
    "EVP_DecryptInit_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc);""",
    """/**
 * @brief Initialize @p ctx for encryption or decryption using the default implementation.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the current algorithm.
 * @param key Key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not required / set later.
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv,
    int enc);""",
    "EVP_CipherInit",
)

patch_both(
    "evp.h",
    """__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    """/**
 * @brief Finalize a cipher operation and write any remaining output bytes.
 * @param ctx Cipher context previously used with EVP_CipherUpdate().
 * @param outm Buffer receiving final output bytes.
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    "EVP_CipherFinal",
)

patch_both(
    "evp.h",
    """__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    """/**
 * @brief Finalize a cipher operation (extended form) and write any remaining output.
 * @param ctx Cipher context previously used with EVP_CipherUpdate().
 * @param outm Buffer receiving final output bytes.
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    "EVP_CipherFinal_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey);""",
    """/**
 * @brief Finish a legacy Sign operation and write the signature using @p pkey.
 * @param ctx Digest/sign context that has absorbed the message via EVP_DigestUpdate().
 * @param md Output buffer for the signature.
 * @param s Receives the signature length in bytes.
 * @param pkey Private key used to produce the signature.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey);""",
    "EVP_SignFinal",
)

patch_both(
    "evp.h",
    """__owur int EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    """/**
 * @brief Finish a legacy Sign operation with an explicit library context and property query.
 * @param ctx Digest/sign context that has absorbed the message via EVP_DigestUpdate().
 * @param md Output buffer for the signature.
 * @param s Receives the signature length in bytes.
 * @param pkey Private key used to produce the signature.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
    EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    "EVP_SignFinal_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen, const unsigned char *tbs,
    size_t tbslen);""",
    """/**
 * @brief Sign @p tbs in one call using a prepared DigestSign context.
 * @param ctx Context initialized with EVP_DigestSignInit().
 * @param sigret Output buffer for the signature, or NULL to query the required length.
 * @param siglen On input, size of @p sigret; on output, signature length.
 * @param tbs Message bytes to sign ("to be signed").
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen, const unsigned char *tbs,
    size_t tbslen);""",
    "EVP_DigestSign",
)

patch_both(
    "evp.h",
    """__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
    size_t siglen);""",
    """/**
 * @brief Finish a DigestVerify operation by checking @p sig against the digested data.
 * @param ctx Context initialized with EVP_DigestVerifyInit() and updated with the message.
 * @param sig Signature bytes to verify.
 * @param siglen Length of @p sig in bytes.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
    size_t siglen);""",
    "EVP_DigestVerifyFinal",
)

patch_both(
    "evp.h",
    "__owur int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);",
    """/**
 * @brief Finalize an open (envelope decrypt) operation and write any remaining plaintext.
 * @param ctx Cipher context initialized with EVP_OpenInit().
 * @param out Buffer receiving final plaintext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);""",
    "EVP_OpenFinal",
)

patch_both(
    "evp.h",
    """__owur int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    unsigned char **ek, int *ekl, unsigned char *iv,
    EVP_PKEY **pubk, int npubk);""",
    """/**
 * @brief Initialize a seal (envelope encrypt) operation for @p npubk recipients.
 * @param ctx Cipher context that will encrypt the content with a generated session key.
 * @param type Symmetric cipher used for the content.
 * @param ek Array of buffers receiving per-recipient encrypted session keys.
 * @param ekl Array receiving the encrypted-key lengths written to @p ek.
 * @param iv Buffer receiving the generated IV (sized for @p type), or NULL if unused.
 * @param pubk Array of recipient public keys used to wrap the session key.
 * @param npubk Number of entries in @p pubk / @p ek / @p ekl.
 * @return Number of recipients successfully processed, or 0 on failure.
 */
__owur int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    unsigned char **ek, int *ekl, unsigned char *iv,
    EVP_PKEY **pubk, int npubk);""",
    "EVP_SealInit",
)

patch_both(
    "evp.h",
    "int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx);",
    """/**
 * @brief Copy a Base64 encode/decode context.
 * @param dctx Destination context (must already be allocated).
 * @param sctx Source context to copy from.
 * @return 1 on success, or 0 on failure.
 */
int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx);""",
    "EVP_ENCODE_CTX_copy",
)

patch_both(
    "evp.h",
    "int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);",
    """/**
 * @brief Return the number of pending (unflushed) bytes in an encode/decode context.
 * @param ctx Encode/decode context to query.
 * @return Number of buffered input bytes awaiting encoding or decoding.
 */
int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);""",
    "EVP_ENCODE_CTX_num",
)

patch_both(
    "evp.h",
    """int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);""",
    """/**
 * @brief Base64-encode a chunk of input, writing complete output lines to @p out.
 * @param ctx Encode context initialized with EVP_EncodeInit().
 * @param out Buffer receiving encoded output (may be empty if data was only buffered).
 * @param outl Receives the number of bytes written to @p out.
 * @param in Input octets to encode.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);""",
    "EVP_EncodeUpdate",
)

patch_both(
    "evp.h",
    "void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);",
    """/**
 * @brief Flush remaining Base64-encoded output from an encode context.
 * @param ctx Encode context previously used with EVP_EncodeUpdate().
 * @param out Buffer receiving the final encoded bytes (and trailing newline when applicable).
 * @param outl Receives the number of bytes written to @p out.
 */
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);""",
    "EVP_EncodeFinal",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);",
    """/**
 * @brief Generate a random key suitable for the cipher currently set on @p ctx.
 * @param ctx Cipher context whose algorithm determines the key length.
 * @param key Buffer receiving the generated key (at least EVP_CIPHER_CTX_get_key_length() bytes).
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);""",
    "EVP_CIPHER_CTX_rand_key",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher);",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_CIPHER algorithm.
 * @param cipher Cipher algorithm whose gettable parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher);""",
    "EVP_CIPHER_gettable_params",
)

patch_both(
    "evp.h",
    "const BIO_METHOD *BIO_f_reliable(void);",
    """/**
 * @brief Return the BIO filter method that adds a digest-protected reliable stream.
 * @return Pointer to the BIO_f_reliable method.
 *
 * Writes are checksummed so a reader can detect truncation or corruption.
 */
const BIO_METHOD *BIO_f_reliable(void);""",
    "BIO_f_reliable",
)

patch_both(
    "evp.h",
    "int EVP_add_cipher(const EVP_CIPHER *cipher);",
    """/**
 * @brief Register @p cipher in the legacy EVP cipher name table.
 * @param cipher Cipher method to add (must remain valid for the process lifetime).
 * @return 1 on success, or 0 on failure.
 */
int EVP_add_cipher(const EVP_CIPHER *cipher);""",
    "EVP_add_cipher",
)

patch_both(
    "evp.h",
    "int EVP_add_digest(const EVP_MD *digest);",
    """/**
 * @brief Register @p digest in the legacy EVP digest name table.
 * @param digest Digest method to add (must remain valid for the process lifetime).
 * @return 1 on success, or 0 on failure.
 */
int EVP_add_digest(const EVP_MD *digest);""",
    "EVP_add_digest",
)

patch_both(
    "evp.h",
    """void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph,
                           const char *from, const char *to, void *x),
    void *arg);""",
    """/**
 * @brief Invoke @p fn for every cipher name mapping in the legacy EVP cipher table.
 * @param fn Callback receiving the cipher method, from-name, to-name, and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph,
                           const char *from, const char *to, void *x),
    void *arg);""",
    "EVP_CIPHER_do_all",
)

patch_both(
    "evp.h",
    """void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph, const char *from,
                                  const char *to, void *x),
    void *arg);""",
    """/**
 * @brief Invoke @p fn for every cipher name mapping, in sorted name order.
 * @param fn Callback receiving the cipher method, from-name, to-name, and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph, const char *from,
                                  const char *to, void *x),
    void *arg);""",
    "EVP_CIPHER_do_all_sorted",
)

# ----- MAC -----
patch_both(
    "evp.h",
    """EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);""",
    """/**
 * @brief Fetch a MAC algorithm implementation from providers.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param algorithm MAC algorithm name (for example "HMAC" or "CMAC").
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_MAC (refcount 1), or NULL on error; free with EVP_MAC_free().
 */
EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);""",
    "EVP_MAC_fetch",
)

patch_both(
    "evp.h",
    "void EVP_MAC_free(EVP_MAC *mac);",
    """/**
 * @brief Release a reference to a fetched EVP_MAC.
 * @param mac MAC algorithm to free; NULL is ignored.
 */
void EVP_MAC_free(EVP_MAC *mac);""",
    "EVP_MAC_free",
)

patch_both(
    "evp.h",
    "const char *EVP_MAC_get0_description(const EVP_MAC *mac);",
    """/**
 * @brief Return a human-readable description of a MAC algorithm.
 * @param mac MAC algorithm to query.
 * @return Internal description string (do not free), or NULL if none is provided.
 */
const char *EVP_MAC_get0_description(const EVP_MAC *mac);""",
    "EVP_MAC_get0_description",
)

patch_both(
    "evp.h",
    "void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);",
    """/**
 * @brief Free a MAC context and its associated resources.
 * @param ctx Context to free; NULL is ignored.
 */
void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);""",
    "EVP_MAC_CTX_free",
)

patch_both(
    "evp.h",
    "EVP_MAC *EVP_MAC_CTX_get0_mac(EVP_MAC_CTX *ctx);",
    """/**
 * @brief Return the EVP_MAC associated with a MAC context.
 * @param ctx MAC context to query.
 * @return Internal EVP_MAC pointer (do not free), or NULL if unset.
 */
EVP_MAC *EVP_MAC_CTX_get0_mac(EVP_MAC_CTX *ctx);""",
    "EVP_MAC_CTX_get0_mac",
)

patch_both(
    "evp.h",
    "int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);",
    """/**
 * @brief Get parameters from a MAC context.
 * @param ctx MAC context to query.
 * @param params Array of OSSL_PARAM request/response descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);""",
    "EVP_MAC_CTX_get_params",
)

patch_both(
    "evp.h",
    "size_t EVP_MAC_CTX_get_block_size(EVP_MAC_CTX *ctx);",
    """/**
 * @brief Return the MAC block size for the algorithm bound to @p ctx.
 * @param ctx Initialized MAC context.
 * @return Block size in bytes, or 0 if unavailable.
 */
size_t EVP_MAC_CTX_get_block_size(EVP_MAC_CTX *ctx);""",
    "EVP_MAC_CTX_get_block_size",
)

patch_both(
    "evp.h",
    "int EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize);",
    """/**
 * @brief Finalize an XOF-style MAC and write @p outsize bytes of output.
 * @param ctx MAC context that has absorbed input via EVP_MAC_update().
 * @param out Buffer receiving the MAC output.
 * @param outsize Number of output bytes requested.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize);""",
    "EVP_MAC_finalXOF",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from an EVP_MAC context.
 * @param mac MAC algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);""",
    "EVP_MAC_gettable_ctx_params",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_MAC_CTX_gettable_params(EVP_MAC_CTX *ctx);",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from a live MAC context.
 * @param ctx MAC context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MAC_CTX_gettable_params(EVP_MAC_CTX *ctx);""",
    "EVP_MAC_CTX_gettable_params",
)

# ----- PKEY misc -----
patch_both(
    "evp.h",
    """int EVP_PKEY_type_names_do_all(const EVP_PKEY *pkey,
    void (*fn)(const char *name, void *data),
    void *data);""",
    """/**
 * @brief Invoke @p fn for every algorithm name associated with @p pkey's type.
 * @param pkey Key whose type names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_type_names_do_all(const EVP_PKEY *pkey,
    void (*fn)(const char *name, void *data),
    void *data);""",
    "EVP_PKEY_type_names_do_all",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);",
    """/**
 * @brief Control whether algorithm parameters are written when serializing @p pkey.
 * @param pkey Key whose parameter-export preference is updated.
 * @param mode Non-zero to include parameters on output, or 0 to omit them when possible.
 * @return Previous mode value.
 */
int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);""",
    "EVP_PKEY_save_parameters",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);",
    """/**
 * @brief Compare two keys for equality of type, parameters, and key material.
 * @param a First key.
 * @param b Second key.
 * @return 1 if equal, 0 if not equal, or a negative value on error.
 */
int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);""",
    "EVP_PKEY_eq",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);",
    """/**
 * @brief Return the default message-digest NID associated with @p pkey.
 * @param pkey Key whose signature defaults are queried.
 * @param pnid Receives the NID (for example NID_sha256), or NID_undef when unrestricted.
 * @return 1 if an advisory default was returned, 2 if the digest is mandatory, or a non-positive value on error.
 */
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);""",
    "EVP_PKEY_get_default_digest_nid",
)

patch_both(
    "evp.h",
    """int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de);""",
    """/**
 * @brief Derive a key and IV from a PKCS#5 v2 PBE AlgorithmIdentifier and initialize @p ctx.
 * @param ctx Cipher context to initialize for encryption or decryption.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if @p pass is a NUL-terminated string.
 * @param param ASN.1 parameters from the PBE AlgorithmIdentifier.
 * @param cipher Cipher suggested by the caller (may be overridden by @p param).
 * @param md Digest suggested by the caller (may be overridden by @p param).
 * @param en_de Non-zero to encrypt, zero to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de);""",
    "PKCS5_v2_PBE_keyivgen",
)

patch_both(
    "evp.h",
    """int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen);""",
    """/**
 * @brief Look up a registered password-based encryption (PBE) algorithm by NID.
 * @param type PBE application type such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE AlgorithmIdentifier.
 * @param pcnid Optional destination for the cipher NID, or NULL.
 * @param pmnid Optional destination for the digest/PRF NID, or NULL.
 * @param pkeygen Optional destination for the keygen function pointer, or NULL.
 * @return 1 if found, or 0 otherwise.
 */
int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
    EVP_PBE_KEYGEN **pkeygen);""",
    "EVP_PBE_find",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);",
    """/**
 * @brief Find a registered EVP_PKEY_METHOD by key type NID (deprecated).
 * @param type Key type such as EVP_PKEY_RSA.
 * @return Matching method, or NULL if none is registered.
 */
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);""",
    "EVP_PKEY_meth_find",
)

patch_both(
    "evp.h",
    "EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);",
    """/**
 * @brief Allocate a key context for operations with @p pkey.
 * @param pkey Key that supplies the algorithm and material for the context.
 * @param e Optional ENGINE implementing the algorithm, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on error; free with EVP_PKEY_CTX_free().
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);""",
    "EVP_PKEY_CTX_new",
)

patch_both(
    "evp.h",
    """EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);""",
    """/**
 * @brief Allocate a key context for an algorithm fetched by name from providers.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param name Algorithm name (for example "RSA" or "EC").
 * @param propquery Property query string, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on error; free with EVP_PKEY_CTX_free().
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);""",
    "EVP_PKEY_CTX_new_from_name",
)

patch_both(
    "evp.h",
    "void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);",
    """/**
 * @brief Attach legacy keygen progress info used by some ENGINE implementations.
 * @param ctx Key context used for key generation.
 * @param dat Array of integers describing generation progress/state (ownership not transferred).
 * @param datlen Number of entries in @p dat.
 */
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);""",
    "EVP_PKEY_CTX_set0_keygen_info",
)

patch_both(
    "evp.h",
    "void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);",
    """/**
 * @brief Store an opaque application pointer on a key context.
 * @param ctx Key context to update.
 * @param data Caller-owned pointer retrieved later with EVP_PKEY_CTX_get_app_data().
 */
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);""",
    "EVP_PKEY_CTX_set_app_data",
)

patch_both(
    "evp.h",
    "void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER *cipher);",
    """/**
 * @brief Release a reference to a fetched asymmetric cipher algorithm.
 * @param cipher Algorithm to free; NULL is ignored.
 */
void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER *cipher);""",
    "EVP_ASYM_CIPHER_free",
)

patch_both(
    "evp.h",
    "const char *EVP_ASYM_CIPHER_get0_name(const EVP_ASYM_CIPHER *cipher);",
    """/**
 * @brief Return the primary algorithm name of an asymmetric cipher.
 * @param cipher Asymmetric cipher algorithm to query.
 * @return Internal name string (do not free), or NULL if unset.
 */
const char *EVP_ASYM_CIPHER_get0_name(const EVP_ASYM_CIPHER *cipher);""",
    "EVP_ASYM_CIPHER_get0_name",
)

patch_both(
    "evp.h",
    """void EVP_ASYM_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_ASYM_CIPHER *cipher,
        void *arg),
    void *arg);""",
    """/**
 * @brief Invoke @p fn for every asymmetric cipher algorithm available in @p libctx.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each fetched cipher and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_ASYM_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_ASYM_CIPHER *cipher,
        void *arg),
    void *arg);""",
    "EVP_ASYM_CIPHER_do_all_provided",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_ASYM_CIPHER_gettable_ctx_params(const EVP_ASYM_CIPHER *ciph);",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable from an asymmetric-cipher context.
 * @param ciph Asymmetric cipher algorithm whose gettable context parameters are requested.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_ASYM_CIPHER_gettable_ctx_params(const EVP_ASYM_CIPHER *ciph);""",
    "EVP_ASYM_CIPHER_gettable_ctx_params",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);",
    """/**
 * @brief Derive a shared secret using a context initialized with EVP_PKEY_derive_init().
 * @param ctx Key derivation context that already has a peer key configured when required.
 * @param key Output buffer for the shared secret, or NULL to query the required length.
 * @param keylen On input, size of @p key; on output, number of bytes written or required.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);""",
    "EVP_PKEY_derive",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_auth_decapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpub,
    const OSSL_PARAM params[]);""",
    """/**
 * @brief Initialize authenticated decapsulation on @p ctx using an authentication public key.
 * @param ctx Key context for a KEM / encapsulate-capable algorithm.
 * @param authpub Authentication public key used by the authenticated decapsulation operation.
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_auth_decapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpub,
    const OSSL_PARAM params[]);""",
    "EVP_PKEY_auth_decapsulate_init",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_PKEY_fromdata_settable(EVP_PKEY_CTX *ctx, int selection);",
    """/**
 * @brief Return the OSSL_PARAM descriptors accepted by EVP_PKEY_fromdata() for @p selection.
 * @param ctx Key context created for the target algorithm.
 * @param selection OSSL_KEYMGMT_SELECT_* bitmask describing which key components are imported.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_fromdata_settable(EVP_PKEY_CTX *ctx, int selection);""",
    "EVP_PKEY_fromdata_settable",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD *pmeth,
    int (*digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));""",
    """/**
 * @brief Set the one-shot DigestVerify callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digestverify Callback implementing EVP_DigestVerify()-style verification, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD *pmeth,
    int (*digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen));""",
    "EVP_PKEY_meth_set_digestverify",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth,
    int (**pctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (**pctrl_str)(EVP_PKEY_CTX *ctx, const char *type,
        const char *value));""",
    """/**
 * @brief Retrieve the ctrl / ctrl_str callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pctrl Optional destination for the integer ctrl callback, or NULL.
 * @param pctrl_str Optional destination for the string ctrl callback, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth,
    int (**pctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
    int (**pctrl_str)(EVP_PKEY_CTX *ctx, const char *type,
        const char *value));""",
    "EVP_PKEY_meth_get_ctrl",
)

patch_both(
    "evp.h",
    "const char *EVP_PKEY_CTX_get0_propq(const EVP_PKEY_CTX *ctx);",
    """/**
 * @brief Return the property query string associated with a key context.
 * @param ctx Key context to query.
 * @return Internal property query string (do not free), or NULL if none was set.
 */
const char *EVP_PKEY_CTX_get0_propq(const EVP_PKEY_CTX *ctx);""",
    "EVP_PKEY_CTX_get0_propq",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  MISSING:", m)
