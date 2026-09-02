#!/usr/bin/env python3
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

def cipher(decl, brief, alg):
    patch_both("evp.h", decl,
        f"/**\n * @brief {brief}\n * @return EVP_CIPHER for {alg}, or NULL if unavailable.\n */\n{decl}",
        alg)

def md(decl, brief, alg):
    patch_both("evp.h", decl,
        f"/**\n * @brief {brief}\n * @return EVP_MD for {alg}, or NULL if unavailable.\n */\n{decl}",
        alg)

# method / struct fields
patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);""",
"""/**
 * @brief Set behaviour flags on a custom EVP_MD method (deprecated).
 * @param md Digest method to update.
 * @param flags EVP_MD_FLAG_* bits controlling copying and oneshot behaviour.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);""",
"EVP_MD_meth_set_flags")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
    int p1, void *p2);""",
"""/**
 * @brief Return the ctrl callback installed on a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Function pointer for EVP_MD_CTX ctrl commands, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
    int p1, void *p2);""",
"EVP_MD_meth_get_ctrl")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);""",
"""/**
 * @brief Duplicate a custom EVP_CIPHER method object (deprecated).
 * @param cipher Method to copy.
 * @return Newly allocated EVP_CIPHER copy, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);""",
"EVP_CIPHER_meth_dup")

patch_both("evp.h",
"""typedef struct {
    unsigned char *out;
    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;""",
"""typedef struct {
    /** Destination buffer for TLS 1.1 multiblock ciphertext or plaintext output. */
    unsigned char *out;
    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;""",
"EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM::out")

patch_both("evp.h",
"""typedef struct evp_cipher_info_st {
    const EVP_CIPHER *cipher;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;""",
"""/**
 * @brief Cipher algorithm pointer paired with an initialization vector buffer.
 */
typedef struct evp_cipher_info_st {
    /** Cipher implementation used with @c iv. */
    const EVP_CIPHER *cipher;
    /** Initialization vector octets for @c cipher (up to EVP_MAX_IV_LENGTH bytes). */
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;""",
"EVP_CIPHER_INFO")

patch_both("evp.h",
"int EVP_MD_is_a(const EVP_MD *md, const char *name);",
"""/**
 * @brief Test whether a digest implementation is known by @p name (including aliases).
 * @param md Digest method to query.
 * @param name Algorithm name such as "SHA256".
 * @return 1 if @p md matches @p name, or 0 otherwise.
 */
int EVP_MD_is_a(const EVP_MD *md, const char *name);""",
"EVP_MD_is_a")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);""",
"""/**
 * @brief Return the EVP_MD currently associated with a digest context (deprecated).
 * @param ctx Digest context to query.
 * @return Digest method pointer, or NULL if unset; prefer EVP_MD_CTX_get0_md().
 */
OSSL_DEPRECATEDIN_3_0
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);""",
"EVP_MD_CTX_md")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);""",
"""/**
 * @brief Return the size of the cipher's legacy implementation context (deprecated).
 * @param cipher Cipher method to query.
 * @return Context size in bytes expected by the method's init/do_cipher callbacks.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);""",
"EVP_CIPHER_impl_ctx_size")

patch_both("evp.h",
"void EVP_CIPHER_free(EVP_CIPHER *cipher);",
"""/**
 * @brief Free a fetched or duplicated EVP_CIPHER method.
 * @param cipher Cipher to free, or NULL.
 */
void EVP_CIPHER_free(EVP_CIPHER *cipher);""",
"EVP_CIPHER_free")

patch_both("evp.h",
"const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);",
"""/**
 * @brief Return the EVP_CIPHER associated with a cipher context.
 * @param ctx Cipher context to query.
 * @return Cipher method pointer, or NULL if unset.
 */
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);""",
"EVP_CIPHER_CTX_cipher")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);",
"""/**
 * @brief Return the IV originally supplied when the cipher context was initialized (deprecated).
 * @param ctx Cipher context to query.
 * @return Pointer to the original IV bytes, or NULL if unavailable.
 */
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);""",
"EVP_CIPHER_CTX_original_iv")

patch_both("evp.h",
"int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);",
"""/**
 * @brief Retrieve algorithm parameters from a digest context into @p params.
 * @param ctx Digest context to query.
 * @param params OSSL_PARAM array describing the values to fetch (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);""",
"EVP_MD_CTX_get_params")

patch_both("evp.h",
"const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx);",
"""/**
 * @brief Return the OSSL_PARAM descriptors for parameters settable on a digest context.
 * @param ctx Digest context whose provider implementation is queried.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx);""",
"EVP_MD_CTX_settable_params")

patch_both("evp.h",
"int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);",
"""/**
 * @brief Test whether the given flag bits are set on a digest context.
 * @param ctx Digest context to query.
 * @param flags EVP_MD_CTX_* flag mask to test.
 * @return Bitwise AND of the context flags with @p flags.
 */
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);""",
"EVP_MD_CTX_test_flags")

patch_both("evp.h",
"""__owur int EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name,
    const char *propq, const void *data, size_t datalen,
    unsigned char *md, size_t *mdlen);""",
"""/**
 * @brief One-shot digest of @p data using a fetched algorithm name.
 * @param libctx Library context for the fetch, or NULL for the default.
 * @param name Digest algorithm name (for example "SHA256").
 * @param propq Property query for the fetch, or NULL.
 * @param data Bytes to hash.
 * @param datalen Number of bytes at @p data.
 * @param md Output buffer for the digest (at least the algorithm size).
 * @param mdlen Optional in/out length of @p md; updated to the digest size.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name,
    const char *propq, const void *data, size_t datalen,
    unsigned char *md, size_t *mdlen);""",
"EVP_Q_digest")

patch_both("evp.h",
"""__owur int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);""",
"""/**
 * @brief Decrypt a chunk of ciphertext into @p out, updating the cipher context.
 * @param ctx Cipher context initialized for decryption.
 * @param out Output buffer for plaintext (may be NULL to pass AAD for AEAD ciphers).
 * @param outl Receives the number of plaintext bytes written.
 * @param in Ciphertext (or AAD) bytes to process.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);""",
"EVP_DecryptUpdate")

patch_both("evp.h",
"""__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
    unsigned int siglen, EVP_PKEY *pkey);""",
"""/**
 * @brief Finish a verify operation by checking @p sigbuf against the digested data.
 * @param ctx Digest/verify context that has absorbed the message via EVP_DigestUpdate().
 * @param sigbuf Signature bytes to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param pkey Public key used for verification.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
    unsigned int siglen, EVP_PKEY *pkey);""",
"EVP_VerifyFinal")

patch_both("evp.h",
"""__owur int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
    size_t siglen, const unsigned char *tbs,
    size_t tbslen);""",
"""/**
 * @brief Verify @p sigret over @p tbs in one call using a prepared DigestVerify context.
 * @param ctx Context initialized with EVP_DigestVerifyInit().
 * @param sigret Signature bytes to verify.
 * @param siglen Length of @p sigret in bytes.
 * @param tbs Message bytes that were signed ("to be signed").
 * @param tbslen Length of @p tbs in bytes.
 * @return 1 if the signature is valid, 0 if it is invalid, or a negative value on error.
 */
__owur int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
    size_t siglen, const unsigned char *tbs,
    size_t tbslen);""",
"EVP_DigestVerify")

patch_both("evp.h",
"__owur int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);",
"""/**
 * @brief Finalize a seal (envelope encrypt) operation and write any remaining ciphertext.
 * @param ctx Cipher context initialized with EVP_SealInit().
 * @param out Buffer receiving final ciphertext bytes.
 * @param outl Receives the number of bytes written to @p out.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);""",
"EVP_SealFinal")

patch_both("evp.h",
"void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);",
"""/**
 * @brief Free a Base64 encode/decode context.
 * @param ctx Context to free, or NULL.
 */
void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);""",
"EVP_ENCODE_CTX_free")

patch_both("evp.h",
"int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);",
"""/**
 * @brief Base64-encode @p n bytes from @p f into @p t as a single block (with NUL terminator).
 * @param t Destination buffer (at least ((n+2)/3)*4 + 1 bytes).
 * @param f Input octets to encode.
 * @param n Number of input bytes.
 * @return Number of Base64 characters written, not counting the trailing NUL.
 */
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);""",
"EVP_EncodeBlock")

patch_both("evp.h",
"int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);",
"""/**
 * @brief Base64-decode @p n characters from @p f into @p t as a single block.
 * @param t Destination buffer for decoded octets.
 * @param f Base64 input characters (whitespace should already be removed for legacy behaviour).
 * @param n Number of input characters; should be a multiple of four.
 * @return Number of decoded bytes written, or -1 on error.
 */
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);""",
"EVP_DecodeBlock")

patch_both("evp.h",
"EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);",
"""/**
 * @brief Allocate an empty cipher context.
 * @return New EVP_CIPHER_CTX, or NULL on allocation failure.
 */
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);""",
"EVP_CIPHER_CTX_new")

patch_both("evp.h",
"int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[]);",
"""/**
 * @brief Retrieve algorithm-level parameters from a cipher implementation.
 * @param cipher Cipher method to query.
 * @param params OSSL_PARAM array describing the values to fetch.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[]);""",
"EVP_CIPHER_get_params")

md("const EVP_MD *EVP_shake256(void);",
   "Return the SHAKE256 XOF digest method.", "shake256")
cipher("const EVP_CIPHER *EVP_rc4(void);",
       "Return the RC4 stream cipher.", "rc4")
cipher("const EVP_CIPHER *EVP_bf_cbc(void);",
       "Return the Blowfish cipher in CBC mode.", "bf-cbc")
cipher("const EVP_CIPHER *EVP_aes_192_gcm(void);",
       "Return the AES-192 cipher in GCM mode.", "aes-192-gcm")
cipher("const EVP_CIPHER *EVP_aes_192_wrap(void);",
       "Return the AES-192 cipher in key-wrap mode (RFC 3394).", "aes-192-wrap")
cipher("const EVP_CIPHER *EVP_aria_256_cfb8(void);",
       "Return the ARIA-256 cipher in 8-bit CFB mode.", "aria-256-cfb8")
cipher("const EVP_CIPHER *EVP_camellia_128_cbc(void);",
       "Return the Camellia-128 cipher in CBC mode.", "camellia-128-cbc")
cipher("const EVP_CIPHER *EVP_camellia_128_ofb(void);",
       "Return the Camellia-128 cipher in OFB mode.", "camellia-128-ofb")
cipher("const EVP_CIPHER *EVP_camellia_256_cbc(void);",
       "Return the Camellia-256 cipher in CBC mode.", "camellia-256-cbc")
cipher("const EVP_CIPHER *EVP_camellia_256_cfb1(void);",
       "Return the Camellia-256 cipher in 1-bit CFB mode.", "camellia-256-cfb1")
cipher("const EVP_CIPHER *EVP_camellia_256_ofb(void);",
       "Return the Camellia-256 cipher in OFB mode.", "camellia-256-ofb")
cipher("const EVP_CIPHER *EVP_chacha20(void);",
       "Return the ChaCha20 stream cipher.", "chacha20")

patch_both("evp.h",
"""int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);""",
"""/**
 * @brief Initialize a MAC context with a key and optional algorithm parameters.
 * @param ctx MAC context created with EVP_MAC_CTX_new().
 * @param key MAC key octets.
 * @param keylen Length of @p key in bytes.
 * @param params Optional OSSL_PARAM array (for example digest selection), or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);""",
"EVP_MAC_init")

patch_both("evp.h",
"const OSSL_PROVIDER *EVP_RAND_get0_provider(const EVP_RAND *rand);",
"""/**
 * @brief Return the provider that supplied a RAND implementation.
 * @param rand RAND method to query.
 * @return Provider pointer, or NULL if unavailable.
 */
const OSSL_PROVIDER *EVP_RAND_get0_provider(const EVP_RAND *rand);""",
"EVP_RAND_get0_provider")

patch_both("evp.h",
"""__owur int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out,
    size_t outlen, unsigned int strength,
    int prediction_resistance,
    const unsigned char *addin, size_t addin_len);""",
"""/**
 * @brief Generate random bytes from a RAND context.
 * @param ctx RAND context to draw from.
 * @param out Buffer receiving random octets.
 * @param outlen Number of bytes to generate.
 * @param strength Requested security strength in bits (0 selects the context default).
 * @param prediction_resistance Non-zero to request prediction resistance / reseed before output.
 * @param addin Optional additional input mixed into the generation, or NULL.
 * @param addin_len Length of @p addin in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out,
    size_t outlen, unsigned int strength,
    int prediction_resistance,
    const unsigned char *addin, size_t addin_len);""",
"EVP_RAND_generate")

patch_both("evp.h",
"__owur int EVP_RAND_enable_locking(EVP_RAND_CTX *ctx);",
"""/**
 * @brief Enable thread-safe locking on a RAND context for concurrent use.
 * @param ctx RAND context that should serialize access internally.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_RAND_enable_locking(EVP_RAND_CTX *ctx);""",
"EVP_RAND_enable_locking")

patch_both("evp.h",
"unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx);",
"""/**
 * @brief Return the current security strength in bits of a RAND context.
 * @param ctx RAND context to query.
 * @return Strength in bits, or 0 if unavailable.
 */
unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx);""",
"EVP_RAND_get_strength")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);""",
"""/**
 * @brief Set the RSA key referenced by an EVP_PKEY, incrementing the RSA reference count (deprecated).
 * @param pkey Destination EVP_PKEY to assign.
 * @param key RSA key to associate; its reference count is incremented.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);""",
"EVP_PKEY_set1_RSA")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);""",
"""/**
 * @brief Return a new reference to the RSA key held by @p pkey (deprecated).
 * @param pkey Key that must hold an RSA key.
 * @return RSA pointer with an incremented reference count (caller frees with RSA_free()), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);""",
"EVP_PKEY_get1_RSA")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);""",
"""/**
 * @brief Return a new reference to the DSA key held by @p pkey (deprecated).
 * @param pkey Key that must hold a DSA key.
 * @return DSA pointer with an incremented reference count (caller frees with DSA_free()), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);""",
"EVP_PKEY_get1_DSA")

patch_both("evp.h",
"void EVP_PKEY_free(EVP_PKEY *pkey);",
"""/**
 * @brief Free an EVP_PKEY, decrementing its reference count.
 * @param pkey Key to free, or NULL.
 */
void EVP_PKEY_free(EVP_PKEY *pkey);""",
"EVP_PKEY_free")

patch_both("evp.h",
"""EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Decode a private key of type @p type from DER using a library context.
 * @param type Key type NID (for example EVP_PKEY_RSA), or 0 to attempt type-specific legacy decoding.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"d2i_PrivateKey_ex")

patch_both("evp.h",
"""EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
    long length);""",
"""/**
 * @brief Decode a private key from DER, detecting the algorithm automatically.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded key.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
    long length);""",
"d2i_AutoPrivateKey")

patch_both("evp.h",
"""int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey,
    char *mdname, size_t mdname_sz);""",
"""/**
 * @brief Write the default digest name recommended for signing with @p pkey.
 * @param pkey Key whose signature defaults are queried.
 * @param mdname Output buffer receiving a NUL-terminated digest name (for example "SHA256").
 * @param mdname_sz Capacity of @p mdname in bytes.
 * @return 1 if a default digest is required, 2 if any digest is allowed, or a negative/zero value on error.
 */
int EVP_PKEY_get_default_digest_name(EVP_PKEY *pkey,
    char *mdname, size_t mdname_sz);""",
"EVP_PKEY_get_default_digest_name")

print(f"evp part1 ok={len(ok)} miss={len(missing)}")
if missing:
    print("MISSING:", *missing, sep="\n  ")
