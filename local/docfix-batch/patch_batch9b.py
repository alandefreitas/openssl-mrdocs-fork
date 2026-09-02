#!/usr/bin/env python3
"""Documentation repair batch 9b: evp.h symbols."""
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


def cipher_fetch(name, brief):
    decl = f"const EVP_CIPHER *{name}(void);"
    return (
        decl,
        f"""/**
 * @brief Return the EVP_CIPHER for {brief}.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
{decl}""",
        name,
    )


def md_fetch(name, brief):
    decl = f"const EVP_MD *{name}(void);"
    return (
        decl,
        f"""/**
 * @brief Return the EVP_MD for {brief}.
 * @return Pointer to the digest method, or NULL if unavailable in this build.
 */
{decl}""",
        name,
    )


# ----- early meth / props -----
patch_both(
    "evp.h",
    "int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx);",
    """/**
 * @brief Query whether the library context's default property query requires FIPS algorithms.
 * @param libctx Library context to query, or NULL for the default context.
 * @return 1 if the default properties imply FIPS-only fetches, or 0 otherwise.
 */
int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx);""",
    "EVP_default_properties_is_fips_enabled",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count));""",
    """/**
 * @brief Set the update callback on a custom EVP_MD method (deprecated).
 * @param md Digest method object to update.
 * @param update Callback that absorbs more message bytes into @p ctx, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count));""",
    "EVP_MD_meth_set_update",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_app_datasize(const EVP_MD *md);",
    """/**
 * @brief Return the application-data size reserved by a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Size in bytes previously set with EVP_MD_meth_set_app_datasize().
 */
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_app_datasize(const EVP_MD *md);""",
    "EVP_MD_meth_get_app_datasize",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);""",
    """/**
 * @brief Return the init callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the init callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);""",
    "EVP_MD_meth_get_init",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
    unsigned char *md);""",
    """/**
 * @brief Return the final callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the finalization callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
    unsigned char *md);""",
    "EVP_MD_meth_get_final",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);""",
    """/**
 * @brief Return the cleanup callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the cleanup callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);""",
    "EVP_MD_meth_get_cleanup",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);""",
    """/**
 * @brief Allocate a custom EVP_CIPHER method object (deprecated).
 * @param cipher_type NID identifying the cipher algorithm.
 * @param block_size Block size in bytes (1 for stream ciphers).
 * @param key_len Default key length in bytes.
 * @return New mutable EVP_CIPHER, or NULL on failure; free with EVP_CIPHER_meth_free().
 */
OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);""",
    "EVP_CIPHER_meth_new",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);""",
    """/**
 * @brief Set how many bytes of cipher-specific context storage to allocate (deprecated).
 * @param cipher Custom cipher method to update.
 * @param ctx_size Size in bytes of the implementation context allocated with each EVP_CIPHER_CTX.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);""",
    "EVP_CIPHER_meth_set_impl_ctx_size",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
    int (*init)(EVP_CIPHER_CTX *ctx,
        const unsigned char *key,
        const unsigned char *iv,
        int enc));""",
    """/**
 * @brief Set the key/IV initialization callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param init Callback that prepares @p ctx for encrypt or decrypt, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
    int (*init)(EVP_CIPHER_CTX *ctx,
        const unsigned char *key,
        const unsigned char *iv,
        int enc));""",
    "EVP_CIPHER_meth_set_init",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
    int (*do_cipher)(EVP_CIPHER_CTX *ctx,
        unsigned char *out,
        const unsigned char *in,
        size_t inl));""",
    """/**
 * @brief Set the encrypt/decrypt update callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param do_cipher Callback that transforms @p inl bytes from @p in to @p out, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
    int (*do_cipher)(EVP_CIPHER_CTX *ctx,
        unsigned char *out,
        const unsigned char *in,
        size_t inl));""",
    "EVP_CIPHER_meth_set_do_cipher",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
    int (*cleanup)(EVP_CIPHER_CTX *));""",
    """/**
 * @brief Set the context-cleanup callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param cleanup Callback invoked when an EVP_CIPHER_CTX using this method is reset or freed.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
    int (*cleanup)(EVP_CIPHER_CTX *));""",
    "EVP_CIPHER_meth_set_cleanup",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *,
        ASN1_TYPE *));""",
    """/**
 * @brief Set the callback that exports cipher parameters into an ASN.1 type (deprecated).
 * @param cipher Custom cipher method to update.
 * @param get_asn1_parameters Callback that fills an ASN1_TYPE from the cipher context, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *,
        ASN1_TYPE *));""",
    "EVP_CIPHER_meth_set_get_asn1_params",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
    int (*ctrl)(EVP_CIPHER_CTX *, int type,
        int arg, void *ptr));""",
    """/**
 * @brief Set the ctrl callback on a custom EVP_CIPHER (deprecated).
 * @param cipher Custom cipher method to update.
 * @param ctrl Callback handling EVP_CIPHER_CTX_ctrl commands, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
    int (*ctrl)(EVP_CIPHER_CTX *, int type,
        int arg, void *ptr));""",
    "EVP_CIPHER_meth_set_ctrl",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t inl);""",
    """/**
 * @brief Return the do_cipher callback from a custom EVP_CIPHER method (deprecated).
 * @param cipher Cipher method to query.
 * @return Pointer to the encrypt/decrypt update callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t inl);""",
    "EVP_CIPHER_meth_get_do_cipher",
)

patch_both(
    "evp.h",
    """typedef struct {
    /** Destination buffer for TLS 1.1 multiblock ciphertext or plaintext output. */
    unsigned char *out;
    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;
    /** Length in bytes of the buffer at @c inp / @c out for the multiblock operation. */
    size_t len;
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;""",
    """/**
 * @brief Parameters for TLS 1.1 AES multiblock EVP_CIPHER_CTX_ctrl operations.
 */
typedef struct {
    /** Destination buffer for TLS 1.1 multiblock ciphertext or plaintext output. */
    unsigned char *out;
    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;
    /** Length in bytes of the buffer at @c inp / @c out for the multiblock operation. */
    size_t len;
    /** Interleave factor selecting how many records are processed together. */
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;""",
    "EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM",
)

patch_both(
    "evp.h",
    """typedef int(EVP_PBE_KEYGEN_EX)(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de, OSSL_LIB_CTX *libctx, const char *propq);""",
    """/**
 * @brief Extended password-based encryption key-setup callback with library context support.
 * @param ctx Cipher context that receives the derived key and IV.
 * @param pass Password bytes (may contain embedded NULs when @p passlen is set).
 * @param passlen Length of @p pass in bytes, or -1 if @p pass is a NUL-terminated string.
 * @param param Algorithm-specific PBE parameters (for example PBKDF2PARAM).
 * @param cipher Cipher to initialize.
 * @param md Digest used by the PBE scheme when applicable.
 * @param en_de 1 to encrypt, 0 to decrypt.
 * @param libctx Library context used when fetching algorithms, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
typedef int(EVP_PBE_KEYGEN_EX)(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de, OSSL_LIB_CTX *libctx, const char *propq);""",
    "EVP_PBE_KEYGEN_EX",
)

# ----- MD / cipher getters -----
patch_both(
    "evp.h",
    "int EVP_MD_get_type(const EVP_MD *md);",
    """/**
 * @brief Return the NID identifying a message-digest algorithm.
 * @param md Digest method to query.
 * @return Algorithm NID such as NID_sha256, or NID_undef on error.
 */
int EVP_MD_get_type(const EVP_MD *md);""",
    "EVP_MD_get_type",
)

patch_both(
    "evp.h",
    "const char *EVP_MD_get0_name(const EVP_MD *md);",
    """/**
 * @brief Return the primary algorithm name of a message digest.
 * @param md Digest method to query.
 * @return Internal NUL-terminated name string (do not free), or NULL on error.
 */
const char *EVP_MD_get0_name(const EVP_MD *md);""",
    "EVP_MD_get0_name",
)

patch_both(
    "evp.h",
    """int EVP_MD_names_do_all(const EVP_MD *md,
    void (*fn)(const char *name, void *data),
    void *data);""",
    """/**
 * @brief Invoke a callback for every known name alias of a message digest.
 * @param md Digest method whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_names_do_all(const EVP_MD *md,
    void (*fn)(const char *name, void *data),
    void *data);""",
    "EVP_MD_names_do_all",
)

patch_both(
    "evp.h",
    "int EVP_MD_get_block_size(const EVP_MD *md);",
    """/**
 * @brief Return the internal block size of a message digest in bytes.
 * @param md Digest method to query.
 * @return Block size in bytes used by the compression function.
 */
int EVP_MD_get_block_size(const EVP_MD *md);""",
    "EVP_MD_get_block_size",
)

patch_both(
    "evp.h",
    "const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx);",
    """/**
 * @brief Return the digest method currently associated with a digest context.
 * @param ctx Digest context to query.
 * @return Internal EVP_MD pointer (do not free), or NULL if unset.
 */
const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx);""",
    "EVP_MD_CTX_get0_md",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
    int (*update)(EVP_MD_CTX *ctx,
        const void *data, size_t count));""",
    """/**
 * @brief Override the update function used by a digest context (deprecated).
 * @param ctx Digest context whose update implementation is replaced.
 * @param update Replacement update callback, or NULL to restore the method default.
 */
OSSL_DEPRECATEDIN_3_0
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
    int (*update)(EVP_MD_CTX *ctx,
        const void *data, size_t count));""",
    "EVP_MD_CTX_set_update_fn",
)

patch_both(
    "evp.h",
    "void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx);",
    """/**
 * @brief Return the digest method's private data pointer for a context.
 * @param ctx Digest context to query.
 * @return Implementation-specific data pointer (do not free), or NULL if unavailable.
 */
void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx);""",
    "EVP_MD_CTX_get0_md_data",
)

patch_both(
    "evp.h",
    "const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher);",
    """/**
 * @brief Return the provider that implements a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL for legacy methods.
 */
const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher);""",
    "EVP_CIPHER_get0_provider",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);",
    """/**
 * @brief Return the block size of a cipher in bytes.
 * @param cipher Cipher method to query.
 * @return Block size in bytes (1 for stream ciphers).
 */
int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);""",
    "EVP_CIPHER_get_block_size",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);",
    """/**
 * @brief Return the default key length of a cipher in bytes.
 * @param cipher Cipher method to query.
 * @return Default key length in bytes.
 */
int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);""",
    "EVP_CIPHER_get_key_length",
)

patch_both(
    "evp.h",
    "const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx);",
    """/**
 * @brief Return the cipher method currently associated with a cipher context.
 * @param ctx Cipher context to query.
 * @return Internal EVP_CIPHER pointer (do not free), or NULL if unset.
 */
const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx);""",
    "EVP_CIPHER_CTX_get0_cipher",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx);",
    """/**
 * @brief Return the NID of the cipher currently bound to a cipher context.
 * @param ctx Cipher context to query.
 * @return Algorithm NID, or NID_undef if no cipher is set.
 */
int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx);""",
    "EVP_CIPHER_CTX_get_nid",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);",
    """/**
 * @brief Return the block size of the cipher bound to a cipher context.
 * @param ctx Cipher context to query.
 * @return Block size in bytes, or 0 if no cipher is set.
 */
int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);""",
    "EVP_CIPHER_CTX_get_block_size",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);",
    """/**
 * @brief Return the key length currently configured on a cipher context.
 * @param ctx Cipher context to query.
 * @return Key length in bytes (may differ from the cipher default after set_key_length).
 */
int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);""",
    "EVP_CIPHER_CTX_get_key_length",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);",
    """/**
 * @brief Return a pointer to the IV stored in a cipher context (deprecated).
 * @param ctx Cipher context to query.
 * @return Internal IV buffer (do not free), or NULL if unavailable.
 *
 * Prefer EVP_CIPHER_CTX_get_updated_iv() / OSSL_PARAM queries for new code.
 */
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);""",
    "EVP_CIPHER_CTX_iv",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);",
    """/**
 * @brief Set the partial-block offset counter stored in a cipher context.
 * @param ctx Cipher context to update.
 * @param num New offset value used by some cipher modes for leftover bytes.
 * @return 1 on success.
 */
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);""",
    "EVP_CIPHER_CTX_set_num",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);",
    """/**
 * @brief Copy the cipher state from one context into another.
 * @param out Destination context; must already be allocated and is reset as needed.
 * @param in Source context whose algorithm state is duplicated.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);""",
    "EVP_CIPHER_CTX_copy",
)

patch_both(
    "evp.h",
    "int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[]);",
    """/**
 * @brief Fetch gettable algorithm parameters from a message-digest method.
 * @param digest Digest method to query.
 * @param params Array of OSSL_PARAM descriptors to fill; terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[]);""",
    "EVP_MD_get_params",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_MD_gettable_params(const EVP_MD *digest);",
    """/**
 * @brief Describe the parameters that can be read from a message-digest method.
 * @param digest Digest method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL on error.
 */
const OSSL_PARAM *EVP_MD_gettable_params(const EVP_MD *digest);""",
    "EVP_MD_gettable_params",
)

patch_both(
    "evp.h",
    """void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);""",
    """/**
 * @brief Set flag bits on a digest context without clearing existing flags.
 * @param ctx Digest context to update.
 * @param flags Bitmask of EVP_MD_CTX_* flags to set.
 */
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
/**
 * @brief Clear flag bits on a digest context.
 * @param ctx Digest context to update.
 * @param flags Bitmask of EVP_MD_CTX_* flags to clear.
 */
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);""",
    "EVP_MD_CTX_set/clear_flags",
)

patch_both(
    "evp.h",
    "__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);",
    """/**
 * @brief Copy a digest context into a freshly allocated destination (legacy helper).
 * @param out Destination context; must not already hold digest state (prefer EVP_MD_CTX_copy_ex).
 * @param in Source context to duplicate.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);""",
    "EVP_MD_CTX_copy",
)

patch_both(
    "evp.h",
    "__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);",
    """/**
 * @brief Initialize a digest context for hashing with @p type (legacy ENGINE-aware form).
 * @param ctx Digest context to initialize.
 * @param type Digest method to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_DigestInit_ex2() for new code.
 */
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);""",
    "EVP_DigestInit",
)

patch_both(
    "evp.h",
    """__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
    unsigned int *s);""",
    """/**
 * @brief Finalize a digest computation and write the message digest.
 * @param ctx Digest context that has been updated with message data.
 * @param md Output buffer of at least EVP_MD_size bytes receiving the digest.
 * @param s Optional pointer receiving the digest length in bytes, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
    unsigned int *s);""",
    "EVP_DigestFinal",
)

patch_both(
    "evp.h",
    """int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
    const char *prompt, int verify);""",
    """/**
 * @brief Prompt for a password with a minimum and maximum length.
 * @param buf Output buffer receiving the password (NUL-terminated).
 * @param minlen Minimum acceptable password length in characters.
 * @param maxlen Maximum length including space for the trailing NUL.
 * @param prompt Prompt string shown to the user.
 * @param verify When non-zero, prompt twice and require matching input.
 * @return 0 on success, or a non-zero value on failure / mismatch.
 */
int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
    const char *prompt, int verify);""",
    "EVP_read_pw_string_min",
)

patch_both(
    "evp.h",
    "void EVP_set_pw_prompt(const char *prompt);",
    """/**
 * @brief Set the default password prompt string used by EVP password helpers.
 * @param prompt NUL-terminated prompt text copied into an internal buffer, or NULL to clear.
 */
void EVP_set_pw_prompt(const char *prompt);""",
    "EVP_set_pw_prompt",
)

patch_both(
    "evp.h",
    """__owur int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
    const unsigned char *salt,
    const unsigned char *data, int datal, int count,
    unsigned char *key, unsigned char *iv);""",
    """/**
 * @brief Derive a cipher key and IV from a password using the legacy EVP_BytesToKey KDF.
 * @param type Cipher whose key and IV lengths determine the output sizes.
 * @param md Digest used in the iterative key derivation (commonly EVP_md5()).
 * @param salt Optional 8-byte salt, or NULL.
 * @param data Password / passphrase bytes.
 * @param datal Length of @p data in bytes.
 * @param count Iteration count (higher slows brute-force attacks).
 * @param key Output buffer for the derived key, or NULL to skip.
 * @param iv Output buffer for the derived IV, or NULL to skip.
 * @return Length of the derived key in bytes, or 0 on error.
 */
__owur int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
    const unsigned char *salt,
    const unsigned char *data, int datal, int count,
    unsigned char *key, unsigned char *iv);""",
    "EVP_BytesToKey",
)

patch_both(
    "evp.h",
    """__owur int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key,
    const unsigned char *iv,
    const OSSL_PARAM params[]);""",
    """/**
 * @brief Initialize a cipher context for encryption with optional OSSL_PARAM settings.
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm, or NULL to reuse the previous cipher.
 * @param key Encryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when the cipher does not need one yet.
 * @param params Optional parameter array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key,
    const unsigned char *iv,
    const OSSL_PARAM params[]);""",
    "EVP_EncryptInit_ex2",
)

patch_both(
    "evp.h",
    """__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv);""",
    """/**
 * @brief Initialize a cipher context for decryption (legacy ENGINE-aware form).
 * @param ctx Cipher context to initialize.
 * @param cipher Cipher algorithm to use.
 * @param key Decryption key bytes, or NULL to set later.
 * @param iv Initialization vector, or NULL when not yet required.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_DecryptInit_ex2() for new code.
 */
__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv);""",
    "EVP_DecryptInit",
)

patch_both(
    "evp.h",
    """__owur int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    """/**
 * @brief Finalize decryption and write any remaining plaintext (including padding removal).
 * @param ctx Cipher context previously used with EVP_DecryptUpdate().
 * @param outm Buffer receiving final plaintext bytes (may need a full block of space).
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, or 0 on failure (for example padding errors).
 */
__owur int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
    "EVP_DecryptFinal_ex",
)

patch_both(
    "evp.h",
    """__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);""",
    """/**
 * @brief Encrypt or decrypt a chunk of data using a cipher context already set for either direction.
 * @param ctx Cipher context initialized for encryption or decryption.
 * @param out Output buffer for ciphertext or plaintext.
 * @param outl Receives the number of bytes written to @p out.
 * @param in Input bytes to process.
 * @param inl Number of bytes at @p in.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl);""",
    "EVP_CipherUpdate",
)

patch_both(
    "evp.h",
    "void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);",
    """/**
 * @brief Free a cipher context and any associated resources.
 * @param c Context to free; NULL is ignored.
 */
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);""",
    "EVP_CIPHER_CTX_free",
)

patch_both(
    "evp.h",
    "int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);",
    """/**
 * @brief Set a variable-length cipher's key length on a cipher context.
 * @param x Cipher context whose cipher supports variable key lengths.
 * @param keylen Desired key length in bytes.
 * @return 1 on success, or 0 if the length is unsupported.
 */
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);""",
    "EVP_CIPHER_CTX_set_key_length",
)

patch_both(
    "evp.h",
    "const BIO_METHOD *BIO_f_base64(void);",
    """/**
 * @brief Return the BIO filter method that Base64-encodes or decodes data.
 * @return Pointer to the Base64 BIO_METHOD for use with BIO_new().
 */
const BIO_METHOD *BIO_f_base64(void);""",
    "BIO_f_base64",
)

for old, new, label in [
    md_fetch("EVP_blake2s256", "BLAKE2s-256"),
    md_fetch("EVP_shake128", "SHAKE128 (XOF)"),
    cipher_fetch("EVP_des_cfb64", "DES in 64-bit CFB mode"),
    cipher_fetch("EVP_idea_cbc", "IDEA in CBC mode"),
    cipher_fetch("EVP_rc2_ofb", "RC2 in OFB mode"),
    cipher_fetch("EVP_cast5_ecb", "CAST5 in ECB mode"),
    cipher_fetch("EVP_aes_128_cfb8", "AES-128 in 8-bit CFB mode"),
    cipher_fetch("EVP_aes_128_gcm", "AES-128 in GCM mode"),
    cipher_fetch("EVP_aes_192_cfb128", "AES-192 in 128-bit CFB mode"),
    cipher_fetch("EVP_aria_192_gcm", "ARIA-192 in GCM mode"),
    cipher_fetch("EVP_camellia_192_cfb128", "Camellia-192 in 128-bit CFB mode"),
]:
    patch_both("evp.h", old, new, label)

patch_both(
    "evp.h",
    """void EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_MD *md, void *arg),
    void *arg);""",
    """/**
 * @brief Invoke a callback for every message digest provided in a library context.
 * @param libctx Library context whose providers are scanned, or NULL for the default.
 * @param fn Callback receiving each available EVP_MD and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_MD *md, void *arg),
    void *arg);""",
    "EVP_MD_do_all_provided",
)

patch_both(
    "evp.h",
    "const char *EVP_RAND_get0_description(const EVP_RAND *md);",
    """/**
 * @brief Return a human-readable description of a random-number algorithm.
 * @param md RAND algorithm implementation to query.
 * @return Internal description string (do not free), or NULL if none is available.
 */
const char *EVP_RAND_get0_description(const EVP_RAND *md);""",
    "EVP_RAND_get0_description",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_parameters_eq(const EVP_PKEY *a, const EVP_PKEY *b);",
    """/**
 * @brief Compare the domain parameters of two keys for equality.
 * @param a First key.
 * @param b Second key.
 * @return 1 if parameters match, 0 if they differ, or a negative value on error.
 */
int EVP_PKEY_parameters_eq(const EVP_PKEY *a, const EVP_PKEY *b);""",
    "EVP_PKEY_parameters_eq",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);""",
    """/**
 * @brief Print a key's domain parameters to a BIO in human-readable form.
 * @param out Output BIO.
 * @param pkey Key whose parameters are printed.
 * @param indent Indentation width in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);""",
    "EVP_PKEY_print_params",
)

patch_both(
    "evp.h",
    "const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);",
    """/**
 * @brief Find the ASN.1 method implementing a public-key algorithm NID.
 * @param pe Optional ENGINE pointer updated when the method comes from an ENGINE, or NULL.
 * @param type Algorithm NID such as EVP_PKEY_RSA.
 * @return Internal EVP_PKEY_ASN1_METHOD pointer, or NULL if not found.
 */
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);""",
    "EVP_PKEY_asn1_find",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len);",
    """/**
 * @brief Set an algorithm-specific identity value on a key operation context (copied).
 * @param ctx Key context that supports an ID parameter (for example SM2).
 * @param id Identity bytes to copy into the context.
 * @param len Length of @p id in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len);""",
    "EVP_PKEY_CTX_set1_id",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);",
    """/**
 * @brief Register an application-defined EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to add to the global list; must remain valid.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer providers for new algorithms.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);""",
    "EVP_PKEY_meth_add0",
)

patch_both(
    "evp.h",
    "const OSSL_PARAM *EVP_KEYMGMT_gettable_params(const EVP_KEYMGMT *keymgmt);",
    """/**
 * @brief Describe parameters that can be read from keys managed by a keymgmt.
 * @param keymgmt Key management implementation to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL on error.
 */
const OSSL_PARAM *EVP_KEYMGMT_gettable_params(const EVP_KEYMGMT *keymgmt);""",
    "EVP_KEYMGMT_gettable_params",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);",
    """/**
 * @brief Return the operation type currently configured on a key context.
 * @param ctx Key context to query.
 * @return One of the EVP_PKEY_OP_* values, or EVP_PKEY_OP_UNDEFINED if unset.
 */
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);""",
    "EVP_PKEY_CTX_get_operation",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);",
    """/**
 * @brief Initialize a key context for public-key encryption with optional parameters.
 * @param ctx Context holding the public key for encryption.
 * @param params Optional OSSL_PARAM array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);""",
    "EVP_PKEY_encrypt_init_ex",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);",
    """/**
 * @brief Initialize a key context for a key-encapsulation (KEM) encapsulate operation.
 * @param ctx Context holding the recipient public key.
 * @param params Optional OSSL_PARAM array terminated by OSSL_PARAM_END, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);""",
    "EVP_PKEY_encapsulate_init",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *wrappedkey, size_t *wrappedkeylen,
    unsigned char *genkey, size_t *genkeylen);""",
    """/**
 * @brief Perform key encapsulation: produce a wrapped key and a shared secret.
 * @param ctx Context previously initialized with EVP_PKEY_encapsulate_init().
 * @param wrappedkey Buffer receiving the encapsulated key, or NULL to query lengths.
 * @param wrappedkeylen In/out length of @p wrappedkey.
 * @param genkey Buffer receiving the generated shared secret, or NULL to query lengths.
 * @param genkeylen In/out length of @p genkey.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *wrappedkey, size_t *wrappedkeylen,
    unsigned char *genkey, size_t *genkeylen);""",
    "EVP_PKEY_encapsulate",
)

patch_both(
    "evp.h",
    "int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);",
    """/**
 * @brief Prepare a key context to import key material via EVP_PKEY_fromdata().
 * @param ctx Context created for the target key type (for example with EVP_PKEY_CTX_new_from_name).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);""",
    "EVP_PKEY_fromdata_init",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_get_int_param(const EVP_PKEY *pkey, const char *key_name,
    int *out);""",
    """/**
 * @brief Read an integer parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name such as OSSL_PKEY_PARAM_BITS.
 * @param out Receives the integer value.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_int_param(const EVP_PKEY *pkey, const char *key_name,
    int *out);""",
    "EVP_PKEY_get_int_param",
)

patch_both(
    "evp.h",
    """int EVP_PKEY_get_utf8_string_param(const EVP_PKEY *pkey, const char *key_name,
    char *str, size_t max_buf_sz, size_t *out_sz);""",
    """/**
 * @brief Read a UTF-8 string parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name such as OSSL_PKEY_PARAM_GROUP_NAME.
 * @param str Output buffer for the NUL-terminated string, or NULL to query size only.
 * @param max_buf_sz Capacity of @p str in bytes.
 * @param out_sz Optional pointer receiving the required/written length including NUL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_utf8_string_param(const EVP_PKEY *pkey, const char *key_name,
    char *str, size_t max_buf_sz, size_t *out_sz);""",
    "EVP_PKEY_get_utf8_string_param",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, void (*cleanup)(EVP_PKEY_CTX *ctx));",
    """/**
 * @brief Set the context-cleanup callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param cleanup Callback that releases operation-specific state on @p ctx, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, void (*cleanup)(EVP_PKEY_CTX *ctx));""",
    "EVP_PKEY_meth_set_cleanup",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth, int (*sign_init)(EVP_PKEY_CTX *ctx),
    int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));""",
    """/**
 * @brief Set the signing callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param sign_init Optional initialization callback before signing, or NULL.
 * @param sign Callback that produces a signature over @p tbs into @p sig.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth, int (*sign_init)(EVP_PKEY_CTX *ctx),
    int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen));""",
    "EVP_PKEY_meth_set_sign",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, int (*verify_init)(EVP_PKEY_CTX *ctx),
    int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen));""",
    """/**
 * @brief Set the signature-verification callbacks on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param verify_init Optional initialization callback before verification, or NULL.
 * @param verify Callback that verifies @p sig over @p tbs.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, int (*verify_init)(EVP_PKEY_CTX *ctx),
    int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen));""",
    "EVP_PKEY_meth_set_verify",
)

patch_both(
    "evp.h",
    "OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));",
    """/**
 * @brief Set the pairwise key-consistency check callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param check Callback invoked by EVP_PKEY_check(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));""",
    "EVP_PKEY_meth_set_check",
)

patch_both(
    "evp.h",
    "OSSL_PROVIDER *EVP_KEYEXCH_get0_provider(const EVP_KEYEXCH *exchange);",
    """/**
 * @brief Return the provider that implements a key-exchange algorithm.
 * @param exchange Key-exchange method to query.
 * @return Internal OSSL_PROVIDER pointer (do not free), or NULL on error.
 */
OSSL_PROVIDER *EVP_KEYEXCH_get0_provider(const EVP_KEYEXCH *exchange);""",
    "EVP_KEYEXCH_get0_provider",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  missing:", m)
