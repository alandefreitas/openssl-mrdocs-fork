#!/usr/bin/env python3
"""Documentation repair batch 23b: encoder.h and modes.h."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


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


print("=== batch 23b ===")

# ----- encoder.h -----

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder);
""",
    """/**
 * @brief Increment the reference count of a fetched encoder.
 * @param encoder Encoder whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder);
""",
    "OSSL_ENCODER_up_ref",
)

patch_one(
    "encoder.h",
    """void OSSL_ENCODER_free(OSSL_ENCODER *encoder);
""",
    """/**
 * @brief Decrement the reference count of a fetched encoder and free it at zero.
 * @param encoder Encoder to release, or NULL (no-op).
 */
void OSSL_ENCODER_free(OSSL_ENCODER *encoder);
""",
    "OSSL_ENCODER_free",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name);
""",
    """/**
 * @brief Test whether an encoder implements the algorithm identified by @p name.
 * @param encoder Encoder to query.
 * @param name Algorithm name or synonym to match.
 * @return 1 if @p encoder is identifiable as @p name, otherwise 0.
 */
int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name);
""",
    "OSSL_ENCODER_is_a",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_names_do_all(const OSSL_ENCODER *encoder,
    void (*fn)(const char *name, void *data),
    void *data);
""",
    """/**
 * @brief Invoke a callback for every name/synonym associated with an encoder.
 * @param encoder Encoder whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque argument passed to @p fn.
 * @return 1 if the callback was invoked for all names, or 0 if none were called.
 */
int OSSL_ENCODER_names_do_all(const OSSL_ENCODER *encoder,
    void (*fn)(const char *name, void *data),
    void *data);
""",
    "OSSL_ENCODER_names_do_all",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_get_params(OSSL_ENCODER *encoder, OSSL_PARAM params[]);
""",
    """/**
 * @brief Retrieve parameters from an encoder into an OSSL_PARAM array.
 * @param encoder Encoder to query.
 * @param params Array of OSSL_PARAM requests; unrecognized keys are ignored.
 * @return 1 on success, or 0 on error.
 */
int OSSL_ENCODER_get_params(OSSL_ENCODER *encoder, OSSL_PARAM params[]);
""",
    "OSSL_ENCODER_get_params",
)

patch_one(
    "encoder.h",
    """OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new(void);
""",
    """/**
 * @brief Create an empty encoder context for chaining and running encoders.
 * @return New OSSL_ENCODER_CTX, or NULL on allocation failure; free with OSSL_ENCODER_CTX_free().
 */
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new(void);
""",
    "OSSL_ENCODER_CTX_new",
)

patch_one(
    "encoder.h",
    """void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx);
""",
    """/**
 * @brief Free an encoder context and invoke any registered cleanup callback.
 * @param ctx Encoder context to free, or NULL (no-op).
 */
void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx);
""",
    "OSSL_ENCODER_CTX_free",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_pem_password_cb(OSSL_ENCODER_CTX *ctx,
    pem_password_cb *cb, void *cbarg);
""",
    """/**
 * @brief Set a legacy PEM password callback used to prompt for a passphrase.
 * @param ctx Encoder context to configure.
 * @param cb PEM-style password callback, or NULL to clear.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_pem_password_cb(OSSL_ENCODER_CTX *ctx,
    pem_password_cb *cb, void *cbarg);
""",
    "OSSL_ENCODER_CTX_set_pem_password_cb",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
    OSSL_PASSPHRASE_CALLBACK *cb,
    void *cbarg);
""",
    """/**
 * @brief Set an OSSL_PASSPHRASE_CALLBACK used to prompt for a passphrase.
 * @param ctx Encoder context to configure.
 * @param cb Passphrase callback invoked when encryption needs a secret.
 * @param cbarg Opaque argument passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
    OSSL_PASSPHRASE_CALLBACK *cb,
    void *cbarg);
""",
    "OSSL_ENCODER_CTX_set_passphrase_cb",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);
""",
    """/**
 * @brief Set a UI method for passphrase prompting on an encoder context.
 * @param ctx Encoder context to configure.
 * @param ui_method UI_METHOD used to read passphrases, or NULL for the default.
 * @param ui_data Application data passed to the UI method.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);
""",
    "OSSL_ENCODER_CTX_set_passphrase_ui",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection);
""",
    """/**
 * @brief Set the key/component selection mask for encoding (OSSL_KEYMGMT_SELECT_*).
 * @param ctx Encoder context to configure.
 * @param selection Non-zero bit mask of components to encode.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection);
""",
    "OSSL_ENCODER_CTX_set_selection",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_output_type(OSSL_ENCODER_CTX *ctx,
    const char *output_type);
""",
    """/**
 * @brief Set the ending output type that a complete encoder chain must produce.
 * @param ctx Encoder context to configure.
 * @param output_type Output type name (for example "DER" or "PEM").
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_output_type(OSSL_ENCODER_CTX *ctx,
    const char *output_type);
""",
    "OSSL_ENCODER_CTX_set_output_type",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder);
""",
    """/**
 * @brief Add an encoder implementation to an encoder context's chain.
 * @param ctx Encoder context to populate.
 * @param encoder Fetched encoder to append for encoding the input object.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder);
""",
    "OSSL_ENCODER_CTX_add_encoder",
)

patch_one(
    "encoder.h",
    """typedef struct ossl_encoder_instance_st OSSL_ENCODER_INSTANCE;
""",
    """/**
 * @brief Opaque pairing of an OSSL_ENCODER with its per-instance encoder context during an encode run.
 */
typedef struct ossl_encoder_instance_st OSSL_ENCODER_INSTANCE;
""",
    "OSSL_ENCODER_INSTANCE",
)

patch_one(
    "encoder.h",
    """const char *
OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst);
""",
    """/**
 * @brief Return the output-structure name for an encoder instance (for example "pkcs8").
 * @param encoder_inst Encoder instance to query.
 * @return Internal NUL-terminated structure string, or NULL if unset.
 */
const char *
OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst);
""",
    "OSSL_ENCODER_INSTANCE_get_output_structure",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_CTX_set_construct(OSSL_ENCODER_CTX *ctx,
    OSSL_ENCODER_CONSTRUCT *construct);
""",
    """/**
 * @brief Register the constructor that builds the provider-side object to encode.
 * @param ctx Encoder context to configure.
 * @param construct Callback returning a provider-native object, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_CTX_set_construct(OSSL_ENCODER_CTX *ctx,
    OSSL_ENCODER_CONSTRUCT *construct);
""",
    "OSSL_ENCODER_CTX_set_construct",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out);
""",
    """/**
 * @brief Run encoding for a context and write the result to a BIO.
 * @param ctx Configured encoder context.
 * @param out Destination BIO (text or binary mode as appropriate for the output type).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out);
""",
    "OSSL_ENCODER_to_bio",
)

patch_one(
    "encoder.h",
    """int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
""",
    """/**
 * @brief Run encoding for a context and write the result to a FILE stream.
 * @param ctx Configured encoder context.
 * @param fp Destination FILE (text or binary mode as appropriate for the output type).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
""",
    "OSSL_ENCODER_to_fp",
)

# ----- modes.h -----

patch_one(
    "modes.h",
    """typedef void (*ecb128_f)(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    int enc);
""",
    """/**
 * @brief Callback that encrypts or decrypts a contiguous span of 16-byte blocks in ECB mode.
 * @param in Input bytes of length @p len (multiple of 16).
 * @param out Output buffer of length @p len.
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key schedule.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
typedef void (*ecb128_f)(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    int enc);
""",
    "ecb128_f",
)

patch_one(
    "modes.h",
    """typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    const unsigned char ivec[16]);
""",
    """/**
 * @brief Callback that encrypts or decrypts whole 16-byte blocks in CTR mode.
 * @param in Input ciphertext or plaintext blocks.
 * @param out Output buffer for the transformed blocks.
 * @param blocks Number of 16-byte blocks to process.
 * @param key Cipher-specific expanded key schedule.
 * @param ivec 16-byte counter block for the stream.
 */
typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    const unsigned char ivec[16]);
""",
    "ctr128_f",
)

patch_one(
    "modes.h",
    """void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);
""",
    """/**
 * @brief Encrypt with a 128-bit block cipher in CBC mode.
 * @param in Input plaintext of length @p len.
 * @param out Output ciphertext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to encrypt.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV; updated to the last ciphertext block on return.
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);
""",
    "CRYPTO_cbc128_encrypt",
)

patch_one(
    "modes.h",
    """void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);
""",
    """/**
 * @brief Decrypt with a 128-bit block cipher in CBC mode.
 * @param in Input ciphertext of length @p len.
 * @param out Output plaintext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to decrypt.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV; updated to the last ciphertext block on return.
 * @param block Block-decrypt function for the underlying cipher.
 */
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);
""",
    "CRYPTO_cbc128_decrypt",
)

patch_one(
    "modes.h",
    """void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    """/**
 * @brief Encrypt or decrypt with a 128-bit block cipher in full-block CFB mode.
 * @param in Input bytes of length @p len.
 * @param out Output buffer of length @p len (may equal @p in).
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV / feedback block updated in place.
 * @param num Offset into the current CFB block (updated; typically starts at 0).
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    "CRYPTO_cfb128_encrypt",
)

patch_one(
    "modes.h",
    """void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    """/**
 * @brief Encrypt or decrypt with a 128-bit block cipher in 8-bit CFB mode.
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV / feedback block updated in place.
 * @param num Offset into the current CFB block (updated).
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    "CRYPTO_cfb128_8_encrypt",
)

patch_one(
    "modes.h",
    """void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
    size_t bits, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    """/**
 * @brief Encrypt or decrypt with a 128-bit block cipher in 1-bit CFB mode.
 * @param in Input bits packed most-significant-bit first.
 * @param out Output buffer holding the transformed bits (same packing).
 * @param bits Number of bits to process.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV / feedback block updated in place.
 * @param num Offset into the current CFB block (updated).
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
    size_t bits, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
""",
    "CRYPTO_cfb128_1_encrypt",
)

patch_one(
    "modes.h",
    """size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);
""",
    """/**
 * @brief Encrypt with CS1 ciphertext stealing using a CBC encrypt function.
 * @param in Input plaintext of length @p len (must be greater than 16).
 * @param out Output ciphertext buffer of length @p len.
 * @param len Number of plaintext bytes.
 * @param key Cipher-specific expanded key for @p cbc.
 * @param ivec 16-byte IV updated like CBC.
 * @param cbc CBC-mode encrypt function for the underlying cipher.
 * @return Number of ciphertext bytes written, or 0 on error.
 */
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);
""",
    "CRYPTO_cts128_encrypt",
)

patch_one(
    "modes.h",
    """size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key,
    unsigned char ivec[16],
    block128_f block);
""",
    """/**
 * @brief Decrypt NIST CS2/CS3-style ciphertext stealing using a block decrypt function.
 * @param in Input ciphertext of length @p len (must be at least 16).
 * @param out Output plaintext buffer of length @p len.
 * @param len Number of ciphertext bytes.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV updated like CBC.
 * @param block Block-decrypt function for the underlying cipher.
 * @return Number of plaintext bytes written, or 0 on error.
 */
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key,
    unsigned char ivec[16],
    block128_f block);
""",
    "CRYPTO_nistcts128_decrypt_block",
)

patch_one(
    "modes.h",
    """int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len);
""",
    """/**
 * @brief Decrypt ciphertext and update the GCM authentication state.
 * @param ctx GCM context ready for decryption (IV and optional AAD set).
 * @param in Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len);
""",
    "CRYPTO_gcm128_decrypt",
)

patch_one(
    "modes.h",
    """int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce,
    size_t nlen, size_t mlen);
""",
    """/**
 * @brief Set the CCM nonce and message length for a subsequent encrypt or decrypt.
 * @param ctx CCM context from CRYPTO_ccm128_init().
 * @param nonce Nonce octets; length must be at least 15 - L for the configured L.
 * @param nlen Length of @p nonce in bytes.
 * @param mlen Length of the message that will be encrypted or decrypted.
 * @return 0 on success, or -1 if @p nlen is too short for the configured L.
 */
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce,
    size_t nlen, size_t mlen);
""",
    "CRYPTO_ccm128_setiv",
)

patch_one(
    "modes.h",
    """int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
""",
    """/**
 * @brief Decrypt ciphertext and update the CCM authentication state.
 * @param ctx CCM context ready for decryption (nonce and optional AAD set).
 * @param inp Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len.
 * @param len Number of bytes to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
""",
    "CRYPTO_ccm128_decrypt",
)

patch_one(
    "modes.h",
    """size_t CRYPTO_128_wrap(void *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, size_t inlen,
    block128_f block);
""",
    """/**
 * @brief Wrap a key with AES Key Wrap (RFC 3394) using @p block.
 * @param key Cipher-specific expanded key for @p block.
 * @param iv Optional 8-byte IV, or NULL for the RFC 3394 default IV.
 * @param out Buffer for the wrapped key (at least @p inlen + 8 bytes).
 * @param in Key material as n 64-bit blocks with n >= 2.
 * @param inlen Length of @p in in bytes (multiple of 8, at least 16).
 * @param block Block-encrypt function used by the wrap algorithm.
 * @return Length of wrapped data written to @p out, or 0 on error.
 */
size_t CRYPTO_128_wrap(void *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, size_t inlen,
    block128_f block);
""",
    "CRYPTO_128_wrap",
)

patch_one(
    "modes.h",
    """size_t CRYPTO_128_wrap_pad(void *key, const unsigned char *icv,
    unsigned char *out, const unsigned char *in,
    size_t inlen, block128_f block);
""",
    """/**
 * @brief Wrap a key with AES Key Wrap with Padding (RFC 5649) using @p block.
 * @param key Cipher-specific expanded key for @p block.
 * @param icv Optional 4-byte AIV integrity value, or NULL for the default.
 * @param out Buffer for the wrapped key material.
 * @param in Key material octets to wrap (any length in the supported range).
 * @param inlen Length of @p in in bytes.
 * @param block Block-encrypt function used by the wrap algorithm.
 * @return Length of wrapped data written to @p out, or 0 on error.
 */
size_t CRYPTO_128_wrap_pad(void *key, const unsigned char *icv,
    unsigned char *out, const unsigned char *in,
    size_t inlen, block128_f block);
""",
    "CRYPTO_128_wrap_pad",
)

patch_one(
    "modes.h",
    """OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec,
    block128_f encrypt, block128_f decrypt,
    ocb128_f stream);
""",
    """/**
 * @brief Allocate and initialise an OCB128_CONTEXT for the given keys and block functions.
 * @param keyenc Cipher-specific expanded key used for encryption-direction operations.
 * @param keydec Cipher-specific expanded key used for decryption-direction operations.
 * @param encrypt Block-encrypt function for the underlying cipher.
 * @param decrypt Block-decrypt function for the underlying cipher.
 * @param stream Optional multi-block OCB acceleration callback, or NULL.
 * @return New context, or NULL on failure; cleanse internals with CRYPTO_ocb128_cleanup().
 */
OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec,
    block128_f encrypt, block128_f decrypt,
    ocb128_f stream);
""",
    "CRYPTO_ocb128_new",
)

patch_one(
    "modes.h",
    """int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
    size_t len, size_t taglen);
""",
    """/**
 * @brief Set the OCB IV / nonce and authentication tag length for an operation.
 * @param ctx OCB context from CRYPTO_ocb128_new() or CRYPTO_ocb128_init().
 * @param iv Nonce octets (1–15 bytes).
 * @param len Length of @p iv in bytes.
 * @param taglen Desired tag length in bytes (1–16).
 * @return 1 on success, or -1 if @p len or @p taglen is out of range.
 */
int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
    size_t len, size_t taglen);
""",
    "CRYPTO_ocb128_setiv",
)

patch_one(
    "modes.h",
    """int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
""",
    """/**
 * @brief Finalise OCB and verify a received authentication tag.
 * @param ctx OCB context after encrypt/decrypt (and AAD) processing.
 * @param tag Expected authentication tag to compare.
 * @param len Length of @p tag in bytes (1–16).
 * @return 0 if @p tag matches, a non-zero value if it does not, or -1 if @p len is invalid.
 */
int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
""",
    "CRYPTO_ocb128_finish",
)

patch_one(
    "modes.h",
    """int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
""",
    """/**
 * @brief Write the computed OCB authentication tag into @p tag.
 * @param ctx OCB context after encryption (and optional AAD) processing.
 * @param tag Destination buffer for the tag.
 * @param len Number of tag bytes to write (1–16).
 * @return 1 on success, or -1 if @p len is invalid.
 */
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
""",
    "CRYPTO_ocb128_tag",
)

patch_one(
    "modes.h",
    """void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);
""",
    """/**
 * @brief Release internal OCB tables and cleanse the context (does not free @p ctx itself).
 * @param ctx Context to cleanse, or NULL (no-op).
 */
void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);
""",
    "CRYPTO_ocb128_cleanup",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
