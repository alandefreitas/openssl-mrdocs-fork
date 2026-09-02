/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MODES_H
#define OPENSSL_MODES_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_MODES_H
#endif

#include <stddef.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Callback that encrypts or decrypts one 16-byte block with a cipher key.
 * @param in 16-byte input block.
 * @param out 16-byte output block.
 * @param key Cipher-specific expanded key schedule.
 */
typedef void (*block128_f)(const unsigned char in[16],
    unsigned char out[16], const void *key);

/**
 * @brief Callback that encrypts or decrypts a contiguous span of bytes in CBC mode.
 * @param in Input bytes of length @p len.
 * @param out Output buffer of length @p len (may equal @p in).
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key schedule.
 * @param ivec 16-byte IV; updated in place by the CBC chaining.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc);

/**
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

/**
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

/**
 * @brief Streaming CCM helper that processes whole 16-byte blocks and updates CMAC state.
 * @param in Input ciphertext or plaintext blocks.
 * @param out Output buffer for the transformed blocks.
 * @param blocks Number of 16-byte blocks to process.
 * @param key Cipher-specific expanded key schedule.
 * @param ivec 16-byte counter / IV block for the stream.
 * @param cmac 16-byte running CMAC / authentication state updated in place.
 */
typedef void (*ccm128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    const unsigned char ivec[16],
    unsigned char cmac[16]);

/**
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
/**
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

/**
 * @brief Encrypt or decrypt with a 128-bit block cipher in CTR mode.
 * @param in Input bytes of length @p len.
 * @param out Output buffer of length @p len (may equal @p in).
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte counter block updated as encryption proceeds.
 * @param ecount_buf 16-byte buffer holding the current encrypted counter block.
 * @param num Offset into @p ecount_buf for residual keystream (updated; start at 0).
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16],
    unsigned char ecount_buf[16], unsigned int *num,
    block128_f block);

/**
 * @brief Encrypt or decrypt in CTR mode using a 32-bit counter stream function.
 * @param in Input bytes of length @p len.
 * @param out Output buffer of length @p len (may equal @p in).
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key for @p ctr.
 * @param ivec 16-byte counter block updated as encryption proceeds.
 * @param ecount_buf 16-byte buffer holding residual encrypted counter output.
 * @param num Offset into @p ecount_buf for residual keystream (updated; start at 0).
 * @param ctr Multi-block CTR stream function for the underlying cipher.
 */
void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16],
    unsigned char ecount_buf[16],
    unsigned int *num, ctr128_f ctr);

/**
 * @brief Encrypt or decrypt with a 128-bit block cipher in OFB mode.
 * @param in Input bytes of length @p len.
 * @param out Output buffer of length @p len (may equal @p in).
 * @param len Number of bytes to process.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV / feedback block updated in place.
 * @param num Offset into the current OFB block (updated; typically starts at 0).
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int *num,
    block128_f block);

/**
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
/**
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
/**
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

/**
 * @brief Encrypt with CS1 ciphertext stealing using a single-block encrypt function.
 * @param in Input plaintext of length @p len (must be greater than 16).
 * @param out Output ciphertext buffer of length @p len.
 * @param len Number of plaintext bytes.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV updated like CBC.
 * @param block Block-encrypt function for the underlying cipher.
 * @return Number of ciphertext bytes written, or 0 on error.
 */
size_t CRYPTO_cts128_encrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key, unsigned char ivec[16],
    block128_f block);
/**
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
/**
 * @brief Decrypt CS1 ciphertext stealing using a single-block decrypt/encrypt pair via @p block.
 * @param in Input ciphertext of length @p len (must be greater than 16).
 * @param out Output plaintext buffer of length @p len.
 * @param len Number of ciphertext bytes.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV updated like CBC.
 * @param block Block cipher function used by the CTS decrypt path.
 * @return Number of plaintext bytes written, or 0 on error.
 */
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key, unsigned char ivec[16],
    block128_f block);
/**
 * @brief Decrypt CS1 ciphertext stealing using a CBC decrypt function.
 * @param in Input ciphertext of length @p len (must be greater than 16).
 * @param out Output plaintext buffer of length @p len.
 * @param len Number of ciphertext bytes.
 * @param key Cipher-specific expanded key for @p cbc.
 * @param ivec 16-byte IV updated like CBC.
 * @param cbc CBC-mode decrypt function for the underlying cipher.
 * @return Number of plaintext bytes written, or 0 on error.
 */
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);

/**
 * @brief Encrypt with NIST CS2/CS3-style ciphertext stealing using a block encrypt function.
 * @param in Input plaintext of length @p len (must be at least 16).
 * @param out Output ciphertext buffer of length @p len.
 * @param len Number of plaintext bytes.
 * @param key Cipher-specific expanded key for @p block.
 * @param ivec 16-byte IV updated like CBC.
 * @param block Block-encrypt function for the underlying cipher.
 * @return Number of ciphertext bytes written, or 0 on error.
 */
size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key,
    unsigned char ivec[16],
    block128_f block);
/**
 * @brief Encrypt with NIST CS2/CS3-style ciphertext stealing using a CBC encrypt function.
 * @param in Input plaintext of length @p len (must be at least 16).
 * @param out Output ciphertext buffer of length @p len.
 * @param len Number of plaintext bytes.
 * @param key Cipher-specific expanded key for @p cbc.
 * @param ivec 16-byte IV updated like CBC.
 * @param cbc CBC-mode encrypt function for the underlying cipher.
 * @return Number of ciphertext bytes written, or 0 on error.
 */
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);
/**
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
/**
 * @brief Decrypt NIST CS2/CS3-style ciphertext stealing using a CBC decrypt function.
 * @param in Input ciphertext of length @p len (must be at least 16).
 * @param out Output plaintext buffer of length @p len.
 * @param len Number of ciphertext bytes.
 * @param key Cipher-specific expanded key for @p cbc.
 * @param ivec 16-byte IV updated like CBC.
 * @param cbc CBC-mode decrypt function for the underlying cipher.
 * @return Number of plaintext bytes written, or 0 on error.
 */
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);

/**
 * @brief Opaque context for CRYPTO_gcm128_* Galois/Counter Mode helpers.
 */
typedef struct gcm128_context GCM128_CONTEXT;

/**
 * @brief Allocate and initialise a GCM128_CONTEXT for @p key and @p block.
 * @param key Cipher-specific expanded key for @p block.
 * @param block Block-encrypt function used for GHASH key derivation and CTR.
 * @return New context, or NULL on allocation failure; free with CRYPTO_gcm128_release().
 */
GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
/**
 * @brief Initialise (or reinitialise) a caller-owned GCM128_CONTEXT.
 * @param ctx Context storage to initialise.
 * @param key Cipher-specific expanded key for @p block.
 * @param block Block-encrypt function used for GHASH key derivation and CTR.
 */
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
/**
 * @brief Set the GCM IV / nonce for a subsequent encrypt or decrypt operation.
 * @param ctx GCM context from CRYPTO_gcm128_new() or CRYPTO_gcm128_init().
 * @param iv IV octets (commonly 12 bytes for GCM).
 * @param len Length of @p iv in bytes.
 */
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
    size_t len);
/**
 * @brief Absorb additional authenticated data into a GCM context before ciphertext.
 * @param ctx GCM context with IV already set.
 * @param aad Additional authenticated data octets.
 * @param len Length of @p aad in bytes.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
    size_t len);
/**
 * @brief Encrypt plaintext and update the GCM authentication state.
 * @param ctx GCM context ready for encryption (IV and optional AAD set).
 * @param in Plaintext bytes of length @p len.
 * @param out Ciphertext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to encrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len);
/**
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
/**
 * @brief Encrypt plaintext in GCM using a 32-bit CTR stream acceleration callback.
 * @param ctx GCM context ready for encryption.
 * @param in Plaintext bytes of length @p len.
 * @param out Ciphertext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to encrypt.
 * @param stream Multi-block CTR function for the underlying cipher.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len, ctr128_f stream);
/**
 * @brief Decrypt ciphertext in GCM using a 32-bit CTR stream acceleration callback.
 * @param ctx GCM context ready for decryption.
 * @param in Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to decrypt.
 * @param stream Multi-block CTR function for the underlying cipher.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len, ctr128_f stream);
/**
 * @brief Finalise GCM and optionally verify a received authentication tag.
 * @param ctx GCM context after encrypt/decrypt (and AAD) processing.
 * @param tag Expected tag to verify, or NULL to skip verification (encrypt path).
 * @param len Length of @p tag in bytes when @p tag is non-NULL.
 * @return 1 on success (and tag match when verifying), or 0 on failure.
 */
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
/**
 * @brief Write the computed GCM authentication tag into @p tag.
 * @param ctx GCM context after encryption (typically after CRYPTO_gcm128_finish with NULL tag).
 * @param tag Destination buffer for the tag.
 * @param len Number of tag bytes to write (commonly 16).
 */
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
/**
 * @brief Free a GCM128_CONTEXT allocated by CRYPTO_gcm128_new().
 * @param ctx Context to free, or NULL (no-op).
 */
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

/**
 * @brief Opaque context for CRYPTO_ccm128_* Counter with CBC-MAC helpers.
 */
typedef struct ccm128_context CCM128_CONTEXT;

/**
 * @brief Initialise a CCM128_CONTEXT with tag length, length-field size, and block cipher.
 * @param ctx Context storage to initialise.
 * @param M Authentication tag length in bytes (for example 8 or 16).
 * @param L Size of the message-length field in bytes (nonce length is 15 - L).
 * @param key Cipher-specific expanded key for @p block.
 * @param block Block-encrypt function for the underlying cipher.
 */
void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,
    unsigned int M, unsigned int L, void *key,
    block128_f block);
/**
 * @brief Set the CCM nonce and message length for a subsequent encrypt or decrypt.
 * @param ctx CCM context from CRYPTO_ccm128_init().
 * @param nonce Nonce octets; length must be at least 15 - L for the configured L.
 * @param nlen Length of @p nonce in bytes.
 * @param mlen Length of the message that will be encrypted or decrypted.
 * @return 0 on success, or -1 if @p nlen is too short for the configured L.
 */
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce,
    size_t nlen, size_t mlen);
/**
 * @brief Absorb additional authenticated data into a CCM context.
 * @param ctx CCM context with nonce already set via CRYPTO_ccm128_setiv().
 * @param aad Additional authenticated data octets.
 * @param alen Length of @p aad in bytes.
 */
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const unsigned char *aad,
    size_t alen);
/**
 * @brief Encrypt plaintext and update the CCM authentication state.
 * @param ctx CCM context ready for encryption (nonce and optional AAD set).
 * @param inp Plaintext bytes of length @p len.
 * @param out Ciphertext buffer of length @p len.
 * @param len Number of bytes to encrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
/**
 * @brief Decrypt ciphertext and update the CCM authentication state.
 * @param ctx CCM context ready for decryption (nonce and optional AAD set).
 * @param inp Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len.
 * @param len Number of bytes to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
/**
 * @brief Encrypt plaintext in CCM using a ccm128_f acceleration callback.
 * @param ctx CCM context ready for encryption.
 * @param inp Plaintext bytes of length @p len.
 * @param out Ciphertext buffer of length @p len.
 * @param len Number of bytes to encrypt.
 * @param stream Streaming CCM block function for the underlying cipher.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len,
    ccm128_f stream);
/**
 * @brief Decrypt ciphertext in CCM using a ccm128_f acceleration callback.
 * @param ctx CCM context ready for decryption.
 * @param inp Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len.
 * @param len Number of bytes to decrypt.
 * @param stream Streaming CCM block function for the underlying cipher.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len,
    ccm128_f stream);
/**
 * @brief Write the computed CCM authentication tag into @p tag.
 * @param ctx CCM context after encryption (and optional AAD) processing.
 * @param tag Destination buffer for the tag; @p len must equal the configured M tag length.
 * @param len Number of tag bytes requested (must match the M value from CRYPTO_ccm128_init()).
 * @return Number of tag bytes written (@p len), or 0 if @p len does not match M.
 */
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);

/**
 * @brief Opaque context holding the two keys used by CRYPTO_xts128_encrypt().
 */
typedef struct xts128_context XTS128_CONTEXT;

/**
 * @brief Encrypt or decrypt data with a 128-bit block cipher in XTS mode.
 * @param ctx XTS context holding the two keys and block functions.
 * @param iv 16-byte tweak / sector IV for this unit.
 * @param inp Input plaintext or ciphertext of length @p len (at least 16).
 * @param out Output buffer of length @p len (may equal @p inp).
 * @param len Number of bytes to process (must be >= 16).
 * @param enc Non-zero to encrypt, zero to decrypt.
 * @return 0 on success, or -1 if @p len is invalid.
 */
int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx,
    const unsigned char iv[16],
    const unsigned char *inp, unsigned char *out,
    size_t len, int enc);

/**
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

/**
 * @brief Unwrap a key with AES Key Wrap (RFC 3394) using @p block.
 * @param key Cipher-specific expanded key for @p block.
 * @param iv Optional expected 8-byte IV, or NULL for the RFC 3394 default IV.
 * @param out Buffer for the unwrapped key (at least @p inlen - 8 bytes).
 * @param in Wrapped key material as n 64-bit blocks with n >= 2.
 * @param inlen Length of @p in in bytes (multiple of 8, at least 16).
 * @param block Block-decrypt function used by the unwrap algorithm.
 * @return Length of unwrapped data written to @p out, or 0 on error (including IV mismatch).
 */
size_t CRYPTO_128_unwrap(void *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, size_t inlen,
    block128_f block);
/**
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
/**
 * @brief Unwrap a key with AES Key Wrap with Padding (RFC 5649) using @p block.
 * @param key Cipher-specific expanded key for @p block.
 * @param icv Optional expected AIV / integrity value, or NULL for the default.
 * @param out Buffer for the unwrapped key material.
 * @param in Wrapped key octets.
 * @param inlen Length of @p in in bytes.
 * @param block Block-encrypt/decrypt function used by the unwrap algorithm.
 * @return Length of unwrapped data written to @p out, or 0 on error.
 */
size_t CRYPTO_128_unwrap_pad(void *key, const unsigned char *icv,
    unsigned char *out, const unsigned char *in,
    size_t inlen, block128_f block);

#ifndef OPENSSL_NO_OCB
/**
 * @brief Opaque context for CRYPTO_ocb128_* Offset Codebook Mode helpers.
 */
typedef struct ocb128_context OCB128_CONTEXT;

/**
 * @brief Streaming OCB helper that processes whole 16-byte blocks and updates checksum state.
 * @param in Input ciphertext or plaintext blocks.
 * @param out Output buffer for the transformed blocks.
 * @param blocks Number of 16-byte blocks to process.
 * @param key Cipher-specific expanded key schedule.
 * @param start_block_num Block index of the first block in this call (for L lookup).
 * @param offset_i 16-byte running Offset_i state updated in place.
 * @param L_ Table of precomputed L values indexed by trailing-zero count.
 * @param checksum 16-byte running checksum state updated in place.
 */
typedef void (*ocb128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    size_t start_block_num,
    unsigned char offset_i[16],
    const unsigned char L_[][16],
    unsigned char checksum[16]);

/**
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
/**
 * @brief Initialise an existing OCB128_CONTEXT for the given keys and block functions.
 * @param ctx Context storage to initialise.
 * @param keyenc Cipher-specific expanded key used for encryption-direction operations.
 * @param keydec Cipher-specific expanded key used for decryption-direction operations.
 * @param encrypt Block-encrypt function for the underlying cipher.
 * @param decrypt Block-decrypt function for the underlying cipher.
 * @param stream Optional multi-block OCB acceleration callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ocb128_init(OCB128_CONTEXT *ctx, void *keyenc, void *keydec,
    block128_f encrypt, block128_f decrypt,
    ocb128_f stream);
/**
 * @brief Copy an OCB context, optionally replacing the encrypt/decrypt key pointers.
 * @param dest Destination context to initialise as a copy of @p src.
 * @param src Source OCB context to copy.
 * @param keyenc Replacement encrypt-direction key, or NULL to keep @p src's.
 * @param keydec Replacement decrypt-direction key, or NULL to keep @p src's.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ocb128_copy_ctx(OCB128_CONTEXT *dest, OCB128_CONTEXT *src,
    void *keyenc, void *keydec);
/**
 * @brief Set the OCB IV / nonce and authentication tag length for an operation.
 * @param ctx OCB context from CRYPTO_ocb128_new() or CRYPTO_ocb128_init().
 * @param iv Nonce octets (1–15 bytes).
 * @param len Length of @p iv in bytes.
 * @param taglen Desired tag length in bytes (1–16).
 * @return 1 on success, or -1 if @p len or @p taglen is out of range.
 */
int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
    size_t len, size_t taglen);
/**
 * @brief Absorb additional authenticated data into an OCB context.
 * @param ctx OCB context with IV already set.
 * @param aad Additional authenticated data octets.
 * @param len Length of @p aad in bytes.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad,
    size_t len);
/**
 * @brief Encrypt plaintext and update the OCB authentication state.
 * @param ctx OCB context ready for encryption.
 * @param in Plaintext bytes of length @p len.
 * @param out Ciphertext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to encrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx, const unsigned char *in,
    unsigned char *out, size_t len);
/**
 * @brief Decrypt ciphertext and update the OCB authentication state.
 * @param ctx OCB context ready for decryption.
 * @param in Ciphertext bytes of length @p len.
 * @param out Plaintext buffer of length @p len (may equal @p in).
 * @param len Number of bytes to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_ocb128_decrypt(OCB128_CONTEXT *ctx, const unsigned char *in,
    unsigned char *out, size_t len);
/**
 * @brief Finalise OCB and verify a received authentication tag.
 * @param ctx OCB context after encrypt/decrypt (and AAD) processing.
 * @param tag Expected authentication tag to compare.
 * @param len Length of @p tag in bytes (1–16).
 * @return 0 if @p tag matches, a non-zero value if it does not, or -1 if @p len is invalid.
 */
int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
/**
 * @brief Write the computed OCB authentication tag into @p tag.
 * @param ctx OCB context after encryption (and optional AAD) processing.
 * @param tag Destination buffer for the tag.
 * @param len Number of tag bytes to write (1–16).
 * @return 1 on success, or -1 if @p len is invalid.
 */
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
/**
 * @brief Release internal OCB tables and cleanse the context (does not free @p ctx itself).
 * @param ctx Context to cleanse, or NULL (no-op).
 */
void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);
#endif /* OPENSSL_NO_OCB */

#ifdef __cplusplus
}
#endif

#endif
