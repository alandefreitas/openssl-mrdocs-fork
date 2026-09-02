#!/usr/bin/env python3
"""Documentation repair batch 23a: aes through provider legacy symbols."""
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


print("=== batch 23a ===")

# ----- aes.h -----

patch_one(
    "aes.h",
    """/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
#endif
    int rounds;
};
""",
    """/* This should be a hidden type, but EVP requires that the size be known */
/**
 * @brief Expanded AES key schedule for the low-level AES_* APIs (deprecated; prefer EVP).
 */
struct aes_key_st {
#ifdef AES_LONG
    /** Round-key words for encryption or decryption (AES_LONG element width). */
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
#else
    /** Round-key words for encryption or decryption. */
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
#endif
    /** Number of AES rounds for this key length (10, 12, or 14). */
    int rounds;
};
""",
    "aes_key_st",
)

patch_one(
    "aes.h",
    """OSSL_DEPRECATEDIN_3_0
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
""",
    """/**
 * @brief Expand a user key into an AES decryption key schedule (deprecated; prefer EVP).
 * @param userKey Raw AES key bytes (16, 24, or 32 bytes for 128/192/256-bit).
 * @param bits Key length in bits (128, 192, or 256).
 * @param key Destination expanded key schedule for AES_decrypt() and decrypting modes.
 * @return 0 on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
""",
    "AES_set_decrypt_key",
)

patch_one(
    "aes.h",
    """OSSL_DEPRECATEDIN_3_0
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key, const int enc);
""",
    """/**
 * @brief Encrypt or decrypt one 16-byte AES block in ECB mode (deprecated; prefer EVP).
 * @param in 16-byte input block.
 * @param out 16-byte output buffer (may equal @p in).
 * @param key Expanded AES key from AES_set_encrypt_key() or AES_set_decrypt_key().
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key, const int enc);
""",
    "AES_ecb_encrypt",
)

patch_one(
    "aes.h",
    """OSSL_DEPRECATEDIN_3_0
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, const int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with AES in CBC mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process (should be a multiple of AES_BLOCK_SIZE).
 * @param key Expanded AES key schedule matching @p enc.
 * @param ivec 16-byte IV updated in place to the last ciphertext block.
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *ivec, const int enc);
""",
    "AES_cbc_encrypt",
)

patch_one(
    "aes.h",
    """/* NB: the IV is _four_ blocks long */
OSSL_DEPRECATEDIN_3_0
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key, const AES_KEY *key2,
    const unsigned char *ivec, const int enc);
""",
    """/* NB: the IV is _four_ blocks long */
/**
 * @brief Encrypt or decrypt with AES in bidirectional IGE mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length (multiple of AES_BLOCK_SIZE).
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param key First expanded AES key schedule.
 * @param key2 Second expanded AES key schedule used in the bidirectional step.
 * @param ivec 64-byte (four-block) IV; not updated by this call.
 * @param enc AES_ENCRYPT to encrypt, or AES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key, const AES_KEY *key2,
    const unsigned char *ivec, const int enc);
""",
    "AES_bi_ige_encrypt",
)

# ----- cast.h -----

patch_one(
    "cast.h",
    """OSSL_DEPRECATEDIN_3_0
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, const CAST_KEY *schedule,
    unsigned char *ivec, int *num, int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with CAST in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded CAST key from CAST_set_key().
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc CAST_ENCRYPT to encrypt, or CAST_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, const CAST_KEY *schedule,
    unsigned char *ivec, int *num, int enc);
""",
    "CAST_cfb64_encrypt",
)

# ----- cmac.h -----

patch_one(
    "cmac.h",
    """/* Opaque */
typedef struct CMAC_CTX_st CMAC_CTX;
""",
    """/* Opaque */
/**
 * @brief Opaque CMAC (Cipher-based MAC) context (deprecated; prefer EVP_MAC).
 */
typedef struct CMAC_CTX_st CMAC_CTX;
""",
    "CMAC_CTX_st",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 CMAC_CTX *CMAC_CTX_new(void);
""",
    """/**
 * @brief Allocate a new CMAC context (deprecated; prefer EVP_MAC).
 * @return New CMAC_CTX, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 CMAC_CTX *CMAC_CTX_new(void);
""",
    "CMAC_CTX_new",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_cleanup(CMAC_CTX *ctx);
""",
    """/**
 * @brief Clear sensitive CMAC state while keeping the context allocated (deprecated).
 * @param ctx Context to clean, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_cleanup(CMAC_CTX *ctx);
""",
    "CMAC_CTX_cleanup",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_free(CMAC_CTX *ctx);
""",
    """/**
 * @brief Free a CMAC context and its resources.
 * @param ctx Context to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void CMAC_CTX_free(CMAC_CTX *ctx);
""",
    "CMAC_CTX_free",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
""",
    """/**
 * @brief Return the internal EVP_CIPHER_CTX used by a CMAC context (deprecated).
 * @param ctx CMAC context.
 * @return Borrowed cipher context pointer owned by @p ctx.
 */
OSSL_DEPRECATEDIN_3_0 EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
""",
    "CMAC_CTX_get0_cipher_ctx",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);
""",
    """/**
 * @brief Copy CMAC state from @p in into @p out (deprecated).
 * @param out Destination CMAC context (already allocated).
 * @param in Source CMAC context to duplicate.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);
""",
    "CMAC_CTX_copy",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 int CMAC_Init(CMAC_CTX *ctx,
    const void *key, size_t keylen,
    const EVP_CIPHER *cipher, ENGINE *impl);
""",
    """/**
 * @brief Initialize a CMAC context with a key and block cipher (deprecated; prefer EVP_MAC).
 * @param ctx CMAC context to initialize.
 * @param key CMAC key material.
 * @param keylen Length of @p key in bytes.
 * @param cipher Block cipher implementing CMAC (for example AES-128-CBC).
 * @param impl Optional ENGINE implementing @p cipher, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Init(CMAC_CTX *ctx,
    const void *key, size_t keylen,
    const EVP_CIPHER *cipher, ENGINE *impl);
""",
    "CMAC_Init",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 int CMAC_Update(CMAC_CTX *ctx,
    const void *data, size_t dlen);
""",
    """/**
 * @brief Absorb more message bytes into a CMAC computation (deprecated).
 * @param ctx CMAC context initialized with CMAC_Init().
 * @param data Message bytes to authenticate.
 * @param dlen Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Update(CMAC_CTX *ctx,
    const void *data, size_t dlen);
""",
    "CMAC_Update",
)

patch_one(
    "cmac.h",
    """OSSL_DEPRECATEDIN_3_0 int CMAC_Final(CMAC_CTX *ctx,
    unsigned char *out, size_t *poutlen);
""",
    """/**
 * @brief Finish a CMAC and write the authentication tag (deprecated).
 * @param ctx CMAC context updated with CMAC_Update().
 * @param out Buffer for the MAC (cipher block size), or NULL to query length only.
 * @param poutlen On entry, capacity of @p out; on success, bytes written (or required).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int CMAC_Final(CMAC_CTX *ctx,
    unsigned char *out, size_t *poutlen);
""",
    "CMAC_Final",
)

# ----- cryptoerr_legacy.h -----

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_ASYNC_strings(void);
""",
    """/**
 * @brief Load ASYNC library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_ASYNC_strings(void);
""",
    "ERR_load_ASYNC_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_X509_strings(void);
""",
    """/**
 * @brief Load X509 library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_X509_strings(void);
""",
    "ERR_load_X509_strings",
)

# ----- decoder.h -----

patch_one(
    "decoder.h",
    """int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder);
""",
    """/**
 * @brief Attach a fetched decoder implementation to a decoder context.
 * @param ctx Decoder context to extend.
 * @param decoder Decoder from OSSL_DECODER_fetch() (reference is up-reffed).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder);
""",
    "OSSL_DECODER_CTX_add_decoder",
)

# ----- des.h -----

patch_one(
    "des.h",
    """typedef unsigned int DES_LONG;
""",
    """/**
 * @brief Host unsigned word type used by low-level DES block primitives.
 */
typedef unsigned int DES_LONG;
""",
    "DES_LONG",
)

patch_one(
    "des.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);
#endif
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Encrypt or decrypt one DES block in place with IP and FP (deprecated low-level core).
 * @param data Two DES_LONG words holding the 64-bit block in little-endian byte order.
 * @param ks Expanded DES key schedule.
 * @param enc Non-zero to encrypt, or zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);
#endif
""",
    "DES_encrypt1",
)

patch_one(
    "des.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
OSSL_DEPRECATEDIN_3_0
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
    DES_key_schedule *ks3);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Encrypt or decrypt one DES block without IP/FP (used internally for 3DES; deprecated).
 * @param data Two DES_LONG words holding the 64-bit block in little-endian byte order.
 * @param ks Expanded DES key schedule.
 * @param enc Non-zero to encrypt, or zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
/**
 * @brief Encrypt one block with triple-DES EDE using three schedules (deprecated low-level).
 * @param data Two DES_LONG words holding the 64-bit block (no outer IP/FP).
 * @param ks1 First DES key schedule (encrypt).
 * @param ks2 Second DES key schedule (decrypt).
 * @param ks3 Third DES key schedule (encrypt).
 */
OSSL_DEPRECATEDIN_3_0
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
    DES_key_schedule *ks3);
""",
    "DES_encrypt2_encrypt3",
)

patch_one(
    "des.h",
    """OSSL_DEPRECATEDIN_3_0 int DES_is_weak_key(const_DES_cblock *key);
""",
    """/**
 * @brief Test whether a DES key is one of the known weak or semi-weak keys (deprecated).
 * @param key Eight-byte DES key to check.
 * @return 1 if @p key is weak or semi-weak, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 int DES_is_weak_key(const_DES_cblock *key);
""",
    "DES_is_weak_key",
)

patch_one(
    "des.h",
    """OSSL_DEPRECATEDIN_3_0
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
""",
    """/**
 * @brief Expand a DES key into a key schedule (checked or unchecked per DES_check_key; deprecated).
 * @param key Eight-byte DES key.
 * @param schedule Destination expanded key schedule.
 * @return 0 on success; when checking is enabled, -1 on parity error or -2 if @p key is weak.
 */
OSSL_DEPRECATEDIN_3_0
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
""",
    "DES_set_key",
)

# ----- ebcdic.h -----

patch_one(
    "ebcdic.h",
    """extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);
""",
    """/**
 * @brief 256-byte table mapping EBCDIC code points to ASCII (exported as _openssl_os_toascii).
 */
extern const unsigned char os_toascii[256];
/**
 * @brief 256-byte table mapping ASCII code points to EBCDIC (exported as _openssl_os_toebcdic).
 */
extern const unsigned char os_toebcdic[256];
/**
 * @brief Convert @p count bytes from EBCDIC to ASCII into @p dest (may equal @p srce).
 * @param dest Destination buffer of at least @p count bytes.
 * @param srce Source EBCDIC bytes.
 * @param count Number of bytes to convert.
 * @return @p dest.
 */
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
/**
 * @brief Convert @p count bytes from ASCII to EBCDIC into @p dest (may equal @p srce).
 * @param dest Destination buffer of at least @p count bytes.
 * @param srce Source ASCII bytes.
 * @param count Number of bytes to convert.
 * @return @p dest.
 */
void *ascii2ebcdic(void *dest, const void *srce, size_t count);
""",
    "ebcdic_tables_and_converters",
)

# ----- idea.h -----

patch_one(
    "idea.h",
    """typedef unsigned int IDEA_INT;

#define IDEA_ENCRYPT 1
#define IDEA_DECRYPT 0

typedef struct idea_key_st {
    IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;
""",
    """/**
 * @brief Unsigned word type used in the IDEA key schedule tables.
 */
typedef unsigned int IDEA_INT;

#define IDEA_ENCRYPT 1
#define IDEA_DECRYPT 0

/**
 * @brief Expanded IDEA key schedule for the low-level IDEA_* APIs (deprecated; prefer EVP).
 */
typedef struct idea_key_st {
    /** Round subkeys arranged as 9 rounds of 6 IDEA_INT words each. */
    IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;
""",
    "IDEA_INT_and_idea_key_st",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 const char *IDEA_options(void);
""",
    """/**
 * @brief Return a short string describing the IDEA implementation (deprecated).
 * @return Static option description string (for example "idea(int)").
 */
OSSL_DEPRECATEDIN_3_0 const char *IDEA_options(void);
""",
    "IDEA_options",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_ecb_encrypt(const unsigned char *in,
    unsigned char *out,
    IDEA_KEY_SCHEDULE *ks);
""",
    """/**
 * @brief Encrypt one 8-byte IDEA block in ECB mode (deprecated; prefer EVP).
 * @param in 8-byte plaintext block.
 * @param out 8-byte ciphertext buffer (may equal @p in).
 * @param ks Expanded encrypt schedule from IDEA_set_encrypt_key().
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_ecb_encrypt(const unsigned char *in,
    unsigned char *out,
    IDEA_KEY_SCHEDULE *ks);
""",
    "IDEA_ecb_encrypt",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_set_encrypt_key(const unsigned char *key,
    IDEA_KEY_SCHEDULE *ks);
""",
    """/**
 * @brief Expand a 16-byte IDEA key into an encryption key schedule (deprecated; prefer EVP).
 * @param key 16-byte IDEA key.
 * @param ks Destination encryption schedule.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_set_encrypt_key(const unsigned char *key,
    IDEA_KEY_SCHEDULE *ks);
""",
    "IDEA_set_encrypt_key",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek,
    IDEA_KEY_SCHEDULE *dk);
""",
    """/**
 * @brief Derive an IDEA decryption schedule from an encryption schedule (deprecated).
 * @param ek Encryption schedule from IDEA_set_encrypt_key().
 * @param dk Destination decryption schedule.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek,
    IDEA_KEY_SCHEDULE *dk);
""",
    "IDEA_set_decrypt_key",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with IDEA in CBC mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA key schedule matching @p enc.
 * @param iv 8-byte IV updated in place.
 * @param enc IDEA_ENCRYPT to encrypt, or IDEA_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int enc);
""",
    "IDEA_cbc_encrypt",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num,
    int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with IDEA in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA encryption schedule.
 * @param iv 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc IDEA_ENCRYPT to encrypt, or IDEA_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num,
    int enc);
""",
    "IDEA_cfb64_encrypt",
)

patch_one(
    "idea.h",
    """OSSL_DEPRECATEDIN_3_0 void IDEA_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num);
""",
    """/**
 * @brief Encrypt or decrypt data with IDEA in 64-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length (may equal @p in).
 * @param length Number of bytes to process.
 * @param ks Expanded IDEA encryption schedule.
 * @param iv 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0 void IDEA_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    IDEA_KEY_SCHEDULE *ks,
    unsigned char *iv, int *num);
""",
    "IDEA_ofb64_encrypt",
)

# ----- mdc2.h -----

patch_one(
    "mdc2.h",
    """typedef struct mdc2_ctx_st {
    unsigned int num;
    unsigned char data[MDC2_BLOCK];
    DES_cblock h, hh;
    unsigned int pad_type; /* either 1 or 2, default 1 */
} MDC2_CTX;
""",
    """/**
 * @brief Incremental MDC-2 digest state (also typedef'd as MDC2_CTX); deprecated low-level API.
 */
typedef struct mdc2_ctx_st {
    unsigned int num;
    /** Current partial message block being accumulated (MDC2_BLOCK bytes). */
    unsigned char data[MDC2_BLOCK];
    /** Running MDC-2 chaining values (two DES blocks). */
    DES_cblock h, hh;
    /** Padding rule: 1 or 2 (default 1). */
    unsigned int pad_type; /* either 1 or 2, default 1 */
} MDC2_CTX;
""",
    "mdc2_ctx_st",
)

patch_one(
    "mdc2.h",
    """OSSL_DEPRECATEDIN_3_0 int MDC2_Update(MDC2_CTX *c, const unsigned char *data,
    size_t len);
""",
    """/**
 * @brief Absorb more message bytes into an MDC-2 digest context (deprecated).
 * @param c MDC-2 context initialized with MDC2_Init().
 * @param data Message bytes to hash.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MDC2_Update(MDC2_CTX *c, const unsigned char *data,
    size_t len);
""",
    "MDC2_Update",
)

patch_one(
    "mdc2.h",
    """OSSL_DEPRECATEDIN_3_0 unsigned char *MDC2(const unsigned char *d, size_t n,
    unsigned char *md);
""",
    """/**
 * @brief Compute the MDC-2 digest of @p n bytes at @p d in one shot (deprecated; prefer EVP_Digest).
 * @param d Input message bytes.
 * @param n Length of @p d in bytes.
 * @param md Output buffer for the 16-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *MDC2(const unsigned char *d, size_t n,
    unsigned char *md);
""",
    "MDC2",
)

# ----- ripemd.h -----

patch_one(
    "ripemd.h",
    """OSSL_DEPRECATEDIN_3_0 unsigned char *RIPEMD160(const unsigned char *d, size_t n,
    unsigned char *md);
""",
    """/**
 * @brief Compute the RIPEMD-160 digest of @p n bytes at @p d in one shot (deprecated; prefer EVP_Digest).
 * @param d Input message bytes.
 * @param n Length of @p d in bytes.
 * @param md Output buffer for the 20-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *RIPEMD160(const unsigned char *d, size_t n,
    unsigned char *md);
""",
    "RIPEMD160",
)

# ----- seed.h -----

patch_one(
    "seed.h",
    """OSSL_DEPRECATEDIN_3_0
void SEED_decrypt(const unsigned char s[SEED_BLOCK_SIZE],
    unsigned char d[SEED_BLOCK_SIZE],
    const SEED_KEY_SCHEDULE *ks);
""",
    """/**
 * @brief Decrypt one 16-byte SEED block (deprecated; prefer EVP).
 * @param s 16-byte ciphertext block.
 * @param d 16-byte plaintext buffer (may equal @p s).
 * @param ks Expanded SEED key from SEED_set_key().
 */
OSSL_DEPRECATEDIN_3_0
void SEED_decrypt(const unsigned char s[SEED_BLOCK_SIZE],
    unsigned char d[SEED_BLOCK_SIZE],
    const SEED_KEY_SCHEDULE *ks);
""",
    "SEED_decrypt",
)

# ----- whrlpool.h -----

patch_one(
    "whrlpool.h",
    """typedef struct {
    union {
        unsigned char c[WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    unsigned char data[WHIRLPOOL_BBLOCK / 8];
    unsigned int bitoff;
    size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
} WHIRLPOOL_CTX;
""",
    """/**
 * @brief Incremental WHIRLPOOL digest state (deprecated; prefer EVP_MD APIs).
 */
typedef struct {
    /** Hash state H stored as bytes or doubles for alignment. */
    union {
        /** Digest bytes (WHIRLPOOL_DIGEST_LENGTH). */
        unsigned char c[WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        /** Alignment padding view forcing 64-bit alignment of H. */
        double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    unsigned char data[WHIRLPOOL_BBLOCK / 8];
    unsigned int bitoff;
    size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
} WHIRLPOOL_CTX;
""",
    "WHIRLPOOL_CTX",
)

patch_one(
    "whrlpool.h",
    """OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
""",
    """/**
 * @brief Initialize a low-level WHIRLPOOL digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
""",
    "WHIRLPOOL_Init",
)

patch_one(
    "whrlpool.h",
    """OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Update(WHIRLPOOL_CTX *c,
    const void *inp, size_t bytes);
""",
    """/**
 * @brief Absorb more message bytes into a WHIRLPOOL digest context (deprecated).
 * @param c Context initialized with WHIRLPOOL_Init().
 * @param inp Message bytes to hash.
 * @param bytes Number of bytes at @p inp.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int WHIRLPOOL_Update(WHIRLPOOL_CTX *c,
    const void *inp, size_t bytes);
""",
    "WHIRLPOOL_Update",
)

patch_one(
    "whrlpool.h",
    """OSSL_DEPRECATEDIN_3_0 void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c,
    const void *inp, size_t bits);
""",
    """/**
 * @brief Absorb @p bits bits of message data into a WHIRLPOOL context (deprecated).
 * @param c Context initialized with WHIRLPOOL_Init().
 * @param inp Bit-oriented message data (consumed MSB-first within each byte).
 * @param bits Number of bits to absorb from @p inp.
 */
OSSL_DEPRECATEDIN_3_0 void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c,
    const void *inp, size_t bits);
""",
    "WHIRLPOOL_BitUpdate",
)

patch_one(
    "whrlpool.h",
    """OSSL_DEPRECATEDIN_3_0 unsigned char *WHIRLPOOL(const void *inp, size_t bytes,
    unsigned char *md);
""",
    """/**
 * @brief Compute the WHIRLPOOL digest of @p bytes at @p inp in one shot (deprecated; prefer EVP_Digest).
 * @param inp Input message bytes.
 * @param bytes Length of @p inp in bytes.
 * @param md Output buffer for the 64-byte digest, or NULL to use a static buffer.
 * @return Pointer to the digest bytes (@p md, or the static buffer when @p md is NULL).
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *WHIRLPOOL(const void *inp, size_t bytes,
    unsigned char *md);
""",
    "WHIRLPOOL",
)

# ----- provider.h -----

patch_one(
    "provider.h",
    """OSSL_PROVIDER *OSSL_PROVIDER_try_load_ex(OSSL_LIB_CTX *, const char *name,
    OSSL_PARAM *params,
    int retain_fallbacks);
""",
    """/**
 * @brief Try to load a provider with parameters, optionally keeping fallback providers.
 * @param ctx Library context that will own the provider, or NULL for the default.
 * @param name Provider name (for example "default" or "legacy").
 * @param params Optional OSSL_PARAM array configuring the provider, or NULL.
 * @param retain_fallbacks Non-zero to leave fallback providers active after a successful load.
 * @return Provider handle on success, or NULL on failure; unload with OSSL_PROVIDER_unload().
 */
OSSL_PROVIDER *OSSL_PROVIDER_try_load_ex(OSSL_LIB_CTX *ctx, const char *name,
    OSSL_PARAM *params,
    int retain_fallbacks);
""",
    "OSSL_PROVIDER_try_load_ex",
)

patch_one(
    "provider.h",
    """int OSSL_PROVIDER_available(OSSL_LIB_CTX *, const char *name);
""",
    """/**
 * @brief Report whether a named provider is available in a library context.
 * @param ctx Library context to query, or NULL for the default.
 * @param name Provider name to look up.
 * @return 1 if the provider is available (loaded or loadable as configured), or 0 otherwise.
 */
int OSSL_PROVIDER_available(OSSL_LIB_CTX *ctx, const char *name);
""",
    "OSSL_PROVIDER_available",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
