/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_DES_H
#define OPENSSL_DES_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_DES_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_DES
#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/e_os2.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Host unsigned word type used by low-level DES block primitives.
 */
typedef unsigned int DES_LONG;

#ifdef OPENSSL_BUILD_SHLIBCRYPTO
#undef OPENSSL_EXTERN
#define OPENSSL_EXTERN OPENSSL_EXPORT
#endif

/**
 * @brief Eight-byte DES block (key or data) used by the legacy DES_* APIs.
 */
typedef unsigned char DES_cblock[8];
/**
 * @brief Const-qualified eight-byte DES block typedef for read-only key/IV inputs.
 *
 * With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
 * const_DES_cblock * are incompatible pointer types.
 */
typedef /* const */ unsigned char const_DES_cblock[8];

/**
 * @brief Legacy DES expanded key schedule (sixteen round subkeys; prefer EVP).
 */
typedef struct DES_ks {
    /**
     * @brief One DES round subkey stored as a DES_cblock or two DES_LONG words.
     */
    union {
        /** Eight-byte DES key-block view of this round subkey. */
        DES_cblock cblock;
        /**
         * Word view ensuring correct size on machines with 8-byte longs.
         */
        DES_LONG deslong[2];
    } ks[16];
} DES_key_schedule;

#define DES_KEY_SZ (sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

#define DES_CBC_MODE 0
#define DES_PCBC_MODE 1

#define DES_ecb2_encrypt(i, o, k1, k2, e) \
    DES_ecb3_encrypt((i), (o), (k1), (k2), (k1), (e))

#define DES_ede2_cbc_encrypt(i, o, l, k1, k2, iv, e) \
    DES_ede3_cbc_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (e))

#define DES_ede2_cfb64_encrypt(i, o, l, k1, k2, iv, n, e) \
    DES_ede3_cfb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n), (e))

#define DES_ede2_ofb64_encrypt(i, o, l, k1, k2, iv, n) \
    DES_ede3_ofb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n))

#define DES_fixup_key_parity DES_set_odd_parity
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return a short string describing compiled DES implementation options (deprecated).
 * @return Static NUL-terminated options string.
 */
OSSL_DEPRECATEDIN_3_0 const char *DES_options(void);
/**
 * @brief Encrypt or decrypt one 8-byte block with triple-DES EDE in ECB mode (deprecated; prefer EVP).
 * @param input 8-byte input block.
 * @param output 8-byte output block (may equal @p input).
 * @param ks1 First DES key schedule (encrypt or decrypt stage).
 * @param ks2 Second DES key schedule (middle stage).
 * @param ks3 Third DES key schedule (final stage).
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
    DES_key_schedule *ks1, DES_key_schedule *ks2,
    DES_key_schedule *ks3, int enc);
/**
 * @brief Compute a DES CBC checksum of @p input and return the last DES_LONG of the MAC (deprecated).
 * @param input Input bytes of length @p length.
 * @param output Optional destination for the full 8-byte checksum, or NULL.
 * @param length Number of input bytes to checksum.
 * @param schedule Expanded DES key schedule.
 * @param ivec Initial 8-byte IV for the CBC MAC (not updated).
 * @return Last DES_LONG of the checksum value.
 */
OSSL_DEPRECATEDIN_3_0
DES_LONG DES_cbc_cksum(const unsigned char *input, DES_cblock *output,
    long length, DES_key_schedule *schedule,
    const_DES_cblock *ivec);
#endif
/* DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Encrypt or decrypt with DES in CBC mode without updating the IV (deprecated; prefer DES_ncbc_encrypt or EVP).
 * @param input Input bytes of length @p length.
 * @param output Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV used for chaining; not updated by this call.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
    long length, DES_key_schedule *schedule, DES_cblock *ivec,
    int enc);
/**
 * @brief Encrypt or decrypt with DES in CBC mode, updating the IV (deprecated; prefer EVP).
 * @param input Input bytes of length @p length.
 * @param output Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key from DES_set_key() or related.
 * @param ivec 8-byte IV updated in place to the last ciphertext block.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ncbc_encrypt(const unsigned char *input, unsigned char *output,
    long length, DES_key_schedule *schedule, DES_cblock *ivec,
    int enc);
/**
 * @brief Encrypt or decrypt with DES in RSA DESX-CBC (XCBC) mode (deprecated; prefer EVP).
 * @param input Input bytes of length @p length.
 * @param output Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param inw Whitening value XORed with plaintext before DES (inw).
 * @param outw Whitening value XORed with DES output (outw).
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_xcbc_encrypt(const unsigned char *input, unsigned char *output,
    long length, DES_key_schedule *schedule, DES_cblock *ivec,
    const_DES_cblock *inw, const_DES_cblock *outw, int enc);
/**
 * @brief Encrypt or decrypt with DES in CFB mode with a configurable bit width (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param numbits Number of bits of feedback per CFB step (1..64).
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_cfb_encrypt(const unsigned char *in, unsigned char *out, int numbits,
    long length, DES_key_schedule *schedule, DES_cblock *ivec,
    int enc);
/**
 * @brief Encrypt or decrypt one 8-byte DES block in ECB mode (deprecated; prefer EVP).
 * @param input 8-byte input block.
 * @param output 8-byte output block (may equal @p input).
 * @param ks Expanded DES key schedule.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output,
    DES_key_schedule *ks, int enc);
#endif

/*
 * This is the DES encryption function that gets called by just about every
 * other DES routine in the library.  You should not use this function except
 * to implement 'modes' of DES.  I say this because the functions that call
 * this routine do the conversion from 'char *' to long, and this needs to be
 * done to make sure 'non-aligned' memory access do not occur.  The
 * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
 * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
 * encryption, zero if decryption.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Encrypt or decrypt one DES block in place with IP and FP (deprecated low-level core).
 * @param data Two DES_LONG words holding the 64-bit block in little-endian byte order.
 * @param ks Expanded DES key schedule.
 * @param enc Non-zero to encrypt, or zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);
#endif

/*
 * This functions is the same as DES_encrypt1() except that the DES initial
 * permutation (IP) and final permutation (FP) have been left out.  As for
 * DES_encrypt1(), you should not use this function. It is used by the
 * routines in the library that implement triple DES. IP() DES_encrypt2()
 * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
 * DES_encrypt1() DES_encrypt1() except faster :-).
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
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
/**
 * @brief Decrypt one block with triple-DES EDE using three schedules (deprecated low-level).
 * @param data Two DES_LONG words holding the 64-bit block (no outer IP/FP).
 * @param ks1 First DES key schedule (decrypt).
 * @param ks2 Second DES key schedule (encrypt).
 * @param ks3 Third DES key schedule (decrypt).
 */
OSSL_DEPRECATEDIN_3_0
void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
    DES_key_schedule *ks3);
/**
 * @brief Encrypt or decrypt with triple-DES EDE in CBC mode (deprecated; prefer EVP).
 * @param input Input bytes of length @p length.
 * @param output Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param ks1 First DES key schedule (encrypt or decrypt stage).
 * @param ks2 Second DES key schedule (middle stage).
 * @param ks3 Third DES key schedule (final stage).
 * @param ivec 8-byte IV updated in place.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
    long length, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3,
    DES_cblock *ivec, int enc);
/**
 * @brief Encrypt or decrypt with triple-DES EDE in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param ks1 First DES key schedule.
 * @param ks2 Second DES key schedule.
 * @param ks3 Third DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ede3_cfb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3,
    DES_cblock *ivec, int *num, int enc);
/**
 * @brief Encrypt or decrypt with triple-DES EDE in CFB mode with a configurable bit width (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param numbits Number of bits of feedback per CFB step (1..64).
 * @param length Number of bytes to process.
 * @param ks1 First DES key schedule.
 * @param ks2 Second DES key schedule.
 * @param ks3 Third DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ede3_cfb_encrypt(const unsigned char *in, unsigned char *out,
    int numbits, long length, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3,
    DES_cblock *ivec, int enc);
/**
 * @brief Encrypt or decrypt with triple-DES EDE in 64-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param ks1 First DES key schedule.
 * @param ks2 Second DES key schedule.
 * @param ks3 Third DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0
void DES_ede3_ofb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3,
    DES_cblock *ivec, int *num);
/**
 * @brief Compute a traditional Unix DES-based password hash into a caller buffer (deprecated).
 * @param buf Password / passphrase to hash.
 * @param salt Two-character salt (or longer string whose first two chars are used).
 * @param ret Caller-provided buffer of at least 14 bytes receiving the NUL-terminated hash.
 * @return @p ret on success, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
char *DES_fcrypt(const char *buf, const char *salt, char *ret);
/**
 * @brief Compute a traditional Unix DES-based password hash using a static result buffer (deprecated).
 * @param buf Password / passphrase to hash.
 * @param salt Two-character salt (or longer string whose first two chars are used).
 * @return Pointer to a static NUL-terminated hash string, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
char *DES_crypt(const char *buf, const char *salt);
/**
 * @brief Encrypt or decrypt with DES in OFB mode with a configurable bit width (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param numbits Number of bits of keystream consumed per step (1..64).
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 */
OSSL_DEPRECATEDIN_3_0
void DES_ofb_encrypt(const unsigned char *in, unsigned char *out, int numbits,
    long length, DES_key_schedule *schedule, DES_cblock *ivec);
/**
 * @brief Encrypt or decrypt with DES in PCBC mode (deprecated; prefer EVP).
 * @param input Input bytes of length @p length.
 * @param output Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_pcbc_encrypt(const unsigned char *input, unsigned char *output,
    long length, DES_key_schedule *schedule,
    DES_cblock *ivec, int enc);
/**
 * @brief Compute a DES-based quadratic checksum over @p input (deprecated).
 * @param input Input bytes of length @p length.
 * @param output Array of DES_cblock results; may be NULL if only the return value is needed.
 * @param length Number of input bytes to checksum.
 * @param out_count Number of 8-byte checksum blocks to write to @p output (1..4).
 * @param seed Seed block updated in place during the checksum.
 * @return Last DES_LONG of the final checksum block.
 */
OSSL_DEPRECATEDIN_3_0
DES_LONG DES_quad_cksum(const unsigned char *input, DES_cblock output[],
    long length, int out_count, DES_cblock *seed);
/**
 * @brief Generate a random DES key with odd parity that is not a weak key (deprecated).
 * @param ret Destination 8-byte DES key block.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DES_random_key(DES_cblock *ret);
/**
 * @brief Set odd parity bits on each byte of a DES key block (deprecated).
 * @param key Eight-byte DES key whose least-significant bits are adjusted for odd parity.
 */
OSSL_DEPRECATEDIN_3_0 void DES_set_odd_parity(DES_cblock *key);
/**
 * @brief Test whether each byte of a DES key has odd parity (deprecated).
 * @param key Eight-byte DES key to check.
 * @return 1 if all bytes have odd parity, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 int DES_check_key_parity(const_DES_cblock *key);
/**
 * @brief Test whether a DES key is one of the known weak or semi-weak keys (deprecated).
 * @param key Eight-byte DES key to check.
 * @return 1 if @p key is weak or semi-weak, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 int DES_is_weak_key(const_DES_cblock *key);
#endif
/*
 * DES_set_key (= set_key = DES_key_sched = key_sched) calls
 * DES_set_key_checked
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Expand a DES key into a key schedule (checked or unchecked per DES_check_key; deprecated).
 * @param key Eight-byte DES key.
 * @param schedule Destination expanded key schedule.
 * @return 0 on success; when checking is enabled, -1 on parity error or -2 if @p key is weak.
 */
OSSL_DEPRECATEDIN_3_0
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
/**
 * @brief Expand a DES key into a key schedule (alias of DES_set_key; deprecated).
 * @param key Eight-byte DES key (parity checked when DES_check_key is enabled).
 * @param schedule Destination expanded key schedule.
 * @return 0 on success, -1 on parity error, or -2 if @p key is a weak key.
 */
OSSL_DEPRECATEDIN_3_0
int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule);
/**
 * @brief Expand a DES key into a key schedule after checking parity and weak keys (deprecated).
 * @param key Eight-byte DES key.
 * @param schedule Destination expanded key schedule.
 * @return 0 on success, -1 on parity error, or -2 if @p key is a weak key.
 */
OSSL_DEPRECATEDIN_3_0
int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule);
/**
 * @brief Expand a DES key into a key schedule without parity or weak-key checks (deprecated).
 * @param key Eight-byte DES key.
 * @param schedule Destination expanded key schedule.
 */
OSSL_DEPRECATEDIN_3_0
void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);
/**
 * @brief Derive a single DES key from a NUL-terminated ASCII string (deprecated).
 * @param str Password / passphrase string mixed into an 8-byte key.
 * @param key Destination DES key block.
 */
OSSL_DEPRECATEDIN_3_0 void DES_string_to_key(const char *str, DES_cblock *key);
/**
 * @brief Derive two DES keys from a NUL-terminated ASCII string (deprecated).
 * @param str Password / passphrase string mixed into two 8-byte keys.
 * @param key1 Destination first DES key block.
 * @param key2 Destination second DES key block.
 */
OSSL_DEPRECATEDIN_3_0
void DES_string_to_2keys(const char *str, DES_cblock *key1, DES_cblock *key2);
/**
 * @brief Encrypt or decrypt with DES in 64-bit CFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 * @param enc DES_ENCRYPT to encrypt, or DES_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0
void DES_cfb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, DES_key_schedule *schedule,
    DES_cblock *ivec, int *num, int enc);
/**
 * @brief Encrypt or decrypt with DES in 64-bit OFB mode (deprecated; prefer EVP).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of length @p length.
 * @param length Number of bytes to process.
 * @param schedule Expanded DES key schedule.
 * @param ivec 8-byte IV updated in place.
 * @param num Feedback offset into the IV (updated; typically starts at 0).
 */
OSSL_DEPRECATEDIN_3_0
void DES_ofb64_encrypt(const unsigned char *in, unsigned char *out,
    long length, DES_key_schedule *schedule,
    DES_cblock *ivec, int *num);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
