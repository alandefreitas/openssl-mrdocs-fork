/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_RC4_H
#define OPENSSL_RC4_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_RC4_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_RC4
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Legacy RC4 key stream state (deprecated; prefer EVP_CIPHER APIs).
 */
typedef struct rc4_key_st {
    /** RC4 state indices into the permutation table. */
    RC4_INT x, y;
    /** RC4 256-byte permutation / S-box. */
    RC4_INT data[256];
} RC4_KEY;
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return a short string describing compiled RC4 implementation options (deprecated).
 * @return Static NUL-terminated options string.
 */
OSSL_DEPRECATEDIN_3_0 const char *RC4_options(void);
/**
 * @brief Initialize an RC4_KEY from a variable-length key (deprecated; prefer EVP_CIPHER).
 * @param key RC4 key schedule to initialize.
 * @param len Length of @p data in bytes.
 * @param data Key material used to set up the RC4 permutation.
 */
OSSL_DEPRECATEDIN_3_0 void RC4_set_key(RC4_KEY *key, int len,
    const unsigned char *data);
/**
 * @brief Encrypt or decrypt @p len bytes with RC4 (deprecated; prefer EVP_CIPHER).
 * @param key RC4 key schedule previously set with RC4_set_key(); updated in place.
 * @param len Number of bytes to process.
 * @param indata Input plaintext or ciphertext.
 * @param outdata Output buffer of at least @p len bytes (may alias @p indata).
 */
OSSL_DEPRECATEDIN_3_0 void RC4(RC4_KEY *key, size_t len,
    const unsigned char *indata,
    unsigned char *outdata);
#endif

#ifdef __cplusplus
}
#endif
#endif

#endif
