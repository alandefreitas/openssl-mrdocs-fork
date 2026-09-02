/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PARAMS_H
#define OPENSSL_PARAMS_H
#pragma once

#include <openssl/core.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSSL_PARAM_UNMODIFIED ((size_t)-1)

#define OSSL_PARAM_END \
    { NULL, 0, NULL, 0, 0 }

#define OSSL_PARAM_DEFN(key, type, addr, sz) \
    { (key), (type), (addr), (sz), OSSL_PARAM_UNMODIFIED }

/* Basic parameter types without return sizes */
#define OSSL_PARAM_int(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int))
#define OSSL_PARAM_uint(key, addr)                              \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
        sizeof(unsigned int))
#define OSSL_PARAM_long(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int))
#define OSSL_PARAM_ulong(key, addr)                             \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
        sizeof(unsigned long int))
#define OSSL_PARAM_int32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t))
#define OSSL_PARAM_uint32(key, addr)                            \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
        sizeof(uint32_t))
#define OSSL_PARAM_int64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t))
#define OSSL_PARAM_uint64(key, addr)                            \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
        sizeof(uint64_t))
#define OSSL_PARAM_size_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))
#define OSSL_PARAM_time_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(time_t))
#define OSSL_PARAM_double(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double))

#define OSSL_PARAM_BN(key, bn, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))
#define OSSL_PARAM_utf8_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz)
#define OSSL_PARAM_octet_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz)

#define OSSL_PARAM_utf8_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, (addr), sz)
#define OSSL_PARAM_octet_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, (addr), sz)

/**
 * @brief Find the first OSSL_PARAM in @p p whose key matches @p key.
 * @param p Parameter array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param key Parameter name to search for.
 * @return Pointer to the matching element, or NULL if not found.
 */
OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);
/**
 * @brief Find the first OSSL_PARAM in a const array whose key matches @p key.
 * @param p Parameter array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param key Parameter name to search for.
 * @return Pointer to the matching element, or NULL if not found.
 */
const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key);

/* Basic parameter type run-time construction */
/**
 * @brief Construct an OSSL_PARAM that locates a signed int value.
 * @param key Parameter name.
 * @param buf Address of the int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
/**
 * @brief Construct an OSSL_PARAM that locates an unsigned int value.
 * @param key Parameter name.
 * @param buf Address of the unsigned int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf);
/**
 * @brief Construct an OSSL_PARAM that locates a signed long int value.
 * @param key Parameter name.
 * @param buf Address of the long int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf);
/**
 * @brief Construct an OSSL_PARAM that locates an unsigned long value.
 * @param key Parameter name.
 * @param buf Address of the unsigned long to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf);
/**
 * @brief Construct an OSSL_PARAM describing a signed 32-bit integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the int32_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_INTEGER sized for int32_t.
 */
OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing an unsigned 32-bit integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the uint32_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_UNSIGNED_INTEGER sized for uint32_t.
 */
OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing a signed 64-bit integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the int64_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_INTEGER sized for int64_t.
 */
OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing an unsigned 64-bit integer at @p buf.
 * @param key Parameter name (for example OSSL_PKEY_PARAM_*).
 * @param buf Address of the uint64_t value to expose.
 * @return OSSL_PARAM value suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf);
/**
 * @brief Construct an OSSL_PARAM that locates a size_t value.
 * @param key Parameter name.
 * @param buf Address of the size_t to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing a time_t integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the time_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_INTEGER sized for time_t.
 */
OSSL_PARAM OSSL_PARAM_construct_time_t(const char *key, time_t *buf);
/**
 * @brief Construct an OSSL_PARAM describing an arbitrary-precision integer in @p buf.
 * @param key Parameter name.
 * @param buf Buffer holding (or receiving) the BN in native unsigned big-endian form.
 * @param bsize Capacity of @p buf in bytes.
 * @return OSSL_PARAM suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
    size_t bsize);
/**
 * @brief Construct an OSSL_PARAM describing a double located at @p buf.
 * @param key Parameter name.
 * @param buf Address of the double value (read or written by the callee).
 * @return OSSL_PARAM suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf);
/**
 * @brief Construct an OSSL_PARAM describing a UTF-8 string buffer.
 * @param key Parameter name.
 * @param buf Storage for the UTF-8 string (writable buffer owned by the caller).
 * @param bsize Capacity of @p buf in bytes; 0 means use strlen(@p buf).
 * @return Populated OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
    size_t bsize);
/**
 * @brief Construct an OSSL_PARAM describing a pointer to a UTF-8 string buffer.
 * @param key Parameter name.
 * @param buf Address of a char* that locates the UTF-8 string.
 * @param bsize Maximum string capacity in bytes, or 0 if unknown.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
    size_t bsize);
/**
 * @brief Construct an OSSL_PARAM describing an octet-string buffer.
 * @param key Parameter name.
 * @param buf Storage for the octet string.
 * @param bsize Size of @p buf in bytes.
 * @return Populated OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
    size_t bsize);
/**
 * @brief Construct an OSSL_PARAM that references an existing octet buffer via pointer.
 * @param key Parameter name.
 * @param buf Address of a void* that points at (or receives) the octet data.
 * @param bsize Size of the buffer addressed by *@p buf when writing, or 0 when only reading.
 * @return OSSL_PARAM of type OSSL_PARAM_OCTET_PTR.
 */
OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
    size_t bsize);
/**
 * @brief Construct the terminating OSSL_PARAM sentinel for a parameter array.
 * @return OSSL_PARAM with a NULL key that marks the end of an OSSL_PARAM list.
 */
OSSL_PARAM OSSL_PARAM_construct_end(void);

/**
 * @brief Allocate and fill an OSSL_PARAM from a textual key/value using a param definition list.
 * @param to Destination parameter; on success owns freshly allocated @c data that the caller must free.
 * @param paramdefs Array of parameter definitions describing allowed keys and types.
 * @param key Parameter name to look up in @p paramdefs.
 * @param value Textual representation of the value (encoding depends on the matched type).
 * @param value_n Length of @p value in bytes (not necessarily NUL-terminated).
 * @param found Optional; set to 1 if @p key was found in @p paramdefs, else 0.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_allocate_from_text(OSSL_PARAM *to,
    const OSSL_PARAM *paramdefs,
    const char *key, const char *value,
    size_t value_n, int *found);

/**
 * @brief Read an integer parameter value from @p p into *@p val.
 * @param p Parameter locator describing an integer-typed value.
 * @param val Receives the converted int.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val);
/**
 * @brief Read an unsigned int parameter value from @p p into *@p val.
 * @param p Parameter locator describing an unsigned integer-typed value.
 * @param val Receives the converted unsigned int.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);
/**
 * @brief Read a long integer parameter value from @p p into *@p val.
 * @param p Parameter locator describing an integer-typed value.
 * @param val Receives the converted long.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val);
/**
 * @brief Read an unsigned long integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val);
/**
 * @brief Read a signed 32-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val);
/**
 * @brief Read an unsigned 32-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val);
/**
 * @brief Read a signed 64-bit integer from an OSSL_PARAM.
 * @param p Parameter of an integer type that can hold the value.
 * @param val Receives the converted value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val);
/**
 * @brief Read an OSSL_PARAM value as a uint64_t (with allowed integer type coercion).
 * @param p Parameter locating the value.
 * @param val Receives the converted integer on success.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val);
/**
 * @brief Read an OSSL_PARAM value as a size_t.
 * @param p Parameter locating the value.
 * @param val Receives the converted integer on success.
 * @return 1 on success, or 0 if the parameter is missing or has an incompatible type.
 */
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val);
/**
 * @brief Read a time_t value from an integer OSSL_PARAM.
 * @param p Parameter whose contents convert to time_t.
 * @param val Receives the time value on success.
 * @return 1 on success, or 0 on type/range error.
 */
int OSSL_PARAM_get_time_t(const OSSL_PARAM *p, time_t *val);

/**
 * @brief Store a signed int into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 if the buffer is too small or of the wrong type.
 */
int OSSL_PARAM_set_int(OSSL_PARAM *p, int val);
/**
 * @brief Write an unsigned int into the storage located by @p p.
 * @param p Parameter locator describing an unsigned integer-typed destination.
 * @param val Value to store.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val);
/**
 * @brief Write @p val into parameter @p as a signed long (with range checks).
 * @param p Destination parameter located by key in an OSSL_PARAM array.
 * @param val Value to store.
 * @return 1 on success, or 0 if @p is NULL, wrong type, or out of range.
 */
int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val);
/**
 * @brief Write @p val into parameter @p as an unsigned long (with range checks).
 * @param p Destination parameter located by key in an OSSL_PARAM array.
 * @param val Value to store.
 * @return 1 on success, or 0 if @p is NULL, wrong type, or out of range.
 */
int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val);
/**
 * @brief Store an int32_t value into an integer OSSL_PARAM.
 * @param p Parameter descriptor whose buffer receives @p val (or whose return_size is filled if data is NULL).
 * @param val Value to write.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val);
/**
 * @brief Store a uint32_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val);
/**
 * @brief Store an int64_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val);
/**
 * @brief Store a uint64_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val);
/**
 * @brief Store a size_t value into an integer OSSL_PARAM.
 * @param p Parameter descriptor whose buffer receives @p val.
 * @param val Value to write.
 * @return 1 on success, or 0 if @p is unsuitable or the value does not fit.
 */
int OSSL_PARAM_set_size_t(OSSL_PARAM *p, size_t val);
/**
 * @brief Store a time_t into an OSSL_PARAM integer buffer.
 * @param p Parameter whose buffer receives @p val.
 * @param val Time value to write.
 * @return 1 on success, or 0 on type or size error.
 */
int OSSL_PARAM_set_time_t(OSSL_PARAM *p, time_t val);

/**
 * @brief Read a floating-point value from an OSSL_PARAM into @p val.
 * @param p Parameter of floating-point type to read.
 * @param val Receives the converted double value on success.
 * @return 1 on success, or 0 on type/size mismatch or other failure.
 */
int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val);
/**
 * @brief Write a double into the storage located by @p p.
 * @param p Parameter locator describing a floating-point destination.
 * @param val Value to store.
 * @return 1 on success, or 0 on type failure.
 */
int OSSL_PARAM_set_double(OSSL_PARAM *p, double val);

/**
 * @brief Decode an unsigned integer OSSL_PARAM into a newly allocated BIGNUM.
 * @param p Parameter holding an unsigned big-endian integer.
 * @param val In/out BIGNUM pointer; allocates when *@p val is NULL, else reuses it.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val);
/**
 * @brief Encode a BIGNUM into an unsigned-integer OSSL_PARAM buffer.
 * @param p Parameter whose buffer receives the unsigned big-endian form of @p val.
 * @param val Non-negative BIGNUM to store; must fit in @p's declared buffer size.
 * @return 1 on success, or 0 on error (including a negative @p val).
 */
int OSSL_PARAM_set_BN(OSSL_PARAM *p, const BIGNUM *val);

/**
 * @brief Copy a UTF-8 string OSSL_PARAM into a caller-provided or allocated buffer.
 * @param p Parameter of type OSSL_PARAM_UTF8_STRING.
 * @param val When *@p val is NULL, receives a newly allocated copy; otherwise writes into the buffer of size @p max_len.
 * @param max_len Capacity of *@p val when non-NULL (including space for the NUL); ignored when allocating.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
/**
 * @brief Write a NUL-terminated UTF-8 string into an OSSL_PARAM destination.
 * @param p Parameter locating a writable UTF-8 string buffer.
 * @param val String to copy (may be truncated to the parameter's size).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val);

/**
 * @brief Copy an OSSL_PARAM octet-string value into a caller buffer.
 * @param p Parameter locating the octet string.
 * @param val Address of a buffer pointer that receives up to @p max_len bytes; may allocate when *@p val is NULL depending on call pattern.
 * @param max_len Capacity of the destination buffer in bytes.
 * @param used_len Optional output set to the number of bytes copied or required.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
    size_t *used_len);
/**
 * @brief Copy @p len octets from @p val into an octet-string OSSL_PARAM.
 * @param p Parameter locator with type OSSL_PARAM_OCTET_STRING.
 * @param val Source buffer of @p len bytes.
 * @param len Number of bytes to copy from @p val.
 * @return 1 on success, or 0 on type/size failure.
 */
int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val, size_t len);

/**
 * @brief Read a UTF-8 pointer parameter without copying the string.
 * @param p Source parameter of type OSSL_PARAM_UTF8_PTR.
 * @param val Receives the pointer stored in @p (borrowed; do not free).
 * @return 1 on success, or 0 on type/error mismatch.
 */
int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val);
/**
 * @brief Set a UTF-8 pointer parameter to refer to @p val (no copy).
 * @param p Parameter locator with type OSSL_PARAM_UTF8_PTR.
 * @param val Pointer to a NUL-terminated string retained by the caller.
 * @return 1 on success, or 0 on type failure.
 */
int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val);

/**
 * @brief Return a pointer to the octet data referenced by an OSSL_PARAM_OCTET_PTR parameter.
 * @param p Parameter of type OSSL_PARAM_OCTET_PTR.
 * @param val Receives the address of the referenced octet data (not a copy).
 * @param used_len Optional; receives the number of meaningful bytes.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);
/**
 * @brief Set an OSSL_PARAM that references an existing octet buffer without copying.
 * @param p Parameter of type OSSL_PARAM_OCTET_PTR to update.
 * @param val Address of the caller-owned octet data.
 * @param used_len Number of meaningful bytes at @p val.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_octet_ptr(OSSL_PARAM *p, const void *val,
    size_t used_len);

/**
 * @brief Return a pointer to the UTF-8 contents of an OSSL_PARAM without copying.
 * @param p Parameter of type OSSL_PARAM_UTF8_STRING or OSSL_PARAM_UTF8_PTR.
 * @param val Receives a pointer to the internal string data (do not free).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_utf8_string_ptr(const OSSL_PARAM *p, const char **val);
/**
 * @brief Return a pointer to the octet-string contents of an OSSL_PARAM without copying.
 * @param p Parameter of type OSSL_PARAM_OCTET_STRING.
 * @param val Receives a pointer to the internal octets (do not free).
 * @param used_len Optional; receives the number of bytes at *@p val.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_get_octet_string_ptr(const OSSL_PARAM *p, const void **val,
    size_t *used_len);

/**
 * @brief Test whether an OSSL_PARAM was written (modified) by a set/get operation.
 * @param p Parameter to query, or NULL.
 * @return 1 if the modified flag is set, or 0 otherwise.
 */
int OSSL_PARAM_modified(const OSSL_PARAM *p);
/**
 * @brief Clear the modified flag on every element of an OSSL_PARAM array.
 * @param p Parameter array terminated by an end sentinel; may be NULL.
 */
void OSSL_PARAM_set_all_unmodified(OSSL_PARAM *p);

/**
 * @brief Deep-copy an OSSL_PARAM array, including owned string/octet buffers.
 * @param p Source array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @return Newly allocated copy freed with OSSL_PARAM_free(), or NULL on failure.
 */
OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *p);
/**
 * @brief Merge two OSSL_PARAM arrays, with @p p2 overriding duplicate keys from @p p1.
 * @param p1 First array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param p2 Second array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @return Newly allocated merged array freed with OSSL_PARAM_free(), or NULL on failure.
 */
OSSL_PARAM *OSSL_PARAM_merge(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
/**
 * @brief Free an OSSL_PARAM array allocated by OSSL_PARAM_dup() or OSSL_PARAM_merge().
 * @param p Parameter array to free, or NULL.
 */
void OSSL_PARAM_free(OSSL_PARAM *p);

#ifdef __cplusplus
}
#endif
#endif
