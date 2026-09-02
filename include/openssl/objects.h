/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_OBJECTS_H
#define OPENSSL_OBJECTS_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_OBJECTS_H
#endif

#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/objectserr.h>

#define OBJ_NAME_TYPE_UNDEF 0x00
#define OBJ_NAME_TYPE_MD_METH 0x01
#define OBJ_NAME_TYPE_CIPHER_METH 0x02
#define OBJ_NAME_TYPE_PKEY_METH 0x03
#define OBJ_NAME_TYPE_COMP_METH 0x04
#define OBJ_NAME_TYPE_MAC_METH 0x05
#define OBJ_NAME_TYPE_KDF_METH 0x06
#define OBJ_NAME_TYPE_NUM 0x07

#define OBJ_NAME_ALIAS 0x8000

#define OBJ_BSEARCH_VALUE_ON_NOMATCH 0x01
#define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH 0x02

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief One entry in OpenSSL's name table mapping algorithm names to type-specific data.
 *
 * Used by OBJ_NAME_add() / OBJ_NAME_get() for digests, ciphers, and related aliases
 * (see OBJ_NAME_TYPE_* and OBJ_NAME_ALIAS).
 */
typedef struct obj_name_st {
    int type; /**< OBJ_NAME_TYPE_* category (optionally OR'd with OBJ_NAME_ALIAS). */
    int alias; /**< Nonzero when @p name is an alias rather than a primary name. */
    const char *name; /**< Name or alias string. */
    const char *data; /**< Type-specific payload (often another name or implementation pointer as string). */
} OBJ_NAME;

#define OBJ_create_and_add_object(a, b, c) OBJ_create(a, b, c)

/**
 * @brief Initialize the OBJ_NAME table used for algorithm name aliases.
 * @return 1 on success, or 0 on failure.
 */
int OBJ_NAME_init(void);
/**
 * @brief Allocate a new OBJ_NAME type index with custom hash, compare, and free callbacks.
 * @param hash_func Hash function for names of this type, or NULL for the default.
 * @param cmp_func Comparison function for names of this type, or NULL for the default.
 * @param free_func Optional freer invoked as free_func(name, type, data) when an entry is removed, or NULL.
 * @return New positive type index on success, or 0 on error.
 */
int OBJ_NAME_new_index(unsigned long (*hash_func)(const char *),
    int (*cmp_func)(const char *, const char *),
    void (*free_func)(const char *, int, const char *));
/**
 * @brief Look up data associated with a named object of the given type.
 * @param name Name string to resolve.
 * @param type OBJ_NAME type such as OBJ_NAME_TYPE_MD_METH or OBJ_NAME_TYPE_CIPHER_METH.
 * @return Associated data string (often an algorithm name), or NULL if not found.
 */
const char *OBJ_NAME_get(const char *name, int type);
/**
 * @brief Register a name-to-data mapping in the OBJ_NAME table (legacy aliases).
 * @param name Alias string to add.
 * @param type OBJ_NAME_TYPE_* class for the alias.
 * @param data Canonical name or payload associated with @p name.
 * @return 1 on success, or 0 on error.
 */
int OBJ_NAME_add(const char *name, int type, const char *data);
/**
 * @brief Remove a name from the OBJ_NAME alias/lookup table.
 * @param name Name entry to remove.
 * @param type Name class (for example OBJ_NAME_TYPE_CIPHER_METH) possibly OR'd with OBJ_NAME_ALIAS.
 * @return 1 if an entry was removed, or 0 if none matched.
 */
int OBJ_NAME_remove(const char *name, int type);
/**
 * @brief Free OBJ_NAME entries of the given type (or all types).
 * @param type OBJ_NAME type to clear, or -1 to free every type.
 */
void OBJ_NAME_cleanup(int type); /* -1 for everything */
/**
 * @brief Invoke a callback for every OBJ_NAME of the given type (unsorted).
 * @param type Name table type to iterate (for example OBJ_NAME_TYPE_MD_METH).
 * @param fn Callback receiving each OBJ_NAME entry and @p arg.
 * @param arg User pointer passed through to @p fn.
 */
void OBJ_NAME_do_all(int type, void (*fn)(const OBJ_NAME *, void *arg),
    void *arg);
/**
 * @brief Invoke a callback for every OBJ_NAME of the given type in sorted name order.
 * @param type Name class such as OBJ_NAME_TYPE_CIPHER_METH (or -1 for every class).
 * @param fn Callback receiving each OBJ_NAME entry and @p arg.
 * @param arg User pointer passed through to @p fn.
 */
void OBJ_NAME_do_all_sorted(int type,
    void (*fn)(const OBJ_NAME *, void *arg),
    void *arg);

/**
 * @brief Deep-copy an ASN1_OBJECT.
 * @param o Object to duplicate.
 * @return Newly allocated ASN1_OBJECT, or NULL on error; free with ASN1_OBJECT_free().
 */
ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o);
/**
 * @brief Return the ASN1_OBJECT for a numeric identifier (NID).
 * @param n Object NID such as NID_sha256.
 * @return Internal ASN1_OBJECT pointer (do not free), or NULL if @p n is unknown.
 */
ASN1_OBJECT *OBJ_nid2obj(int n);
/**
 * @brief Return the long name string for a numeric object identifier (NID).
 * @param n NID to look up.
 * @return Internal long-name string (do not free), or NULL if unknown.
 */
const char *OBJ_nid2ln(int n);
/**
 * @brief Return the short name string for a numeric object identifier (NID).
 * @param n NID to look up.
 * @return Internal short-name string (do not free), or NULL if unknown.
 */
const char *OBJ_nid2sn(int n);
/**
 * @brief Return the NID for an ASN1_OBJECT.
 * @param o Object identifier to look up.
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_obj2nid(const ASN1_OBJECT *o);
/**
 * @brief Parse a textual OID (dot notation or name) into an ASN1_OBJECT.
 * @param s OID text such as "1.2.840.113549.1.1.1" or "sha256WithRSAEncryption".
 * @param no_name When non-zero, only numeric OID forms are accepted (names are rejected).
 * @return Newly allocated ASN1_OBJECT, or NULL on error; free with ASN1_OBJECT_free().
 */
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
/**
 * @brief Format an ASN1_OBJECT as text (dotted OID and/or registered name).
 * @param buf Destination buffer for the NUL-terminated text, or NULL to measure length only.
 * @param buf_len Capacity of @p buf in bytes when non-NULL.
 * @param a Object identifier to render.
 * @param no_name When non-zero, always emit numeric OID form; when zero, prefer a known name.
 * @return Length of the text (excluding NUL) that was or would be written, or -1 on error.
 */
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
/**
 * @brief Return the NID for a text object identifier.
 * @param s Long name, short name, or numerical OID string.
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_txt2nid(const char *s);
/**
 * @brief Return the NID for an object long name.
 * @param s Long name to look up (for example "commonName").
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_ln2nid(const char *s);
/**
 * @brief Look up the numeric object identifier (NID) for a short name string.
 * @param s Short name such as "SHA256" or "rsaEncryption".
 * @return Matching NID, or NID_undef if @p s is not recognised.
 */
int OBJ_sn2nid(const char *s);
/**
 * @brief Compare two ASN1_OBJECT values.
 * @param a First object identifier.
 * @param b Second object identifier.
 * @return 0 if @p a and @p b are identical; non-zero otherwise.
 */
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
/**
 * @brief Binary-search a sorted array of fixed-size elements using a comparator.
 * @param key Pointer to the search key passed as the first argument to @p cmp.
 * @param base Base address of the sorted array.
 * @param num Number of elements in the array.
 * @param size Size of each element in bytes.
 * @param cmp Comparison callback returning negative, zero, or positive like strcmp.
 * @return Pointer to the matching element, or NULL if not found.
 *
 * Used internally by the OBJ_bsearch_* helpers; prefer those type-safe wrappers.
 */
const void *OBJ_bsearch_(const void *key, const void *base, int num, int size,
    int (*cmp)(const void *, const void *));
/**
 * @brief Binary-search a sorted object table with optional flags (internal helper).
 * @param key Pointer to the search key.
 * @param base Pointer to the first element of the sorted array.
 * @param num Number of elements in the array.
 * @param size Size of each element in bytes.
 * @param cmp Comparison function returning negative, zero, or positive.
 * @param flags Search flags such as OBJ_BSEARCH_VALUE_ON_NOMATCH.
 * @return Pointer to the matching element, or NULL / a related pointer depending on @p flags.
 */
const void *OBJ_bsearch_ex_(const void *key, const void *base, int num,
    int size,
    int (*cmp)(const void *, const void *),
    int flags);

#define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)        \
    static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
    static int nm##_cmp(type1 const *, type2 const *);              \
    scope type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

#define DECLARE_OBJ_BSEARCH_CMP_FN(type1, type2, cmp) \
    _DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)
#define DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm) \
    type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

/*-
 * Unsolved problem: if a type is actually a pointer type, like
 * nid_triple is, then its impossible to get a const where you need
 * it. Consider:
 *
 * typedef int nid_triple[3];
 * const void *a_;
 * const nid_triple const *a = a_;
 *
 * The assignment discards a const because what you really want is:
 *
 * const int const * const *a = a_;
 *
 * But if you do that, you lose the fact that a is an array of 3 ints,
 * which breaks comparison functions.
 *
 * Thus we end up having to cast, sadly, or unpack the
 * declarations. Or, as I finally did in this case, declare nid_triple
 * to be a struct, which it should have been in the first place.
 *
 * Ben, August 2008.
 *
 * Also, strictly speaking not all types need be const, but handling
 * the non-constness means a lot of complication, and in practice
 * comparison routines do always not touch their arguments.
 */

#define IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1, type2, nm)                     \
    static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)     \
    {                                                                      \
        type1 const *a = a_;                                               \
        type2 const *b = b_;                                               \
        return nm##_cmp(a, b);                                             \
    }                                                                      \
    static type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
    {                                                                      \
        return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2),        \
            nm##_cmp_BSEARCH_CMP_FN);                                      \
    }                                                                      \
    extern void dummy_prototype(void)

#define IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)          \
    static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_) \
    {                                                                  \
        type1 const *a = a_;                                           \
        type2 const *b = b_;                                           \
        return nm##_cmp(a, b);                                         \
    }                                                                  \
    type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)    \
    {                                                                  \
        return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2),    \
            nm##_cmp_BSEARCH_CMP_FN);                                  \
    }                                                                  \
    extern void dummy_prototype(void)

#define OBJ_bsearch(type1, key, type2, base, num, cmp)                              \
    ((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1, key), CHECKED_PTR_OF(type2, base), \
        num, sizeof(type2),                                                         \
        ((void)CHECKED_PTR_OF(type1, cmp##_type_1),                                 \
            (void)CHECKED_PTR_OF(type2, cmp##_type_2),                              \
            cmp##_BSEARCH_CMP_FN)))

#define OBJ_bsearch_ex(type1, key, type2, base, num, cmp, flags)                       \
    ((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1, key), CHECKED_PTR_OF(type2, base), \
         num, sizeof(type2),                                                           \
         ((void)CHECKED_PTR_OF(type1, cmp##_type_1),                                   \
             (void)type_2 = CHECKED_PTR_OF(type2, cmp##_type_2),                       \
             cmp##_BSEARCH_CMP_FN)),                                                   \
        flags)

/**
 * @brief Allocate one or more new numeric object identifiers (NIDs).
 * @param num Number of consecutive NIDs to reserve.
 * @return First newly allocated NID, or NID_undef on failure.
 */
int OBJ_new_nid(int num);
/**
 * @brief Add @p obj to the process-wide object database (NID/sn/ln tables).
 * @param obj Object identifier to register (copied internally as needed).
 * @return New NID on success, or NID_undef on error.
 */
int OBJ_add_object(const ASN1_OBJECT *obj);
/**
 * @brief Register a new ASN.1 object identifier with short and long names.
 * @param oid Numeric OID string (for example "1.2.3.4").
 * @param sn Short name to associate with the OID.
 * @param ln Long name to associate with the OID.
 * @return New NID on success, or NID_undef on error.
 */
int OBJ_create(const char *oid, const char *sn, const char *ln);
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define OBJ_cleanup() \
    while (0)         \
    continue
#endif
/**
 * @brief Load OID definitions from text lines read from @p in into the internal object table.
 * @param in BIO supplying lines of the form "oid [shortName [longName]]".
 * @return Number of objects successfully created before EOF or the first failure/invalid line.
 */
int OBJ_create_objects(BIO *in);

/**
 * @brief Return the length in bytes of an ASN.1 object's encoded OID content.
 * @param obj Object identifier to query; NULL yields 0.
 * @return Number of content octets in the OID, or 0 if @p obj is NULL or has no data.
 */
size_t OBJ_length(const ASN1_OBJECT *obj);
/**
 * @brief Return the DER-encoded content octets of an ASN1_OBJECT.
 * @param obj Object to query.
 * @return Internal pointer to the OID content bytes (do not free), or NULL if unavailable.
 */
const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj);

/**
 * @brief Look up the digest and public-key NIDs that compose a signature algorithm.
 * @param signid NID of the composite signature algorithm.
 * @param pdig_nid Optional out-parameter for the digest algorithm NID, or NULL.
 * @param ppkey_nid Optional out-parameter for the public-key algorithm NID, or NULL.
 * @return 1 if @p signid is found, or 0 otherwise.
 */
int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
/**
 * @brief Look up the composite signature NID for a digest and public-key algorithm pair.
 * @param psignid On success, receives the signature algorithm NID.
 * @param dig_nid Digest algorithm NID (may be NID_undef for pure signatures).
 * @param pkey_nid Public-key algorithm NID.
 * @return 1 if a mapping was found, or 0 otherwise.
 */
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
/**
 * @brief Register a signature OID as the combination of a digest and public-key algorithm.
 * @param signid NID of the composite signature algorithm.
 * @param dig_id NID of the digest algorithm component.
 * @param pkey_id NID of the public-key algorithm component.
 * @return 1 on success, or 0 on failure.
 */
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
/**
 * @brief Free the signature-algorithm OID alias table populated by OBJ_add_sigid().
 */
void OBJ_sigid_free(void);

#ifdef __cplusplus
}
#endif
#endif
