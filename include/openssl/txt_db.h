/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_TXT_DB_H
#define OPENSSL_TXT_DB_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_TXT_DB_H
#endif

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include <openssl/lhash.h>

#define DB_ERROR_OK 0
#define DB_ERROR_MALLOC 1
#define DB_ERROR_INDEX_CLASH 2
#define DB_ERROR_INDEX_OUT_OF_RANGE 3
#define DB_ERROR_NO_INDEX 4
#define DB_ERROR_INSERT_INDEX_CLASH 5
#define DB_ERROR_WRONG_NUM_FIELDS 6

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Pointer to an OPENSSL_STRING (char *); used as the row type in TXT_DB stacks.
 */
typedef OPENSSL_STRING *OPENSSL_PSTRING;
DEFINE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)

/**
 * @brief In-memory text database parsed from newline-separated, comma-separated rows.
 */
typedef struct txt_db_st {
    /** Number of fields expected in each row. */
    int num_fields;
    /** Stack of rows; each row is an OPENSSL_STRING array of @c num_fields entries. */
    STACK_OF(OPENSSL_PSTRING) *data;
    /** Per-field hash indexes (may be NULL for unindexed columns). */
    LHASH_OF(OPENSSL_STRING) **index;
    /** Optional per-field predicates; when non-NULL, only rows for which qual(row) is true are indexed. */
    int (**qual)(OPENSSL_STRING *);
    /** Last TXT_DB error code (DB_ERROR_*). */
    long error;
    /** Auxiliary numeric value set by some TXT_DB operations on error (meaning depends on @c error). */
    long arg1;
    /** Second auxiliary value set on index clashes (for example conflicting row index). */
    long arg2;
    /** Pointer to an existing conflicting row when an insert/index clash is detected. */
    OPENSSL_STRING *arg_row;
} TXT_DB;

/**
 * @brief Read a text database from a BIO into memory.
 * @param in BIO supplying newline-terminated rows of comma-separated fields.
 * @param num Expected number of fields per row.
 * @return Parsed TXT_DB, or NULL on error (see @c error on partial objects).
 */
TXT_DB *TXT_DB_read(BIO *in, int num);
/**
 * @brief Write a text database to a BIO in comma-separated row format.
 * @param out Destination BIO.
 * @param db Database to serialize.
 * @return Number of bytes written, or -1 on error.
 */
long TXT_DB_write(BIO *out, TXT_DB *db);
/**
 * @brief Build a hash index on column @p field of a text database.
 * @param db Database whose rows will be indexed.
 * @param field Zero-based field number to index.
 * @param qual Optional predicate; when non-NULL, only rows for which qual(row) is true are indexed.
 * @param hash Hash function for field strings.
 * @param cmp Comparison function for field strings.
 * @return 1 on success, or 0 on failure (see @c db->error).
 */
int TXT_DB_create_index(TXT_DB *db, int field, int (*qual)(OPENSSL_STRING *),
    OPENSSL_LH_HASHFUNC hash, OPENSSL_LH_COMPFUNC cmp);
/**
 * @brief Free a text database and all stored rows.
 * @param db Database to free, or NULL.
 */
void TXT_DB_free(TXT_DB *db);
/**
 * @brief Look up a row by the value of indexed field @p idx.
 * @param db Database whose indexes were built with TXT_DB_create_index().
 * @param idx Zero-based field number that must have an index.
 * @param value Row (or key row) whose @p idx field is the lookup key.
 * @return Matching row, or NULL on error (see @c db->error for DB_ERROR_*).
 */
OPENSSL_STRING *TXT_DB_get_by_index(TXT_DB *db, int idx,
    OPENSSL_STRING *value);
/**
 * @brief Insert a row into a text database and update any indexes.
 * @param db Database to update.
 * @param value Row with @c num_fields string fields to store (ownership transfers on success).
 * @return 1 on success, or 0 on clash/allocation failure (see @c db->error / @c arg_row).
 */
int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *value);

#ifdef __cplusplus
}
#endif

#endif
