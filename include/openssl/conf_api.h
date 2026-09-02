/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CONF_API_H
#define OPENSSL_CONF_API_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_CONF_API_H
#endif

#include <openssl/lhash.h>
#include <openssl/conf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Up until OpenSSL 0.9.5a, this was new_section */
/**
 * @brief Create a new named section in the internal CONF data store.
 * @param conf Configuration object to update.
 * @param section Section name to create.
 * @return CONF_VALUE representing the new section, or NULL on error.
 */
CONF_VALUE *_CONF_new_section(CONF *conf, const char *section);
/* Up until OpenSSL 0.9.5a, this was get_section */
/**
 * @brief Look up a section CONF_VALUE in the internal CONF data store.
 * @param conf Configuration object.
 * @param section Section name to find.
 * @return Internal section CONF_VALUE, or NULL if absent; do not free.
 */
CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section);
/* Up until OpenSSL 0.9.5a, this was CONF_get_section */
/**
 * @brief Return the CONF_VALUE stack for @p section from the internal CONF data store.
 * @param conf Configuration object.
 * @param section Section name to look up.
 * @return Internal stack of values, or NULL if absent; do not free.
 */
STACK_OF(CONF_VALUE) *_CONF_get_section_values(const CONF *conf,
    const char *section);

/**
 * @brief Insert a name/value pair into a CONF section (internal CONF helper).
 * @param conf Configuration object whose hash table is updated.
 * @param section Section CONF_VALUE that owns the entry.
 * @param value Name/value CONF_VALUE to add; ownership transfers on success.
 * @return 1 on success, or 0 on error.
 */
int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);
/**
 * @brief Look up a string in the internal CONF data store (legacy helper).
 * @param conf Configuration object.
 * @param section Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Internal value string, or NULL if not found; do not free.
 */
char *_CONF_get_string(const CONF *conf, const char *section,
    const char *name);
/**
 * @brief Look up a numeric value in the internal CONF data store (legacy helper).
 * @param conf Configuration object.
 * @param section Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Parsed long integer, or 0 if missing / not a number.
 */
long _CONF_get_number(const CONF *conf, const char *section,
    const char *name);

/**
 * @brief Allocate the internal LHASH used to store CONF values (internal helper).
 * @param conf Configuration object whose data table is created when missing.
 * @return 1 on success, or 0 on allocation failure.
 */
int _CONF_new_data(CONF *conf);
/**
 * @brief Free the internal LHASH and CONF_VALUE entries stored in @p conf.
 * @param conf Configuration object whose data table is released; NULL is ignored.
 */
void _CONF_free_data(CONF *conf);

#ifdef __cplusplus
}
#endif
#endif
