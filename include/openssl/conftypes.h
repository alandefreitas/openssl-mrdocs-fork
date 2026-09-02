/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CONFTYPES_H
#define OPENSSL_CONFTYPES_H
#pragma once

#ifndef OPENSSL_CONF_H
#include <openssl/conf.h>
#endif

/*
 * The contents of this file are deprecated and will be made opaque
 */
/**
 * @brief Legacy CONF method vtable (deprecated; contents will become opaque).
 */
struct conf_method_st {
    /** Short name identifying this CONF_METHOD implementation. */
    const char *name;
    /** Allocate a new CONF object for this method (may be NULL). */
    CONF *(*create)(CONF_METHOD *meth);
    /** Initialize a CONF object after allocation (may be NULL). */
    int (*init)(CONF *conf);
    /** Tear down a CONF object created by @c create (method-specific cleanup). */
    int (*destroy)(CONF *conf);
    /** Release configuration data held by @p conf without destroying the object. */
    int (*destroy_data)(CONF *conf);
    /** Load configuration syntax from a BIO into @p conf; @p eline receives error line. */
    int (*load_bio)(CONF *conf, BIO *bp, long *eline);
    /** Dump the configuration contents of @p conf to @p bp. */
    int (*dump)(const CONF *conf, BIO *bp);
    /** Return non-zero if @p c is a digit in this CONF method's number syntax. */
    int (*is_number)(const CONF *conf, char c);
    /** Convert digit character @p c to its integer value for this CONF method. */
    int (*to_int)(const CONF *conf, char c);
    /** Load configuration from a named file into @p conf; @p eline receives error line. */
    int (*load)(CONF *conf, const char *name, long *eline);
};

struct conf_st {
    /** Active CONF_METHOD vtable for this configuration object. */
    CONF_METHOD *meth;
    /** Opaque method-specific data for @c meth (CONF_METHOD private state). */
    void *meth_data;
    /** Hash table of CONF_VALUE entries (section/name/value triples). */
    LHASH_OF(CONF_VALUE) *data;
    /** Non-zero when dollar-prefixed identifiers ("$var") are enabled in CONF syntax. */
    int flag_dollarid;
    /** Non-zero when .include paths are treated as absolute rather than relative. */
    int flag_abspath;
    /** Directory prepended to relative .include paths, or NULL. */
    char *includedir;
    /** Library context associated with this CONF, or NULL for the default. */
    OSSL_LIB_CTX *libctx;
};

#endif
