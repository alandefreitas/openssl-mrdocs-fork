/*
 * Copyright 2000-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ENGINE_H
#define OPENSSL_ENGINE_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_ENGINE_H
#endif

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_ENGINE
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/ui.h>
#include <openssl/err.h>
#endif
#include <openssl/types.h>
#include <openssl/symhacks.h>
#include <openssl/x509.h>
#include <openssl/engineerr.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * These flags are used to control combinations of algorithm (methods) by
 * bitwise "OR"ing.
 */
#define ENGINE_METHOD_RSA (unsigned int)0x0001
#define ENGINE_METHOD_DSA (unsigned int)0x0002
#define ENGINE_METHOD_DH (unsigned int)0x0004
#define ENGINE_METHOD_RAND (unsigned int)0x0008
#define ENGINE_METHOD_CIPHERS (unsigned int)0x0040
#define ENGINE_METHOD_DIGESTS (unsigned int)0x0080
#define ENGINE_METHOD_PKEY_METHS (unsigned int)0x0200
#define ENGINE_METHOD_PKEY_ASN1_METHS (unsigned int)0x0400
#define ENGINE_METHOD_EC (unsigned int)0x0800
/* Obvious all-or-nothing cases. */
#define ENGINE_METHOD_ALL (unsigned int)0xFFFF
#define ENGINE_METHOD_NONE (unsigned int)0x0000

/*
 * This(ese) flag(s) controls behaviour of the ENGINE_TABLE mechanism used
 * internally to control registration of ENGINE implementations, and can be
 * set by ENGINE_set_table_flags(). The "NOINIT" flag prevents attempts to
 * initialise registered ENGINEs if they are not already initialised.
 */
#define ENGINE_TABLE_FLAG_NOINIT (unsigned int)0x0001

/* ENGINE flags that can be set by ENGINE_set_flags(). */
/* Not used */
/* #define ENGINE_FLAGS_MALLOCED        0x0001 */

/*
 * This flag is for ENGINEs that wish to handle the various 'CMD'-related
 * control commands on their own. Without this flag, ENGINE_ctrl() handles
 * these control commands on behalf of the ENGINE using their "cmd_defns"
 * data.
 */
#define ENGINE_FLAGS_MANUAL_CMD_CTRL (int)0x0002

/*
 * This flag is for ENGINEs who return new duplicate structures when found
 * via "ENGINE_by_id()". When an ENGINE must store state (eg. if
 * ENGINE_ctrl() commands are called in sequence as part of some stateful
 * process like key-generation setup and execution), it can set this flag -
 * then each attempt to obtain the ENGINE will result in it being copied into
 * a new structure. Normally, ENGINEs don't declare this flag so
 * ENGINE_by_id() just increments the existing ENGINE's structural reference
 * count.
 */
#define ENGINE_FLAGS_BY_ID_COPY (int)0x0004

/*
 * This flag if for an ENGINE that does not want its methods registered as
 * part of ENGINE_register_all_complete() for example if the methods are not
 * usable as default methods.
 */

#define ENGINE_FLAGS_NO_REGISTER_ALL (int)0x0008

/*
 * ENGINEs can support their own command types, and these flags are used in
 * ENGINE_CTRL_GET_CMD_FLAGS to indicate to the caller what kind of input
 * each command expects. Currently only numeric and string input is
 * supported. If a control command supports none of the _NUMERIC, _STRING, or
 * _NO_INPUT options, then it is regarded as an "internal" control command -
 * and not for use in config setting situations. As such, they're not
 * available to the ENGINE_ctrl_cmd_string() function, only raw ENGINE_ctrl()
 * access. Changes to this list of 'command types' should be reflected
 * carefully in ENGINE_cmd_is_executable() and ENGINE_ctrl_cmd_string().
 */

/* accepts a 'long' input value (3rd parameter to ENGINE_ctrl) */
#define ENGINE_CMD_FLAG_NUMERIC (unsigned int)0x0001
/*
 * accepts string input (cast from 'void*' to 'const char *', 4th parameter
 * to ENGINE_ctrl)
 */
#define ENGINE_CMD_FLAG_STRING (unsigned int)0x0002
/*
 * Indicates that the control command takes *no* input. Ie. the control
 * command is unparameterised.
 */
#define ENGINE_CMD_FLAG_NO_INPUT (unsigned int)0x0004
/*
 * Indicates that the control command is internal. This control command won't
 * be shown in any output, and is only usable through the ENGINE_ctrl_cmd()
 * function.
 */
#define ENGINE_CMD_FLAG_INTERNAL (unsigned int)0x0008

/*
 * NB: These 3 control commands are deprecated and should not be used.
 * ENGINEs relying on these commands should compile conditional support for
 * compatibility (eg. if these symbols are defined) but should also migrate
 * the same functionality to their own ENGINE-specific control functions that
 * can be "discovered" by calling applications. The fact these control
 * commands wouldn't be "executable" (ie. usable by text-based config)
 * doesn't change the fact that application code can find and use them
 * without requiring per-ENGINE hacking.
 */

/*
 * These flags are used to tell the ctrl function what should be done. All
 * command numbers are shared between all engines, even if some don't make
 * sense to some engines.  In such a case, they do nothing but return the
 * error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED.
 */
#define ENGINE_CTRL_SET_LOGSTREAM 1
#define ENGINE_CTRL_SET_PASSWORD_CALLBACK 2
#define ENGINE_CTRL_HUP 3 /* Close and reinitialise  \
                           * any handles/connections \
                           * etc. */
#define ENGINE_CTRL_SET_USER_INTERFACE 4 /* Alternative to callback */
#define ENGINE_CTRL_SET_CALLBACK_DATA 5 /* User-specific data, used  \
                                         * when calling the password \
                                         * callback and the user     \
                                         * interface */
#define ENGINE_CTRL_LOAD_CONFIGURATION 6 /* Load a configuration,  \
                                          * given a string that    \
                                          * represents a file name \
                                          * or so */
#define ENGINE_CTRL_LOAD_SECTION 7 /* Load data from a given \
                                    * section in the already \
                                    * loaded configuration */

/*
 * These control commands allow an application to deal with an arbitrary
 * engine in a dynamic way. Warn: Negative return values indicate errors FOR
 * THESE COMMANDS because zero is used to indicate 'end-of-list'. Other
 * commands, including ENGINE-specific command types, return zero for an
 * error. An ENGINE can choose to implement these ctrl functions, and can
 * internally manage things however it chooses - it does so by setting the
 * ENGINE_FLAGS_MANUAL_CMD_CTRL flag (using ENGINE_set_flags()). Otherwise
 * the ENGINE_ctrl() code handles this on the ENGINE's behalf using the
 * cmd_defns data (set using ENGINE_set_cmd_defns()). This means an ENGINE's
 * ctrl() handler need only implement its own commands - the above "meta"
 * commands will be taken care of.
 */

/*
 * Returns non-zero if the supplied ENGINE has a ctrl() handler. If "not",
 * then all the remaining control commands will return failure, so it is
 * worth checking this first if the caller is trying to "discover" the
 * engine's capabilities and doesn't want errors generated unnecessarily.
 */
#define ENGINE_CTRL_HAS_CTRL_FUNCTION 10
/*
 * Returns a positive command number for the first command supported by the
 * engine. Returns zero if no ctrl commands are supported.
 */
#define ENGINE_CTRL_GET_FIRST_CMD_TYPE 11
/*
 * The 'long' argument specifies a command implemented by the engine, and the
 * return value is the next command supported, or zero if there are no more.
 */
#define ENGINE_CTRL_GET_NEXT_CMD_TYPE 12
/*
 * The 'void*' argument is a command name (cast from 'const char *'), and the
 * return value is the command that corresponds to it.
 */
#define ENGINE_CTRL_GET_CMD_FROM_NAME 13
/*
 * The next two allow a command to be converted into its corresponding string
 * form. In each case, the 'long' argument supplies the command. In the
 * NAME_LEN case, the return value is the length of the command name (not
 * counting a trailing EOL). In the NAME case, the 'void*' argument must be a
 * string buffer large enough, and it will be populated with the name of the
 * command (WITH a trailing EOL).
 */
#define ENGINE_CTRL_GET_NAME_LEN_FROM_CMD 14
#define ENGINE_CTRL_GET_NAME_FROM_CMD 15
/* The next two are similar but give a "short description" of a command. */
#define ENGINE_CTRL_GET_DESC_LEN_FROM_CMD 16
#define ENGINE_CTRL_GET_DESC_FROM_CMD 17
/*
 * With this command, the return value is the OR'd combination of
 * ENGINE_CMD_FLAG_*** values that indicate what kind of input a given
 * engine-specific ctrl command expects.
 */
#define ENGINE_CTRL_GET_CMD_FLAGS 18

/*
 * ENGINE implementations should start the numbering of their own control
 * commands from this value. (ie. ENGINE_CMD_BASE, ENGINE_CMD_BASE + 1, etc).
 */
#define ENGINE_CMD_BASE 200

/*
 * NB: These 2 nCipher "chil" control commands are deprecated, and their
 * functionality is now available through ENGINE-specific control commands
 * (exposed through the above-mentioned 'CMD'-handling). Code using these 2
 * commands should be migrated to the more general command handling before
 * these are removed.
 */

/* Flags specific to the nCipher "chil" engine */
#define ENGINE_CTRL_CHIL_SET_FORKCHECK 100
/*
 * Depending on the value of the (long)i argument, this sets or
 * unsets the SimpleForkCheck flag in the CHIL API to enable or
 * disable checking and workarounds for applications that fork().
 */
#define ENGINE_CTRL_CHIL_NO_LOCKING 101
/*
 * This prevents the initialisation function from providing mutex
 * callbacks to the nCipher library.
 */

/*
 * If an ENGINE supports its own specific control commands and wishes the
 * framework to handle the above 'ENGINE_CMD_***'-manipulation commands on
 * its behalf, it should supply a null-terminated array of ENGINE_CMD_DEFN
 * entries to ENGINE_set_cmd_defns(). It should also implement a ctrl()
 * handler that supports the stated commands (ie. the "cmd_num" entries as
 * described by the array). NB: The array must be ordered in increasing order
 * of cmd_num. "null-terminated" means that the last ENGINE_CMD_DEFN element
 * has cmd_num set to zero and/or cmd_name set to NULL.
 */
/**
 * @brief Describes one ENGINE-specific control command for ENGINE_set_cmd_defns().
 *
 * Arrays of these are null-terminated: the last element has cmd_num 0 and/or
 * cmd_name NULL. Entries must be ordered by increasing cmd_num.
 */
typedef struct ENGINE_CMD_DEFN_st {
    /** Numeric identifier of the command (ENGINE_CMD_BASE and above for custom commands). */
    unsigned int cmd_num;
    /** NUL-terminated command name used by ENGINE_ctrl_cmd() and config strings. */
    const char *cmd_name;
    /** Short human-readable description of the command. */
    const char *cmd_desc;
    /** Bitmask of ENGINE_CMD_FLAG_* describing the expected input form. */
    unsigned int cmd_flags;
} ENGINE_CMD_DEFN;

/**
 * @brief Generic ENGINE callback with no parameters.
 * @return Implementation-defined status; typically nonzero for success.
 */
typedef int (*ENGINE_GEN_FUNC_PTR)(void);
/**
 * @brief Generic ENGINE callback receiving the ENGINE being operated on.
 * @param e ENGINE passed to the callback.
 * @return Implementation-defined status; typically nonzero for success.
 */
typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
/**
 * @brief ENGINE control-command handler (same calling convention as ENGINE_ctrl()).
 * @param e ENGINE receiving the command.
 * @param cmd Control command number.
 * @param i Integer argument for the command.
 * @param p Pointer argument for the command.
 * @param f Optional function-pointer argument for the command.
 * @return Positive on success, or non-positive on failure (command-dependent).
 */
typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *,
    void (*f)(void));
/**
 * @brief Callback that loads a key from an ENGINE-backed store.
 * @param e ENGINE that owns the key material.
 * @param key_id Identifier of the key within the ENGINE.
 * @param ui_method UI method used to collect passphrases or a PIN, or NULL.
 * @param callback_data Application data passed to @p ui_method.
 * @return Newly allocated EVP_PKEY, or NULL on failure.
 */
typedef EVP_PKEY *(*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
    UI_METHOD *ui_method,
    void *callback_data);
/**
 * @brief ENGINE callback that supplies a client certificate and key for an SSL connection.
 * @param ssl SSL connection requesting a client certificate.
 * @param ca_dn Acceptable CA distinguished names from the server, or NULL.
 * @param pcert Receives the selected client certificate.
 * @param pkey Receives the matching private key.
 * @param pother Optional chain certificates to send, or NULL if unused.
 * @param ui_method UI method for interactive PIN/passphrase prompts, or NULL.
 * @param callback_data User pointer associated with the ENGINE load operation.
 * @return 1 on success, 0 on failure, or a negative value on fatal error.
 */
typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
    STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **pkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method,
    void *callback_data);
/*-
 * These callback types are for an ENGINE's handler for cipher and digest logic.
 * These handlers have these prototypes;
 *   int foo(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
 *   int foo(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
 * Looking at how to implement these handlers in the case of cipher support, if
 * the framework wants the EVP_CIPHER for 'nid', it will call;
 *   foo(e, &p_evp_cipher, NULL, nid);    (return zero for failure)
 * If the framework wants a list of supported 'nid's, it will call;
 *   foo(e, NULL, &p_nids, 0); (returns number of 'nids' or -1 for error)
 */
/*
 * Returns to a pointer to the array of supported cipher 'nid's. If the
 * second parameter is non-NULL it is set to the size of the returned array.
 */
/**
 * @brief ENGINE ciphers handler: list supported NIDs or return an EVP_CIPHER for a NID.
 *
 * Called as foo(e, &cipher, NULL, nid) to fetch a cipher, or foo(e, NULL, &nids, 0)
 * to list supported NIDs (returns the count, or a negative value on error).
 */
typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, const EVP_CIPHER **,
    const int **, int);
/**
 * @brief ENGINE digests handler: list supported NIDs or return an EVP_MD for a NID.
 *
 * Called as foo(e, &md, NULL, nid) to fetch a digest, or foo(e, NULL, &nids, 0)
 * to list supported NIDs (returns the count, or a negative value on error).
 */
typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, const EVP_MD **, const int **,
    int);
/**
 * @brief ENGINE public-key method handler: list supported NIDs or return an EVP_PKEY_METHOD.
 * @param e ENGINE being queried (first parameter of the callback).
 * @param pmeth When non-NULL, receives the EVP_PKEY_METHOD for the requested NID.
 * @param nids When @p pmeth is NULL, receives the array of supported NIDs.
 * @param nid NID to look up when @p pmeth is non-NULL.
 * @return Number of NIDs when listing, 1 when a method is returned, or 0 on failure.
 */
typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **,
    const int **, int);
/**
 * @brief ENGINE ASN.1 method handler: list supported NIDs or return an EVP_PKEY_ASN1_METHOD.
 *
 * Same calling convention as ENGINE_DIGESTS_PTR / ENGINE_CIPHERS_PTR: fetch by
 * NID when the method out-parameter is non-NULL, otherwise enumerate NIDs.
 */
typedef int (*ENGINE_PKEY_ASN1_METHS_PTR)(ENGINE *, EVP_PKEY_ASN1_METHOD **,
    const int **, int);
/*
 * STRUCTURE functions ... all of these functions deal with pointers to
 * ENGINE structures where the pointers have a "structural reference". This
 * means that their reference is to allowed access to the structure but it
 * does not imply that the structure is functional. To simply increment or
 * decrement the structural reference count, use ENGINE_by_id and
 * ENGINE_free. NB: This is not required when iterating using ENGINE_get_next
 * as it will automatically decrement the structural reference count of the
 * "current" ENGINE and increment the structural reference count of the
 * ENGINE it returns (unless it is NULL).
 */

/* Get the first/last "ENGINE" type available. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the first ENGINE in OpenSSL's loaded list.
 * @return Structural reference to the first ENGINE, or NULL if the list is empty.
 *
 * Pair with ENGINE_get_next() to iterate; release the returned reference with ENGINE_free()
 * when finished, unless ENGINE_get_next() has already released it.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_first(void);
/**
 * @brief Return the last ENGINE in the global ENGINE list (deprecated).
 * @return ENGINE with an incremented structural reference, or NULL if the list is empty.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_last(void);
#endif
/* Iterate to the next/previous "ENGINE" type (NULL = end of the list). */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the next ENGINE in OpenSSL's loaded list and release @p e.
 * @param e Structural reference to the current ENGINE; released on behalf of the caller.
 * @return Structural reference to the next ENGINE, or NULL at the end of the list.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_next(ENGINE *e);
/**
 * @brief Return the previous ENGINE in OpenSSL's loaded list and release @p e.
 * @param e Structural reference to the current ENGINE; released on behalf of the caller.
 * @return Structural reference to the previous ENGINE, or NULL at the start of the list.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_prev(ENGINE *e);
#endif
/* Add another "ENGINE" type into the array. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Add @p e to OpenSSL's internal list of loaded ENGINEs.
 * @param e Structural reference to the ENGINE to register; the caller retains ownership and must still ENGINE_free() it.
 * @return 1 on success, or 0 on failure.
 *
 * On success OpenSSL holds its own structural reference internally.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_add(ENGINE *e);
#endif
/* Remove an existing "ENGINE" type from the array. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Remove an ENGINE from the global ENGINE list (deprecated).
 * @param e Structural reference to the ENGINE to unregister.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_remove(ENGINE *e);
#endif
/* Retrieve an engine from the list by its unique "id" value. */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Look up a registered ENGINE by its unique id string (deprecated).
 * @param id ENGINE identifier (for example "dynamic" or a built-in engine id).
 * @return Structural reference to the ENGINE, or NULL if not found; free with ENGINE_free().
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_by_id(const char *id);
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define ENGINE_load_openssl() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, NULL)
#define ENGINE_load_dynamic() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL)
#ifndef OPENSSL_NO_STATIC_ENGINE
#define ENGINE_load_padlock() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_PADLOCK, NULL)
#define ENGINE_load_capi() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CAPI, NULL)
#define ENGINE_load_afalg() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL)
#endif
#define ENGINE_load_cryptodev() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CRYPTODEV, NULL)
#define ENGINE_load_rdrand() \
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_RDRAND, NULL)
#endif
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register all compiled-in ENGINE implementations (deprecated in OpenSSL 3).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_load_builtin_engines(void);
#endif

/*
 * Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
 * "registry" handling.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the global ENGINE algorithm-table flags.
 * @return Bitmask of ENGINE_TABLE_FLAG_* values.
 */
OSSL_DEPRECATEDIN_3_0 unsigned int ENGINE_get_table_flags(void);
/**
 * @brief Set the global ENGINE algorithm-table flags (deprecated).
 * @param flags Bitmask of ENGINE_TABLE_FLAG_* values (for example ENGINE_TABLE_FLAG_NOINIT).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_set_table_flags(unsigned int flags);
#endif

/*- Manage registration of ENGINEs per "table". For each type, there are 3
 * functions;
 *   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
 *   ENGINE_unregister_***(e) - unregister the implementation from 'e'
 *   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
 * Cleanup is automatically registered from each table when required.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register @p e's RSA method in the ENGINE RSA implementation table.
 * @param e ENGINE whose RSA implementation should become available for selection.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_RSA(ENGINE *e);
/**
 * @brief Remove @p e's RSA method from the ENGINE RSA implementation table.
 * @param e ENGINE previously registered for RSA.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_RSA(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides an RSA method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_RSA(void);
/**
 * @brief Register @p e's DSA method with the ENGINE DSA implementation table (deprecated).
 * @param e ENGINE that provides a DSA_METHOD.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DSA(ENGINE *e);
/**
 * @brief Remove @p e's DSA method from the ENGINE DSA implementation table.
 * @param e ENGINE previously registered for DSA.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_DSA(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides a DSA method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_DSA(void);
/**
 * @brief Register @p e's EC method in the ENGINE EC implementation table.
 * @param e ENGINE whose EC implementation should become available for selection.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_EC(ENGINE *e);
/**
 * @brief Remove @p e's EC method from the ENGINE EC implementation table.
 * @param e ENGINE previously registered for EC.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_EC(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides an EC method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_EC(void);
/**
 * @brief Register @p e's DH method in the ENGINE DH implementation table (deprecated).
 * @param e ENGINE whose DH implementation should become available for selection.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DH(ENGINE *e);
/**
 * @brief Remove @p e's DH method from the ENGINE DH implementation table (deprecated).
 * @param e ENGINE previously registered for DH.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_DH(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides a DH method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_DH(void);
/**
 * @brief Register @p e's RAND implementation with the global RAND table (deprecated).
 * @param e ENGINE whose RAND method should be registered.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_RAND(ENGINE *e);
/**
 * @brief Unregister an ENGINE as a RAND implementation (deprecated).
 * @param e ENGINE previously registered for RAND to remove from the RAND table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_RAND(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides a RAND method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_RAND(void);
/**
 * @brief Register @p e's cipher implementations with the global cipher table (deprecated).
 * @param e ENGINE whose ciphers should be registered.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_ciphers(ENGINE *e);
/**
 * @brief Unregister all cipher implementations previously registered from @p e (deprecated).
 * @param e ENGINE whose cipher methods are removed from the global cipher table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_ciphers(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides cipher implementations.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_ciphers(void);
/**
 * @brief Register @p e's digest implementations in the ENGINE digests table.
 * @param e ENGINE whose digests should become available for selection.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_digests(ENGINE *e);
/**
 * @brief Unregister @p e's digest implementations from the ENGINE digests table (deprecated).
 * @param e ENGINE whose digests should be removed from selection.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_digests(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides digest implementations (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_digests(void);
/**
 * @brief Register @p e's EVP_PKEY_METHOD implementations with the global table (deprecated).
 * @param e ENGINE providing public-key methods to register.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_meths(ENGINE *e);
/**
 * @brief Unregister @p e's EVP_PKEY_METHOD implementations from the global table (deprecated).
 * @param e ENGINE whose pkey methods should be removed.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_meths(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides EVP_PKEY_METHOD implementations.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_pkey_meths(void);
/**
 * @brief Register the ASN.1 public-key methods provided by @p e (deprecated).
 * @param e ENGINE that implements one or more EVP_PKEY_ASN1_METHOD handlers.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_asn1_meths(ENGINE *e);
/**
 * @brief Unregister the EVP_PKEY ASN.1 methods previously registered from @p e (deprecated).
 * @param e ENGINE whose pkey ASN.1 methods should be removed from the global table.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_asn1_meths(ENGINE *e);
/**
 * @brief Register every loaded ENGINE that provides EVP_PKEY ASN.1 methods (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_pkey_asn1_meths(void);
#endif

/*
 * These functions register all support from the above categories. Note, use
 * of these functions can result in static linkage of code your application
 * may not need. If you only need a subset of functionality, consider using
 * more selective initialisation.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register every algorithm category that @p e implements.
 * @param e ENGINE whose RSA/DSA/EC/DH/RAND/cipher/digest/pkey support should all be registered.
 * @return Always 1.
 *
 * Prefer selective ENGINE_register_*() calls if you only need a subset, to avoid
 * pulling in unused static ENGINE code.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_complete(ENGINE *e);
/**
 * @brief Register all loaded ENGINEs for every algorithm they implement (deprecated).
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_all_complete(void);
#endif

/*
 * Send parameterised control commands to the engine. The possibilities to
 * send down an integer, a pointer to data or a function pointer are
 * provided. Any of the parameters may or may not be NULL, depending on the
 * command number. In actuality, this function only requires a structural
 * (rather than functional) reference to an engine, but many control commands
 * may require the engine be functional. The caller should be aware of trying
 * commands that require an operational ENGINE, and only use functional
 * references in such situations.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Dispatch a control command to an ENGINE (deprecated).
 * @param e ENGINE receiving the command.
 * @param cmd Control command (ENGINE_CTRL_* or ENGINE-specific).
 * @param i Integer argument for @p cmd.
 * @param p Pointer argument for @p cmd, or NULL when unused.
 * @param f Optional function-pointer argument for @p cmd, or NULL.
 * @return Command-specific positive value on success, or non-positive on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p,
    void (*f)(void));
#endif

/*
 * This function tests if an ENGINE-specific command is usable as a
 * "setting". Eg. in an application's config file that gets processed through
 * ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
 * ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Test whether an ENGINE control command may be used as a config/setting command (deprecated).
 * @param e ENGINE whose command definitions are queried.
 * @param cmd Numeric command identifier from the ENGINE's cmd_defns.
 * @return 1 if @p cmd is usable via ENGINE_ctrl_cmd_string(), or 0 if it is internal-only / unavailable.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_cmd_is_executable(ENGINE *e, int cmd);
#endif

/*
 * This function works like ENGINE_ctrl() with the exception of taking a
 * command name instead of a command number, and can handle optional
 * commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
 * on how to use the cmd_name and cmd_optional.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Invoke an ENGINE control command looked up by name rather than number.
 * @param e Structural reference to the ENGINE; many commands also require it to be functional.
 * @param cmd_name NUL-terminated name of the command (from the ENGINE's cmd_defns).
 * @param i Integer argument forwarded to the ENGINE ctrl handler.
 * @param p Pointer argument forwarded to the ENGINE ctrl handler.
 * @param f Optional function-pointer argument forwarded to the ENGINE ctrl handler.
 * @param cmd_optional Non-zero to treat an unsupported @p cmd_name as success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
    long i, void *p, void (*f)(void),
    int cmd_optional);
#endif

/*
 * This function passes a command-name and argument to an ENGINE. The
 * cmd_name is converted to a command number and the control command is
 * called using 'arg' as an argument (unless the ENGINE doesn't support such
 * a command, in which case no control command is called). The command is
 * checked for input flags, and if necessary the argument will be converted
 * to a numeric value. If cmd_optional is non-zero, then if the ENGINE
 * doesn't support the given cmd_name the return value will be success
 * anyway. This function is intended for applications to use so that users
 * (or config files) can supply engine-specific config data to the ENGINE at
 * run-time to control behaviour of specific engines. As such, it shouldn't
 * be used for calling ENGINE_ctrl() functions that return data, deal with
 * binary data, or that are otherwise supposed to be used directly through
 * ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
 * operation in this function will be lost - the return value is interpreted
 * as failure if the return value is zero, success otherwise, and this
 * function returns a boolean value as a result. In other words, vendors of
 * 'ENGINE'-enabled devices should write ENGINE implementations with
 * parameterisations that work in this scheme, so that compliant ENGINE-based
 * applications can work consistently with the same configuration for the
 * same ENGINE-enabled devices, across applications.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Run a named ENGINE control command whose argument is a string (deprecated).
 * @param e ENGINE that receives the command.
 * @param cmd_name Command name as advertised by the ENGINE.
 * @param arg String argument for the command, or NULL.
 * @param cmd_optional Non-zero to treat an unknown command as success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
    int cmd_optional);
#endif

/*
 * These functions are useful for manufacturing new ENGINE structures. They
 * don't address reference counting at all - one uses them to populate an
 * ENGINE structure with personalised implementations of things prior to
 * using it directly or adding it to the builtin ENGINE list in OpenSSL.
 * These are also here so that the ENGINE structure doesn't have to be
 * exposed and break binary compatibility!
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Allocate a new empty ENGINE with a structural reference count of one.
 * @return New ENGINE ready to configure with ENGINE_set_*(), or NULL on allocation failure.
 *
 * Does not initialise the ENGINE for functional use; call ENGINE_init() after
 * populating methods, or ENGINE_add() to insert it into the global list.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_new(void);
/**
 * @brief Release one structural reference to an ENGINE.
 * @param e ENGINE to free, or NULL (no-op).
 * @return Always 1.
 *
 * The ENGINE is destroyed only when its last structural reference is released.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_free(ENGINE *e);
/**
 * @brief Increment the structural reference count of an ENGINE.
 * @param e ENGINE whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_up_ref(ENGINE *e);
/**
 * @brief Set the unique string identifier for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param id NUL-terminated id; must remain valid for the life of @p e.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_id(ENGINE *e, const char *id);
/**
 * @brief Set the human-readable name string for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param name NUL-terminated display name; must remain valid for the life of @p e.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_name(ENGINE *e, const char *name);
/**
 * @brief Attach an RSA_METHOD to an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param rsa_meth RSA method table, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);
/**
 * @brief Attach a DSA_METHOD implementation to an ENGINE.
 * @param e ENGINE whose DSA method pointer is replaced.
 * @param dsa_meth DSA method table to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth);
/**
 * @brief Attach an EC_KEY_METHOD implementation to an ENGINE (deprecated).
 * @param e ENGINE that will expose the method.
 * @param ecdsa_meth EC key method table for ECDSA/ECDH operations, or NULL to clear.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_EC(ENGINE *e, const EC_KEY_METHOD *ecdsa_meth);
/**
 * @brief Attach a DH_METHOD implementation to an ENGINE (deprecated).
 * @param e ENGINE whose DH method pointer is replaced.
 * @param dh_meth DH method table to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);
/**
 * @brief Attach a RAND_METHOD implementation to an ENGINE.
 * @param e ENGINE whose RAND method pointer is replaced.
 * @param rand_meth RAND method table to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth);
/**
 * @brief Set the callback invoked when the last structural reference to an ENGINE is released.
 * @param e ENGINE whose destroy hook is replaced.
 * @param destroy_f Function called to tear down @p e, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f);
/**
 * @brief Set the callback invoked by ENGINE_init() to bring an ENGINE to operational state.
 * @param e ENGINE whose init hook is replaced.
 * @param init_f Function called to initialise @p e for functional use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
/**
 * @brief Set the callback invoked by ENGINE_finish() to shut down an ENGINE.
 * @param e ENGINE whose finish hook is replaced.
 * @param finish_f Function called to release functional state of @p e, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
/**
 * @brief Set the ctrl callback used by ENGINE_ctrl() for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param ctrl_f Control function, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);
/**
 * @brief Set the callback used by ENGINE_load_private_key() to load private keys.
 * @param e ENGINE whose private-key loader is replaced.
 * @param loadpriv_f Loader callback, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);
/**
 * @brief Set the callback used by ENGINE_load_public_key() to load public keys.
 * @param e ENGINE whose public-key loader is replaced.
 * @param loadpub_f Loader callback, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f);
/**
 * @brief Set the callback that loads an SSL/TLS client certificate and key from an ENGINE (deprecated).
 * @param e ENGINE whose SSL client-cert loader is replaced.
 * @param loadssl_f Loader callback invoked during client certificate selection, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_load_ssl_client_cert_function(ENGINE *e,
    ENGINE_SSL_CLIENT_CERT_PTR loadssl_f);
/**
 * @brief Set the cipher enumeration callback for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param f Callback that lists or fetches EVP_CIPHER implementations, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);
/**
 * @brief Set the callback that enumerates or looks up EVP_MD digests provided by an ENGINE.
 * @param e ENGINE whose digests handler is replaced.
 * @param f Digests callback, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f);
/**
 * @brief Set the callback that enumerates or looks up EVP_PKEY_METHOD entries provided by an ENGINE.
 * @param e ENGINE whose pkey-methods handler is replaced.
 * @param f Pkey-methods callback, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_pkey_meths(ENGINE *e, ENGINE_PKEY_METHS_PTR f);
/**
 * @brief Install the ENGINE callback that enumerates public-key ASN.1 methods (deprecated).
 * @param e ENGINE whose pkey ASN.1 method table callback is set.
 * @param f Callback of type ENGINE_PKEY_ASN1_METHS_PTR, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f);
/**
 * @brief Replace the behavioural flags stored on an ENGINE.
 * @param e ENGINE whose flags are updated.
 * @param flags Bitmask of ENGINE_FLAGS_* values.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_flags(ENGINE *e, int flags);
/**
 * @brief Attach the ENGINE_CMD_DEFN table describing control commands for an ENGINE.
 * @param e ENGINE whose command definitions are replaced.
 * @param defns NUL-terminated array of command definitions, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_cmd_defns(ENGINE *e,
    const ENGINE_CMD_DEFN *defns);
#endif
/* These functions allow control over any per-structure ENGINE data. */
#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Store application data on an ENGINE at an ex_data index.
 * @param e ENGINE whose CRYPTO_EX_DATA is updated.
 * @param idx Index previously obtained from ENGINE_get_ex_new_index().
 * @param arg Pointer to store at @p idx.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg);
/**
 * @brief Retrieve application data previously stored on an ENGINE.
 * @param e ENGINE to query.
 * @param idx Index previously obtained from ENGINE_get_ex_new_index().
 * @return Pointer stored at @p idx, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *ENGINE_get_ex_data(const ENGINE *e, int idx);
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/*
 * This function previously cleaned up anything that needs it. Auto-deinit will
 * now take care of it so it is no longer required to call this function.
 */
#define ENGINE_cleanup() \
    while (0)            \
    continue
#endif

/*
 * These return values from within the ENGINE structure. These can be useful
 * with functional references as well as structural references - it depends
 * which you obtained. Using the result for functional purposes if you only
 * obtained a structural reference may be problematic!
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the unique identifier string of an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return NUL-terminated id (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const char *ENGINE_get_id(const ENGINE *e);
/**
 * @brief Return the human-readable name string of an ENGINE.
 * @param e ENGINE to query.
 * @return NUL-terminated name, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const char *ENGINE_get_name(const ENGINE *e);
/**
 * @brief Return the RSA_METHOD currently attached to an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return RSA method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);
/**
 * @brief Return the DSA_METHOD currently attached to an ENGINE.
 * @param e ENGINE to query.
 * @return DSA method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e);
/**
 * @brief Return the EC_KEY_METHOD currently attached to an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return EC key method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *ENGINE_get_EC(const ENGINE *e);
/**
 * @brief Return the DH_METHOD currently attached to an ENGINE.
 * @param e ENGINE to query.
 * @return DH method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const DH_METHOD *ENGINE_get_DH(const ENGINE *e);
/**
 * @brief Return the RAND_METHOD implemented by an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return RAND method pointer, or NULL if @p e does not provide RAND.
 */
OSSL_DEPRECATEDIN_3_0 const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
/**
 * @brief Return the destroy callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Destroy function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e);
/**
 * @brief Return the init callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Init function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e);
/**
 * @brief Return the finish callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Finish function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);
/**
 * @brief Return the ctrl callback registered on an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return Ctrl function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);
/**
 * @brief Return the private-key loader callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Private-key loader, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e);
/**
 * @brief Return the public-key loader callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Public-key loader, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e);
/**
 * @brief Return the SSL client-certificate loader registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Client-cert loader callback, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function(const ENGINE *e);
/**
 * @brief Return the ciphers enumeration/lookup callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Ciphers callback, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_CIPHERS_PTR ENGINE_get_ciphers(const ENGINE *e);
/**
 * @brief Return the digests enumeration/lookup callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Digests callback, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE *e);
/**
 * @brief Return the EVP_PKEY_METHOD enumeration/lookup callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Pkey-methods callback, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_PKEY_METHS_PTR ENGINE_get_pkey_meths(const ENGINE *e);
/**
 * @brief Return the EVP_PKEY_ASN1_METHOD enumeration/lookup callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return ASN.1 pkey-methods callback, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_PKEY_ASN1_METHS_PTR ENGINE_get_pkey_asn1_meths(const ENGINE *e);
/**
 * @brief Return the EVP_CIPHER that @p e provides for algorithm @p nid.
 * @param e ENGINE whose ciphers handler is queried.
 * @param nid NID of the cipher algorithm to look up.
 * @return Matching EVP_CIPHER, or NULL if @p e does not implement @p nid.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid);
/**
 * @brief Return the EVP_MD that @p e provides for algorithm @p nid.
 * @param e ENGINE whose digests handler is queried.
 * @param nid NID of the digest algorithm to look up.
 * @return Matching EVP_MD, or NULL if @p e does not implement @p nid.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_MD *ENGINE_get_digest(ENGINE *e, int nid);
/**
 * @brief Return the EVP_PKEY_METHOD that @p e provides for algorithm @p nid.
 * @param e ENGINE whose pkey-method handler is queried.
 * @param nid NID of the public-key algorithm to look up.
 * @return Matching EVP_PKEY_METHOD, or NULL if @p e does not implement @p nid.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_METHOD *ENGINE_get_pkey_meth(ENGINE *e, int nid);
/**
 * @brief Return the EVP_PKEY_ASN1_METHOD that @p e provides for algorithm @p nid (deprecated).
 * @param e ENGINE whose ASN.1 pkey-method handler is queried.
 * @param nid NID of the public-key algorithm to look up.
 * @return Matching EVP_PKEY_ASN1_METHOD, or NULL if @p e does not implement @p nid.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth(ENGINE *e, int nid);
/**
 * @brief Look up an ENGINE's EVP_PKEY_ASN1_METHOD by PEM string name.
 * @param e ENGINE whose ASN.1 pkey methods are searched.
 * @param str PEM algorithm name to match (case-insensitive).
 * @param len Length of @p str in bytes, or -1 to use strlen(@p str).
 * @return Matching EVP_PKEY_ASN1_METHOD, or NULL if not found.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth_str(ENGINE *e,
    const char *str,
    int len);
/**
 * @brief Find an EVP_PKEY_ASN1_METHOD by PEM/string name across ENGINEs (deprecated).
 * @param pe Optional address that receives the ENGINE that provided the method (structurally referenced), or NULL.
 * @param str Method name bytes (not necessarily NUL-terminated).
 * @param len Length of @p str in bytes.
 * @return Matching ASN.1 method, or NULL if none is found.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe,
    const char *str, int len);
/**
 * @brief Return the control-command definition table registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Array of ENGINE_CMD_DEFN entries (typically terminated by a zero cmd_num), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e);
/**
 * @brief Return the behavioural flag mask stored on an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return Bitmask of ENGINE_FLAGS_* values currently set on @p e.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_get_flags(const ENGINE *e);
#endif

/*
 * FUNCTIONAL functions. These functions deal with ENGINE structures that
 * have (or will) be initialised for use. Broadly speaking, the structural
 * functions are useful for iterating the list of available engine types,
 * creating new engine types, and other "list" operations. These functions
 * actually deal with ENGINEs that are to be used. As such these functions
 * can fail (if applicable) when particular engines are unavailable - eg. if
 * a hardware accelerator is not attached or not functioning correctly. Each
 * ENGINE has 2 reference counts; structural and functional. Every time a
 * functional reference is obtained or released, a corresponding structural
 * reference is automatically obtained or released too.
 */

/*
 * Initialise an engine type for use (or up its reference count if it's
 * already in use). This will fail if the engine is not currently operational
 * and cannot initialise.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Initialise an ENGINE for functional use (deprecated).
 * @param e ENGINE to initialise; takes a functional reference on success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_init(ENGINE *e);
#endif
/*
 * Free a functional reference to an engine type. This does not require a
 * corresponding call to ENGINE_free as it also releases a structural
 * reference.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Release a functional reference obtained from ENGINE_init() or a get-default call.
 * @param e ENGINE whose functional (and implicit structural) reference is dropped.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_finish(ENGINE *e);
#endif

/*
 * The following functions handle keys that are stored in some secondary
 * location, handled by the engine.  The storage may be on a card or
 * whatever.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Load a private key from an ENGINE by key identifier (deprecated).
 * @param e Initialised ENGINE that implements key loading.
 * @param key_id ENGINE-specific key identifier string.
 * @param ui_method UI method for PIN/passphrase prompts, or NULL.
 * @param callback_data Application pointer passed to @p ui_method.
 * @return Loaded EVP_PKEY, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data);
/**
 * @brief Load a public key from storage managed by an ENGINE.
 * @param e Functional ENGINE reference that implements key loading.
 * @param key_id ENGINE-specific identifier of the key to load.
 * @param ui_method Optional UI method for PIN/passphrase prompts, or NULL.
 * @param callback_data Caller data forwarded to @p ui_method.
 * @return New EVP_PKEY on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data);
/**
 * @brief Load an SSL client certificate and key via an ENGINE (deprecated).
 * @param e Initialised ENGINE that implements SSL client-cert loading.
 * @param s SSL connection requesting a client certificate.
 * @param ca_dn Acceptable CA names from the server, or NULL.
 * @param pcert Receives the selected client certificate.
 * @param ppkey Receives the matching private key.
 * @param pother Optional stack receiving additional chain certificates, or NULL.
 * @param ui_method UI method for PIN/passphrase prompts, or NULL.
 * @param callback_data Application pointer passed to @p ui_method.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **ppkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method, void *callback_data);
#endif

/*
 * This returns a pointer for the current ENGINE structure that is (by
 * default) performing any RSA operations. The value returned is an
 * incremented reference, so it should be free'd (ENGINE_finish) before it is
 * discarded.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Obtain a functional reference to the default ENGINE for RSA operations.
 * @return Initialised ENGINE on success, or NULL if no default ENGINE is available.
 *
 * Release the reference with ENGINE_finish() when finished.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_default_RSA(void);
#endif
/* Same for the other "methods" */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Obtain a functional reference to the default ENGINE for DSA operations.
 * @return Initialised ENGINE on success, or NULL if no default ENGINE is available.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_default_DSA(void);
/**
 * @brief Obtain a functional reference to the default ENGINE for EC operations.
 * @return Initialised ENGINE on success, or NULL if no default ENGINE is available.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_default_EC(void);
/**
 * @brief Obtain a functional reference to the default ENGINE for DH operations.
 * @return Initialised ENGINE on success, or NULL if no default ENGINE is available.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_default_DH(void);
/**
 * @brief Obtain a functional reference to the default ENGINE for RAND operations.
 * @return Initialised ENGINE on success, or NULL if no default ENGINE is available.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_default_RAND(void);
#endif
/*
 * These functions can be used to get a functional reference to perform
 * ciphering or digesting corresponding to "nid".
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Obtain a functional reference to the default ENGINE implementing cipher @p nid.
 * @param nid NID of the EVP_CIPHER algorithm to look up.
 * @return Initialised ENGINE on success, or NULL if none is registered for @p nid.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_cipher_engine(int nid);
/**
 * @brief Obtain a functional reference to the default ENGINE implementing digest @p nid.
 * @param nid NID of the EVP_MD algorithm to look up.
 * @return Initialised ENGINE on success, or NULL if none is registered for @p nid.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_digest_engine(int nid);
/**
 * @brief Obtain a functional reference to the default ENGINE implementing pkey method @p nid (deprecated).
 * @param nid NID of the EVP_PKEY_METHOD to look up.
 * @return Initialised ENGINE on success, or NULL if none is registered for @p nid.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_pkey_meth_engine(int nid);
/**
 * @brief Obtain a functional reference to the default ENGINE implementing ASN.1 method @p nid.
 * @param nid NID of the EVP_PKEY_ASN1_METHOD to look up.
 * @return Initialised ENGINE on success, or NULL if none is registered for @p nid.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_pkey_asn1_meth_engine(int nid);
#endif

/**
 * @brief Register @p e as the default ENGINE for RSA operations.
 * @param e ENGINE to install as the RSA default; its structural reference
 *     count is incremented on success, so the caller must still free @p e.
 * @return 1 on success, or 0 on error.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register @p e as the default ENGINE for RSA operations (deprecated).
 * @param e ENGINE to install as the RSA default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RSA(ENGINE *e);
/**
 * @brief Set defaults for the method kinds named in a comma-separated list.
 * @param e ENGINE whose implementations become defaults for the listed kinds.
 * @param def_list Comma-separated names such as "RSA", "DSA", "DH", "RAND",
 *     "CIPHERS", "DIGESTS", "PKEY", "PKEY_CRYPTO", "PKEY_ASN1", or "ALL".
 * @return 1 on success, or 0 if the list is invalid or registration fails.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_string(ENGINE *e,
    const char *def_list);
#endif
/* Same for the other "methods" */
#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register @p e as the default ENGINE for DSA operations (deprecated).
 * @param e ENGINE to install as the DSA default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_DSA(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for EC operations (deprecated).
 * @param e ENGINE to install as the EC default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_EC(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for Diffie-Hellman operations.
 * @param e ENGINE to install as the DH default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_DH(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for RAND operations (deprecated).
 * @param e ENGINE to install as the RAND default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RAND(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for all cipher NIDs it implements (deprecated).
 * @param e ENGINE whose cipher implementations should become defaults.
 * @return Non-zero on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_ciphers(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for digest algorithms (deprecated).
 * @param e ENGINE to install as the digests default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_digests(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for EVP_PKEY methods.
 * @param e ENGINE to install as the default for public-key method tables.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_pkey_meths(ENGINE *e);
/**
 * @brief Register @p e as the default ENGINE for EVP_PKEY ASN.1 methods (deprecated).
 * @param e ENGINE to install as the pkey ASN.1-method default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_pkey_asn1_meths(ENGINE *e);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Register @p e as the default ENGINE for the method flags given.
 * @param e ENGINE to install as default for the selected method kinds.
 * @param flags Bitwise OR of ENGINE_METHOD_* selectors (e.g. ENGINE_METHOD_ALL).
 * @return 1 on success, or 0 on error.
 *
 * Prefer the selective ENGINE_set_default_* helpers when only a few method
 * kinds are needed, to avoid pulling unused static ENGINE code into the link.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default(ENGINE *e, unsigned int flags);
/**
 * @brief Register the built-in OpenSSL CONF module that loads ENGINE sections.
 *
 * After this call, configuration files may contain an [engines] module that
 * loads and configures ENGINE implementations at library init time.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_add_conf_module(void);
#endif

/* Deprecated functions ... */
/* int ENGINE_clear_defaults(void); */

/*--------------------------*/
/* DYNAMIC ENGINE SUPPORT   */
/*--------------------------*/

/* Binary/behaviour compatibility levels */
/** Version of the dynamic ENGINE ABI expected by this OpenSSL build. */
#define OSSL_DYNAMIC_VERSION (unsigned long)0x00030000
/*
 * Binary versions older than this are too old for us (whether we're a loader
 * or a loadee)
 */
#define OSSL_DYNAMIC_OLDEST (unsigned long)0x00030000

/*
 * When compiling an ENGINE entirely as an external shared library, loadable
 * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
 * structure type provides the calling application's (or library's) error
 * functionality and memory management function pointers to the loaded
 * library. These should be used/set in the loaded library code so that the
 * loading application's 'state' will be used/changed in all operations. The
 * 'static_state' pointer allows the loaded library to know if it shares the
 * same static data as the calling application (or library), and thus whether
 * these callbacks need to be set or not.
 */
/**
 * @brief Allocator callback supplied by the loading application to a dynamic ENGINE.
 * @param num Number of bytes to allocate.
 * @param file Source file name for leak tracking, or NULL.
 * @param line Source line for leak tracking.
 * @return Allocated memory, or NULL on failure.
 */
typedef void *(*dyn_MEM_malloc_fn)(size_t num, const char *file, int line);
/**
 * @brief Reallocator callback supplied by the loading application to a dynamic ENGINE.
 * @param ptr Existing allocation to resize, or NULL.
 * @param num New size in bytes.
 * @param file Source file name for leak tracking, or NULL.
 * @param line Source line for leak tracking.
 * @return Resized allocation, or NULL on failure.
 */
typedef void *(*dyn_MEM_realloc_fn)(void *ptr, size_t num, const char *file,
    int line);
/**
 * @brief Free callback supplied by the loading application to a dynamic ENGINE.
 * @param ptr Allocation to release.
 * @param file Source file name for leak tracking, or NULL.
 * @param line Source line for leak tracking.
 */
typedef void (*dyn_MEM_free_fn)(void *ptr, const char *file, int line);
/**
 * @brief Memory-management callbacks passed into a dynamically loaded ENGINE.
 */
typedef struct st_dynamic_MEM_fns {
    /** Allocator matching CRYPTO_malloc. */
    dyn_MEM_malloc_fn malloc_fn;
    /** Reallocator matching CRYPTO_realloc. */
    dyn_MEM_realloc_fn realloc_fn;
    /** Deallocator matching CRYPTO_free. */
    dyn_MEM_free_fn free_fn;
} dynamic_MEM_fns;
/*
 * FIXME: Perhaps the memory and locking code (crypto.h) should declare and
 * use these types so we (and any other dependent code) can simplify a bit??
 */
/**
 * @brief Callbacks and static-state cookie passed when binding a dynamic ENGINE.
 */
typedef struct st_dynamic_fns {
    /** Pointer comparing static data identity with ENGINE_get_static_state(). */
    void *static_state;
    /** Memory callbacks the loaded ENGINE should install if static data differs. */
    dynamic_MEM_fns mem_fns;
} dynamic_fns;

/**
 * @brief Version-check entry point expected from a dynamically loaded ENGINE.
 * @param ossl_version OSSL_DYNAMIC_VERSION of the loading OpenSSL/application.
 * @return 0 if the ENGINE rejects the loader version; otherwise the ENGINE's
 *     supported OSSL_DYNAMIC_VERSION (loader may still veto the load).
 *
 * Exported as the shared-library symbol @c v_check; IMPLEMENT_DYNAMIC_CHECK_FN()
 * provides a default implementation.
 */
typedef unsigned long (*dynamic_v_check_fn)(unsigned long ossl_version);
#define IMPLEMENT_DYNAMIC_CHECK_FN()                       \
    OPENSSL_EXPORT unsigned long v_check(unsigned long v); \
    OPENSSL_EXPORT unsigned long v_check(unsigned long v)  \
    {                                                      \
        if (v >= OSSL_DYNAMIC_OLDEST)                      \
            return OSSL_DYNAMIC_VERSION;                   \
        return 0;                                          \
    }

/**
 * @brief Bind entry point that populates an ENGINE loaded from a shared library.
 * @param e ENGINE structure to initialise; do not adjust structural/functional refs.
 * @param id Requested ENGINE id, or NULL to allow a default ENGINE from the library.
 * @param fns Loader callbacks (memory functions and static-state cookie).
 * @return Non-zero on success; 0 aborts the load, restores prior ENGINE state,
 *     and unloads the shared library (clean up internally on failure to avoid leaks).
 *
 * Exported as the shared-library symbol @c bind_engine.
 * IMPLEMENT_DYNAMIC_BIND_FN(fn) wraps a callback of type
 * @c int fn(ENGINE *e, const char *id).
 */
typedef int (*dynamic_bind_engine)(ENGINE *e, const char *id,
    const dynamic_fns *fns);
#define IMPLEMENT_DYNAMIC_BIND_FN(fn)                                   \
    OPENSSL_EXPORT                                                      \
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
    OPENSSL_EXPORT                                                      \
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)  \
    {                                                                   \
        if (ENGINE_get_static_state() == fns->static_state)             \
            goto skip_cbs;                                              \
        CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn,                \
            fns->mem_fns.realloc_fn,                                    \
            fns->mem_fns.free_fn);                                      \
        OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);              \
    skip_cbs:                                                           \
        if (!fn(e, id))                                                 \
            return 0;                                                   \
        return 1;                                                       \
    }

/**
 * @brief Return a pointer that identifies this process's OpenSSL static data for ENGINE loaders.
 * @return Opaque pointer comparing OPENSSL and ENGINE static-data instances across DLL boundaries.
 *
 * If the loader and ENGINE share the same libcrypto static data, callbacks need not be reset;
 * comparing this pointer detects whether separate copies exist (see OPENSSL_Applink on Windows).
 */
void *ENGINE_get_static_state(void);

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0 void ENGINE_setup_bsd_cryptodev(void);
#endif
#endif

#ifdef __cplusplus
}
#endif
#endif /* OPENSSL_NO_ENGINE */
#endif /* OPENSSL_ENGINE_H */
