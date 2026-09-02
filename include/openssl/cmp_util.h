/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMP_UTIL_H
#define OPENSSL_CMP_UTIL_H
#pragma once

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CMP

#include <openssl/macros.h>
#include <openssl/trace.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open the default CMP logging channel (stderr) if not already open.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CMP_log_open(void);
/**
 * @brief Flush pending CMP log output and release the default CMP logging channel.
 *
 * Safe to call multiple times; also invoked during OpenSSL shutdown.
 */
void OSSL_CMP_log_close(void);
#define OSSL_CMP_LOG_PREFIX "CMP "

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
/**
 * @brief Syslog-style severity level for CMP log messages (OSSL_CMP_LOG_*).
 */
typedef int OSSL_CMP_severity;
#define OSSL_CMP_LOG_EMERG 0
#define OSSL_CMP_LOG_ALERT 1
#define OSSL_CMP_LOG_CRIT 2
#define OSSL_CMP_LOG_ERR 3
#define OSSL_CMP_LOG_WARNING 4
#define OSSL_CMP_LOG_NOTICE 5
#define OSSL_CMP_LOG_INFO 6
#define OSSL_CMP_LOG_DEBUG 7
#define OSSL_CMP_LOG_TRACE 8
#define OSSL_CMP_LOG_MAX OSSL_CMP_LOG_TRACE
/**
 * @brief Callback type for CMP logging: receive component, source location, severity, and message.
 * @param func Component or function name, or NULL.
 * @param file Source file pathname, or NULL.
 * @param line Source line number, or 0 if unknown.
 * @param level Severity (OSSL_CMP_LOG_*).
 * @param msg NUL-terminated log line, typically ending with a newline.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*OSSL_CMP_log_cb_t)(const char *func, const char *file, int line,
    OSSL_CMP_severity level, const char *msg);

/**
 * @brief Format a CMP log record (component, location, severity, message) onto a BIO.
 * @param bio Destination BIO.
 * @param component Function or module name; if NULL/empty/"(unknown function)", "CMP" is used.
 * @param file Source file pathname, or NULL.
 * @param line Source line number, or 0 if unknown.
 * @param level Severity (OSSL_CMP_LOG_*).
 * @param msg NUL-terminated message text.
 * @return 1 on success, or 0 on write failure.
 */
int OSSL_CMP_print_to_bio(BIO *bio, const char *component, const char *file,
    int line, OSSL_CMP_severity level, const char *msg);
/**
 * @brief Print the OpenSSL error queue via a CMP logging callback.
 * @param log_fn Callback invoked for each error-queue entry; if NULL, errors go to stderr via the default CMP logger.
 */
void OSSL_CMP_print_errors_cb(OSSL_CMP_log_cb_t log_fn);

#ifdef __cplusplus
}
#endif
#endif /* !defined(OPENSSL_NO_CMP) */
#endif /* !defined(OPENSSL_CMP_UTIL_H) */
