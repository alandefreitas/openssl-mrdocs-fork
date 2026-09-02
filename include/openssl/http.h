/*
 * Copyright 2000-2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2018-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HTTP_H
#define OPENSSL_HTTP_H
#pragma once

#include <openssl/opensslconf.h>

#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/conf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSSL_HTTP_NAME "http"
#define OSSL_HTTPS_NAME "https"
#define OSSL_HTTP_PREFIX OSSL_HTTP_NAME "://"
#define OSSL_HTTPS_PREFIX OSSL_HTTPS_NAME "://"
#define OSSL_HTTP_PORT "80"
#define OSSL_HTTPS_PORT "443"
#define OPENSSL_NO_PROXY "NO_PROXY"
#define OPENSSL_HTTP_PROXY "HTTP_PROXY"
#define OPENSSL_HTTPS_PROXY "HTTPS_PROXY"

#ifndef OPENSSL_NO_HTTP

#define OSSL_HTTP_DEFAULT_MAX_LINE_LEN (4 * 1024)
#define OSSL_HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)
#define OSSL_HTTP_DEFAULT_MAX_CRL_LEN (32 * 1024 * 1024)
#define OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES 256

/* Low-level HTTP API */
/**
 * @brief Allocate a low-level HTTP request context bound to write and read BIOs.
 * @param wbio BIO used to send the request (may equal @p rbio).
 * @param rbio BIO used to receive the response (may equal @p wbio).
 * @param buf_size Max response header line length and read chunk size; <= 0 uses OSSL_HTTP_DEFAULT_MAX_LINE_LEN.
 * @return New request context including an internal memory BIO for headers, or NULL on failure.
 */
OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int buf_size);
/**
 * @brief Free an HTTP request context and its owned BIO/state.
 * @param rctx Context to free, or NULL.
 */
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
/**
 * @brief Set the first HTTP request line (method and request-target) on @p rctx.
 * @param rctx Request context to update.
 * @param method_POST Nonzero for POST; zero for GET.
 * @param server Optional origin host an HTTP proxy should forward to, or NULL.
 * @param port Optional origin port for proxy forwarding, or NULL.
 * @param path Request path (NULL means "/"); may be an absolute http:// URI for proxy use (then @p server/@p port must be NULL).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX *rctx, int method_POST,
    const char *server, const char *port,
    const char *path);
/**
 * @brief Append an HTTP request header name/value pair to an HTTP request context.
 * @param rctx Request context previously created with OSSL_HTTP_REQ_CTX_new().
 * @param name Header field name (for example "Content-Type").
 * @param value Header field value, or NULL to send a header with an empty value.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX *rctx,
    const char *name, const char *value);
/**
 * @brief Configure response Content-Type, ASN.1, timeout, and keep-alive expectations on @p rctx.
 * @param rctx Request context; call before OSSL_HTTP_REQ_CTX_set1_req() when @p keep_alive is nonzero.
 * @param content_type Required response Content-Type (exact or prefix before ';'), or NULL to accept any.
 * @param asn1 Nonzero if the body must be ASN.1 DER (disables streaming; use the memory BIO).
 * @param timeout Soft transfer timeout in seconds (>0 limited; 0 wait forever; <0 keep prior/open default).
 * @param keep_alive 0 close after response; 1 request persistence; 2 require persistence or fail.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set_expected(OSSL_HTTP_REQ_CTX *rctx,
    const char *content_type, int asn1,
    int timeout, int keep_alive);
/**
 * @brief Finalize the request by attaching an ASN.1 DER body and Content-Type/Length headers.
 * @param rctx Request context prepared with OSSL_HTTP_REQ_CTX_set_request_line() (and keep-alive expectations if needed).
 * @param content_type Content-Type header value; must be NULL when @p req is NULL.
 * @param it ASN.1 item template used to encode @p req (DER; not streaming).
 * @param req ASN.1 value to send as the body, or NULL for a body-less (for example GET) request when keep-alive still needs finalization.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_REQ_CTX_set1_req(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
    const ASN1_ITEM *it, const ASN1_VALUE *req);
/**
 * @brief Continue a non-blocking HTTP request/response exchange on @p rctx.
 * @param rctx Request context previously prepared with headers/body.
 * @return 1 when the exchange completed, -1 when more I/O is needed, or 0 on error.
 */
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
/**
 * @brief Exchange an HTTP request non-blockingly and decode the response body as ASN.1.
 * @param rctx Request context prepared with headers/body; may need multiple calls when BIOs would block.
 * @param pval Destination for the decoded ASN.1 value (type described by @p it).
 * @param it ASN.1 item descriptor used to decode the HTTP response body.
 * @return 1 on completion with success, 0 on failure, or -1 if the I/O would block (retry later).
 */
int OSSL_HTTP_REQ_CTX_nbio_d2i(OSSL_HTTP_REQ_CTX *rctx,
    ASN1_VALUE **pval, const ASN1_ITEM *it);
/**
 * @brief Exchange the prepared HTTP request and response, retrying non-blocking I/O until done or timeout.
 * @param rctx Request context with BIOs and headers/body configured.
 * @return BIO positioned at the response body (memory BIO for expected ASN.1, else @p rbio); do not free; NULL on failure.
 */
BIO *OSSL_HTTP_REQ_CTX_exchange(OSSL_HTTP_REQ_CTX *rctx);
/**
 * @brief Return the internal memory BIO that accumulates the HTTP request headers for @p rctx.
 * @param rctx Request context previously created with OSSL_HTTP_REQ_CTX_new().
 * @return Memory BIO owned by @p rctx (do not free), or NULL if unavailable.
 */
BIO *OSSL_HTTP_REQ_CTX_get0_mem_bio(const OSSL_HTTP_REQ_CTX *rctx);
/**
 * @brief Return the number of response body bytes accumulated so far.
 * @param rctx HTTP request context that has been exchanging data.
 * @return Current response length in bytes.
 */
size_t OSSL_HTTP_REQ_CTX_get_resp_len(const OSSL_HTTP_REQ_CTX *rctx);
/**
 * @brief Cap the maximum HTTP response body length accepted by @p rctx.
 * @param rctx HTTP request context.
 * @param len Maximum response length in bytes (0 may restore the implementation default).
 */
void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
    unsigned long len);
/**
 * @brief Test whether an HTTP request context still has a keep-alive connection.
 * @param rctx Request context from a prior OSSL_HTTP_open() / exchange, or NULL.
 * @return 1 if @p rctx is non-NULL and keep-alive is active, or 0 otherwise.
 */
int OSSL_HTTP_is_alive(const OSSL_HTTP_REQ_CTX *rctx);

/* High-level HTTP API */
/**
 * @brief Optional callback that updates or replaces the HTTP connection BIO around connect/TLS.
 * @param bio Current connection BIO (may be NULL before connect).
 * @param arg User pointer supplied to OSSL_HTTP_open().
 * @param connect Non-zero when establishing the connection; zero when disconnecting.
 * @param detail Non-zero to request detailed error reporting from the callback.
 * @return BIO to use for subsequent HTTP I/O, or NULL on failure.
 */
typedef BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail);
/**
 * @brief Open an HTTP (or HTTPS) connection and allocate a request context.
 * @param server Hostname or address of the HTTP server.
 * @param port Port string, or NULL for the default (80/443).
 * @param proxy Optional HTTP proxy host, or NULL.
 * @param no_proxy Optional comma-separated bypass list, or NULL.
 * @param use_ssl Non-zero to use TLS (HTTPS).
 * @param bio Optional pre-existing write BIO, or NULL to create one.
 * @param rbio Optional separate read BIO, or NULL to use @p bio for both.
 * @param bio_update_fn Optional connect/disconnect BIO callback, or NULL.
 * @param arg User pointer passed to @p bio_update_fn.
 * @param buf_size I/O buffer size hint (0 for default).
 * @param overall_timeout Overall transfer timeout in seconds (0 for default/none).
 * @return New OSSL_HTTP_REQ_CTX, or NULL on failure; free with OSSL_HTTP_REQ_CTX_free().
 */
OSSL_HTTP_REQ_CTX *OSSL_HTTP_open(const char *server, const char *port,
    const char *proxy, const char *no_proxy,
    int use_ssl, BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, int overall_timeout);
/**
 * @brief Perform an HTTP CONNECT through a proxy on an already-connected BIO.
 * @param bio BIO connected to the HTTP proxy; on success becomes a tunnel to @p server:@p port.
 * @param server Target hostname to CONNECT to.
 * @param port Target port (decimal string) or service name.
 * @param proxyuser Optional proxy username for Basic auth, or NULL.
 * @param proxypass Optional proxy password for Basic auth, or NULL.
 * @param timeout Overall timeout in seconds (0 for none / BIO default).
 * @param bio_err Optional BIO for diagnostic output, or NULL.
 * @param prog Optional program name prefix for diagnostics, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
    const char *proxyuser, const char *proxypass,
    int timeout, BIO *bio_err, const char *prog);
/**
 * @brief Configure the HTTP request path, headers, body, and response expectations on @p rctx.
 * @param rctx HTTP request context previously created with OSSL_HTTP_open() or OSSL_HTTP_REQ_CTX_new().
 * @param path Request-URI path (or absolute http:// URI for a proxy); NULL defaults to "/".
 * @param headers Optional additional request headers, or NULL.
 * @param content_type Content-Type for @p req when a body is present, or NULL.
 * @param req Optional BIO holding the request body, or NULL for a GET-style request without a body.
 * @param expected_content_type Expected response Content-Type, or NULL to accept any.
 * @param expect_asn1 Nonzero if the response body should be treated as ASN.1 DER.
 * @param max_resp_len Maximum accepted response length in bytes.
 * @param timeout Overall soft timeout in seconds for the exchange (<= 0 means none / keep previous).
 * @param keep_alive Keep-alive preference (0 off, 1 on, 2 prefer and fail if unavailable).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_HTTP_set1_request(OSSL_HTTP_REQ_CTX *rctx, const char *path,
    const STACK_OF(CONF_VALUE) *headers,
    const char *content_type, BIO *req,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout, int keep_alive);
/**
 * @brief Perform the HTTP exchange and return a BIO of the response body.
 * @param rctx Request context prepared with method, headers, and optional request body.
 * @param redirection_url Optional receiver for an allocated redirect URL on 3xx, or NULL.
 * @return Memory BIO containing the response body, or NULL on failure; free with BIO_free().
 */
BIO *OSSL_HTTP_exchange(OSSL_HTTP_REQ_CTX *rctx, char **redirection_url);
/**
 * @brief Perform an HTTP GET and return a memory BIO holding the response body.
 * @param url Absolute http:// or https:// URL to fetch.
 * @param proxy Optional HTTP(S) proxy URL/host, or NULL to use environment defaults.
 * @param no_proxy Optional host exclusion list, or NULL for environment defaults.
 * @param bio Optional write BIO; NULL builds an internal connect BIO from @p url.
 * @param rbio Optional read BIO paired with @p bio when both are non-NULL.
 * @param bio_update_fn Optional connect/TLS BIO callback (needed for https when @p bio is NULL).
 * @param arg Opaque argument forwarded to @p bio_update_fn.
 * @param buf_size Max header line length / read chunk; <= 0 uses the default.
 * @param headers Optional additional request headers, or NULL.
 * @param expected_content_type Required Content-Type (exact or prefix), or NULL for any.
 * @param expect_asn1 Nonzero if the body must be ASN.1 DER.
 * @param max_resp_len Maximum accepted response body length in bytes; 0 means unlimited.
 * @param timeout Soft transfer timeout in seconds (<= 0 waits indefinitely where supported).
 * @return Memory BIO with the response body on success (caller frees), or NULL on failure.
 */
BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout);
/**
 * @brief Open (or reuse), send one HTTP request, receive the response, and optionally keep the connection.
 * @param prctx Optional address of an OSSL_HTTP_REQ_CTX*; reuses *@p prctx when non-NULL, else opens; may be set to NULL when closed.
 * @param server Hostname or address to contact when opening a new connection.
 * @param port Service port, or NULL for the default (80/443).
 * @param path Request path (or absolute URI for a proxy).
 * @param use_ssl Nonzero to use HTTPS (requires @p bio_update_fn when opening via sockets).
 * @param proxy Optional HTTP(S) proxy, or NULL to consult environment defaults.
 * @param no_proxy Optional comma/whitespace host exclusion list, or NULL for environment defaults.
 * @param bio Optional write BIO; NULL builds an internal connect BIO from @p server/@p port.
 * @param rbio Optional read BIO used with @p bio when both are non-NULL (no auto-connect).
 * @param bio_update_fn Optional connect/disconnect BIO callback (required for TLS when @p bio is NULL).
 * @param arg Callback argument for @p bio_update_fn (not consumed).
 * @param buf_size Max header line length / read chunk; <= 0 uses the default.
 * @param headers Optional additional request headers, or NULL.
 * @param content_type Content-Type for @p req, or NULL.
 * @param req Optional request-body BIO, or NULL for a GET-style exchange.
 * @param expected_content_type Expected response Content-Type, or NULL.
 * @param expect_asn1 Nonzero if the response body should be treated as ASN.1 DER.
 * @param max_resp_len Maximum accepted response length in bytes.
 * @param timeout Soft overall timeout in seconds for this exchange.
 * @param keep_alive Keep-alive preference (0/1/2 as for OSSL_HTTP_set1_request()).
 * @return Response-body BIO owned by the caller (free with BIO_free*), or NULL on failure.
 */
BIO *OSSL_HTTP_transfer(OSSL_HTTP_REQ_CTX **prctx,
    const char *server, const char *port,
    const char *path, int use_ssl,
    const char *proxy, const char *no_proxy,
    BIO *bio, BIO *rbio,
    OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
    int buf_size, const STACK_OF(CONF_VALUE) *headers,
    const char *content_type, BIO *req,
    const char *expected_content_type, int expect_asn1,
    size_t max_resp_len, int timeout, int keep_alive);
/**
 * @brief Close the HTTP connection and free the request context.
 * @param rctx Context from OSSL_HTTP_open()/OSSL_HTTP_transfer(); may be NULL.
 * @param ok 1 if the transfer succeeded (passed to any BIO update callback), or 0 on error.
 * @return 1 if disconnect completed cleanly, or 0 if anything went wrong while closing.
 */
int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX *rctx, int ok);

/* Auxiliary functions */
/**
 * @brief Parse @p url into allocated scheme/user/host/port/path/query/fragment components.
 * @param url URL string to parse.
 * @param pscheme Receives allocated scheme (for example "https"), or NULL to skip.
 * @param puser Receives allocated userinfo, or NULL to skip.
 * @param phost Receives allocated host, or NULL to skip.
 * @param pport Receives allocated port string, or NULL to skip.
 * @param pport_num Receives numeric port, or NULL to skip.
 * @param ppath Receives allocated path (at least "/"), or NULL to skip.
 * @param pquery Receives allocated query without leading '?', or NULL to skip.
 * @param pfrag Receives allocated fragment without leading '#', or NULL to skip.
 * @return 1 on success, or 0 on failure; free each returned string with OPENSSL_free().
 */
int OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
/**
 * @brief Parse an http or https URL into allocated component strings.
 * @param url URL of the form [http[s]://][userinfo@]host[:port][/path][?query][#fragment].
 * @param pssl Optional; set to 1 if the scheme is https, else 0.
 * @param puser Optional out for userinfo (empty string if absent); free with OPENSSL_free.
 * @param phost Optional out for host (IPv6 enclosed in brackets); free with OPENSSL_free.
 * @param pport Optional out for port string (defaults "80"/"443"); free with OPENSSL_free.
 * @param pport_num Optional out for the numeric port.
 * @param ppath Optional out for path (always begins with '/'); free with OPENSSL_free.
 * @param pquery Optional out for query (empty if absent); free with OPENSSL_free.
 * @param pfrag Optional out for fragment (empty if absent); free with OPENSSL_free.
 * @return 1 on success, or 0 on error.
 */
int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
    char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);
/**
 * @brief Choose an HTTP(S) proxy string, applying no_proxy exclusions and environment defaults.
 * @param proxy Explicit proxy hostname, or NULL to use http_proxy/HTTP_PROXY (or https variants when @p use_ssl).
 * @param no_proxy Exclusion list (comma/whitespace), or NULL to use no_proxy/NO_PROXY.
 * @param server Destination host; if listed in the exclusion set, no proxy is used.
 * @param use_ssl Nonzero selects HTTPS proxy environment variables when @p proxy is NULL.
 * @return Constant proxy hostname string to use, or NULL when no proxy should be used.
 */
const char *OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
    const char *server, int use_ssl);

/**
 * @brief Limit how many HTTP response header lines @p rctx will accept.
 * @param rctx Request context to update.
 * @param count Maximum header lines (0 means unlimited / implementation default).
 */
void OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(OSSL_HTTP_REQ_CTX *rctx,
    size_t count);

#endif /* !defined(OPENSSL_NO_HTTP) */
#ifdef __cplusplus
}
#endif
#endif /* !defined(OPENSSL_HTTP_H) */
