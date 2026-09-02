#!/usr/bin/env python3
"""Documentation repair batch 7c: ssl, tls1, types, x509, x509_vfy + mrdocs exclude."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


def patch_both(rel, old, new, label):
    paths = [INC / rel]
    if not rel.endswith(".in"):
        paths.append(INC / (rel + ".in"))
    found = False
    for path in paths:
        if not path.exists():
            continue
        found = True
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"  MISS: {path.name} :: {label}")
            missing.append(f"{path.name}:{label}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    if not found:
        missing.append(f"{rel}:{label}:no-file")


def asn1_funcs(typename, brief):
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {typename}, or NULL on allocation failure.
 */
{typename} *{typename}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {typename}_free({typename} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {typename}, or NULL on error.
 */
{typename} *d2i_{typename}({typename} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{typename}(const {typename} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {typename}.
 * @return Pointer to the static ASN1_ITEM for {typename}.
 */
const ASN1_ITEM *{typename}_it(void);"""


# ----- types.h -----
patch_both("types.h",
"typedef struct asn1_type_st ASN1_TYPE;",
"""/**
 * @brief ASN.1 ANY / CHOICE container holding a typed value and its V_ASN1_* tag.
 */
typedef struct asn1_type_st ASN1_TYPE;""",
"ASN1_TYPE")

patch_both("types.h",
"typedef struct evp_cipher_st EVP_CIPHER;",
"""/**
 * @brief Opaque symmetric cipher method (algorithm implementation) used with EVP_CIPHER_CTX.
 */
typedef struct evp_cipher_st EVP_CIPHER;""",
"EVP_CIPHER")

patch_both("types.h",
"typedef struct evp_rand_st EVP_RAND;",
"""/**
 * @brief Opaque random-number generator method fetched from a provider (DRBG and related).
 */
typedef struct evp_rand_st EVP_RAND;""",
"EVP_RAND")

patch_both("types.h",
"""#ifndef OPENSSL_NO_DEPRECATED_3_0
typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
#endif""",
"""#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Opaque RSA key object (deprecated; prefer EVP_PKEY).
 */
typedef struct rsa_st RSA;
/**
 * @brief Opaque RSA method table for ENGINE-style RSA implementations (deprecated).
 */
typedef struct rsa_meth_st RSA_METHOD;
#endif""",
"RSA_RSA_METHOD")

# ----- tls1.h -----
patch_both("tls1.h",
"int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);",
"""/**
 * @brief Set the maximum fragment length mode advertised by an SSL context (RFC 6066).
 * @param ctx SSL context to configure.
 * @param mode TLSEXT_max_fragment_length_* constant, or TLSEXT_max_fragment_length_DISABLED.
 * @return 1 on success, or 0 if @p mode is invalid.
 */
int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);""",
"SSL_CTX_set_tlsext_max_fragment_length")

patch_both("tls1.h",
"""struct tls_session_ticket_ext_st {
    unsigned short length;
    void *data;
};""",
"""struct tls_session_ticket_ext_st {
    /** Length in bytes of the ticket extension payload at @c data. */
    unsigned short length;
    /** Opaque session-ticket extension bytes of length @c length. */
    void *data;
};""",
"tls_session_ticket_ext_st::data")

# ----- ssl.h (typedefs / callbacks / early APIs) -----
patch_both("ssl.h",
"typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;",
"""/**
 * @brief TLS session-ticket extension payload (length plus opaque data bytes).
 */
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;""",
"TLS_SESSION_TICKET_EXT")

patch_both("ssl.h",
"typedef struct ssl_conf_ctx_st SSL_CONF_CTX;",
"""/**
 * @brief Opaque configuration context used with the SSL_CONF_* command API.
 */
typedef struct ssl_conf_ctx_st SSL_CONF_CTX;""",
"SSL_CONF_CTX")

patch_both("ssl.h",
"""typedef int (*SSL_custom_ext_add_cb_ex)(SSL *s, unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *add_arg);""",
"""/**
 * @brief Callback that supplies the contents of a custom TLS extension being sent.
 * @param s SSL connection constructing the extension.
 * @param ext_type TLS extension type code.
 * @param context Bitmask identifying the message and role (SSL_EXT_*).
 * @param out Set to point at the extension payload bytes to send.
 * @param outlen Receives the length of *@p out.
 * @param x Certificate associated with this extension when relevant, or NULL.
 * @param chainidx Index of @p x in the certificate chain when applicable.
 * @param al Set to a TLS alert code on failure.
 * @param add_arg User argument from SSL_CTX_add_custom_ext.
 * @return 1 to include the extension, 0 to omit it, or -1 to abort with *@p al.
 */
typedef int (*SSL_custom_ext_add_cb_ex)(SSL *s, unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *add_arg);""",
"SSL_custom_ext_add_cb_ex")

patch_both("ssl.h",
"""OSSL_DEPRECATEDIN_3_0 __owur int SSL_srp_server_param_with_username(SSL *s,
    int *ad);""",
"""/**
 * @brief Finish server-side SRP parameter setup after the username is known (deprecated).
 * @param s Server SSL connection negotiating SRP.
 * @param ad Receives a TLS alert description if the call fails.
 * @return SSL_ERROR_NONE on success, or an SSL error code / alert-triggering status.
 */
OSSL_DEPRECATEDIN_3_0 __owur int SSL_srp_server_param_with_username(SSL *s,
    int *ad);""",
"SSL_srp_server_param_with_username")

patch_both("ssl.h",
"""SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl,
    const unsigned char *data,
    int len, int *copy);""",
"""/**
 * @brief Return the external session-cache lookup callback installed on an SSL_CTX.
 * @param ctx SSL context to query.
 * @return Session get callback, or NULL if none is set.
 */
SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl,
    const unsigned char *data,
    int len, int *copy);""",
"SSL_CTX_sess_get_get_cb")

patch_both("ssl.h",
"""typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
    const unsigned char **out,
    unsigned int *outlen,
    void *arg);""",
"""/**
 * @brief NPN server callback that advertises the server's protocol list.
 * @param ssl Server SSL connection performing NPN.
 * @param out Set to the wire-format protocol list to advertise.
 * @param outlen Receives the length of *@p out.
 * @param arg User argument from SSL_CTX_set_next_protos_advertised_cb.
 * @return SSL_TLSEXT_ERR_OK to send the list, or another SSL_TLSEXT_ERR_* code.
 */
typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
    const unsigned char **out,
    unsigned int *outlen,
    void *arg);""",
"SSL_CTX_npn_advertised_cb_func")

patch_both("ssl.h",
"""__owur int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
    unsigned int protos_len);""",
"""/**
 * @brief Set the ALPN protocol list advertised or offered by an SSL context.
 * @param ctx SSL context to configure.
 * @param protos Wire-format protocol list (length-prefixed names); empty clears ALPN.
 * @param protos_len Length of @p protos in bytes.
 * @return 0 on success, or non-zero on failure (inverted success convention).
 */
__owur int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
    unsigned int protos_len);""",
"SSL_CTX_set_alpn_protos")

patch_both("ssl.h",
"""typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
    const char *identity,
    unsigned char *psk,
    unsigned int max_psk_len);""",
"""/**
 * @brief PSK server callback that supplies the pre-shared key for a client identity.
 * @param ssl Server SSL connection negotiating PSK.
 * @param identity NUL-terminated PSK identity from the client, or NULL.
 * @param psk Buffer receiving up to @p max_psk_len key bytes.
 * @param max_psk_len Capacity of @p psk in bytes.
 * @return Length of the key written to @p psk, or 0 to abort the handshake.
 */
typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
    const char *identity,
    unsigned char *psk,
    unsigned int max_psk_len);""",
"SSL_psk_server_cb_func")

patch_both("ssl.h",
"void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb);",
"""/**
 * @brief Set the PSK identity callback used by server SSL objects from a context.
 * @param ctx SSL context whose default server PSK callback is set.
 * @param cb Callback that supplies the PSK for a given identity, or NULL to clear.
 */
void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb);""",
"SSL_CTX_set_psk_server_callback")

patch_both("ssl.h",
"""void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx,
    SSL_psk_use_session_cb_func cb);""",
"""/**
 * @brief Set the PSK use-session callback for client SSL objects from a context.
 * @param ctx SSL context whose default PSK use-session callback is set.
 * @param cb Callback that supplies identity and SSL_SESSION for the PSK, or NULL to clear.
 */
void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx,
    SSL_psk_use_session_cb_func cb);""",
"SSL_CTX_set_psk_use_session_callback")

patch_both("ssl.h",
"__owur int SSL_extension_supported(unsigned int ext_type);",
"""/**
 * @brief Report whether OpenSSL has built-in handling for a TLS extension type.
 * @param ext_type TLS extension type code.
 * @return 1 if the extension is known/handled internally, or 0 otherwise.
 */
__owur int SSL_extension_supported(unsigned int ext_type);""",
"SSL_extension_supported")

patch_both("ssl.h",
"""typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);""",
"""/**
 * @brief Callback that logs a single line of TLS key material for debugging.
 * @param ssl SSL connection whose keys are being logged.
 * @param line NUL-terminated key-log line (without trailing newline).
 */
typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);""",
"SSL_CTX_keylog_cb_func")

patch_both("ssl.h",
"""typedef enum {
    TLS_ST_BEFORE,""",
"""typedef enum {
    /** @brief No handshake has been initiated yet. */
    TLS_ST_BEFORE,""",
"TLS_ST_BEFORE")

patch_both("ssl.h",
"size_t SSL_get_finished(const SSL *s, void *buf, size_t count);",
"""/**
 * @brief Copy up to @p count bytes of the local Finished message into @p buf.
 * @param s SSL connection whose handshake Finished is queried.
 * @param buf Destination buffer, or NULL to only query the Finished length.
 * @param count Maximum number of bytes to copy into @p buf.
 * @return Actual Finished length in bytes (may exceed @p count).
 */
size_t SSL_get_finished(const SSL *s, void *buf, size_t count);""",
"SSL_get_finished")

patch_both("ssl.h",
"__owur SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);",
"""/**
 * @brief Create a new SSL_CTX for connections using method @p meth.
 * @param meth Connection method such as TLS_method() or DTLS_method().
 * @return New SSL_CTX, or NULL on failure; free with SSL_CTX_free.
 */
__owur SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);""",
"SSL_CTX_new")

patch_both("ssl.h",
"int SSL_CTX_up_ref(SSL_CTX *ctx);",
"""/**
 * @brief Increment the reference count on an SSL_CTX.
 * @param ctx Context to retain.
 * @return 1 on success, or 0 on failure.
 */
int SSL_CTX_up_ref(SSL_CTX *ctx);""",
"SSL_CTX_up_ref")

patch_both("ssl.h",
"__owur X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);",
"""/**
 * @brief Return the certificate verification store associated with an SSL_CTX.
 * @param ctx SSL context to query.
 * @return Internal X509_STORE pointer (do not free), or NULL if unset.
 */
__owur X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);""",
"SSL_CTX_get_cert_store")

patch_both("ssl.h",
"__owur int SSL_get_rfd(const SSL *s);",
"""/**
 * @brief Return the file descriptor linked to an SSL object's read BIO.
 * @param s SSL connection to query.
 * @return Read-side file descriptor >= 0, or -1 if the read BIO is not fd-based.
 */
__owur int SSL_get_rfd(const SSL *s);""",
"SSL_get_rfd")

patch_both("ssl.h",
"__owur int SSL_get_read_ahead(const SSL *s);",
"""/**
 * @brief Report whether an SSL connection will read ahead on its underlying BIO.
 * @param s SSL connection to query.
 * @return Non-zero if read-ahead is enabled, or 0 otherwise.
 */
__owur int SSL_get_read_ahead(const SSL *s);""",
"SSL_get_read_ahead")

patch_both("ssl.h",
"void SSL_set0_rbio(SSL *s, BIO *rbio);",
"""/**
 * @brief Set the read BIO for an SSL connection, transferring ownership of @p rbio.
 * @param s SSL connection whose read channel is replaced; any previous read BIO is freed.
 * @param rbio BIO used for reading encrypted records; freed when @p s is freed.
 */
void SSL_set0_rbio(SSL *s, BIO *rbio);""",
"SSL_set0_rbio")

patch_both("ssl.h",
"__owur int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);",
"""/**
 * @brief Set the TLSv1.3 ciphersuite list for an SSL context.
 * @param ctx SSL context to configure.
 * @param str Colon-separated list of TLSv1.3 ciphersuite names.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);""",
"SSL_CTX_set_ciphersuites")

patch_both("ssl.h",
"""__owur int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
    STACK_OF(X509) *chain, int override);""",
"""/**
 * @brief Configure an SSL object's certificate, private key, and optional chain.
 * @param ssl SSL connection to update.
 * @param x509 End-entity certificate; reference count is incremented on success.
 * @param privatekey Matching private key; reference count is incremented on success.
 * @param chain Optional intermediate certificates, or NULL.
 * @param override Non-zero to replace an existing cert/key even if already set.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
    STACK_OF(X509) *chain, int override);""",
"SSL_use_cert_and_key")

patch_both("ssl.h",
"""__owur int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file,
    int type);""",
"""/**
 * @brief Load a certificate from a file into an SSL context.
 * @param ctx SSL context that receives the certificate.
 * @param file Path to a PEM or ASN.1 certificate file.
 * @param type Encoding: SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file,
    int type);""",
"SSL_CTX_use_certificate_file")

patch_both("ssl.h",
"""int SSL_add_store_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
    const char *uri);""",
"""/**
 * @brief Load certificate subjects from an OSSL_STORE URI into a name stack.
 * @param stackCAs Destination stack of X509_NAME subject names.
 * @param uri OSSL_STORE URI identifying a directory, file, or other cert collection.
 * @return 1 on success, or 0 on failure.
 */
int SSL_add_store_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
    const char *uri);""",
"SSL_add_store_cert_subjects_to_stack")

patch_both("ssl.h",
"__owur long SSL_SESSION_set_time(SSL_SESSION *s, long t);",
"""/**
 * @brief Set the creation time of an SSL_SESSION (seconds since the Unix epoch).
 * @param s Session to update.
 * @param t New session timestamp.
 * @return 1 on success.
 */
__owur long SSL_SESSION_set_time(SSL_SESSION *s, long t);""",
"SSL_SESSION_set_time")

patch_both("ssl.h",
"""__owur int SSL_SESSION_set_max_early_data(SSL_SESSION *s,
    uint32_t max_early_data);""",
"""/**
 * @brief Set the maximum early-data (0-RTT) size advertised for a session.
 * @param s Session to update.
 * @param max_early_data Maximum early-data bytes allowed when resuming @p s.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_SESSION_set_max_early_data(SSL_SESSION *s,
    uint32_t max_early_data);""",
"SSL_SESSION_set_max_early_data")

patch_both("ssl.h",
"__owur int SSL_SESSION_is_resumable(const SSL_SESSION *s);",
"""/**
 * @brief Report whether a session may be used for resumption / PSK.
 * @param s Session to query.
 * @return 1 if the session is resumable, or 0 otherwise.
 */
__owur int SSL_SESSION_is_resumable(const SSL_SESSION *s);""",
"SSL_SESSION_is_resumable")

patch_both("ssl.h",
"""const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *s,
    unsigned int *len);""",
"""/**
 * @brief Return the session-id context bytes associated with a session.
 * @param s Session to query.
 * @param len If non-NULL, receives the context length in bytes.
 * @return Pointer to the internal context bytes (do not free), or NULL if unset.
 */
const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *s,
    unsigned int *len);""",
"SSL_SESSION_get0_id_context")

patch_both("ssl.h",
"__owur int SSL_set_session(SSL *to, SSL_SESSION *session);",
"""/**
 * @brief Attach a session to an SSL object for client-side resumption.
 * @param to SSL connection that will offer @p session.
 * @param session Session to resume; reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_session(SSL *to, SSL_SESSION *session);""",
"SSL_set_session")

patch_both("ssl.h",
"int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *session);",
"""/**
 * @brief Add a session to an SSL context's internal session cache.
 * @param ctx SSL context whose cache receives @p session.
 * @param session Session to cache; reference count is incremented on success.
 * @return 1 on success, or 0 if the session was already present or on error.
 */
int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *session);""",
"SSL_CTX_add_session")

patch_both("ssl.h",
"""SSL_SESSION *d2i_SSL_SESSION_ex(SSL_SESSION **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Decode an SSL_SESSION from DER with an explicit library context.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded value.
 * @param length Number of bytes available at *@p pp.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded SSL_SESSION, or NULL on error.
 */
SSL_SESSION *d2i_SSL_SESSION_ex(SSL_SESSION **a, const unsigned char **pp,
    long length, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"d2i_SSL_SESSION_ex")

patch_both("ssl.h",
"""OSSL_DEPRECATEDIN_3_0
__owur int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
    long len);""",
"""/**
 * @brief Load an RSA private key from a DER buffer into an SSL context (deprecated).
 * @param ctx SSL context that receives the key.
 * @param d DER-encoded RSAPrivateKey bytes.
 * @param len Length of @p d in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
__owur int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
    long len);""",
"SSL_CTX_use_RSAPrivateKey_ASN1")

patch_both("ssl.h",
"__owur int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);",
"""/**
 * @brief Set the end-entity certificate used by an SSL context.
 * @param ctx SSL context that receives the certificate.
 * @param x Certificate to install; reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);""",
"SSL_CTX_use_certificate")

patch_both("ssl.h",
"void SSL_set_default_passwd_cb_userdata(SSL *s, void *u);",
"""/**
 * @brief Set the user-data pointer passed to an SSL object's PEM password callback.
 * @param s SSL connection whose password callback userdata is set.
 * @param u Pointer forwarded to the pem_password_cb as u.
 */
void SSL_set_default_passwd_cb_userdata(SSL *s, void *u);""",
"SSL_set_default_passwd_cb_userdata")

patch_both("ssl.h",
"void SSL_set_hostflags(SSL *s, unsigned int flags);",
"""/**
 * @brief Set X509_CHECK_FLAG_* host-checking flags for certificate hostname matching.
 * @param s SSL connection whose verification host flags are set.
 * @param flags Bitmask of X509_CHECK_FLAG_* values.
 */
void SSL_set_hostflags(SSL *s, unsigned int flags);""",
"SSL_set_hostflags")

patch_both("ssl.h",
"__owur int SSL_get0_dane_authority(SSL *s, X509 **mcert, EVP_PKEY **mspki);",
"""/**
 * @brief Return the matching DANE-TA / DANE-EE authority depth and optional anchors.
 * @param s SSL connection that completed DANE verification.
 * @param mcert If non-NULL, receives the matching certificate when applicable (borrowed).
 * @param mspki If non-NULL, receives the matching public key when applicable (borrowed).
 * @return Depth of the matching authority (>=0), or a negative value if none.
 */
__owur int SSL_get0_dane_authority(SSL *s, X509 **mcert, EVP_PKEY **mspki);""",
"SSL_get0_dane_authority")

patch_both("ssl.h",
"""size_t SSL_client_hello_get0_compression_methods(SSL *s,
    const unsigned char **out);""",
"""/**
 * @brief Return the raw compression_methods field from a parsed ClientHello.
 * @param s Server SSL connection inside a ClientHello callback (or with a parsed ClientHello).
 * @param out If non-NULL, set to point at the compression methods bytes.
 * @return Length of the compression_methods field in bytes, or 0 if unavailable.
 */
size_t SSL_client_hello_get0_compression_methods(SSL *s,
    const unsigned char **out);""",
"SSL_client_hello_get0_compression_methods")

patch_both("ssl.h",
"int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen);",
"""/**
 * @brief Allocate and return the list of extension types present in a ClientHello.
 * @param s Server SSL connection inside a ClientHello callback (or with a parsed ClientHello).
 * @param out Receives a newly allocated array of extension type integers; free with OPENSSL_free.
 * @param outlen Receives the number of entries in *@p out.
 * @return 1 on success, or 0 on failure.
 */
int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen);""",
"SSL_client_hello_get1_extensions_present")

patch_both("ssl.h",
"""int SSL_client_hello_get0_ext(SSL *s, unsigned int type,
    const unsigned char **out, size_t *outlen);""",
"""/**
 * @brief Return a pointer to a specific extension's payload in a parsed ClientHello.
 * @param s Server SSL connection inside a ClientHello callback (or with a parsed ClientHello).
 * @param type TLS extension type to look up.
 * @param out Set to the extension payload bytes (excluding type/length headers).
 * @param outlen Receives the payload length in bytes.
 * @return 1 if the extension is present, or 0 otherwise.
 */
int SSL_client_hello_get0_ext(SSL *s, unsigned int type,
    const unsigned char **out, size_t *outlen);""",
"SSL_client_hello_get0_ext")

patch_both("ssl.h",
"__owur int SSL_waiting_for_async(SSL *s);",
"""/**
 * @brief Report whether an SSL connection is paused waiting for an async crypto job.
 * @param s SSL connection using SSL_MODE_ASYNC.
 * @return 1 if waiting for async completion, or 0 otherwise.
 */
__owur int SSL_waiting_for_async(SSL *s);""",
"SSL_waiting_for_async")

patch_both("ssl.h",
"__owur int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds);",
"""/**
 * @brief Retrieve every file descriptor an async SSL operation is waiting on.
 * @param s SSL connection waiting for async completion.
 * @param fds Buffer receiving wait fds, or NULL to only query the required count.
 * @param numfds On entry, capacity of @p fds when non-NULL; on exit, number of fds.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds);""",
"SSL_get_all_async_fds")

patch_both("ssl.h",
"""__owur int SSL_get_changed_async_fds(SSL *s, OSSL_ASYNC_FD *addfd,
    size_t *numaddfds, OSSL_ASYNC_FD *delfd,
    size_t *numdelfds);""",
"""/**
 * @brief Retrieve async wait fds added or removed since the previous query.
 * @param s SSL connection waiting for async completion.
 * @param addfd Buffer for newly added fds, or NULL to only query counts.
 * @param numaddfds On entry/exit, capacity and count for @p addfd.
 * @param delfd Buffer for removed fds, or NULL to only query counts.
 * @param numdelfds On entry/exit, capacity and count for @p delfd.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_get_changed_async_fds(SSL *s, OSSL_ASYNC_FD *addfd,
    size_t *numaddfds, OSSL_ASYNC_FD *delfd,
    size_t *numdelfds);""",
"SSL_get_changed_async_fds")

patch_both("ssl.h",
"__owur int SSL_stateless(SSL *s);",
"""/**
 * @brief Attempt a stateless (cookie) DTLS listen / HelloVerifyRequest exchange.
 * @param s DTLS server SSL object with a ClientHello ready to process.
 * @return 1 if a complete ClientHello with valid cookie was received, 0 if a
 *         HelloVerifyRequest was sent, or -1 on error.
 */
__owur int SSL_stateless(SSL *s);""",
"SSL_stateless")

patch_both("ssl.h",
"""__owur ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size,
    int flags);""",
"""/**
 * @brief Send file contents over TLS using kernel sendfile where available.
 * @param s SSL connection to write to.
 * @param fd Open file descriptor positioned / addressed by @p offset.
 * @param offset Starting file offset.
 * @param size Maximum number of bytes to send.
 * @param flags Implementation-specific flags (typically 0).
 * @return Number of bytes written, or a negative value on error / want-IO.
 */
__owur ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size,
    int flags);""",
"SSL_sendfile")

patch_both("ssl.h",
"""__owur int SSL_write_early_data(SSL *s, const void *buf, size_t num,
    size_t *written);""",
"""/**
 * @brief Write early data (0-RTT) on a client SSL connection before the handshake completes.
 * @param s Client SSL connection that may send early data.
 * @param buf Plaintext to send as early data.
 * @param num Number of bytes from @p buf to write.
 * @param written Receives the number of bytes accepted on success.
 * @return 1 on success, or 0 on failure / want-IO (see SSL_get_error).
 */
__owur int SSL_write_early_data(SSL *s, const void *buf, size_t num,
    size_t *written);""",
"SSL_write_early_data")

patch_both("ssl.h",
"""OSSL_DEPRECATEDIN_3_0
__owur int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);""",
"""/**
 * @brief Replace the SSL_METHOD used by an SSL_CTX (deprecated).
 * @param ctx SSL context whose default method is updated.
 * @param meth New connection method such as TLS_method().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
__owur int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);""",
"SSL_CTX_set_ssl_version")

# DTLS/TLS version-specific methods
for decl, brief in [
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_2_method(void); /* TLSv1.2 */",
     "Return an SSL_METHOD for TLSv1.2 only (client and server; deprecated)."),
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *DTLSv1_server_method(void);",
     "Return a server-only SSL_METHOD for DTLSv1.0 (deprecated)."),
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *DTLSv1_client_method(void);",
     "Return a client-only SSL_METHOD for DTLSv1.0 (deprecated)."),
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *DTLSv1_2_method(void);",
     "Return an SSL_METHOD for DTLSv1.2 only (client and server; deprecated)."),
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *DTLSv1_2_server_method(void);",
     "Return a server-only SSL_METHOD for DTLSv1.2 (deprecated)."),
    ("OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *DTLSv1_2_client_method(void);",
     "Return a client-only SSL_METHOD for DTLSv1.2 (deprecated)."),
]:
    # extract function name for label
    name = decl.split("*")[1].split("(")[0].strip() if "*" in decl else decl
    patch_both("ssl.h", decl,
        f"""/**
 * @brief {brief}
 * @return Pointer to a static SSL_METHOD.
 */
{decl}""",
        name)

patch_both("ssl.h",
"__owur const SSL_METHOD *DTLS_client_method(void); /* DTLS 1.0 and 1.2 */",
"""/**
 * @brief Return a client-only SSL_METHOD negotiating DTLSv1.0 or DTLSv1.2.
 * @return Pointer to a static SSL_METHOD.
 */
__owur const SSL_METHOD *DTLS_client_method(void); /* DTLS 1.0 and 1.2 */""",
"DTLS_client_method")

patch_both("ssl.h",
"void SSL_set_post_handshake_auth(SSL *s, int val);",
"""/**
 * @brief Enable or disable TLSv1.3 post-handshake authentication on a connection.
 * @param s SSL connection to configure.
 * @param val Non-zero to allow post-handshake CertificateRequest, or 0 to disable.
 */
void SSL_set_post_handshake_auth(SSL *s, int val);""",
"SSL_set_post_handshake_auth")

patch_both("ssl.h",
"__owur const SSL_METHOD *SSL_get_ssl_method(const SSL *s);",
"""/**
 * @brief Return the SSL_METHOD currently associated with an SSL connection.
 * @param s SSL connection to query.
 * @return Pointer to the connection's SSL_METHOD.
 */
__owur const SSL_METHOD *SSL_get_ssl_method(const SSL *s);""",
"SSL_get_ssl_method")

patch_both("ssl.h",
"__owur const STACK_OF(X509_NAME) *SSL_CTX_get0_CA_list(const SSL_CTX *ctx);",
"""/**
 * @brief Return the list of CA names the context will advertise to peers.
 * @param ctx SSL context to query.
 * @return Internal stack of X509_NAME (do not free), or NULL if unset.
 */
__owur const STACK_OF(X509_NAME) *SSL_CTX_get0_CA_list(const SSL_CTX *ctx);""",
"SSL_CTX_get0_CA_list")

patch_both("ssl.h",
"void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode);",
"""/**
 * @brief Set quiet-shutdown mode for SSL objects created from a context.
 * @param ctx SSL context whose default quiet-shutdown flag is set.
 * @param mode Non-zero to skip sending/receiving close_notify, or 0 for normal shutdown.
 */
void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode);""",
"SSL_CTX_set_quiet_shutdown")

patch_both("ssl.h",
"__owur int SSL_get_quiet_shutdown(const SSL *ssl);",
"""/**
 * @brief Return whether quiet-shutdown mode is enabled on an SSL connection.
 * @param ssl SSL connection to query.
 * @return Non-zero if quiet shutdown is set, or 0 for a normal bidirectional close.
 */
__owur int SSL_get_quiet_shutdown(const SSL *ssl);""",
"SSL_get_quiet_shutdown")

patch_both("ssl.h",
"void *SSL_get_ex_data(const SSL *ssl, int idx);",
"""/**
 * @brief Retrieve application-specific data previously stored on an SSL object.
 * @param ssl SSL connection to query.
 * @param idx Index returned by SSL_get_ex_new_index / CRYPTO_get_ex_new_index.
 * @return Pointer previously passed to SSL_set_ex_data, or NULL.
 */
void *SSL_get_ex_data(const SSL *ssl, int idx);""",
"SSL_get_ex_data")

patch_both("ssl.h",
"__owur int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);",
"""/**
 * @brief Attach opaque session-ticket extension data to a client SSL connection.
 * @param s Client SSL connection that will send the ticket extension.
 * @param ext_data Extension payload bytes, or NULL to clear.
 * @param ext_len Length of @p ext_data in bytes.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);""",
"SSL_set_session_ticket_ext")

patch_both("ssl.h",
"int SSL_set_num_tickets(SSL *s, size_t num_tickets);",
"""/**
 * @brief Set how many NewSessionTicket messages a TLSv1.3 server connection should send.
 * @param s Server SSL connection to configure.
 * @param num_tickets Number of tickets to send after the handshake (0 disables tickets).
 * @return 1 on success, or 0 on failure.
 */
int SSL_set_num_tickets(SSL *s, size_t num_tickets);""",
"SSL_set_num_tickets")

patch_both("ssl.h",
"int SSL_handle_events(SSL *s);",
"""/**
 * @brief Advance an SSL object's event state (DTLS timers, QUIC event loop helper).
 * @param s SSL connection that may have pending timeout or I/O events.
 * @return 1 on success, or 0 on failure.
 */
int SSL_handle_events(SSL *s);""",
"SSL_handle_events")

patch_both("ssl.h",
"__owur int SSL_net_read_desired(SSL *s);",
"""/**
 * @brief Report whether the SSL object wants to read from the network BIO.
 * @param s SSL connection (typically QUIC or non-blocking DTLS/TLS).
 * @return 1 if a network read should be attempted, or 0 otherwise.
 */
__owur int SSL_net_read_desired(SSL *s);""",
"SSL_net_read_desired")

patch_both("ssl.h",
"__owur int SSL_set_default_stream_mode(SSL *s, uint32_t mode);",
"""/**
 * @brief Configure how the default QUIC stream behaves for an SSL connection.
 * @param s QUIC SSL connection to configure.
 * @param mode SSL_DEFAULT_STREAM_MODE_* constant controlling default-stream creation.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_default_stream_mode(SSL *s, uint32_t mode);""",
"SSL_set_default_stream_mode")

patch_both("ssl.h",
"void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx);",
"""/**
 * @brief Free an SSL_CONF_CTX and any associated command state.
 * @param cctx Configuration context to free, or NULL.
 */
void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx);""",
"SSL_CONF_CTX_free")

patch_both("ssl.h",
"void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl);",
"""/**
 * @brief Bind an SSL_CONF_CTX so subsequent SSL_CONF_cmd calls apply to @p ssl.
 * @param cctx Configuration context to update.
 * @param ssl SSL connection that receives configuration commands, or NULL to clear.
 */
void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl);""",
"SSL_CONF_CTX_set_ssl")

patch_both("ssl.h",
"""enum {
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    SSL_CT_VALIDATION_STRICT
};""",
"""enum {
    /** Continue the handshake even if SCT validation fails; the application decides later. */
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    /** Require at least one valid SCT or request handshake termination (unless SSL_VERIFY_NONE). */
    SSL_CT_VALIDATION_STRICT
};""",
"SSL_CT_VALIDATION_*")

patch_both("ssl.h",
"void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE *logs);",
"""/**
 * @brief Install a CT log store on an SSL context, transferring ownership of @p logs.
 * @param ctx SSL context whose CT log store is replaced.
 * @param logs CTLOG_STORE to use for SCT validation; owned by @p ctx after the call.
 */
void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE *logs);""",
"SSL_CTX_set0_ctlog_store")

patch_both("ssl.h",
"const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx);",
"""/**
 * @brief Return the CT log store installed on an SSL context.
 * @param ctx SSL context to query.
 * @return Internal CTLOG_STORE pointer (do not free), or NULL if unset.
 */
const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx);""",
"SSL_CTX_get0_ctlog_store")

patch_both("ssl.h",
"int SSL_set1_cert_comp_preference(SSL *ssl, int *algs, size_t len);",
"""/**
 * @brief Set the preferred certificate-compression algorithms for an SSL connection.
 * @param ssl SSL connection to configure.
 * @param algs Array of TLSEXT_comp_cert_* algorithm identifiers in preference order.
 * @param len Number of entries in @p algs.
 * @return 1 on success, or 0 on failure.
 */
int SSL_set1_cert_comp_preference(SSL *ssl, int *algs, size_t len);""",
"SSL_set1_cert_comp_preference")

# ----- x509.h -----
patch_both("x509.h",
"typedef struct x509_cert_aux_st X509_CERT_AUX;",
"""/**
 * @brief Auxiliary trust/reject OID lists and related metadata attached to an X509.
 */
typedef struct x509_cert_aux_st X509_CERT_AUX;""",
"X509_CERT_AUX")

patch_both("x509.h",
"    X509_ALGOR *enc_algor;",
"""    /** AlgorithmIdentifier for the encrypted private key in @c enc_pkey. */
    X509_ALGOR *enc_algor;""",
"private_key_st::enc_algor")

patch_both("x509.h",
"    ASN1_BIT_STRING *signature;",
"""    /** BIT STRING signature over @c spkac under @c sig_algor. */
    ASN1_BIT_STRING *signature;""",
"NETSCAPE_SPKI::signature")

patch_both("x509.h",
"""int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);""",
"""/**
 * @brief Digest the DER encoding of a certificate request with hash @p type.
 * @param data Certificate request to hash.
 * @param type Digest method to use.
 * @param md Buffer receiving the digest (at least EVP_MD_size(@p type) bytes).
 * @param len Receives the digest length in bytes.
 * @return 1 on success, or 0 on error.
 */
int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type,
    unsigned char *md, unsigned int *len);""",
"X509_REQ_digest")

patch_both("x509.h",
"OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);",
"""/**
 * @brief Read a DER-encoded EC private key from a BIO (deprecated).
 * @param bp BIO positioned at an ECPrivateKey encoding.
 * @param eckey Optional destination pointer updated to the result, or NULL.
 * @return Decoded EC_KEY, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);""",
"d2i_ECPrivateKey_bio")

patch_both("x509.h",
"DECLARE_ASN1_DUP_FUNCTION(X509_NAME_ENTRY)",
"""/**
 * @brief Deep-copy an X509_NAME_ENTRY.
 * @param ne Entry to duplicate.
 * @return Newly allocated copy, or NULL on error; free with X509_NAME_ENTRY_free.
 */
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(const X509_NAME_ENTRY *ne);""",
"X509_NAME_ENTRY_dup")

patch_both("x509.h",
"""int X509_cmp_timeframe(const X509_VERIFY_PARAM *vpm,
    const ASN1_TIME *start, const ASN1_TIME *end);""",
"""/**
 * @brief Compare a verification reference time against a notBefore/notAfter window.
 * @param vpm Verification parameters supplying the comparison time (or current time).
 * @param start notBefore time, or NULL to skip the lower bound.
 * @param end notAfter time, or NULL to skip the upper bound.
 * @return 0 if the reference time lies within the window, or non-zero if outside / on error.
 */
int X509_cmp_timeframe(const X509_VERIFY_PARAM *vpm,
    const ASN1_TIME *start, const ASN1_TIME *end);""",
"X509_cmp_timeframe")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_NAME_ENTRY)",
asn1_funcs("X509_NAME_ENTRY", "X.509 Name entry (AttributeTypeAndValue)"),
"X509_NAME_ENTRY_funcs")

patch_both("x509.h",
"""int X509_SIG_INFO_get(const X509_SIG_INFO *siginf, int *mdnid, int *pknid,
    int *secbits, uint32_t *flags);""",
"""/**
 * @brief Read digest NID, public-key NID, security bits, and flags from X509_SIG_INFO.
 * @param siginf Signature-info object to query.
 * @param mdnid Receives the message-digest NID, or NULL.
 * @param pknid Receives the public-key NID, or NULL.
 * @param secbits Receives an estimated security strength in bits, or NULL.
 * @param flags Receives X509_SIG_INFO_* flag bits, or NULL.
 * @return 1 if usable signature info is present, or 0 otherwise.
 */
int X509_SIG_INFO_get(const X509_SIG_INFO *siginf, int *mdnid, int *pknid,
    int *secbits, uint32_t *flags);""",
"X509_SIG_INFO_get")

patch_both("x509.h",
"int X509_check_private_key(const X509 *cert, const EVP_PKEY *pkey);",
"""/**
 * @brief Verify that @p pkey is the private key matching certificate @p cert.
 * @param cert Certificate whose public key is compared.
 * @param pkey Candidate private (or key pair) to check.
 * @return 1 if the keys match, or 0 if they do not / on error.
 */
int X509_check_private_key(const X509 *cert, const EVP_PKEY *pkey);""",
"X509_check_private_key")

patch_both("x509.h",
"""int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
    unsigned long flags);""",
"""/**
 * @brief Encode @p value as a CRL extension of type @p nid and append it.
 * @param x CRL receiving the extension.
 * @param nid Extension NID (for example NID_authority_key_identifier).
 * @param value Extension-specific structure pointer interpreted for @p nid.
 * @param crit Non-zero to mark the extension critical.
 * @param flags X509V3_ADD_* behaviour flags.
 * @return 1 on success, 0 on error, or -1 on an internal failure.
 */
int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
    unsigned long flags);""",
"X509_CRL_add1_ext_i2d")

patch_both("x509.h",
"""int PKCS8_pkey_add1_attr_by_OBJ(PKCS8_PRIV_KEY_INFO *p8, const ASN1_OBJECT *obj,
    int type, const unsigned char *bytes, int len);""",
"""/**
 * @brief Append an attribute identified by @p obj to a PKCS#8 private key info.
 * @param p8 PKCS#8 structure receiving the attribute.
 * @param obj Attribute type OID.
 * @param type ASN.1 string/value type for @p bytes (V_ASN1_*).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 if @p bytes is NUL-terminated where applicable.
 * @return 1 on success, or 0 on failure.
 */
int PKCS8_pkey_add1_attr_by_OBJ(PKCS8_PRIV_KEY_INFO *p8, const ASN1_OBJECT *obj,
    int type, const unsigned char *bytes, int len);""",
"PKCS8_pkey_add1_attr_by_OBJ")

# ----- x509_vfy.h -----
patch_both("x509_vfy.h",
"int X509_TRUST_get_flags(const X509_TRUST *xp);",
"""/**
 * @brief Return the flag bits associated with an X509_TRUST table entry.
 * @param xp Trust entry to query.
 * @return Bitmask of X509_TRUST_* flags for @p xp.
 */
int X509_TRUST_get_flags(const X509_TRUST *xp);""",
"X509_TRUST_get_flags")

patch_both("x509_vfy.h",
"""X509_STORE_CTX_check_revocation_fn
X509_STORE_get_check_revocation(const X509_STORE *xs);""",
"""/**
 * @brief Return the certificate-revocation check callback installed on a store.
 * @param xs Certificate store to query.
 * @return check_revocation callback, or NULL if the default is used.
 */
X509_STORE_CTX_check_revocation_fn
X509_STORE_get_check_revocation(const X509_STORE *xs);""",
"X509_STORE_get_check_revocation")

patch_both("x509_vfy.h",
"X509_CRL *X509_STORE_CTX_get0_current_crl(const X509_STORE_CTX *ctx);",
"""/**
 * @brief Return the CRL currently being considered during revocation checking.
 * @param ctx Verification store context mid-verification (or after an error).
 * @return Internal X509_CRL pointer (do not free), or NULL if none is set.
 */
X509_CRL *X509_STORE_CTX_get0_current_crl(const X509_STORE_CTX *ctx);""",
"X509_STORE_CTX_get0_current_crl")

patch_both("x509_vfy.h",
"void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);",
"""/**
 * @brief Set the verification reference time used as \"now\" for validity checks.
 * @param param Verification parameters to update.
 * @param t Absolute time used instead of the current clock.
 */
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);""",
"X509_VERIFY_PARAM_set_time")

patch_both("x509_vfy.h",
"""int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,
    const unsigned char *ip, size_t iplen);""",
"""/**
 * @brief Set the expected IP address for certificate name checks (binary form).
 * @param param Verification parameters to update.
 * @param ip IPv4 (4 bytes) or IPv6 (16 bytes) address in network byte order.
 * @param iplen Length of @p ip in bytes (4 or 16).
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,
    const unsigned char *ip, size_t iplen);""",
"X509_VERIFY_PARAM_set1_ip")

# ----- mrdocs.yml: exclude macro-generated LHASH record shells -----
yml = ROOT / "docs" / "mrdocs.yml"
text = yml.read_text(encoding="utf-8")
needle = "  - 'stack_st_OSSL_CMP_POLLREP'\n"
insert = ("  - 'stack_st_OSSL_CMP_POLLREP'\n"
          "  - 'lhash_st_*'\n"
          "  - 'lhash_st_*::**'\n")
if "lhash_st_*" not in text:
    if needle not in text:
        print("  MISS: mrdocs.yml :: lhash_st exclude anchor")
        missing.append("mrdocs.yml:lhash_st")
    else:
        yml.write_text(text.replace(needle, insert, 1), encoding="utf-8")
        print("  OK: mrdocs.yml :: lhash_st_* exclude")
        ok.append("mrdocs.yml:lhash_st")
else:
    print("  SKIP: mrdocs.yml already has lhash_st_*")

print(f"\nDone 7c: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print(" ", m)
