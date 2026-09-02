#!/usr/bin/env python3
"""Documentation repair batch 15c: ssl.h, tls1.h, ui.h SSL/TLS/UI symbols."""
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


print("=== batch 15c ===")

# ----- ssl.h -----
patch_both(
    "ssl.h",
    """typedef struct ssl_method_st SSL_METHOD;
""",
    """/**
 * @brief Opaque SSL/TLS protocol method table used with SSL_CTX_new and related APIs.
 */
typedef struct ssl_method_st SSL_METHOD;
""",
    "SSL_METHOD",
)

patch_both(
    "ssl.h",
    """#ifndef OPENSSL_NO_ENGINE
__owur int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);
#endif
""",
    """#ifndef OPENSSL_NO_ENGINE
/**
 * @brief Set an ENGINE used to obtain a client certificate when a server requests one.
 * @param ctx SSL context that will use @p e for client-certificate selection.
 * @param e ENGINE that implements a client-certificate load function (initialized by this call).
 * @return 1 on success, or 0 if @p e cannot be initialized or has no client-cert method.
 */
__owur int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);
#endif
""",
    "SSL_CTX_set_client_cert_engine",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_psk_find_session_callback(SSL_CTX *ctx,
    SSL_psk_find_session_cb_func cb);
""",
    """/**
 * @brief Set the TLSv1.3 PSK find-session callback for SSL objects created from a context (server).
 * @param ctx Server SSL context whose default PSK find-session callback is set.
 * @param cb Callback that returns an SSL_SESSION for the given identity, or NULL to clear.
 */
void SSL_CTX_set_psk_find_session_callback(SSL_CTX *ctx,
    SSL_psk_find_session_cb_func cb);
""",
    "SSL_CTX_set_psk_find_session_callback",
)

patch_both(
    "ssl.h",
    """int SSL_is_init_finished(const SSL *s);
""",
    """/**
 * @brief Test whether the connection is ready for fully protected application data.
 * @param s SSL connection to query.
 * @return 1 if the handshake has finished and protected app data can be transferred, or 0 otherwise.
 */
int SSL_is_init_finished(const SSL *s);
""",
    "SSL_is_init_finished",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *);
""",
    """/**
 * @brief Replace the context certificate store, incrementing @p store's reference count.
 * @param ctx SSL context whose verification store is replaced.
 * @param store X509_STORE to install; any previous store is freed, and @p store's refcount is incremented.
 */
void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *);
""",
    "SSL_CTX_set1_cert_store",
)

patch_both(
    "ssl.h",
    """__owur STACK_OF(X509_NAME) *SSL_load_client_CA_file_ex(const char *file, OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    """/**
 * @brief Read certificates from a file and return a stack of their subject names (provider-aware).
 * @param file Path to a PEM file of certificates (typically for SSL_set_client_CA_list).
 * @param libctx Library context used when fetching algorithms from providers, or NULL for the default.
 * @param propq Property query string for provider algorithm selection, or NULL.
 * @return New STACK_OF(X509_NAME) on success (caller frees with sk_X509_NAME_pop_free), or NULL on failure.
 */
__owur STACK_OF(X509_NAME) *SSL_load_client_CA_file_ex(const char *file, OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    "SSL_load_client_CA_file_ex",
)

patch_both(
    "ssl.h",
    """__owur X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
""",
    """/**
 * @brief Return the peer certificate stored in an SSL session (borrowed pointer).
 * @param s Session to query.
 * @return Peer X509 certificate, or NULL if none is available; do not free unless X509_up_ref was called.
 */
__owur X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
""",
    "SSL_SESSION_get0_peer",
)

patch_both(
    "ssl.h",
    """int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *session);
""",
    """/**
 * @brief Remove a session from an SSL context's internal session cache and mark it non-resumable.
 * @param ctx SSL context whose cache is updated.
 * @param session Session to remove; SSL_SESSION_free is called once for it.
 * @return 1 on success, or 0 if the session was not found in the cache.
 */
int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *session);
""",
    "SSL_CTX_remove_session",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb);
""",
    """/**
 * @brief Set the callback used to generate new session IDs for server SSL objects from a context.
 * @param ctx Server SSL context whose session-ID generator is replaced.
 * @param cb Generator callback; see GEN_SESSION_CB.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb);
""",
    "SSL_CTX_set_generate_session_id",
)

patch_both(
    "ssl.h",
    """void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx);
""",
    """/**
 * @brief Return the userdata pointer passed to the context's default PEM password callback.
 * @param ctx SSL context to query.
 * @return Userdata previously set with SSL_CTX_set_default_passwd_cb_userdata, or NULL if unset.
 */
void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx);
""",
    "SSL_CTX_get_default_passwd_cb_userdata",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_dane_enable(SSL_CTX *ctx);
""",
    """/**
 * @brief Initialize shared DANE TLSA authentication state on an SSL context.
 * @param ctx Client SSL context that will create DANE-enabled SSL connections.
 * @return Positive value on success, 0 for invalid usage, or a negative value on resource failure.
 */
__owur int SSL_CTX_dane_enable(SSL_CTX *ctx);
""",
    "SSL_CTX_dane_enable",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_3_0 int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name);
""",
    """/**
 * @brief Set the default SRP username for clients created from a context (deprecated).
 * @param ctx Client SSL context that stores the username; call before creating the connection.
 * @param name SRP username (at most 255 characters).
 * @return 1 on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name);
""",
    "SSL_CTX_set_srp_username",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_3_0 __owur BIGNUM *SSL_get_srp_N(SSL *s);
""",
    """/**
 * @brief Return the SRP prime N configured on a connection (deprecated).
 * @param s SSL connection with SRP parameters set (falls back to the parent SSL_CTX if unset on @p s).
 * @return Pointer to the SRP prime BIGNUM, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 __owur BIGNUM *SSL_get_srp_N(SSL *s);
""",
    "SSL_get_srp_N",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_set_async_callback(SSL_CTX *ctx, SSL_async_callback_fn callback);
""",
    """/**
 * @brief Set the asynchronous completion callback inherited by SSL objects from a context.
 * @param ctx SSL context whose default async callback is installed.
 * @param callback Function invoked when an async-capable engine finishes a crypto operation (with SSL_MODE_ASYNC).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_async_callback(SSL_CTX *ctx, SSL_async_callback_fn callback);
""",
    "SSL_CTX_set_async_callback",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_set_async_callback_arg(SSL_CTX *ctx, void *arg);
""",
    """/**
 * @brief Set the user argument passed to the context's asynchronous completion callback.
 * @param ctx SSL context whose async callback receives @p arg.
 * @param arg Pointer forwarded to the async callback when a crypto operation completes.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_async_callback_arg(SSL_CTX *ctx, void *arg);
""",
    "SSL_CTX_set_async_callback_arg",
)

patch_both(
    "ssl.h",
    """__owur int SSL_set_async_callback(SSL *s, SSL_async_callback_fn callback);
""",
    """/**
 * @brief Set the asynchronous completion callback on an SSL connection.
 * @param s SSL connection that uses SSL_MODE_ASYNC with an async-capable engine.
 * @param callback Function invoked when the engine finishes a crypto operation so the app can resume work.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_async_callback(SSL *s, SSL_async_callback_fn callback);
""",
    "SSL_set_async_callback",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_2_server_method(void);
""",
    """/**
 * @brief Return a server-only SSL_METHOD restricted to TLS 1.2 (deprecated; prefer TLS_server_method).
 * @return Pointer to the static TLSv1.2 server SSL_METHOD for use with SSL_CTX_new.
 */
OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_2_server_method(void);
""",
    "TLSv1_2_server_method",
)

patch_both(
    "ssl.h",
    """int SSL_new_session_ticket(SSL *s);
int SSL_shutdown(SSL *s);
""",
    """int SSL_new_session_ticket(SSL *s);
/**
 * @brief Shut down an active TLS/DTLS or QUIC connection (close_notify / connection close).
 * @param s SSL connection to shut down; do not call after a prior fatal SSL_ERROR_SYSCALL or SSL_ERROR_SSL.
 * @return 1 when the shutdown has completed, 0 if it is in progress (e.g. nonblocking), or a negative value on error.
 */
int SSL_shutdown(SSL *s);
""",
    "SSL_shutdown",
)

patch_both(
    "ssl.h",
    """void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
""",
    """/**
 * @brief Set the list of CA names sent when requesting a client certificate on a connection.
 * @param s Server SSL connection that owns @p name_list after this call (overrides the parent context list).
 * @param name_list Stack of X509_NAME objects identifying acceptable CAs; ownership transfers to @p s.
 */
void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
""",
    "SSL_set_client_CA_list",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x);
""",
    """/**
 * @brief Add a CA subject name to the context's client-CA list sent when requesting a client certificate.
 * @param ctx Server SSL context whose client-CA list is extended (created if none was set).
 * @param x Certificate whose subject name is appended (not taken ownership of).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x);
""",
    "SSL_CTX_add_client_CA",
)

patch_both(
    "ssl.h",
    """__owur char *SSL_CIPHER_description(const SSL_CIPHER *, char *buf, int size);
""",
    """/**
 * @brief Write a human-readable description of a cipher suite into a buffer.
 * @param cipher Cipher suite to describe.
 * @param buf Destination buffer of at least 128 bytes, or NULL to allocate with OPENSSL_malloc (caller frees).
 * @param size Capacity of @p buf in bytes when @p buf is non-NULL.
 * @return Pointer to the NUL-terminated description (possibly newly allocated), or NULL on error / undersized buffer.
 */
__owur char *SSL_CIPHER_description(const SSL_CIPHER *, char *buf, int size);
""",
    "SSL_CIPHER_description",
)

patch_both(
    "ssl.h",
    """__owur int SSL_get_wpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc);
""",
    """/**
 * @brief Obtain a poll descriptor indicating when the SSL object can usefully write to the network.
 * @param s SSL connection (QUIC or with configured write BIO) to query.
 * @param desc On success, receives a BIO_POLL_DESCRIPTOR for writability (see BIO_get_wpoll_descriptor).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_get_wpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc);
""",
    "SSL_get_wpoll_descriptor",
)

patch_both(
    "ssl.h",
    """__owur int SSL_set_blocking_mode(SSL *s, int blocking);
""",
    """/**
 * @brief Enable or disable blocking mode on a QUIC connection SSL object.
 * @param s QUIC connection SSL object to configure.
 * @param blocking 1 to block in SSL_read/SSL_write until the operation can complete, or 0 for nonblocking.
 * @return 1 on success, or 0 if @p s is not a QUIC connection or blocking mode cannot be used.
 */
__owur int SSL_set_blocking_mode(SSL *s, int blocking);
""",
    "SSL_set_blocking_mode",
)

patch_both(
    "ssl.h",
    """__owur int SSL_get_stream_read_error_code(SSL *ssl, uint64_t *app_error_code);
""",
    """/**
 * @brief Get the application error code from a non-normal QUIC stream receive abort.
 * @param ssl QUIC stream SSL object, or a QUIC connection SSL with a default stream.
 * @param app_error_code On success, receives the signalled application error code.
 * @return 1 on success, 0 if the receive part terminated normally, or -1 on error
 *     (still healthy, wrong stream direction, non-QUIC, or no default stream).
 */
__owur int SSL_get_stream_read_error_code(SSL *ssl, uint64_t *app_error_code);
""",
    "SSL_get_stream_read_error_code",
)

patch_both(
    "ssl.h",
    """__owur void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx);
""",
    """/**
 * @brief Return the application pointer passed as @c ex to the context security callback.
 * @param ctx SSL context to query.
 * @return Extra data previously set with SSL_CTX_set0_security_ex_data, or NULL if unset.
 */
__owur void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx);
""",
    "SSL_CTX_get0_security_ex_data",
)

# ----- tls1.h -----
patch_both(
    "tls1.h",
    """int SSL_get_shared_sigalgs(SSL *s, int idx,
    int *psign, int *phash, int *psignandhash,
    unsigned char *rsig, unsigned char *rhash);
""",
    """/**
 * @brief Get a shared (mutually supported) signature algorithm by index.
 * @param s SSL connection to query after the peer advertised signature algorithms.
 * @param idx Zero-based index into the shared signature algorithm list (0 is highest preference).
 * @param psign Receives the signature NID; may be NULL.
 * @param phash Receives the hash NID; may be NULL.
 * @param psignandhash Receives the combined sign-and-hash NID; may be NULL.
 * @param rsig Receives the raw signature algorithm byte; may be NULL.
 * @param rhash Receives the raw hash algorithm byte; may be NULL.
 * @return Number of shared signature algorithms, or 0 if @p idx is out of range.
 */
int SSL_get_shared_sigalgs(SSL *s, int idx,
    int *psign, int *phash, int *psignandhash,
    unsigned char *rsig, unsigned char *rhash);
""",
    "SSL_get_shared_sigalgs",
)

# ----- ui.h (keep old /* */ comments; insert /** @brief */ between them and the decl) -----
patch_both(
    "ui.h",
    """ * methods may not, however.
 */
void *UI_add_user_data(UI *ui, void *user_data);
""",
    """ * methods may not, however.
 */
/**
 * @brief Store application user data on a UI, replacing any previous pointer.
 * @param ui UI that holds the user-data pointer for its method.
 * @param user_data Application pointer for the method to use (UI_OpenSSL ignores it).
 * @return Previous user-data pointer, or NULL if none was set / it was destroyed as duplicated data.
 */
void *UI_add_user_data(UI *ui, void *user_data);
""",
    "UI_add_user_data",
)

patch_both(
    "ui.h",
    """ * used to get information from a UI.
 */
int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void));
""",
    """ * used to get information from a UI.
 */
/**
 * @brief Send a parameterised control command to a UI (or query UI state).
 * @param ui UI to control.
 * @param cmd Command such as UI_CTRL_PRINT_ERRORS or UI_CTRL_IS_REDOABLE.
 * @param i Integer argument for @p cmd (for example 1 to enable UI_CTRL_PRINT_ERRORS).
 * @param p Optional data pointer for @p cmd; unused for the built-in commands.
 * @param f Optional function pointer for @p cmd; unused for the built-in commands.
 * @return Command-specific value on success (e.g. redoable flag), or -1 on error.
 */
int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void));
""",
    "UI_ctrl",
)

patch_both(
    "ui.h",
    """ * to avoid internal default.
 */
const UI_METHOD *UI_null(void);
""",
    """ * to avoid internal default.
 */
/**
 * @brief Return a no-op UI_METHOD that performs no prompting.
 * @return Pointer to the null method (useful as a placeholder instead of relying on internal defaults).
 */
const UI_METHOD *UI_null(void);
""",
    "UI_null",
)

patch_both(
    "ui.h",
    """/* Set the result of a UI_STRING. */
int UI_set_result(UI *ui, UI_STRING *uis, const char *result);
""",
    """/* Set the result of a UI_STRING. */
/**
 * @brief Store a NUL-terminated prompt result on a UI_STRING (length taken from the string).
 * @param ui UI that owns @p uis (used for error reporting).
 * @param uis Prompt, verify, or boolean string receiving the result.
 * @param result NUL-terminated result text to copy (same rules as UI_set_result_ex).
 * @return 0 on success (or when @p uis is not a result-bearing type), or -1 on error.
 */
int UI_set_result(UI *ui, UI_STRING *uis, const char *result);
""",
    "UI_set_result",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
