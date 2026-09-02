#!/usr/bin/env python3
"""Documentation repair batch 8c: ssl, ui, x509, x509_vfy, x509v3."""
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


# ----- ssl.h -----
patch_both("ssl.h",
"""typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
    int len, void *arg);""",
"""/**
 * @brief Callback invoked with the TLS session-ticket extension payload.
 * @param s SSL connection that received the extension.
 * @param data Extension data bytes.
 * @param len Length of @p data in bytes.
 * @param arg Application pointer supplied when the callback was registered.
 * @return 1 on success, or 0 to fail the handshake / reject the extension.
 */
typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
    int len, void *arg);""",
"tls_session_ticket_ext_cb_fn")

patch_both("ssl.h",
"int SSL_in_init(const SSL *s);",
"""/**
 * @brief Test whether an SSL object is currently performing a handshake.
 * @param s SSL connection to query.
 * @return 1 if a handshake is in progress, or 0 otherwise.
 */
int SSL_in_init(const SSL *s);""",
"SSL_in_init")

patch_both("ssl.h",
"__owur const char *OPENSSL_cipher_name(const char *rfc_name);",
"""/**
 * @brief Map an RFC cipher suite name to the corresponding OpenSSL cipher name.
 * @param rfc_name RFC standard name (for example "TLS_AES_128_GCM_SHA256").
 * @return OpenSSL cipher name string (do not free), or "UNKNOWN" if unmapped.
 */
__owur const char *OPENSSL_cipher_name(const char *rfc_name);""",
"OPENSSL_cipher_name")

patch_both("ssl.h",
"__owur int SSL_set_ciphersuites(SSL *s, const char *str);",
"""/**
 * @brief Set the TLSv1.3 ciphersuite list for an SSL connection.
 * @param s SSL object to configure.
 * @param str Colon-separated TLSv1.3 ciphersuite names (OpenSSL names).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_ciphersuites(SSL *s, const char *str);""",
"SSL_set_ciphersuites")

patch_both("ssl.h",
"__owur const char *SSL_state_string_long(const SSL *s);",
"""/**
 * @brief Return a long descriptive string for the current SSL state.
 * @param s SSL connection to query.
 * @return NUL-terminated state description (do not free).
 */
__owur const char *SSL_state_string_long(const SSL *s);""",
"SSL_state_string_long")

patch_both("ssl.h",
"__owur long SSL_SESSION_get_time(const SSL_SESSION *s);",
"""/**
 * @brief Return the session creation time as seconds since the Epoch.
 * @param s Session to query.
 * @return Session timestamp, or 0 if unavailable.
 */
__owur long SSL_SESSION_get_time(const SSL_SESSION *s);""",
"SSL_SESSION_get_time")

patch_both("ssl.h",
"__owur X509 *SSL_get0_peer_certificate(const SSL *s);",
"""/**
 * @brief Return the peer's leaf certificate without incrementing its reference count.
 * @param s SSL connection after a handshake that presented a certificate.
 * @return Peer X509 (owned by @p s; do not free), or NULL if none is available.
 */
__owur X509 *SSL_get0_peer_certificate(const SSL *s);""",
"SSL_get0_peer_certificate")

patch_both("ssl.h",
"__owur int SSL_CTX_set_trust(SSL_CTX *ctx, int trust);",
"""/**
 * @brief Set the default X509 trust purpose NID for certificate verification on a context.
 * @param ctx SSL context to configure.
 * @param trust Trust purpose such as X509_TRUST_SSL_CLIENT or X509_TRUST_SSL_SERVER.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_trust(SSL_CTX *ctx, int trust);""",
"SSL_CTX_set_trust")

patch_both("ssl.h",
"__owur size_t DTLS_get_data_mtu(const SSL *s);",
"""/**
 * @brief Return the maximum application-data payload size for a DTLS connection.
 * @param s DTLS SSL object whose path MTU / record overhead are considered.
 * @return Maximum bytes of application data per datagram, or 0 if unknown.
 */
__owur size_t DTLS_get_data_mtu(const SSL *s);""",
"DTLS_get_data_mtu")

patch_both("ssl.h",
"__owur const char *SSL_alert_type_string(int value);",
"""/**
 * @brief Return a short string for an SSL/TLS alert level.
 * @param value Alert description encoded as in the TLS Alert protocol (level in the high bits as used by OpenSSL callbacks).
 * @return "W" (warning), "F" (fatal), or "U" (unknown); do not free.
 */
__owur const char *SSL_alert_type_string(int value);""",
"SSL_alert_type_string")

patch_both("ssl.h",
"void SSL_set_accept_state(SSL *s);",
"""/**
 * @brief Configure an SSL object to behave as a server (accept) endpoint.
 * @param s SSL connection that will perform the server role in the handshake.
 */
void SSL_set_accept_state(SSL *s);""",
"SSL_set_accept_state")

patch_both("ssl.h",
"void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx);",
"""/**
 * @brief Retrieve application data previously stored on an SSL_SESSION.
 * @param ss Session to query.
 * @param idx Index from CRYPTO_get_ex_new_index() / SSL_SESSION_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx);""",
"SSL_SESSION_get_ex_data")

patch_both("ssl.h",
"__owur int SSL_is_stream_local(SSL *s);",
"""/**
 * @brief Test whether a QUIC stream SSL object was created locally (client-initiated locally).
 * @param s SSL object representing a QUIC stream.
 * @return 1 if the stream is locally initiated, 0 if remote, or a negative value on error.
 */
__owur int SSL_is_stream_local(SSL *s);""",
"SSL_is_stream_local")

patch_both("ssl.h",
"""static ossl_inline ossl_unused BIO_POLL_DESCRIPTOR
SSL_as_poll_descriptor(SSL *s)
{
    BIO_POLL_DESCRIPTOR d;

    d.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    d.value.ssl = s;
    return d;
}""",
"""/**
 * @brief Build a BIO_POLL_DESCRIPTOR that refers to SSL object @p s.
 * @param s SSL connection to poll (for example with SSL_handle_events / BIO_poll).
 * @return Descriptor with type BIO_POLL_DESCRIPTOR_TYPE_SSL and value.ssl set to @p s.
 */
static ossl_inline ossl_unused BIO_POLL_DESCRIPTOR
SSL_as_poll_descriptor(SSL *s)
{
    BIO_POLL_DESCRIPTOR d;

    d.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    d.value.ssl = s;
    return d;
}""",
"SSL_as_poll_descriptor")

patch_both("ssl.h",
"""enum {
    /** Continue the handshake even if SCT validation fails; the application decides later. */
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    /** Require at least one valid SCT or request handshake termination (unless SSL_VERIFY_NONE). */
    SSL_CT_VALIDATION_STRICT
};""",
"""/**
 * @brief Certificate Transparency validation policy for SSL_CTX_enable_ct().
 */
enum SSL_ct_validation_mode {
    /** Continue the handshake even if SCT validation fails; the application decides later. */
    SSL_CT_VALIDATION_PERMISSIVE = 0,
    /** Require at least one valid SCT or request handshake termination (unless SSL_VERIFY_NONE). */
    SSL_CT_VALIDATION_STRICT
};""",
"SSL_ct_validation_mode")

patch_both("ssl.h",
"""typedef SSL_TICKET_RETURN (*SSL_CTX_decrypt_session_ticket_fn)(SSL *s, SSL_SESSION *ss,
    const unsigned char *keyname,
    size_t keyname_length,
    SSL_TICKET_STATUS status,
    void *arg);""",
"""/**
 * @brief Application callback that decrypts/validates a received session ticket.
 * @param s SSL connection that received the ticket.
 * @param ss Session object to populate or reject.
 * @param keyname Ticket key name from the ticket header.
 * @param keyname_length Length of @p keyname in bytes.
 * @param status Preliminary ticket parse status (SSL_TICKET_*), before app decrypt.
 * @param arg Application pointer supplied to SSL_CTX_set_session_ticket_cb().
 * @return SSL_TICKET_RETURN_* instructing OpenSSL how to proceed.
 */
typedef SSL_TICKET_RETURN (*SSL_CTX_decrypt_session_ticket_fn)(SSL *s, SSL_SESSION *ss,
    const unsigned char *keyname,
    size_t keyname_length,
    SSL_TICKET_STATUS status,
    void *arg);""",
"SSL_CTX_decrypt_session_ticket_fn")

patch_both("ssl.h",
"size_t SSL_CTX_get1_compressed_cert(SSL_CTX *ctx, int alg, unsigned char **data, size_t *orig_len);",
"""/**
 * @brief Get a copy of a compressed certificate configured on an SSL_CTX.
 * @param ctx SSL context that may hold compressed certificates.
 * @param alg Compression algorithm identifier (TLSEXT_comp_cert_*).
 * @param data Receives a newly allocated compressed certificate buffer (caller frees with OPENSSL_free).
 * @param orig_len Receives the uncompressed certificate length in bytes.
 * @return Length of *@p data in bytes, or 0 if unavailable / on error.
 */
size_t SSL_CTX_get1_compressed_cert(SSL_CTX *ctx, int alg, unsigned char **data, size_t *orig_len);""",
"SSL_CTX_get1_compressed_cert")

patch_both("ssl.h",
"__owur int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len);",
"""/**
 * @brief Set the server certificate type values advertised by an SSL_CTX (RFC 7250).
 * @param ctx SSL context to configure.
 * @param val Buffer of certificate type bytes (for example TLSEXT_cert_type_*).
 * @param len Number of bytes at @p val.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len);""",
"SSL_CTX_set1_server_cert_type")

# ----- ui.h -----
patch_both("ui.h",
"""int UI_add_verify_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize,
    const char *test_buf);""",
"""/**
 * @brief Add a string prompt whose result must match @p test_buf (for example password confirm).
 * @param ui UI object collecting prompts.
 * @param prompt Text shown to the user.
 * @param flags UI_INPUT_FLAG_* behaviour bits.
 * @param result_buf Buffer receiving the user input (size at least @p maxsize+1).
 * @param minsize Minimum accepted result length.
 * @param maxsize Maximum accepted result length.
 * @param test_buf Expected string that the result must equal.
 * @return Non-negative index of the added string on success, or a negative value on error.
 */
int UI_add_verify_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize,
    const char *test_buf);""",
"UI_add_verify_string")

patch_both("ui.h",
"""int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action_desc,
    const char *ok_chars, const char *cancel_chars,
    int flags, char *result_buf);""",
"""/**
 * @brief Add a boolean prompt, copying the prompt strings into @p ui.
 * @param ui UI object collecting prompts.
 * @param prompt Text shown to the user.
 * @param action_desc Optional description of the action being affirmed, or NULL.
 * @param ok_chars Characters that mean "yes" (for example "yY").
 * @param cancel_chars Characters that mean "no" (for example "nN").
 * @param flags UI_INPUT_FLAG_* behaviour bits.
 * @param result_buf Single-byte buffer receiving the chosen ok/cancel character.
 * @return Non-negative index of the added boolean on success, or a negative value on error.
 */
int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action_desc,
    const char *ok_chars, const char *cancel_chars,
    int flags, char *result_buf);""",
"UI_dup_input_boolean")

patch_both("ui.h",
"UI_METHOD *UI_create_method(const char *name);",
"""/**
 * @brief Allocate a new UI_METHOD with the given name.
 * @param name Human-readable method name stored on the method.
 * @return New UI_METHOD, or NULL on allocation failure; free with UI_destroy_method.
 */
UI_METHOD *UI_create_method(const char *name);""",
"UI_create_method")

patch_both("ui.h",
"int UI_get_result_minsize(UI_STRING *uis);",
"""/**
 * @brief Return the minimum accepted result length for a UI string prompt.
 * @param uis UI_STRING of type UIT_PROMPT / UIT_VERIFY.
 * @return Minimum size in characters, or -1 if not applicable.
 */
int UI_get_result_minsize(UI_STRING *uis);""",
"UI_get_result_minsize")

# ----- x509.h -----
patch_both("x509.h",
"""    ASN1_TYPE *salt;
    ASN1_INTEGER *iter;
    ASN1_INTEGER *keylength;""",
"""    ASN1_TYPE *salt;
    /** PBKDF2 iteration count. */
    ASN1_INTEGER *iter;
    /** Optional derived key length in octets; NULL means the cipher default. */
    ASN1_INTEGER *keylength;""",
"PBKDF2PARAM_iter")

patch_both("x509.h",
"X509_PUBKEY *d2i_X509_PUBKEY_fp(FILE *fp, X509_PUBKEY **xpk);",
"""/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo (X509_PUBKEY) from a FILE.
 * @param fp FILE positioned at DER input.
 * @param xpk Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_PUBKEY, or NULL on error.
 */
X509_PUBKEY *d2i_X509_PUBKEY_fp(FILE *fp, X509_PUBKEY **xpk);""",
"d2i_X509_PUBKEY_fp")

patch_both("x509.h",
"EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);",
"""/**
 * @brief Read a DER-encoded SubjectPublicKeyInfo into an EVP_PKEY from a BIO.
 * @param bp BIO positioned at DER input.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @return Decoded EVP_PKEY, or NULL on error.
 */
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);""",
"d2i_PUBKEY_bio")

patch_both("x509.h",
"DECLARE_ASN1_ENCODE_FUNCTIONS_only(X509, X509_AUX)",
"""/**
 * @brief Decode an X.509 certificate with trusted-certificate auxiliary data from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded X509 (with aux info), or NULL on error.
 */
X509 *d2i_X509_AUX(X509 **a, const unsigned char **in, long len);
/**
 * @brief Encode an X.509 certificate plus trusted-certificate auxiliary data to DER.
 * @param a Certificate whose aux trust information is included when present.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_X509_AUX(const X509 *a, unsigned char **out);""",
"X509_AUX")

patch_both("x509.h",
"ASN1_INTEGER *X509_get_serialNumber(X509 *x);",
"""/**
 * @brief Return the mutable serial number field of a certificate.
 * @param x Certificate to query.
 * @return Internal ASN1_INTEGER pointer (do not free); changes affect @p x.
 */
ASN1_INTEGER *X509_get_serialNumber(X509 *x);""",
"X509_get_serialNumber")

patch_both("x509.h",
"int X509_up_ref(X509 *x);",
"""/**
 * @brief Increment the reference count on an X509 certificate.
 * @param x Certificate to retain.
 * @return 1 on success, or 0 on failure.
 */
int X509_up_ref(X509 *x);""",
"X509_up_ref")

patch_both("x509.h",
"int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);",
"""/**
 * @brief Set the public key on a certificate request from @p pkey.
 * @param x Request to update.
 * @param pkey Public key (or key pair) whose public component is encoded into @p x.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);""",
"X509_REQ_set_pubkey")

patch_both("x509.h",
"int X509_issuer_name_cmp(const X509 *a, const X509 *b);",
"""/**
 * @brief Compare the issuer names of two certificates.
 * @param a First certificate.
 * @param b Second certificate.
 * @return 0 if issuer names are equal, or non-zero like X509_NAME_cmp otherwise.
 */
int X509_issuer_name_cmp(const X509 *a, const X509 *b);""",
"X509_issuer_name_cmp")

patch_both("x509.h",
"int X509_NAME_print(BIO *bp, const X509_NAME *name, int obase);",
"""/**
 * @brief Print an X.509 distinguished name to a BIO with legacy oneline-style wrapping.
 * @param bp Output BIO.
 * @param name Name to print.
 * @param obase Indentation / base column used when wrapping long lines.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_print(BIO *bp, const X509_NAME *name, int obase);""",
"X509_NAME_print")

patch_both("x509.h",
"X509 *X509_find_by_subject(STACK_OF(X509) *sk, const X509_NAME *name);",
"""/**
 * @brief Find the first certificate in a stack whose subject name equals @p name.
 * @param sk Stack of certificates to search.
 * @param name Subject distinguished name to match.
 * @return Matching X509 from @p sk (do not free), or NULL if none matches.
 */
X509 *X509_find_by_subject(STACK_OF(X509) *sk, const X509_NAME *name);""",
"X509_find_by_subject")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(PBEPARAM)",
asn1_funcs("PBEPARAM", "PKCS#5 PBES1 parameter structure (salt and iteration count)"),
"PBEPARAM")

patch_both("x509.h",
"""X509_ALGOR *PKCS5_pbe2_set_iv_ex(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen,
    unsigned char *aiv, int prf_nid,
    OSSL_LIB_CTX *libctx);""",
"""/**
 * @brief Build a PBES2 AlgorithmIdentifier with explicit IV and library context.
 * @param cipher Content-encryption cipher for the PBES2 encryption scheme.
 * @param iter PBKDF2 iteration count; <=0 selects the default.
 * @param salt Optional salt bytes; NULL generates a random salt of @p saltlen.
 * @param saltlen Salt length in bytes when @p salt is NULL / length of @p salt.
 * @param aiv Optional IV bytes for @p cipher; NULL generates a random IV.
 * @param prf_nid PBKDF2 PRF NID (for example NID_hmacWithSHA256), or -1 for the default.
 * @param libctx Library context for random/algorithm fetches, or NULL for the default.
 * @return New X509_ALGOR encoding PBES2 parameters, or NULL on error.
 */
X509_ALGOR *PKCS5_pbe2_set_iv_ex(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen,
    unsigned char *aiv, int prf_nid,
    OSSL_LIB_CTX *libctx);""",
"PKCS5_pbe2_set_iv_ex")

patch_both("x509.h",
"""EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Convert PKCS#8 private key info into an EVP_PKEY using a library context.
 * @param p8 PKCS#8 PrivateKeyInfo structure to decode.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return New EVP_PKEY, or NULL on error.
 */
EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"EVP_PKCS82PKEY_ex")

# ----- x509_vfy.h -----
patch_both("x509_vfy.h",
"""typedef struct x509_trust_st {
    int trust;
    int flags;""",
"""typedef struct x509_trust_st {
    /** Trust purpose NID (X509_TRUST_*). */
    int trust;
    /** Behaviour flags for this trust entry (X509_TRUST_DYNAMIC and related). */
    int flags;""",
"X509_TRUST_flags")

patch_both("x509_vfy.h",
"typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);",
"""/**
 * @brief Callback that verifies a certificate chain in an X509_STORE_CTX.
 * @param ctx Store context whose chain and trust settings are used.
 * @return 1 if verification succeeds, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *ctx);""",
"X509_STORE_CTX_verify_fn")

patch_both("x509_vfy.h",
"""typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
    X509_STORE_CTX *ctx, X509 *x);""",
"""/**
 * @brief Callback that finds an issuer certificate for @p x.
 * @param issuer Receives the issuer certificate (typically with an incremented reference).
 * @param ctx Store context providing lookup state.
 * @param x Certificate whose issuer is sought.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
    X509_STORE_CTX *ctx, X509 *x);""",
"X509_STORE_CTX_get_issuer_fn")

patch_both("x509_vfy.h",
"int X509_STORE_up_ref(X509_STORE *xs);",
"""/**
 * @brief Increment the reference count on an X509_STORE.
 * @param xs Certificate store to retain.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_up_ref(X509_STORE *xs);""",
"X509_STORE_up_ref")

patch_both("x509_vfy.h",
"X509_VERIFY_PARAM *X509_STORE_get0_param(const X509_STORE *xs);",
"""/**
 * @brief Return the verification parameters associated with a certificate store.
 * @param xs Store to query.
 * @return Internal X509_VERIFY_PARAM pointer (do not free), or NULL if unset.
 */
X509_VERIFY_PARAM *X509_STORE_get0_param(const X509_STORE *xs);""",
"X509_STORE_get0_param")

patch_both("x509_vfy.h",
"""void X509_STORE_set_get_issuer(X509_STORE *xs,
    X509_STORE_CTX_get_issuer_fn get_issuer);""",
"""/**
 * @brief Set the get-issuer callback used by store contexts created from @p xs.
 * @param xs Certificate store to configure.
 * @param get_issuer Callback that locates issuer certificates, or NULL for the default.
 */
void X509_STORE_set_get_issuer(X509_STORE *xs,
    X509_STORE_CTX_get_issuer_fn get_issuer);""",
"X509_STORE_set_get_issuer")

patch_both("x509_vfy.h",
"void *X509_STORE_get_ex_data(const X509_STORE *xs, int idx);",
"""/**
 * @brief Retrieve application data previously stored on an X509_STORE.
 * @param xs Store to query.
 * @param idx Index from CRYPTO_get_ex_new_index() for X509_STORE.
 * @return Stored pointer, or NULL if unset.
 */
void *X509_STORE_get_ex_data(const X509_STORE *xs, int idx);""",
"X509_STORE_get_ex_data")

patch_both("x509_vfy.h",
"X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(const X509_STORE_CTX *ctx);",
"""/**
 * @brief Return the chain-verification callback installed on a store context.
 * @param ctx Store context to query.
 * @return Verify callback pointer, or NULL if the default should be used.
 */
X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(const X509_STORE_CTX *ctx);""",
"X509_STORE_CTX_get_verify")

patch_both("x509_vfy.h",
"""typedef int (*X509_LOOKUP_ctrl_ex_fn)(
    X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"""/**
 * @brief Extended control callback for an X509_LOOKUP_METHOD (with library context).
 * @param ctx Lookup object receiving the command.
 * @param cmd Control command such as X509_L_FILE_LOAD.
 * @param argc String argument for @p cmd, or NULL.
 * @param argl Integer argument for @p cmd.
 * @param ret Optional address receiving a result string, or NULL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Command-specific positive value on success, or non-positive on failure.
 */
typedef int (*X509_LOOKUP_ctrl_ex_fn)(
    X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"X509_LOOKUP_ctrl_ex_fn")

patch_both("x509_vfy.h",
"""int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_subject_fn fn);""",
"""/**
 * @brief Set the get-by-subject callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param fn Callback that finds objects by subject name, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_subject_fn fn);""",
"X509_LOOKUP_meth_set_get_by_subject")

patch_both("x509_vfy.h",
"void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *, X509_VERIFY_PARAM *);",
"""/**
 * @brief Move the peername string from @p from onto @p to, clearing the source.
 * @param to Destination parameters that receive ownership of the peername.
 * @param from Source parameters, or NULL to clear and free @p to's peername only.
 */
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *to, X509_VERIFY_PARAM *from);""",
"X509_VERIFY_PARAM_move_peername")

# ----- x509v3.h -----
patch_both("x509v3.h",
"typedef void *(*X509V3_EXT_D2I)(void *, const unsigned char **, long);",
"""/**
 * @brief Decode an X.509v3 extension value from DER.
 * @param ext Optional existing extension value to reuse, or NULL to allocate.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Extension-specific value, or NULL on error.
 */
typedef void *(*X509V3_EXT_D2I)(void *ext, const unsigned char **in, long len);""",
"X509V3_EXT_D2I")

patch_both("x509v3.h",
"    void *usr_data; /* Any extension specific data */",
"""    /** Extension-specific data pointer for method callbacks. */
    void *usr_data;""",
"usr_data")

patch_both("x509v3.h",
"""int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
    const char *section, X509_CRL *crl);""",
"""/**
 * @brief Add CRL extensions described by a config section to a CRL.
 * @param conf Configuration hash containing @p section.
 * @param ctx Extension context (issuer, CRL, flags) for extension construction.
 * @param section Name of the config section listing extensions.
 * @param crl CRL that receives the extensions.
 * @return 1 on success, or 0 on failure.
 */
int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
    const char *section, X509_CRL *crl);""",
"X509V3_EXT_CRL_add_conf")

print(f"\nDone 8c: {len(ok)} ok, {len(missing)} missing")
if missing:
    print("MISSING:", *missing, sep="\n  ")
