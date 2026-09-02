#!/usr/bin/env python3
"""Documentation repair batch 19d: evp, lhash, params, pem, pkcs7, rsa, srtp, ssl, tls1."""
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


def patch_one(rel, old, new, label):
    path = INC / rel
    if not path.exists():
        print(f"  MISS: {rel} :: {label}:no-file")
        missing.append(f"{rel}:{label}:no-file")
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(f"{path.name}:{label}")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {path.name} :: {label}")
    ok.append(f"{path.name}:{label}")


print("=== batch 19d: evp/lhash/params/pem/pkcs7/rsa/srtp/ssl/tls1 ===")

# ----- evp.h -----

patch_one(
    "evp.h",
    """int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Set the default property query string used for algorithm fetches in @p libctx.
 * @param libctx Library context to update, or NULL for the default context.
 * @param propq Property query string (for example "fips=yes"), or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "EVP_set_default_properties",
)

patch_one(
    "evp.h",
    """int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable);
""",
    """/**
 * @brief Enable or disable the FIPS constraint in a library context's default properties.
 * @param libctx Library context to update, or NULL for the default context.
 * @param enable Non-zero to require FIPS algorithms in default fetches, or 0 to clear that constraint.
 * @return 1 on success, or 0 on failure.
 */
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable);
""",
    "EVP_default_properties_enable_fips",
)

patch_one(
    "evp.h",
    """int EVP_MD_get_size(const EVP_MD *md);
""",
    """/**
 * @brief Return the output size of a message digest in bytes.
 * @param md Digest method to query.
 * @return Digest length in bytes, or a negative value if unavailable / for unbounded XOFs.
 */
int EVP_MD_get_size(const EVP_MD *md);
""",
    "EVP_MD_get_size",
)

patch_one(
    "evp.h",
    """__owur int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);
""",
    """/**
 * @brief Finalize an XOF digest and write @p outlen bytes of output.
 * @param ctx Digest context after EVP_DigestUpdate() (for example SHAKE).
 * @param out Buffer that receives @p outlen bytes of XOF output.
 * @param outlen Number of output bytes to produce.
 * @return 1 on success, or 0 on failure.
 */
__owur int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *out,
    size_t outlen);
""",
    "EVP_DigestFinalXOF",
)

patch_one(
    "evp.h",
    """int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
""",
    """/**
 * @brief Decode a chunk of Base64 input into @p out, updating the decode context.
 * @param ctx Decode context previously initialized with EVP_DecodeInit().
 * @param out Buffer receiving decoded octets for this chunk.
 * @param outl Receives the number of bytes written to @p out.
 * @param in Base64 input characters for this update.
 * @param inl Number of bytes in @p in.
 * @return 1 if more data may follow, 0 if an EOF marker was seen, or -1 on error.
 */
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
""",
    "EVP_DecodeUpdate",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_des_ede_cbc(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for two-key triple-DES in CBC mode.
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_des_ede_cbc(void);
""",
    "EVP_des_ede_cbc",
)

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_seed_cbc(void);
""",
    """/**
 * @brief Return the SEED cipher in CBC mode.
 * @return EVP_CIPHER for seed-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_seed_cbc(void);
""",
    "EVP_seed_cbc",
)

patch_one(
    "evp.h",
    """size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx);
""",
    """/**
 * @brief Return the MAC output size for the algorithm bound to @p ctx.
 * @param ctx Initialized MAC context.
 * @return Tag/MAC length in bytes, or 0 if unavailable.
 */
size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx);
""",
    "EVP_MAC_CTX_get_mac_size",
)

patch_one(
    "evp.h",
    """const char *EVP_KEM_get0_description(const EVP_KEM *wrap);
""",
    """/**
 * @brief Return a human-readable description of a fetched KEM algorithm.
 * @param wrap KEM implementation from EVP_KEM_fetch().
 * @return Internal description string, or NULL; do not free.
 */
const char *EVP_KEM_get0_description(const EVP_KEM *wrap);
""",
    "EVP_KEM_get0_description",
)

patch_one(
    "evp.h",
    """int EVP_PKEY_todata(const EVP_PKEY *pkey, int selection, OSSL_PARAM **params);
""",
    """/**
 * @brief Export selected key components from an EVP_PKEY as a newly allocated OSSL_PARAM array.
 * @param pkey Provider-backed key to export.
 * @param selection OSSL_KEYMGMT_SELECT_* mask describing which parts to export.
 * @param params Receives a newly allocated parameter array; free with OSSL_PARAM_free().
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_todata(const EVP_PKEY *pkey, int selection, OSSL_PARAM **params);
""",
    "EVP_PKEY_todata",
)

# ----- lhash.h / lhash.h.in -----

patch_both(
    "lhash.h",
    """typedef unsigned long (*OPENSSL_LH_HASHFUNC)(const void *);
""",
    """/**
 * @brief Hash callback that maps an LHASH element pointer to an unsigned long hash value.
 */
typedef unsigned long (*OPENSSL_LH_HASHFUNC)(const void *);
""",
    "OPENSSL_LH_HASHFUNC",
)

patch_both(
    "lhash.h",
    """typedef void (*OPENSSL_LH_DOALL_FUNC_THUNK)(void *, OPENSSL_LH_DOALL_FUNC doall);
""",
    """/**
 * @brief Adapter that invokes a typed OPENSSL_LH_DOALL_FUNC on a void* element.
 */
typedef void (*OPENSSL_LH_DOALL_FUNC_THUNK)(void *, OPENSSL_LH_DOALL_FUNC doall);
""",
    "OPENSSL_LH_DOALL_FUNC_THUNK",
)

patch_both(
    "lhash.h",
    """typedef void (*OPENSSL_LH_DOALL_FUNCARG)(void *, void *);
""",
    """/**
 * @brief Callback applied to each element by OPENSSL_LH_doall_arg() with a user argument.
 */
typedef void (*OPENSSL_LH_DOALL_FUNCARG)(void *, void *);
""",
    "OPENSSL_LH_DOALL_FUNCARG",
)

patch_both(
    "lhash.h",
    """OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c);
""",
    """/**
 * @brief Allocate a new LHASH table using hash function @p h and compare function @p c.
 * @param h Hash callback for elements stored in the table.
 * @param c Comparison callback returning 0 for equal elements.
 * @return Newly allocated OPENSSL_LHASH, or NULL on failure.
 */
OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c);
""",
    "OPENSSL_LH_new",
)

patch_both(
    "lhash.h",
    """OPENSSL_LHASH *OPENSSL_LH_set_thunks(OPENSSL_LHASH *lh,
    OPENSSL_LH_HASHFUNCTHUNK hw,
    OPENSSL_LH_COMPFUNCTHUNK cw,
    OPENSSL_LH_DOALL_FUNC_THUNK daw,
    OPENSSL_LH_DOALL_FUNCARG_THUNK daaw);
""",
    """/**
 * @brief Install type-safe thunk adapters used by DEFINE_LHASH_OF wrappers on @p lh.
 * @param lh Hash table to configure (often freshly created by OPENSSL_LH_new()).
 * @param hw Thunk that applies a typed hash function to a void* element.
 * @param cw Thunk that applies a typed compare function to void* elements.
 * @param daw Thunk that applies a typed doall callback to a void* element.
 * @param daaw Thunk that applies a typed doall-arg callback to void* element/arg.
 * @return @p lh on success (for chaining), or NULL on failure.
 */
OPENSSL_LHASH *OPENSSL_LH_set_thunks(OPENSSL_LHASH *lh,
    OPENSSL_LH_HASHFUNCTHUNK hw,
    OPENSSL_LH_COMPFUNCTHUNK cw,
    OPENSSL_LH_DOALL_FUNC_THUNK daw,
    OPENSSL_LH_DOALL_FUNCARG_THUNK daaw);
""",
    "OPENSSL_LH_set_thunks",
)

patch_both(
    "lhash.h",
    """void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data);
""",
    """/**
 * @brief Look up the entry matching @p data in an LHASH.
 * @param lh Hash table to search.
 * @param data Key/element used for lookup (compared via the table's compare function).
 * @return Matching element pointer, or NULL if not found.
 */
void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data);
""",
    "OPENSSL_LH_retrieve",
)

patch_both(
    "lhash.h",
    """void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func);
""",
    """/**
 * @brief Call @p func once for every element currently stored in an LHASH.
 * @param lh Hash table to traverse.
 * @param func Callback invoked with each element pointer.
 */
void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func);
""",
    "OPENSSL_LH_doall",
)

patch_both(
    "lhash.h",
    """OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
""",
    """/**
 * @brief Print hash-bucket usage / load statistics for a hash table to a BIO (deprecated).
 * @param lh Hash table to describe.
 * @param out BIO that receives the human-readable report.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
""",
    "OPENSSL_LH_node_usage_stats_bio",
)

# ----- params.h -----

patch_one(
    "params.h",
    """int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val);
""",
    """/**
 * @brief Write @p val into parameter @p as an unsigned long (with range checks).
 * @param p Destination parameter located by key in an OSSL_PARAM array.
 * @param val Value to store.
 * @return 1 on success, or 0 if @p is NULL, wrong type, or out of range.
 */
int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val);
""",
    "OSSL_PARAM_set_ulong",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val, size_t len);
""",
    """/**
 * @brief Copy @p len octets from @p val into an octet-string OSSL_PARAM.
 * @param p Parameter locator with type OSSL_PARAM_OCTET_STRING.
 * @param val Source buffer of @p len bytes.
 * @param len Number of bytes to copy from @p val.
 * @return 1 on success, or 0 on type/size failure.
 */
int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val, size_t len);
""",
    "OSSL_PARAM_set_octet_string",
)

# ----- pem.h -----

patch_one(
    "pem.h",
    """int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
""",
    """/**
 * @brief Read a named PEM object from a BIO into secure memory, decrypting if needed.
 * @param pdata Receives newly allocated DER payload in secure memory (caller frees with OPENSSL_secure_free).
 * @param plen Receives the length of *@p pdata in bytes.
 * @param pnm Optional; receives the actual PEM type name from the BEGIN line (caller frees).
 * @param name Expected PEM type label (for example "CERTIFICATE"); non-matching types are skipped.
 * @param bp BIO to read from.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
""",
    "PEM_bytes_read_bio_secmem",
)

# ----- pkcs7.h / pkcs7.h.in -----

patch_both(
    "pkcs7.h",
    """        /* Anything else */
        ASN1_TYPE *other;
""",
    """        /* Anything else */
        /** Catch-all content for unrecognized PKCS#7 types (ASN.1 ANY). */
        ASN1_TYPE *other;
""",
    "PKCS7.d.other",
)

patch_both(
    "pkcs7.h",
    """BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
""",
    """/**
 * @brief Create a BIO chain for writing content into a PKCS#7 structure (digest/encrypt filters).
 * @param p7 PKCS#7 object being signed, enveloped, digested, or encrypted.
 * @param bio Optional BIO supplying detached content, or NULL to embed content in @p p7.
 * @return BIO to which application data should be written, or NULL on failure.
 */
BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
""",
    "PKCS7_dataInit",
)

# ----- rsa.h -----

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_multi_prime_keygen(RSA_METHOD *meth,
    int (*keygen)(RSA *rsa, int bits,
        int primes, BIGNUM *e,
        BN_GENCB *cb));
""",
    """/**
 * @brief Set the multi-prime key-generation callback on a custom RSA_METHOD (deprecated).
 * @param meth Method object to update.
 * @param keygen Callback implementing multi-prime RSA key generation, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_multi_prime_keygen(RSA_METHOD *meth,
    int (*keygen)(RSA *rsa, int bits,
        int primes, BIGNUM *e,
        BN_GENCB *cb));
""",
    "RSA_meth_set_multi_prime_keygen",
)

# ----- srtp.h -----

patch_one(
    "srtp.h",
    """__owur int SSL_set_tlsext_use_srtp(SSL *ssl, const char *profiles);
""",
    """/**
 * @brief Set the DTLS use_srtp extension protection profiles for a connection.
 * @param ssl SSL/DTLS connection to configure.
 * @param profiles Colon-separated list of SRTP profile names.
 * @return 0 on success, or 1 on error.
 */
__owur int SSL_set_tlsext_use_srtp(SSL *ssl, const char *profiles);
""",
    "SSL_set_tlsext_use_srtp",
)

# ----- ssl.h / ssl.h.in -----

patch_both(
    "ssl.h",
    """void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
    SSL_CTX_npn_advertised_cb_func cb,
    void *arg);
""",
    """/**
 * @brief Set the Next Protocol Negotiation (NPN) advertisement callback for servers.
 * @param s SSL context used by NPN servers.
 * @param cb Callback that supplies the protocol list to advertise, or NULL to clear.
 * @param arg User pointer forwarded to @p cb.
 */
void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
    SSL_CTX_npn_advertised_cb_func cb,
    void *arg);
""",
    "SSL_CTX_set_next_protos_advertised_cb",
)

patch_both(
    "ssl.h",
    """int SSL_SESSION_print(BIO *fp, const SSL_SESSION *ses);
""",
    """/**
 * @brief Print a human-readable summary of an SSL_SESSION to a BIO.
 * @param fp Output BIO.
 * @param ses Session to describe.
 * @return 1 on success, or 0 on failure.
 */
int SSL_SESSION_print(BIO *fp, const SSL_SESSION *ses);
""",
    "SSL_SESSION_print",
)

patch_both(
    "ssl.h",
    """void *SSL_get_default_passwd_cb_userdata(SSL *s);
""",
    """/**
 * @brief Return the user-data pointer passed to an SSL object's PEM password callback.
 * @param s SSL connection to query.
 * @return Pointer previously set with SSL_set_default_passwd_cb_userdata(), or NULL.
 */
void *SSL_get_default_passwd_cb_userdata(SSL *s);
""",
    "SSL_get_default_passwd_cb_userdata",
)

patch_both(
    "ssl.h",
    """/*
 * Bridge opacity barrier between libcrypt and libssl, also needed to support
 * offline testing in test/danetest.c
 */
SSL_DANE *SSL_get0_dane(SSL *ssl);
""",
    """/**
 * @brief Return the internal SSL_DANE state for @p ssl (libcrypto/libssl bridge).
 * @param ssl SSL connection whose DANE state is queried.
 * @return Internal SSL_DANE pointer owned by @p ssl; do not free. Also used by offline DANE tests.
 */
SSL_DANE *SSL_get0_dane(SSL *ssl);
""",
    "SSL_get0_dane",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb,
    void *arg);
""",
    """/**
 * @brief Install a server callback invoked after each ClientHello is parsed.
 * @param c Server SSL context that receives ClientHellos.
 * @param cb Callback of type SSL_client_hello_cb_fn, or NULL to clear.
 * @param arg Application pointer forwarded to @p cb.
 */
void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb,
    void *arg);
""",
    "SSL_CTX_set_client_hello_cb",
)

patch_both(
    "ssl.h",
    """size_t SSL_client_hello_get0_session_id(SSL *s, const unsigned char **out);
""",
    """/**
 * @brief Return the session_id field from the ClientHello being processed.
 * @param s SSL object during a client-hello callback.
 * @param out Receives a pointer to the session id octets; do not free.
 * @return Length of the session id in bytes, or 0 if unavailable.
 */
size_t SSL_client_hello_get0_session_id(SSL *s, const unsigned char **out);
""",
    "SSL_client_hello_get0_session_id",
)

patch_both(
    "ssl.h",
    """__owur int SSL_write_ex2(SSL *s, const void *buf, size_t num,
    uint64_t flags,
    size_t *written);
""",
    """/**
 * @brief Write application data to a TLS/SSL/QUIC connection with extended write flags.
 * @param s SSL connection to write to.
 * @param buf Source buffer of plaintext to encrypt and send.
 * @param num Number of bytes from @p buf to write.
 * @param flags Write flags such as SSL_WRITE_FLAG_CONCLUDE.
 * @param written On success, receives the number of bytes written.
 * @return 1 on success, or 0 on failure / want-IO (see SSL_get_error).
 */
__owur int SSL_write_ex2(SSL *s, const void *buf, size_t num,
    uint64_t flags,
    size_t *written);
""",
    "SSL_write_ex2",
)

patch_both(
    "ssl.h",
    """int SSL_key_update(SSL *s, int updatetype);
""",
    """/**
 * @brief Schedule a TLS 1.3 / QUIC key update of the requested type on @p s.
 * @param s SSL connection that has negotiated TLSv1.3 (or QUIC).
 * @param updatetype SSL_KEY_UPDATE_REQUESTED or SSL_KEY_UPDATE_NOT_REQUESTED.
 * @return 1 on success, or 0 on error.
 */
int SSL_key_update(SSL *s, int updatetype);
""",
    "SSL_key_update",
)

patch_both(
    "ssl.h",
    """__owur X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx);
""",
    """/**
 * @brief Return the local certificate configured on an SSL context (if any).
 * @param ctx SSL context to query.
 * @return X509 for the context's local identity, or NULL; do not free.
 */
__owur X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx);
""",
    "SSL_CTX_get0_certificate",
)

patch_both(
    "ssl.h",
    """__owur int SSL_CTX_set_default_verify_file(SSL_CTX *ctx);
""",
    """/**
 * @brief Load only the default CA certificate file into an SSL context's trust store.
 * @param ctx SSL context that receives the default certs file (or SSL_CERT_FILE).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_default_verify_file(SSL_CTX *ctx);
""",
    "SSL_CTX_set_default_verify_file",
)

patch_both(
    "ssl.h",
    """const char *OSSL_default_ciphersuites(void);
""",
    """/**
 * @brief Return the built-in default TLSv1.3 ciphersuite list string.
 * @return NUL-terminated ciphersuite list used when no explicit list is configured.
 */
const char *OSSL_default_ciphersuites(void);
""",
    "OSSL_default_ciphersuites",
)

# ----- tls1.h -----

patch_one(
    "tls1.h",
    """int SSL_CTX_set_tlsext_ticket_key_evp_cb(SSL_CTX *ctx, int (*fp)(SSL *, unsigned char *, unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int));
""",
    """/**
 * @brief Set the TLS session-ticket key callback using EVP cipher and MAC contexts.
 * @param ctx SSL context whose ticket encryption keys are managed by @p fp.
 * @param fp Callback invoked to initialize encrypt/decrypt/HMAC state for ticket processing, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int SSL_CTX_set_tlsext_ticket_key_evp_cb(SSL_CTX *ctx, int (*fp)(SSL *, unsigned char *, unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int));
""",
    "SSL_CTX_set_tlsext_ticket_key_evp_cb",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
