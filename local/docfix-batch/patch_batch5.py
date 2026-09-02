#!/usr/bin/env python3
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

# Remaining EVP
patch_both("evp.h",
"int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);",
"""/**
 * @brief Encode the cipher context IV into an ASN.1 OCTET STRING inside @p type.
 * @param c Cipher context whose IV is serialized.
 * @param type ASN1_TYPE that receives an OCTET STRING encoding of the IV.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);""",
"EVP_CIPHER_set_asn1_iv")

patch_both("evp.h",
"""int EVP_PBE_scrypt(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen);""",
"""/**
 * @brief Derive a key with scrypt from a password and salt.
 * @param pass Password bytes (may be NULL when @p passlen is 0).
 * @param passlen Length of @p pass in bytes.
 * @param salt Salt octets.
 * @param saltlen Length of @p salt in bytes.
 * @param N CPU/memory cost parameter (power of two).
 * @param r Block size parameter.
 * @param p Parallelization parameter.
 * @param maxmem Memory limit in bytes (0 selects the library default).
 * @param key Output buffer for the derived key.
 * @param keylen Desired derived-key length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_scrypt(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen);""",
"EVP_PBE_scrypt")

patch_both("evp.h",
"""int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de);""",
"""/**
 * @brief Initialize @p ctx for PBE using scrypt parameters from ASN.1 (PKCS#5 v2).
 * @param ctx Cipher context to initialize.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if NUL-terminated.
 * @param param ASN.1 parameters describing salt and scrypt settings.
 * @param c Content cipher to initialize.
 * @param md Unused for scrypt (may be NULL); retained for keygen callback signature compatibility.
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de);""",
"PKCS5_v2_scrypt_keyivgen")

patch_both("evp.h",
"""int PKCS5_v2_scrypt_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"""/**
 * @brief Initialize @p ctx for scrypt-based PBE using a library context.
 * @param ctx Cipher context to initialize.
 * @param pass Password bytes.
 * @param passlen Length of @p pass, or -1 if NUL-terminated.
 * @param param ASN.1 parameters describing salt and scrypt settings.
 * @param c Content cipher to initialize.
 * @param md Unused for scrypt (may be NULL).
 * @param en_de 1 to encrypt, or 0 to decrypt.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int PKCS5_v2_scrypt_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass,
    int passlen, ASN1_TYPE *param,
    const EVP_CIPHER *c, const EVP_MD *md, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"PKCS5_v2_scrypt_keyivgen_ex")

patch_both("evp.h",
"""int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
    int md_nid, EVP_PBE_KEYGEN *keygen);""",
"""/**
 * @brief Register a password-based encryption algorithm by type and NIDs.
 * @param pbe_type PBE category such as EVP_PBE_TYPE_OUTER or EVP_PBE_TYPE_PRF.
 * @param pbe_nid NID of the PBE algorithm OID being registered.
 * @param cipher_nid Cipher NID used by the algorithm, or -1 if none.
 * @param md_nid Digest NID used by the algorithm, or -1 if none.
 * @param keygen Key/IV derivation callback invoked for this PBE algorithm.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
    int md_nid, EVP_PBE_KEYGEN *keygen);""",
"EVP_PBE_alg_add_type")

patch_both("evp.h",
"int EVP_PKEY_asn1_get_count(void);",
"""/**
 * @brief Return the number of registered EVP_PKEY_ASN1_METHOD implementations.
 * @return Count of ASN.1 methods available via EVP_PKEY_asn1_get0().
 */
int EVP_PKEY_asn1_get_count(void);""",
"EVP_PKEY_asn1_get_count")

patch_both("evp.h",
"""void EVP_PKEY_asn1_set_param_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_param_check)(const EVP_PKEY *pk));""",
"""/**
 * @brief Install a callback that validates algorithm parameters on an EVP_PKEY.
 * @param ameth ASN.1 method object to update.
 * @param pkey_param_check Function that returns 1 if @p pk parameters are valid.
 */
void EVP_PKEY_asn1_set_param_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_param_check)(const EVP_PKEY *pk));""",
"EVP_PKEY_asn1_set_param_check")

patch_both("evp.h",
"int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len);",
"""/**
 * @brief Return the length of an algorithm-specific ID associated with a key context.
 * @param ctx Key context that holds an ID (for example SM2 user id).
 * @param id_len Receives the ID length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len);""",
"EVP_PKEY_CTX_get1_id_len")

patch_both("evp.h",
"int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX *ctx, const char *op);",
"""/**
 * @brief Select the KEM operation mode on a key context (for example "encapsulate").
 * @param ctx Key context prepared for a KEM algorithm.
 * @param op Operation name understood by the provider.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX *ctx, const char *op);""",
"EVP_PKEY_CTX_set_kem_op")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
    const EVP_PKEY_METHOD *meth);""",
"""/**
 * @brief Read the algorithm id and flags from an EVP_PKEY_METHOD (deprecated).
 * @param ppkey_id Optional output receiving the method's EVP_PKEY_* id.
 * @param pflags Optional output receiving the method flags.
 * @param meth Method object to query.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
    const EVP_PKEY_METHOD *meth);""",
"EVP_PKEY_meth_get0_info")

patch_both("evp.h",
"const char *EVP_KEYMGMT_get0_description(const EVP_KEYMGMT *keymgmt);",
"""/**
 * @brief Return a human-readable description of a keymgmt implementation.
 * @param keymgmt Key management method to query.
 * @return Description string, or NULL if none is available.
 */
const char *EVP_KEYMGMT_get0_description(const EVP_KEYMGMT *keymgmt);""",
"EVP_KEYMGMT_get0_description")

patch_both("evp.h",
"""void EVP_KEYMGMT_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYMGMT *keymgmt, void *arg),
    void *arg);""",
"""/**
 * @brief Invoke @p fn for every KEYMGMT implementation available in @p libctx.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each keymgmt and @p arg.
 * @param arg Opaque pointer forwarded to @p fn.
 */
void EVP_KEYMGMT_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEYMGMT *keymgmt, void *arg),
    void *arg);""",
"EVP_KEYMGMT_do_all_provided")

patch_both("evp.h",
"EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);",
"""/**
 * @brief Allocate a key context for algorithm @p id, optionally using an ENGINE.
 * @param id Algorithm identifier such as EVP_PKEY_RSA.
 * @param e ENGINE implementing the algorithm, or NULL for the default implementation.
 * @return New EVP_PKEY_CTX, or NULL on failure.
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);""",
"EVP_PKEY_CTX_new_id")

patch_both("evp.h",
"""EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey, const char *propquery);""",
"""/**
 * @brief Allocate a key context for operations on an existing EVP_PKEY.
 * @param libctx Library context used to fetch algorithms, or NULL for the default.
 * @param pkey Key that determines the algorithm and provides key material.
 * @param propquery Property query for algorithm fetches, or NULL.
 * @return New EVP_PKEY_CTX, or NULL on failure.
 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey, const char *propquery);""",
"EVP_PKEY_CTX_new_from_pkey")

patch_both("evp.h",
"""int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, uint64_t value);""",
"""/**
 * @brief Send a control command with a uint64_t argument to a key context.
 * @param ctx Key context receiving the command.
 * @param keytype Expected key type, or -1 to skip the type check.
 * @param optype Expected operation type, or -1 to skip the operation check.
 * @param cmd Algorithm-specific control command.
 * @param value 64-bit integer argument for @p cmd.
 * @return Positive value on success, or a non-positive value on failure / unsupported command.
 */
int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, uint64_t value);""",
"EVP_PKEY_CTX_ctrl_uint64")

patch_both("evp.h",
"int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);",
"""/**
 * @brief Set a digest algorithm on a key context by name for the given operation.
 * @param ctx Key context to update.
 * @param optype Operation type such as EVP_PKEY_OP_TYPE_SIG.
 * @param cmd Control command that expects an EVP_MD (for example EVP_PKEY_CTRL_MD).
 * @param md Digest name such as "SHA256".
 * @return Positive value on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);""",
"EVP_PKEY_CTX_md")

patch_both("evp.h",
"int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);",
"""/**
 * @brief Initialize @p ctx for decryption and apply optional algorithm parameters.
 * @param ctx Key context associated with the decryption key.
 * @param params Optional OSSL_PARAM array configuring the operation, or NULL.
 * @return 1 on success, or 0 / negative on failure.
 */
int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);""",
"EVP_PKEY_decrypt_init_ex")

patch_both("evp.h",
"""int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name,
    BIGNUM **bn);""",
"""/**
 * @brief Fetch a named BIGNUM parameter from an EVP_PKEY.
 * @param pkey Key to query.
 * @param key_name Parameter name (OSSL_PKEY_PARAM_*).
 * @param bn On success, set to a newly allocated BIGNUM (caller frees with BN_free()).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name,
    BIGNUM **bn);""",
"EVP_PKEY_get_bn_param")

patch_both("evp.h",
"int EVP_PKEY_set_params(EVP_PKEY *pkey, OSSL_PARAM params[]);",
"""/**
 * @brief Set multiple algorithm parameters on an EVP_PKEY from an OSSL_PARAM array.
 * @param pkey Key to update.
 * @param params Parameters to apply (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_params(EVP_PKEY *pkey, OSSL_PARAM params[]);""",
"EVP_PKEY_set_params")

patch_both("evp.h",
"EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Return the keygen progress callback currently installed on a key context.
 * @param ctx Key context to query.
 * @return Callback pointer, or NULL if none is set.
 */
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_CTX_get_cb")

patch_both("evp.h",
"int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);",
"""/**
 * @brief Return a key-generation progress info value previously published on @p ctx.
 * @param ctx Key context during or after keygen.
 * @param idx Info index; -1 returns the number of available values.
 * @return Info value at @p idx, or the count when @p idx is -1.
 */
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);""",
"EVP_PKEY_CTX_get_keygen_info")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth, int (**pinit)(EVP_PKEY_CTX *ctx));",
"""/**
 * @brief Retrieve the init callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method object to query.
 * @param pinit Receives the function pointer that initializes an EVP_PKEY_CTX.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth, int (**pinit)(EVP_PKEY_CTX *ctx));""",
"EVP_PKEY_meth_get_init")

patch_both("evp.h",
"int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name);",
"""/**
 * @brief Test whether a key-exchange implementation is known by @p name.
 * @param keyexch Key-exchange method to query.
 * @param name Algorithm name or alias.
 * @return 1 if @p keyexch matches @p name, or 0 otherwise.
 */
int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name);""",
"EVP_KEYEXCH_is_a")

# ssl
patch_both("ssl.h",
"""int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509,
    EVP_PKEY **pkey);""",
"""/**
 * @brief Return the client-certificate callback installed on an SSL_CTX.
 * @param ctx SSL context to query.
 * @return Callback that supplies a client certificate and key, or NULL if unset.
 */
int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509,
    EVP_PKEY **pkey);""",
"SSL_CTX_get_client_cert_cb")

patch_both("ssl.h",
"""__owur int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    const unsigned char *client,
    unsigned int client_len);""",
"""/**
 * @brief Select an ALPN/NPN protocol from a server list given client preferences.
 * @param out On success, set to a pointer into @p client for the chosen protocol.
 * @param outlen Receives the length of the chosen protocol.
 * @param in Server-offered protocol list in length-prefixed wire form.
 * @param inlen Length of @p in in bytes.
 * @param client Client-preferred protocol list in length-prefixed wire form.
 * @param client_len Length of @p client in bytes.
 * @return OPENSSL_NPN_NEGOTIATED, OPENSSL_NPN_NO_OVERLAP, or OPENSSL_NPN_UNSUPPORTED.
 */
__owur int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    const unsigned char *client,
    unsigned int client_len);""",
"SSL_select_next_proto")

patch_both("ssl.h",
"void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb);",
"""/**
 * @brief Set the PSK identity callback used by a TLS server SSL object.
 * @param ssl Server SSL connection that will invoke @p cb during a PSK handshake.
 * @param cb Callback that supplies the PSK for a given identity, or NULL to clear.
 */
void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb);""",
"SSL_set_psk_server_callback")

patch_both("ssl.h",
"__owur int SSL_CTX_set_default_verify_store(SSL_CTX *ctx);",
"""/**
 * @brief Load the default trusted certificate store into an SSL context.
 * @param ctx SSL context whose verification store is populated from system defaults.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_CTX_set_default_verify_store(SSL_CTX *ctx);""",
"SSL_CTX_set_default_verify_store")

patch_both("ssl.h",
"""__owur int SSL_SESSION_set1_master_key(SSL_SESSION *sess,
    const unsigned char *in, size_t len);""",
"""/**
 * @brief Set the master secret on an SSL session by copying @p in.
 * @param sess Session whose master key is replaced.
 * @param in Master secret octets.
 * @param len Length of @p in in bytes (must be acceptable for the protocol).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_SESSION_set1_master_key(SSL_SESSION *sess,
    const unsigned char *in, size_t len);""",
"SSL_SESSION_set1_master_key")

patch_both("ssl.h",
"""__owur int SSL_stream_reset(SSL *ssl,
    const SSL_STREAM_RESET_ARGS *args,
    size_t args_len);""",
"""/**
 * @brief Reset a QUIC stream associated with @p ssl, optionally sending an app error code.
 * @param ssl SSL object representing the stream to reset.
 * @param args Optional reset arguments (application error code), or NULL.
 * @param args_len Size of @p args in bytes when non-NULL; use sizeof(*args).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_stream_reset(SSL *ssl,
    const SSL_STREAM_RESET_ARGS *args,
    size_t args_len);""",
"SSL_stream_reset")

patch_both("ssl.h",
"const char *OSSL_default_cipher_list(void);",
"""/**
 * @brief Return the built-in default TLSv1.2 (and earlier) cipher-list string.
 * @return NUL-terminated cipher list used when no explicit list is configured.
 */
const char *OSSL_default_cipher_list(void);""",
"OSSL_default_cipher_list")

# x509 fields / macros / functions
patch_both("x509.h",
"typedef struct X509_sig_st X509_SIG;",
"""/**
 * @brief Opaque DigestInfo / encrypted-key structure used by PKCS#8 and related APIs.
 */
typedef struct X509_sig_st X509_SIG;""",
"X509_SIG")

patch_both("x509.h",
"""typedef struct X509_info_st {
    X509 *x509;
    X509_CRL *crl;
    X509_PKEY *x_pkey;""",
"""typedef struct X509_info_st {
    X509 *x509;
    X509_CRL *crl;
    /** Encrypted private key material associated with this PEM info bundle. */
    X509_PKEY *x_pkey;""",
"X509_INFO::x_pkey")

patch_both("x509.h",
"""    /** @brief CPU/memory cost parameter (N) for scrypt. */
    ASN1_INTEGER *costParameter;
    ASN1_INTEGER *blockSize;
    ASN1_INTEGER *parallelizationParameter;""",
"""    /** @brief CPU/memory cost parameter (N) for scrypt. */
    ASN1_INTEGER *costParameter;
    /** @brief Block-size parameter (r) for scrypt. */
    ASN1_INTEGER *blockSize;
    ASN1_INTEGER *parallelizationParameter;""",
"SCRYPT_PARAMS::blockSize")

patch_both("x509.h",
"X509 *X509_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);",
"""/**
 * @brief Download an X.509 certificate from @p url over HTTP(S).
 * @param url URL of the certificate resource.
 * @param bio Optional BIO used for the outbound connection, or NULL to create one.
 * @param rbio Optional separate read BIO for bidirectional setups, or NULL.
 * @param timeout Transfer timeout in seconds (0 uses the default).
 * @return Decoded X509 certificate, or NULL on error.
 */
X509 *X509_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);""",
"X509_load_http")

patch_both("x509.h",
"OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);",
"""/**
 * @brief Read a DER-encoded RSA private key from a FILE (deprecated).
 * @param fp Input stream positioned at the DER key.
 * @param rsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded RSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);""",
"d2i_RSAPrivateKey_fp")

patch_both("x509.h",
"OSSL_DEPRECATEDIN_3_0 int i2d_DSA_PUBKEY_fp(FILE *fp, const DSA *dsa);",
"""/**
 * @brief Write a DSA public key in SubjectPublicKeyInfo DER form to a FILE (deprecated).
 * @param fp Output stream.
 * @param dsa DSA key whose public key is encoded.
 * @return Number of bytes written, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSA_PUBKEY_fp(FILE *fp, const DSA *dsa);""",
"i2d_DSA_PUBKEY_fp")

patch_both("x509.h",
"X509 *d2i_X509_bio(BIO *bp, X509 **x509);",
"""/**
 * @brief Decode an X.509 certificate in DER form from a BIO.
 * @param bp BIO supplying DER bytes.
 * @param x509 Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509, or NULL on error.
 */
X509 *d2i_X509_bio(BIO *bp, X509 **x509);""",
"d2i_X509_bio")

patch_both("x509.h",
"OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);",
"""/**
 * @brief Decode an RSA public key (SubjectPublicKeyInfo) in DER form from a BIO (deprecated).
 * @param bp BIO supplying DER bytes.
 * @param rsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded RSA public key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);""",
"d2i_RSA_PUBKEY_bio")

patch_both("x509.h",
"int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey);",
"""/**
 * @brief Write a private key in traditional DER form to a BIO.
 * @param bp Destination BIO.
 * @param pkey Private key to encode.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey);""",
"i2d_PrivateKey_bio")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_CINF)",
asn1_funcs("X509_CINF", "X.509 TBSCertificate (X509_CINF) structure"),
"X509_CINF functions")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(X509_REVOKED)",
asn1_funcs("X509_REVOKED", "CRL revoked-certificate entry"),
"X509_REVOKED functions")

patch_both("x509.h",
"const ASN1_TIME *X509_get0_notBefore(const X509 *x);",
"""/**
 * @brief Return the notBefore validity time of a certificate without copying it.
 * @param x Certificate to query.
 * @return Internal ASN1_TIME pointer; do not free.
 */
const ASN1_TIME *X509_get0_notBefore(const X509 *x);""",
"X509_get0_notBefore")

patch_both("x509.h",
"const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x);",
"""/**
 * @brief Return the signature AlgorithmIdentifier from the TBSCertificate.
 * @param x Certificate to query.
 * @return Internal X509_ALGOR pointer; do not free.
 */
const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x);""",
"X509_get0_tbs_sigalg")

patch_both("x509.h",
"int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos);",
"""/**
 * @brief Find the next X.509 request attribute with the given NID.
 * @param req Certificate request to search.
 * @param nid Attribute NID to locate.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Attribute index, or -1 if not found.
 */
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos);""",
"X509_REQ_get_attr_by_NID")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(PBE2PARAM)",
asn1_funcs("PBE2PARAM", "PKCS#5 PBES2 parameter structure"),
"PBE2PARAM functions")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)",
asn1_funcs("PBKDF2PARAM", "PKCS#5 PBKDF2 parameter structure"),
"PBKDF2PARAM functions")

patch_both("x509.h",
"DECLARE_ASN1_FUNCTIONS(SCRYPT_PARAMS)",
asn1_funcs("SCRYPT_PARAMS", "PKCS#5 scrypt parameter structure"),
"SCRYPT_PARAMS functions")

patch_both("x509.h",
"""void X509_PUBKEY_set0_public_key(X509_PUBKEY *pub,
    unsigned char *penc, int penclen);""",
"""/**
 * @brief Set the encoded public-key bit string on an X509_PUBKEY, transferring ownership of @p penc.
 * @param pub Public-key container to update.
 * @param penc DER-encoded public key bits; ownership transfers to @p pub.
 * @param penclen Length of @p penc in bytes.
 */
void X509_PUBKEY_set0_public_key(X509_PUBKEY *pub,
    unsigned char *penc, int penclen);""",
"X509_PUBKEY_set0_public_key")

# x509_vfy
patch_both("x509_vfy.h",
"X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(const X509_STORE *xs);",
"""/**
 * @brief Return the CRL-check callback installed on a certificate store.
 * @param xs Store to query.
 * @return Callback used to verify CRLs, or NULL if the default is used.
 */
X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(const X509_STORE *xs);""",
"X509_STORE_get_check_crl")

patch_both("x509_vfy.h",
"X509_LOOKUP_METHOD *X509_LOOKUP_store(void);",
"""/**
 * @brief Return the X509_LOOKUP_METHOD that loads certificates/CRLs via OSSL_STORE URIs.
 * @return Pointer to the store-based lookup method.
 */
X509_LOOKUP_METHOD *X509_LOOKUP_store(void);""",
"X509_LOOKUP_store")

patch_both("x509_vfy.h",
"unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param);",
"""/**
 * @brief Return the verification flag mask stored in @p param.
 * @param param Verification parameters to query.
 * @return X509_V_FLAG_* bits currently set.
 */
unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param);""",
"X509_VERIFY_PARAM_get_flags")

patch_both("x509_vfy.h",
"""int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param,
    uint32_t flags);""",
"""/**
 * @brief Set inheritance flags controlling which fields copy from @p param to others.
 * @param param Verification parameters to update.
 * @param flags X509_VP_FLAG_* inheritance mask.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param,
    uint32_t flags);""",
"X509_VERIFY_PARAM_set_inh_flags")

patch_both("x509_vfy.h",
"""void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,
    unsigned int flags);""",
"""/**
 * @brief Set hostname-checking flags used with X509_VERIFY_PARAM_set1_host().
 * @param param Verification parameters to update.
 * @param flags X509_CHECK_FLAG_* bits controlling name matching.
 */
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,
    unsigned int flags);""",
"X509_VERIFY_PARAM_set_hostflags")

patch_both("x509_vfy.h",
"const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);",
"""/**
 * @brief Return the policy OID associated with a certificate policy tree node.
 * @param node Policy node to query.
 * @return Internal ASN1_OBJECT pointer for the policy OID; do not free.
 */
const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);""",
"X509_policy_node_get0_policy")

# x509v3
patch_both("x509v3.h",
"    GENERAL_NAME *location;",
"""    /** Access location (URI, directory name, etc.) for @c method. */
    GENERAL_NAME *location;""",
"ACCESS_DESCRIPTION::location")

patch_both("x509v3.h",
"DECLARE_ASN1_ITEM(BASIC_CONSTRAINTS)",
"""/**
 * @brief Return the ASN.1 item descriptor for BASIC_CONSTRAINTS.
 * @return Pointer to the static ASN1_ITEM for BASIC_CONSTRAINTS.
 */
const ASN1_ITEM *BASIC_CONSTRAINTS_it(void);""",
"BASIC_CONSTRAINTS_it")

patch_both("x509v3.h",
"DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, const unsigned char **in, long len);",
"""/**
 * @brief Decode a CRL distribution point from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DIST_POINT, or NULL on error.
 */
DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, const unsigned char **in, long len);""",
"d2i_DIST_POINT")

patch_both("x509v3.h",
"int X509_check_issued(X509 *issuer, X509 *subject);",
"""/**
 * @brief Check whether @p issuer appears to have issued @p subject (name and AKID match).
 * @param issuer Candidate issuer certificate.
 * @param subject Certificate whose issuer fields are compared.
 * @return X509_V_OK if @p issuer matches, or an X509_VERR_* reason code otherwise.
 */
int X509_check_issued(X509 *issuer, X509 *subject);""",
"X509_check_issued")

print(f"done ok={len(ok)} miss={len(missing)}")
if missing:
    print("MISSING:", *missing, sep="\n  ")
