#!/usr/bin/env python3
"""Documentation repair batch 14d: pkcs7, rand, rsa, sha, ssl, types, x509*."""
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


print("=== batch 14d ===")

# ----- pkcs7.h -----
patch_both(
    "pkcs7.h",
    """int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
    const EVP_MD *dgst);
""",
    """/**
 * @brief Populate a PKCS#7 signer info with certificate, key, and digest algorithm.
 * @param p7i SignerInfo to configure.
 * @param x509 Signer's certificate (sets issuer/serial).
 * @param pkey Signer's private key.
 * @param dgst Digest algorithm used for the signature.
 * @return 1 on success, or 0 on error.
 */
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
    const EVP_MD *dgst);
""",
    "PKCS7_SIGNER_INFO_set",
)

# ----- rand.h -----
patch_one(
    "rand.h",
    """void RAND_keep_random_devices_open(int keep);
""",
    """/**
 * @brief Keep OS random devices open across forks when @p keep is nonzero.
 * @param keep Nonzero to retain open /dev/urandom-style descriptors; zero to allow close-on-fork.
 */
void RAND_keep_random_devices_open(int keep);
""",
    "RAND_keep_random_devices_open",
)

patch_one(
    "rand.h",
    """int RAND_load_file(const char *file, long max_bytes);
""",
    """/**
 * @brief Mix up to @p max_bytes of file @p file into the PRNG seed pool.
 * @param file Path of the seed file to read.
 * @param max_bytes Maximum bytes to read, or -1 to read the whole file.
 * @return Number of bytes read, or a negative value on error.
 */
int RAND_load_file(const char *file, long max_bytes);
""",
    "RAND_load_file",
)

# ----- rsa.h -----
patch_one(
    "rsa.h",
    """int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
""",
    """/**
 * @brief Set the RSA-PSS salt length for sign/verify on @p ctx.
 * @param ctx Key context for an RSA-PSS operation.
 * @param saltlen Salt length in bytes, or RSA_PSS_SALTLEN_* special values.
 * @return 1 on success, or a non-positive value on error.
 */
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
""",
    "EVP_PKEY_CTX_set_rsa_pss_saltlen",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 RSA *RSA_new_method(ENGINE *engine);
""",
    """/**
 * @brief Allocate an RSA object that uses @p engine's RSA method (deprecated).
 * @param engine ENGINE providing the RSA implementation, or NULL for the default.
 * @return New RSA, or NULL on error; free with RSA_free().
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSA_new_method(ENGINE *engine);
""",
    "RSA_new_method",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_security_bits(const RSA *rsa);
""",
    """/**
 * @brief Estimate the security strength of @p rsa in bits (deprecated).
 * @param rsa RSA key whose modulus size is assessed.
 * @return Approximate security strength in bits, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_security_bits(const RSA *rsa);
""",
    "RSA_security_bits",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_get_multi_prime_extra_count(const RSA *r);
""",
    """/**
 * @brief Return how many extra primes beyond p and q a multi-prime RSA key has (deprecated).
 * @param r RSA key to query.
 * @return Extra prime count (>=0), or 0 if the key is two-prime / on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_get_multi_prime_extra_count(const RSA *r);
""",
    "RSA_get_multi_prime_extra_count",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_0_9_8 RSA *RSA_generate_key(int bits, unsigned long e, void (*callback)(int, int, void *),
    void *cb_arg);
""",
    """/**
 * @brief Generate an RSA key pair (very old API; deprecated — prefer RSA_generate_key_ex).
 * @param bits Modulus size in bits.
 * @param e Public exponent (for example 65537).
 * @param callback Optional progress callback, or NULL.
 * @param cb_arg Opaque argument passed to @p callback.
 * @return New RSA key pair, or NULL on error.
 */
OSSL_DEPRECATEDIN_0_9_8 RSA *RSA_generate_key(int bits, unsigned long e, void (*callback)(int, int, void *),
    void *cb_arg);
""",
    "RSA_generate_key",
)

patch_one(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_X931_generate_key_ex(RSA *rsa, int bits,
    const BIGNUM *e,
    BN_GENCB *cb);
""",
    """/**
 * @brief Generate an RSA key pair using the X9.31 prime-generation method (deprecated).
 * @param rsa Destination RSA object to populate.
 * @param bits Desired modulus size in bits.
 * @param e Public exponent.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_X931_generate_key_ex(RSA *rsa, int bits,
    const BIGNUM *e,
    BN_GENCB *cb);
""",
    "RSA_X931_generate_key_ex",
)

# ----- sha.h -----
patch_one(
    "sha.h",
    """typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
""",
    """typedef struct SHAstate_st {
    /** Chaining variables H0..H4 of the SHA-1 compression function. */
    SHA_LONG h0, h1, h2, h3, h4;
""",
    "SHA_CTX::h0..h4",
)

patch_one(
    "sha.h",
    """    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;
""",
    """    SHA_LONG data[SHA_LBLOCK];
    /** Number of bytes currently buffered in @c data toward a full block. */
    unsigned int num;
} SHA_CTX;
""",
    "SHA_CTX::num",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
""",
    """/**
 * @brief Process one SHA-1 compression round on a full 64-byte block (deprecated).
 * @param c SHA-1 context whose chaining variables are updated.
 * @param data Pointer to SHA_CBLOCK input bytes.
 */
OSSL_DEPRECATEDIN_3_0 void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
""",
    "SHA1_Transform",
)

patch_one(
    "sha.h",
    """    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;
""",
    """    SHA_LONG data[SHA_LBLOCK];
    /** Bytes buffered in @c data, and configured digest length (SHA-224 vs SHA-256). */
    unsigned int num, md_len;
} SHA256_CTX;
""",
    "SHA256_CTX::num,md_len",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA256_Init(SHA256_CTX *c);
""",
    """/**
 * @brief Initialise a SHA-256 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialise.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA256_Init(SHA256_CTX *c);
""",
    "SHA256_Init",
)

patch_one(
    "sha.h",
    """unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
""",
    """/**
 * @brief Compute the SHA-224 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA224_DIGEST_LENGTH bytes, or NULL for a static buffer.
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
""",
    "SHA224",
)

patch_one(
    "sha.h",
    """    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
""",
    """    /**
     * @brief Current message block viewed as 64-bit words (@c d) or bytes (@c p).
     */
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
""",
    "SHA512_CTX::u",
)

patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 int SHA384_Final(unsigned char *md, SHA512_CTX *c);
""",
    """/**
 * @brief Finalise a SHA-384 digest and write the 48-byte hash (deprecated).
 * @param md Output buffer of at least SHA384_DIGEST_LENGTH bytes.
 * @param c Context previously updated with SHA384_Update().
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int SHA384_Final(unsigned char *md, SHA512_CTX *c);
""",
    "SHA384_Final",
)

patch_one(
    "sha.h",
    """unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
""",
    """/**
 * @brief Compute the SHA-384 digest of @p n bytes at @p d in one shot.
 * @param d Input message bytes.
 * @param n Number of bytes at @p d.
 * @param md Output buffer of at least SHA384_DIGEST_LENGTH bytes, or NULL for a static buffer.
 * @return Pointer to the digest bytes, or NULL on error.
 */
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
""",
    "SHA384",
)

# ----- ssl.h -----
patch_both(
    "ssl.h",
    """typedef struct srtp_protection_profile_st {
    const char *name;
    unsigned long id;
} SRTP_PROTECTION_PROFILE;
""",
    """typedef struct srtp_protection_profile_st {
    /** IANA SRTP profile name string (for example "SRTP_AES128_CM_SHA1_80"). */
    const char *name;
    /** IANA SRTP protection profile identifier. */
    unsigned long id;
} SRTP_PROTECTION_PROFILE;
""",
    "SRTP_PROTECTION_PROFILE::id",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_3_0 __owur int SSL_SRP_CTX_init(SSL *s);
""",
    """/**
 * @brief Initialise SRP fields inside SSL object @p s (deprecated).
 * @param s SSL connection that will negotiate SRP.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 __owur int SSL_SRP_CTX_init(SSL *s);
""",
    "SSL_SRP_CTX_init",
)

patch_both(
    "ssl.h",
    """__owur long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);
""",
    """/**
 * @brief Set the default session timeout for @p ctx in seconds.
 * @param ctx SSL context whose session cache timeout is updated.
 * @param t New timeout in seconds.
 * @return Previous timeout value in seconds.
 */
__owur long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);
""",
    "SSL_CTX_set_timeout",
)

patch_both(
    "ssl.h",
    """__owur uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c);
""",
    """/**
 * @brief Return the OpenSSL-internal 32-bit identifier for cipher @p c.
 * @param c Cipher suite object.
 * @return Cipher id (version bits in the high word, suite id in the low word).
 */
__owur uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c);
""",
    "SSL_CIPHER_get_id",
)

patch_both(
    "ssl.h",
    """void SSL_set_read_ahead(SSL *s, int yes);
""",
    """/**
 * @brief Enable or disable read-ahead buffering on SSL @p s.
 * @param s SSL connection.
 * @param yes Nonzero to allow reading ahead into the record buffer; zero to disable.
 */
void SSL_set_read_ahead(SSL *s, int yes);
""",
    "SSL_set_read_ahead",
)

patch_both(
    "ssl.h",
    """__owur int SSL_peek(SSL *ssl, void *buf, int num);
""",
    """/**
 * @brief Copy up to @p num pending application bytes without consuming them.
 * @param ssl SSL connection.
 * @param buf Destination buffer.
 * @param num Maximum number of bytes to copy.
 * @return Number of bytes copied, 0 on EOF, or a negative value on error.
 */
__owur int SSL_peek(SSL *ssl, void *buf, int num);
""",
    "SSL_peek",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_1_client_method(void);
""",
    """/**
 * @brief Return the deprecated TLSv1.1 client-only method (prefer TLS_client_method).
 * @return Pointer to the static SSL_METHOD for TLS 1.1 clients.
 */
OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_1_client_method(void);
""",
    "TLSv1_1_client_method",
)

patch_both(
    "ssl.h",
    """struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl);
""",
    """/**
 * @brief Return the local private key configured on @p ssl (borrowed pointer).
 * @param ssl SSL connection.
 * @return EVP_PKEY used for the local certificate, or NULL if unset.
 */
struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl);
""",
    "SSL_get_privatekey",
)

patch_both(
    "ssl.h",
    """int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *v);
""",
    """/**
 * @brief Read a uint64 feature/value identified by @p class_ / @p id from SSL @p s.
 * @param s SSL connection.
 * @param class_ Value class (SSL_VALUE_CLASS_*).
 * @param id Value identifier within @p class_ (SSL_VALUE_*).
 * @param v Receives the retrieved value on success.
 * @return 1 on success, or 0 on error / unsupported value.
 */
int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *v);
""",
    "SSL_get_value_uint",
)

# ----- types.h -----
patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_GENERALSTRING;
""",
    """/**
 * @brief ASN.1 GeneralString stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_GENERALSTRING;
""",
    "ASN1_GENERALSTRING",
)

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_VISIBLESTRING;
""",
    """/**
 * @brief ASN.1 VisibleString stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_VISIBLESTRING;
""",
    "ASN1_VISIBLESTRING",
)

patch_one(
    "types.h",
    """typedef struct ASN1_ITEM_st ASN1_ITEM;
""",
    """/**
 * @brief Opaque ASN.1 item descriptor used by the generic encode/decode/print APIs.
 */
typedef struct ASN1_ITEM_st ASN1_ITEM;
""",
    "ASN1_ITEM",
)

patch_one(
    "types.h",
    """typedef struct bignum_st BIGNUM;
""",
    """/**
 * @brief Arbitrary-precision integer used throughout OpenSSL's public-key math.
 */
typedef struct bignum_st BIGNUM;
""",
    "BIGNUM",
)

patch_one(
    "types.h",
    """typedef struct err_state_st ERR_STATE;
""",
    """/**
 * @brief Opaque per-thread (or saved) OpenSSL error-queue state.
 */
typedef struct err_state_st ERR_STATE;
""",
    "ERR_STATE",
)

patch_one(
    "types.h",
    """typedef struct rand_meth_st RAND_METHOD;
""",
    """/**
 * @brief Legacy RAND method table (deprecated; prefer EVP_RAND providers).
 */
typedef struct rand_meth_st RAND_METHOD;
""",
    "RAND_METHOD",
)

patch_one(
    "types.h",
    """typedef struct conf_st CONF;
""",
    """/**
 * @brief Opaque NCONF configuration object holding sections and name/value pairs.
 */
typedef struct conf_st CONF;
""",
    "CONF",
)

patch_one(
    "types.h",
    """typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
""",
    """/**
 * @brief X.509v3 AuthorityKeyIdentifier extension value.
 */
typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
""",
    "AUTHORITY_KEYID",
)

patch_one(
    "types.h",
    """typedef struct ocsp_response_st OCSP_RESPONSE;
""",
    """/**
 * @brief Opaque OCSP response structure (RFC 6960).
 */
typedef struct ocsp_response_st OCSP_RESPONSE;
""",
    "OCSP_RESPONSE",
)

patch_one(
    "types.h",
    """typedef struct ossl_store_search_st OSSL_STORE_SEARCH;
""",
    """/**
 * @brief Opaque search criterion object used with OSSL_STORE_expect / find APIs.
 */
typedef struct ossl_store_search_st OSSL_STORE_SEARCH;
""",
    "OSSL_STORE_SEARCH",
)

# ----- x509.h -----
patch_both(
    "x509.h",
    """int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);
""",
    """/**
 * @brief Compare two AlgorithmIdentifier values for equality.
 * @param a First algorithm identifier.
 * @param b Second algorithm identifier.
 * @return 0 if equal, or nonzero if they differ.
 */
int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);
""",
    "X509_ALGOR_cmp",
)

patch_both(
    "x509.h",
    """const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x);
""",
    """/**
 * @brief Return a borrowed pointer to certificate @p x's serial number.
 * @param x Certificate to query.
 * @return Internal ASN1_INTEGER pointer (do not free), or NULL on error.
 */
const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x);
""",
    "X509_get0_serialNumber",
)

patch_both(
    "x509.h",
    """int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
    const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len);
""",
    """/**
 * @brief Append an attribute identified by OID @p obj to a certificate request.
 * @param req Certificate signing request to modify.
 * @param obj Attribute OID.
 * @param type ASN.1 string type for @p bytes (for example V_ASN1_UTF8STRING).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 for a NUL-terminated string.
 * @return 1 on success, or 0 on error.
 */
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
    const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len);
""",
    "X509_REQ_add1_attr_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_CRL_get_signature_nid(const X509_CRL *crl);
""",
    """/**
 * @brief Return the NID of the signature algorithm used on CRL @p crl.
 * @param crl Certificate revocation list to query.
 * @return Signature algorithm NID, or NID_undef on error.
 */
int X509_CRL_get_signature_nid(const X509_CRL *crl);
""",
    "X509_CRL_get_signature_nid",
)

patch_both(
    "x509.h",
    """int i2d_re_X509_CRL_tbs(X509_CRL *req, unsigned char **pp);
""",
    """/**
 * @brief Re-encode the to-be-signed CRL body of @p req (refreshing cached DER).
 * @param req CRL whose TBSCertList is encoded (cache updated).
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_re_X509_CRL_tbs(X509_CRL *req, unsigned char **pp);
""",
    "i2d_re_X509_CRL_tbs",
)

patch_both(
    "x509.h",
    """int X509_chain_check_suiteb(int *perror_depth,
    X509 *x, STACK_OF(X509) *chain,
    unsigned long flags);
""",
    """/**
 * @brief Verify that certificate @p x and @p chain comply with Suite B constraints.
 * @param perror_depth Receives the chain depth of the first failing cert, or may be NULL.
 * @param x EE/leaf certificate being checked.
 * @param chain Intermediate certificates (may be NULL).
 * @param flags Suite B mode flags (for example X509_V_FLAG_SUITEB_128_LOS).
 * @return X509_V_OK on success, or an X509_V_ERR_* Suite B error code.
 */
int X509_chain_check_suiteb(int *perror_depth,
    X509 *x, STACK_OF(X509) *chain,
    unsigned long flags);
""",
    "X509_chain_check_suiteb",
)

patch_both(
    "x509.h",
    """unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
    const char *propq, int *ok);
""",
    """/**
 * @brief Hash an X.509 Name for directory lookup using SHA-1 via @p libctx.
 * @param x Name to hash.
 * @param libctx Library context for the digest fetch, or NULL for the default.
 * @param propq Property query for the digest, or NULL.
 * @param ok Receives 1 on success / 0 on failure, or may be NULL.
 * @return Canonical name hash, or 0 on failure (inspect *@p ok).
 */
unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
    const char *propq, int *ok);
""",
    "X509_NAME_hash_ex",
)

patch_both(
    "x509.h",
    """int X509_print_fp(FILE *bp, X509 *x);
""",
    """/**
 * @brief Print a human-readable certificate dump to a stdio FILE.
 * @param bp Output FILE.
 * @param x Certificate to print.
 * @return 1 on success, or 0 on error.
 */
int X509_print_fp(FILE *bp, X509 *x);
""",
    "X509_print_fp",
)

patch_both(
    "x509.h",
    """int X509_CRL_print(BIO *bp, X509_CRL *x);
""",
    """/**
 * @brief Print a human-readable CRL dump to BIO @p bp.
 * @param bp Output BIO.
 * @param x CRL to print.
 * @return 1 on success, or 0 on error.
 */
int X509_CRL_print(BIO *bp, X509_CRL *x);
""",
    "X509_CRL_print",
)

patch_both(
    "x509.h",
    """int X509_NAME_get_text_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj,
    char *buf, int len);
""",
    """/**
 * @brief Copy the first RDN text matching OID @p obj from @p name into @p buf.
 * @param name Subject/issuer name to search.
 * @param obj Attribute OID to locate (for example NID_commonName's object).
 * @param buf Destination buffer, or NULL to return only the required length.
 * @param len Capacity of @p buf in bytes.
 * @return Length of the value (excluding NUL) on success, or -1 on error / not found.
 */
int X509_NAME_get_text_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj,
    char *buf, int len);
""",
    "X509_NAME_get_text_by_OBJ",
)

patch_both(
    "x509.h",
    """X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
""",
    """/**
 * @brief Remove and return the name entry at index @p loc.
 * @param name Name to modify.
 * @param loc Zero-based entry index.
 * @return Detached X509_NAME_ENTRY (caller frees), or NULL on error.
 */
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
""",
    "X509_NAME_delete_entry",
)

patch_both(
    "x509.h",
    """int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
""",
    """/**
 * @brief Add an RDN attribute identified by @p nid to @p name.
 * @param name Destination X.509 Name.
 * @param nid Attribute NID (for example NID_commonName).
 * @param type ASN.1 string type for @p bytes.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 for a NUL-terminated string.
 * @param loc Insertion index, or -1 to append.
 * @param set -1/0/1 controlling whether to join an existing RDN set at @p loc.
 * @return 1 on success, or 0 on error.
 */
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
""",
    "X509_NAME_add_entry_by_NID",
)

patch_both(
    "x509.h",
    """int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos);
""",
    """/**
 * @brief Find a CRL extension by criticality flag, searching after @p lastpos.
 * @param x CRL whose extensions are searched.
 * @param crit 1 to match critical extensions, 0 for non-critical.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Extension index on success, or -1 if not found.
 */
int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos);
""",
    "X509_CRL_get_ext_by_critical",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
    const ASN1_OBJECT *obj, int crit,
    ASN1_OCTET_STRING *data);
""",
    """/**
 * @brief Create (or reuse) an X509_EXTENSION with OID @p obj and octet @p data.
 * @param ex Optional destination pointer updated to the result, or NULL.
 * @param obj Extension OID.
 * @param crit Nonzero to mark the extension critical.
 * @param data Extension value octets (copied).
 * @return The extension object, or NULL on error.
 */
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
    const ASN1_OBJECT *obj, int crit,
    ASN1_OCTET_STRING *data);
""",
    "X509_EXTENSION_create_by_OBJ",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
    const char *atrname, int type,
    const unsigned char *bytes,
    int len);
""",
    """/**
 * @brief Create an X509_ATTRIBUTE from a textual OID/name and value bytes.
 * @param attr Optional destination pointer updated to the result, or NULL.
 * @param atrname Attribute OID string or short/long name.
 * @param type ASN.1 string type for @p bytes.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 for a NUL-terminated string.
 * @return The attribute object, or NULL on error.
 */
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
    const char *atrname, int type,
    const unsigned char *bytes,
    int len);
""",
    "X509_ATTRIBUTE_create_by_txt",
)

patch_both(
    "x509.h",
    """int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
""",
    """/**
 * @brief Set the OID of attribute @p attr to a copy of @p obj.
 * @param attr Attribute to update.
 * @param obj New attribute type OID.
 * @return 1 on success, or 0 on error.
 */
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
""",
    "X509_ATTRIBUTE_set1_object",
)

patch_both(
    "x509.h",
    """int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
    int ptype, void *pval,
    unsigned char *penc, int penclen);
""",
    """/**
 * @brief Set algorithm and encoded public-key bits on @p pub, transferring ownership.
 * @param pub Public-key container to update.
 * @param aobj Algorithm OID taken over by @p pub (may be NULL to leave unchanged).
 * @param ptype ASN.1 type of @p pval (V_ASN1_*), or 0 to leave parameters unchanged.
 * @param pval Algorithm parameters taken over when @p ptype is set.
 * @param penc DER bit string content taken over, or NULL to leave key data unchanged.
 * @param penclen Length of @p penc when non-NULL.
 * @return 1 on success, or 0 on error.
 */
int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
    int ptype, void *pval,
    unsigned char *penc, int penclen);
""",
    "X509_PUBKEY_set0_param",
)

# ----- x509_vfy.h -----
patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_check_policy_fn)(X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Callback type that evaluates certificate policies for a verification context.
 * @param ctx Store context whose chain and policy state are examined.
 * @return 1 if policy checking succeeds, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_check_policy_fn)(X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_check_policy_fn",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(const X509_STORE *xs);
""",
    """/**
 * @brief Return the cleanup callback installed on X509_STORE @p xs.
 * @param xs Certificate store to query.
 * @return Cleanup function pointer, or NULL if none is set.
 */
X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(const X509_STORE *xs);
""",
    "X509_STORE_get_cleanup",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_init_rpk(X509_STORE_CTX *ctx, X509_STORE *trust_store,
    EVP_PKEY *rpk);
""",
    """/**
 * @brief Initialise a verification context to validate raw public key @p rpk.
 * @param ctx Store context to initialise.
 * @param trust_store Trust store used for verification, or NULL.
 * @param rpk Raw public key being verified (as an EVP_PKEY).
 * @return 1 on success, or 0 on error.
 */
int X509_STORE_CTX_init_rpk(X509_STORE_CTX *ctx, X509_STORE *trust_store,
    EVP_PKEY *rpk);
""",
    "X509_STORE_CTX_init_rpk",
)

patch_both(
    "x509_vfy.h",
    """int (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Return the new-item callback from an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Function pointer that allocates per-lookup state, or NULL if unset.
 */
int (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_meth_get_new_item",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
""",
    """/**
 * @brief Store application ex_data on a verification context at index @p idx.
 * @param ctx Store context.
 * @param idx Index from X509_STORE_CTX_get_ex_new_index().
 * @param data Pointer to store.
 * @return 1 on success, or 0 on error.
 */
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
""",
    "X509_STORE_CTX_set_ex_data",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
""",
    """/**
 * @brief OR additional X509_V_FLAG_* verification flags into @p ctx.
 * @param ctx Store context.
 * @param flags Flag bits to set (combined with any flags already present).
 */
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
""",
    "X509_STORE_CTX_set_flags",
)

patch_both(
    "x509_vfy.h",
    """X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the policy tree built during verification of @p ctx (borrowed).
 * @param ctx Store context after a verification attempt with policy checking enabled.
 * @return Internal X509_POLICY_TREE pointer, or NULL if none was built.
 */
X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_policy_tree",
)

# ----- x509v3.h -----
patch_both(
    "x509v3.h",
    """typedef struct PKEY_USAGE_PERIOD_st {
    ASN1_GENERALIZEDTIME *notBefore;
""",
    """typedef struct PKEY_USAGE_PERIOD_st {
    /** Start of the private key usage interval, or NULL if unset. */
    ASN1_GENERALIZEDTIME *notBefore;
""",
    "PKEY_USAGE_PERIOD::notBefore",
)

patch_both(
    "x509v3.h",
    """int i2d_USERNOTICE(const USERNOTICE *a, unsigned char **out);
""",
    """/**
 * @brief Encode a USERNOTICE structure to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_USERNOTICE(const USERNOTICE *a, unsigned char **out);
""",
    "i2d_USERNOTICE",
)

patch_both(
    "x509v3.h",
    """int X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x, int nid, void *value,
    int crit, unsigned long flags);
""",
    """/**
 * @brief Encode extension structure @p value and add/replace it on stack *@p x.
 * @param x Address of the extension stack (allocated if NULL).
 * @param nid Extension NID to create.
 * @param value Extension-specific C structure understood by the X509V3 method for @p nid.
 * @param crit Nonzero to mark the extension critical.
 * @param flags X509V3_ADD_* behaviour flags (append, replace, keep existing, …).
 * @return 1 on success, 0 on error, or -1 when a replace was requested but no match existed.
 */
int X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x, int nid, void *value,
    int crit, unsigned long flags);
""",
    "X509V3_add1_i2d",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
