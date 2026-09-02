#!/usr/bin/env python3
"""Documentation repair batch 9c: objects, pkcs7, rsa, ssl, ui, x509*."""
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


# ----- objects.h -----
patch_both(
    "objects.h",
    "int OBJ_NAME_init(void);",
    """/**
 * @brief Initialize the OBJ_NAME table used for algorithm name aliases.
 * @return 1 on success, or 0 on failure.
 */
int OBJ_NAME_init(void);""",
    "OBJ_NAME_init",
)

patch_both(
    "objects.h",
    "const char *OBJ_NAME_get(const char *name, int type);",
    """/**
 * @brief Look up data associated with a named object of the given type.
 * @param name Name string to resolve.
 * @param type OBJ_NAME type such as OBJ_NAME_TYPE_MD_METH or OBJ_NAME_TYPE_CIPHER_METH.
 * @return Associated data string (often an algorithm name), or NULL if not found.
 */
const char *OBJ_NAME_get(const char *name, int type);""",
    "OBJ_NAME_get",
)

patch_both(
    "objects.h",
    "void OBJ_NAME_cleanup(int type); /* -1 for everything */",
    """/**
 * @brief Free OBJ_NAME entries of the given type (or all types).
 * @param type OBJ_NAME type to clear, or -1 to free every type.
 */
void OBJ_NAME_cleanup(int type); /* -1 for everything */""",
    "OBJ_NAME_cleanup",
)

patch_both(
    "objects.h",
    "DECLARE_ASN1_DUP_FUNCTION_name(ASN1_OBJECT, OBJ)",
    """/**
 * @brief Deep-copy an ASN1_OBJECT.
 * @param o Object to duplicate.
 * @return Newly allocated ASN1_OBJECT, or NULL on error; free with ASN1_OBJECT_free().
 */
ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o);""",
    "OBJ_dup",
)

patch_both(
    "objects.h",
    """const char *OBJ_nid2ln(int n);
const char *OBJ_nid2sn(int n);""",
    """/**
 * @brief Return the long name string for a numeric object identifier (NID).
 * @param n NID to look up.
 * @return Internal long-name string (do not free), or NULL if unknown.
 */
const char *OBJ_nid2ln(int n);
/**
 * @brief Return the short name string for a numeric object identifier (NID).
 * @param n NID to look up.
 * @return Internal short-name string (do not free), or NULL if unknown.
 */
const char *OBJ_nid2sn(int n);""",
    "OBJ_nid2ln/sn",
)

patch_both(
    "objects.h",
    "ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);",
    """/**
 * @brief Parse a textual OID (dot notation or name) into an ASN1_OBJECT.
 * @param s OID text such as "1.2.840.113549.1.1.1" or "sha256WithRSAEncryption".
 * @param no_name When non-zero, only numeric OID forms are accepted (names are rejected).
 * @return Newly allocated ASN1_OBJECT, or NULL on error; free with ASN1_OBJECT_free().
 */
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);""",
    "OBJ_txt2obj",
)

patch_both(
    "objects.h",
    """const void *OBJ_bsearch_ex_(const void *key, const void *base, int num,
    int size,
    int (*cmp)(const void *, const void *),
    int flags);""",
    """/**
 * @brief Binary-search a sorted object table with optional flags (internal helper).
 * @param key Pointer to the search key.
 * @param base Pointer to the first element of the sorted array.
 * @param num Number of elements in the array.
 * @param size Size of each element in bytes.
 * @param cmp Comparison function returning negative, zero, or positive.
 * @param flags Search flags such as OBJ_BSEARCH_VALUE_ON_NOMATCH.
 * @return Pointer to the matching element, or NULL / a related pointer depending on @p flags.
 */
const void *OBJ_bsearch_ex_(const void *key, const void *base, int num,
    int size,
    int (*cmp)(const void *, const void *),
    int flags);""",
    "OBJ_bsearch_ex_",
)

patch_both(
    "objects.h",
    "int OBJ_new_nid(int num);",
    """/**
 * @brief Allocate one or more new numeric object identifiers (NIDs).
 * @param num Number of consecutive NIDs to reserve.
 * @return First newly allocated NID, or NID_undef on failure.
 */
int OBJ_new_nid(int num);""",
    "OBJ_new_nid",
)

patch_both(
    "objects.h",
    "const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj);",
    """/**
 * @brief Return the DER-encoded content octets of an ASN1_OBJECT.
 * @param obj Object to query.
 * @return Internal pointer to the OID content bytes (do not free), or NULL if unavailable.
 */
const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj);""",
    "OBJ_get0_data",
)

patch_both(
    "objects.h",
    "void OBJ_sigid_free(void);",
    """/**
 * @brief Free the signature-algorithm OID alias table populated by OBJ_add_sigid().
 */
void OBJ_sigid_free(void);""",
    "OBJ_sigid_free",
)

# ----- pkcs7.h -----
patch_both(
    "pkcs7.h",
    """    EVP_PKEY *pkey;
    const PKCS7_CTX *ctx;
} PKCS7_SIGNER_INFO;""",
    """    EVP_PKEY *pkey;
    /** Library/provider context associated with this signer info (not serialized). */
    const PKCS7_CTX *ctx;
} PKCS7_SIGNER_INFO;""",
    "PKCS7_SIGNER_INFO.ctx",
)

patch_both(
    "pkcs7.h",
    """    X509 *cert;
    const PKCS7_CTX *ctx;
} PKCS7_RECIP_INFO;""",
    """    X509 *cert;
    /** Library/provider context associated with this recipient info (not serialized). */
    const PKCS7_CTX *ctx;
} PKCS7_RECIP_INFO;""",
    "PKCS7_RECIP_INFO.ctx",
)

patch_both(
    "pkcs7.h",
    """    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_ENC_CONTENT *enc_data;
    /** @brief Per-recipient encrypted key infos. */""",
    """    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    /** Encrypted content info for SignedAndEnvelopedData. */
    PKCS7_ENC_CONTENT *enc_data;
    /** @brief Per-recipient encrypted key infos. */""",
    "PKCS7_SIGN_ENVELOPE.enc_data",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SERIAL)",
    asn1_funcs("PKCS7_ISSUER_AND_SERIAL", "PKCS#7 IssuerAndSerialNumber")
    + "\n",
    "PKCS7_ISSUER_AND_SERIAL",
)

# ----- rsa.h -----
patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
    """/**
 * @brief Set the MGF1 digest used when generating an RSA-PSS key.
 * @param ctx Key-generation context for an RSA-PSS key.
 * @param md Digest used inside MGF1 (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
    "EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md",
)

patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
    """/**
 * @brief Set the message digest used when generating an RSA-PSS key.
 * @param ctx Key-generation context for an RSA-PSS key.
 * @param md Digest associated with the PSS parameters (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
    "EVP_PKEY_CTX_set_rsa_pss_keygen_md",
)

patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
    """/**
 * @brief Set the message digest used by RSA-OAEP padding on a key context.
 * @param ctx Encrypt/decrypt context for an RSA key using OAEP.
 * @param md OAEP hash algorithm (for example EVP_sha256()).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
    "EVP_PKEY_CTX_set_rsa_oaep_md",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 void RSA_get0_crt_params(const RSA *r,
    const BIGNUM **dmp1,
    const BIGNUM **dmq1,
    const BIGNUM **iqmp);""",
    """/**
 * @brief Borrow pointers to the RSA CRT parameters d mod (p-1), d mod (q-1), and q^-1 mod p (deprecated).
 * @param r RSA key to query.
 * @param dmp1 Receives dmp1, or NULL to skip; do not free.
 * @param dmq1 Receives dmq1, or NULL to skip; do not free.
 * @param iqmp Receives iqmp, or NULL to skip; do not free.
 */
OSSL_DEPRECATEDIN_3_0 void RSA_get0_crt_params(const RSA *r,
    const BIGNUM **dmp1,
    const BIGNUM **dmq1,
    const BIGNUM **iqmp);""",
    "RSA_get0_crt_params",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2,
    BIGNUM *q1, BIGNUM *q2,
    const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1,
    const BIGNUM *Xq2, const BIGNUM *Xq,
    const BIGNUM *e, BN_GENCB *cb);""",
    """/**
 * @brief Derive an RSA key from ANSI X9.31 intermediate values (deprecated).
 * @param rsa Destination RSA object that receives the derived key.
 * @param p1 Optional output for the first p factor component, or NULL.
 * @param p2 Optional output for the second p factor component, or NULL.
 * @param q1 Optional output for the first q factor component, or NULL.
 * @param q2 Optional output for the second q factor component, or NULL.
 * @param Xp1 X9.31 Xp1 input value.
 * @param Xp2 X9.31 Xp2 input value.
 * @param Xp X9.31 Xp input value.
 * @param Xq1 X9.31 Xq1 input value.
 * @param Xq2 X9.31 Xq2 input value.
 * @param Xq X9.31 Xq input value.
 * @param e Public exponent.
 * @param cb Optional BN_GENCB progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2,
    BIGNUM *q1, BIGNUM *q2,
    const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1,
    const BIGNUM *Xq2, const BIGNUM *Xq,
    const BIGNUM *e, BN_GENCB *cb);""",
    "RSA_X931_derive_ex",
)

patch_both(
    "rsa.h",
    """DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(OSSL_DEPRECATEDIN_3_0,
    RSA, RSAPublicKey)""",
    """/**
 * @brief Decode an RSA public key from DER in PKCS#1 RSAPublicKey form (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded RSA public key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len);
/**
 * @brief Encode an RSA public key to DER in PKCS#1 RSAPublicKey form (deprecated).
 * @param a RSA key whose public components are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_RSAPublicKey(const RSA *a, unsigned char **out);""",
    "d2i/i2d_RSAPublicKey",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const unsigned char *EM,
    int sLen);""",
    """/**
 * @brief Verify an RSA-PSS encoded message EM against a message hash (deprecated).
 * @param rsa RSA public key used for verification context (size / parameters).
 * @param mHash Hash of the original message.
 * @param Hash Digest that produced @p mHash and is used by PSS.
 * @param EM Encoded message of RSA_size(@p rsa) bytes (typically after RSA public operation).
 * @param sLen PSS salt length in bytes, or a special negative sentinel accepted by the implementation.
 * @return 1 if the PSS encoding is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const unsigned char *EM,
    int sLen);""",
    "RSA_verify_PKCS1_PSS",
)

patch_both(
    "rsa.h",
    "OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth);",
    """/**
 * @brief Duplicate an RSA_METHOD structure (deprecated).
 * @param meth Method to copy.
 * @return Newly allocated RSA_METHOD, or NULL on failure; free with RSA_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth);""",
    "RSA_meth_dup",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);""",
    """/**
 * @brief Return the private-encrypt (signing) callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the priv_enc callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);""",
    "RSA_meth_get_priv_enc",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_priv_dec(RSA_METHOD *rsa,
    int (*priv_dec)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));""",
    """/**
 * @brief Set the private-decrypt callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param priv_dec Callback performing RSA private decryption / signature recovery, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_priv_dec(RSA_METHOD *rsa,
    int (*priv_dec)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa,
        int padding));""",
    "RSA_meth_set_priv_dec",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(BIGNUM *r0,
    const BIGNUM *i,
    RSA *rsa, BN_CTX *ctx);""",
    """/**
 * @brief Return the CRT modular-exponentiation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(BIGNUM *r0,
    const BIGNUM *i,
    RSA *rsa, BN_CTX *ctx);""",
    "RSA_meth_get_mod_exp",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(BIGNUM *r,
    const BIGNUM *a,
    const BIGNUM *p,
    const BIGNUM *m,
    BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);""",
    """/**
 * @brief Return the BN modular-exponentiation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the bn_mod_exp callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(BIGNUM *r,
    const BIGNUM *a,
    const BIGNUM *p,
    const BIGNUM *m,
    BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);""",
    "RSA_meth_get_bn_mod_exp",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_finish(const RSA_METHOD *meth))(RSA *rsa);""",
    """/**
 * @brief Return the finish/cleanup callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the finish callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_finish(const RSA_METHOD *meth))(RSA *rsa);""",
    "RSA_meth_get_finish",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_sign(const RSA_METHOD *meth))(int type,
    const unsigned char *m,
    unsigned int m_length,
    unsigned char *sigret,
    unsigned int *siglen,
    const RSA *rsa);""",
    """/**
 * @brief Return the high-level sign callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the sign callback used by RSA_sign(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_sign(const RSA_METHOD *meth))(int type,
    const unsigned char *m,
    unsigned int m_length,
    unsigned char *sigret,
    unsigned int *siglen,
    const RSA *rsa);""",
    "RSA_meth_get_sign",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_verify(const RSA_METHOD *meth))(int dtype,
    const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen,
    const RSA *rsa);""",
    """/**
 * @brief Return the high-level verify callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the verify callback used by RSA_verify(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_verify(const RSA_METHOD *meth))(int dtype,
    const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen,
    const RSA *rsa);""",
    "RSA_meth_get_verify",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))(RSA *rsa,
    int bits,
    int primes,
    BIGNUM *e,
    BN_GENCB *cb);""",
    """/**
 * @brief Return the multi-prime key-generation callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the multi-prime keygen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))(RSA *rsa,
    int bits,
    int primes,
    BIGNUM *e,
    BN_GENCB *cb);""",
    "RSA_meth_get_multi_prime_keygen",
)

# ----- ssl.h -----
patch_both(
    "ssl.h",
    """} SRTP_PROTECTION_PROFILE;
/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE)""",
    """} SRTP_PROTECTION_PROFILE;
/**
 * @brief Opaque STACK_OF(SRTP_PROTECTION_PROFILE) container type.
 */
struct stack_st_SRTP_PROTECTION_PROFILE;
/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE, SRTP_PROTECTION_PROFILE)""",
    "stack_st_SRTP_PROTECTION_PROFILE",
)

# ssl.h.in uses generate_stack_macros
patch_both(
    "ssl.h.in",
    """} SRTP_PROTECTION_PROFILE;
/* clang-format off */
{-
    generate_stack_macros("SRTP_PROTECTION_PROFILE");
-}""",
    """} SRTP_PROTECTION_PROFILE;
/**
 * @brief Opaque STACK_OF(SRTP_PROTECTION_PROFILE) container type.
 */
struct stack_st_SRTP_PROTECTION_PROFILE;
/* clang-format off */
{-
    generate_stack_macros("SRTP_PROTECTION_PROFILE");
-}""",
    "stack_st_SRTP_PROTECTION_PROFILE.in",
)

patch_both(
    "ssl.h",
    """void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*gen_stateless_cookie_cb)(SSL *ssl,
        unsigned char *cookie,
        size_t *cookie_len));""",
    """/**
 * @brief Register the callback that generates cookies for TLS 1.3 HelloRetryRequest / DTLS cookie exchange.
 * @param ctx SSL_CTX that will invoke the callback for stateless cookie generation.
 * @param gen_stateless_cookie_cb Callback that writes a cookie into @p cookie and sets @p cookie_len, or NULL to clear.
 */
void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*gen_stateless_cookie_cb)(SSL *ssl,
        unsigned char *cookie,
        size_t *cookie_len));""",
    "SSL_CTX_set_stateless_cookie_generate_cb",
)

patch_both(
    "ssl.h",
    """typedef enum {
    /** @brief No handshake has been initiated yet. */
    TLS_ST_BEFORE,""",
    """/**
 * @brief Fine-grained TLS/DTLS handshake state machine values reported by SSL_get_state().
 */
typedef enum {
    /** @brief No handshake has been initiated yet. */
    TLS_ST_BEFORE,""",
    "OSSL_HANDSHAKE_STATE",
)

patch_both(
    "ssl.h",
    "__owur int SSL_SESSION_set_protocol_version(SSL_SESSION *s, int version);",
    """/**
 * @brief Set the protocol version recorded on an SSL_SESSION.
 * @param s Session object to update.
 * @param version Wire protocol version constant such as TLS1_3_VERSION.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_SESSION_set_protocol_version(SSL_SESSION *s, int version);""",
    "SSL_SESSION_set_protocol_version",
)

patch_both(
    "ssl.h",
    "__owur int SSL_get_handshake_rtt(const SSL *s, uint64_t *rtt);",
    """/**
 * @brief Return the measured TLS handshake round-trip time in microseconds when available.
 * @param s SSL connection to query.
 * @param rtt Receives the RTT in microseconds.
 * @return 1 if an RTT measurement is available, or 0 / a negative value otherwise.
 */
__owur int SSL_get_handshake_rtt(const SSL *s, uint64_t *rtt);""",
    "SSL_get_handshake_rtt",
)

patch_both(
    "ssl.h",
    "__owur const SSL_METHOD *TLS_method(void);",
    """/**
 * @brief Return an SSL_METHOD that negotiates the highest mutually supported TLS version.
 * @return Pointer to the flexible TLS client/server method for SSL_CTX_new().
 */
__owur const SSL_METHOD *TLS_method(void);""",
    "TLS_method",
)

patch_both(
    "ssl.h",
    "__owur const STACK_OF(X509_NAME) *SSL_get0_peer_CA_list(const SSL *s);",
    """/**
 * @brief Return the list of CA names the peer advertised for client authentication.
 * @param s SSL connection to query (typically on the client after CertificateRequest).
 * @return Internal STACK_OF(X509_NAME) (do not free), or NULL if none was received.
 */
__owur const STACK_OF(X509_NAME) *SSL_get0_peer_CA_list(const SSL *s);""",
    "SSL_get0_peer_CA_list",
)

patch_both(
    "ssl.h",
    "void SSL_set_connect_state(SSL *s);",
    """/**
 * @brief Configure an SSL object to operate as a TLS client.
 * @param s SSL connection that will initiate the handshake as a client.
 */
void SSL_set_connect_state(SSL *s);""",
    "SSL_set_connect_state",
)

patch_both(
    "ssl.h",
    """__owur size_t SSL_get_client_random(const SSL *ssl, unsigned char *out,
    size_t outlen);""",
    """/**
 * @brief Copy the TLS ClientHello random value from a connection.
 * @param ssl SSL connection whose client_random is requested.
 * @param out Destination buffer, or NULL to query the required length only.
 * @param outlen Capacity of @p out in bytes.
 * @return Number of bytes available / copied (typically SSL3_RANDOM_SIZE).
 */
__owur size_t SSL_get_client_random(const SSL *ssl, unsigned char *out,
    size_t outlen);""",
    "SSL_get_client_random",
)

patch_both(
    "ssl.h",
    "__owur int SSL_SESSION_set_ex_data(SSL_SESSION *ss, int idx, void *data);",
    """/**
 * @brief Store application data on an SSL_SESSION at a CRYPTO_EX index.
 * @param ss Session object to update.
 * @param idx Index from SSL_SESSION_get_ex_new_index().
 * @param data Application pointer to store (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_SESSION_set_ex_data(SSL_SESSION *ss, int idx, void *data);""",
    "SSL_SESSION_set_ex_data",
)

patch_both(
    "ssl.h",
    """void SSL_set_not_resumable_session_callback(SSL *ssl,
    int (*cb)(SSL *ssl,
        int is_forward_secure));""",
    """/**
 * @brief Register a callback that decides whether a session may be resumed.
 * @param ssl SSL connection that will invoke the callback when creating sessions.
 * @param cb Callback returning non-zero to mark the session non-resumable; @p is_forward_secure indicates forward secrecy.
 */
void SSL_set_not_resumable_session_callback(SSL *ssl,
    int (*cb)(SSL *ssl,
        int is_forward_secure));""",
    "SSL_set_not_resumable_session_callback",
)

patch_both(
    "ssl.h",
    "int SSL_enable_ct(SSL *s, int validation_mode);",
    """/**
 * @brief Enable Certificate Transparency validation on an SSL connection.
 * @param s SSL connection to configure.
 * @param validation_mode SSL_CT_VALIDATION_PERMISSIVE or SSL_CT_VALIDATION_STRICT.
 * @return 1 on success, or 0 on failure.
 */
int SSL_enable_ct(SSL *s, int validation_mode);""",
    "SSL_enable_ct",
)

patch_both(
    "ssl.h",
    "__owur int SSL_set1_server_cert_type(SSL *s, const unsigned char *val, size_t len);",
    """/**
 * @brief Set the list of server certificate types this connection is willing to use.
 * @param s SSL connection to configure.
 * @param val Array of certificate type bytes (for example TLSEXT_cert_type_* values).
 * @param len Number of bytes in @p val.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set1_server_cert_type(SSL *s, const unsigned char *val, size_t len);""",
    "SSL_set1_server_cert_type",
)

# ----- ui.h -----
patch_both(
    "ui.h",
    """int UI_dup_verify_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize,
    const char *test_buf);""",
    """/**
 * @brief Add a password prompt that must match @p test_buf, copying the prompt string.
 * @param ui UI object that will collect the response.
 * @param prompt Prompt text duplicated into @p ui.
 * @param flags UI string flags such as UI_INPUT_FLAG_DEFAULT_PWD.
 * @param result_buf Buffer receiving the user's input.
 * @param minsize Minimum acceptable input length.
 * @param maxsize Capacity of @p result_buf.
 * @param test_buf Expected verification string that the input must equal.
 * @return Index of the added string on success, or a negative value on error.
 */
int UI_dup_verify_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize,
    const char *test_buf);""",
    "UI_dup_verify_string",
)

# ----- x509.h -----
patch_both(
    "x509.h",
    """typedef struct PBE2PARAM_st {
    /** @brief Key derivation function AlgorithmIdentifier (for example PBKDF2). */
    X509_ALGOR *keyfunc;
    X509_ALGOR *encryption;
} PBE2PARAM;

typedef struct PBKDF2PARAM_st {
    /* Usually OCTET STRING but could be anything */
    ASN1_TYPE *salt;
    /** PBKDF2 iteration count. */
    ASN1_INTEGER *iter;
    /** Optional derived key length in octets; NULL means the cipher default. */
    ASN1_INTEGER *keylength;
    X509_ALGOR *prf;
} PBKDF2PARAM;""",
    """/**
 * @brief PKCS#5 PBES2 parameters: key-derivation function and encryption scheme.
 */
typedef struct PBE2PARAM_st {
    /** @brief Key derivation function AlgorithmIdentifier (for example PBKDF2). */
    X509_ALGOR *keyfunc;
    /** Encryption scheme AlgorithmIdentifier applied after key derivation. */
    X509_ALGOR *encryption;
} PBE2PARAM;

/**
 * @brief PKCS#5 PBKDF2 parameters: salt, iteration count, optional key length, and PRF.
 */
typedef struct PBKDF2PARAM_st {
    /** Salt value; usually an OCTET STRING but may be another ASN.1 type. */
    ASN1_TYPE *salt;
    /** PBKDF2 iteration count. */
    ASN1_INTEGER *iter;
    /** Optional derived key length in octets; NULL means the cipher default. */
    ASN1_INTEGER *keylength;
    /** Pseudorandom function AlgorithmIdentifier (defaults to HMAC-SHA1 when absent). */
    X509_ALGOR *prf;
} PBKDF2PARAM;""",
    "PBE2PARAM/PBKDF2PARAM",
)

patch_both(
    "x509.h",
    """    ASN1_INTEGER *parallelizationParameter;
    ASN1_INTEGER *keyLength;
} SCRYPT_PARAMS;""",
    """    /** Parallelization parameter (p) for scrypt. */
    ASN1_INTEGER *parallelizationParameter;
    /** Desired derived key length in octets. */
    ASN1_INTEGER *keyLength;
} SCRYPT_PARAMS;""",
    "SCRYPT_PARAMS.parallelizationParameter",
)

patch_both(
    "x509.h",
    """int X509_REQ_verify_ex(X509_REQ *a, EVP_PKEY *r, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    """/**
 * @brief Verify a certificate request's signature with an explicit library context.
 * @param a Certificate signing request to verify.
 * @param r Public key expected to have signed @p a.
 * @param libctx Library context used when fetching algorithms, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 if the signature is valid, 0 if invalid, or a negative value on error.
 */
int X509_REQ_verify_ex(X509_REQ *a, EVP_PKEY *r, OSSL_LIB_CTX *libctx,
    const char *propq);""",
    "X509_REQ_verify_ex",
)

patch_both(
    "x509.h",
    "int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);",
    """/**
 * @brief Sign a certificate revocation list with a private key and digest.
 * @param x CRL whose TBSCertList is signed; signature fields are filled in.
 * @param pkey Private key used for signing.
 * @param md Message digest identifying the signature algorithm.
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);""",
    "X509_CRL_sign",
)

patch_both(
    "x509.h",
    "OSSL_DEPRECATEDIN_3_0 int i2d_ECPrivateKey_bio(BIO *bp, const EC_KEY *eckey);",
    """/**
 * @brief Write an EC private key in SEC1 ECPrivateKey DER form to a BIO (deprecated).
 * @param bp Output BIO.
 * @param eckey EC key whose private key is encoded.
 * @return Number of bytes written, or a negative / zero value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_ECPrivateKey_bio(BIO *bp, const EC_KEY *eckey);""",
    "i2d_ECPrivateKey_bio",
)

patch_both(
    "x509.h",
    "int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, const EVP_PKEY *key);",
    """/**
 * @brief Write a private key as an unencrypted PKCS#8 PrivateKeyInfo DER blob to a BIO.
 * @param bp Output BIO.
 * @param key Key to encode.
 * @return 1 on success, or 0 on failure.
 */
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, const EVP_PKEY *key);""",
    "i2d_PKCS8PrivateKeyInfo_bio",
)

patch_both(
    "x509.h",
    "int X509_ALGOR_copy(X509_ALGOR *dest, const X509_ALGOR *src);",
    """/**
 * @brief Copy an AlgorithmIdentifier into an existing X509_ALGOR object.
 * @param dest Destination algorithm identifier; previous contents are replaced.
 * @param src Source algorithm identifier to copy.
 * @return 1 on success, or 0 on failure.
 */
int X509_ALGOR_copy(X509_ALGOR *dest, const X509_ALGOR *src);""",
    "X509_ALGOR_copy",
)

patch_both(
    "x509.h",
    "DECLARE_ASN1_FUNCTIONS(X509_NAME)",
    asn1_funcs("X509_NAME", "X.509 distinguished name (Name)") + "\n",
    "X509_NAME ASN.1",
)

patch_both(
    "x509.h",
    "int i2d_re_X509_tbs(X509 *x, unsigned char **pp);",
    """/**
 * @brief Re-encode a certificate's TBSCertificate to DER, refreshing the cached encoding.
 * @param x Certificate whose TBSCertificate is encoded.
 * @param pp Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_re_X509_tbs(X509 *x, unsigned char **pp);""",
    "i2d_re_X509_tbs",
)

patch_both(
    "x509.h",
    "X509_CRL *X509_CRL_new_ex(OSSL_LIB_CTX *libctx, const char *propq);",
    """/**
 * @brief Allocate an empty X509_CRL associated with a library context.
 * @param libctx Library context used for subsequent algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return New CRL, or NULL on allocation failure.
 */
X509_CRL *X509_CRL_new_ex(OSSL_LIB_CTX *libctx, const char *propq);""",
    "X509_CRL_new_ex",
)

patch_both(
    "x509.h",
    "X509_PKEY *X509_PKEY_new(void);",
    """/**
 * @brief Allocate an empty X509_PKEY structure for encrypted private-key packaging.
 * @return New X509_PKEY, or NULL on allocation failure; free with X509_PKEY_free().
 */
X509_PKEY *X509_PKEY_new(void);""",
    "X509_PKEY_new",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0
int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
    unsigned char *md, unsigned int *len);""",
    """/**
 * @brief Digest the DER encoding of an ASN.1 structure using a supplied i2d encoder (deprecated).
 * @param i2d Encoder function that serializes @p data to DER.
 * @param type Message digest algorithm to apply to the DER encoding.
 * @param data Pointer to the ASN.1 structure passed to @p i2d.
 * @param md Output buffer receiving the digest.
 * @param len Receives the digest length in bytes.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
    unsigned char *md, unsigned int *len);""",
    "ASN1_digest",
)

patch_both(
    "x509.h",
    "ASN1_TIME *X509_getm_notBefore(const X509 *x);",
    """/**
 * @brief Return the mutable notBefore validity time of a certificate.
 * @param x Certificate to query.
 * @return Internal ASN1_TIME pointer (do not free); changes affect @p x.
 */
ASN1_TIME *X509_getm_notBefore(const X509 *x);""",
    "X509_getm_notBefore",
)

patch_both(
    "x509.h",
    "int X509_CRL_set_version(X509_CRL *x, long version);",
    """/**
 * @brief Set the version field of a certificate revocation list.
 * @param x CRL to update.
 * @param version CRL version value (for example 1 for v2 CRLs).
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_set_version(X509_CRL *x, long version);""",
    "X509_CRL_set_version",
)

patch_both(
    "x509.h",
    "STACK_OF(X509_REVOKED) *X509_CRL_get_REVOKED(X509_CRL *crl);",
    """/**
 * @brief Return the mutable stack of revoked-certificate entries in a CRL.
 * @param crl CRL to query.
 * @return Internal STACK_OF(X509_REVOKED) (do not free the stack itself), or NULL if empty/unset.
 */
STACK_OF(X509_REVOKED) *X509_CRL_get_REVOKED(X509_CRL *crl);""",
    "X509_CRL_get_REVOKED",
)

patch_both(
    "x509.h",
    """int X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_subject_name_hash(X509 *x);""",
    """/**
 * @brief Compare the subject names of two certificates.
 * @param a First certificate.
 * @param b Second certificate.
 * @return 0 if the subject names are equal, or a non-zero value if they differ.
 */
int X509_subject_name_cmp(const X509 *a, const X509 *b);
/**
 * @brief Hash a certificate's subject name for OpenSSL certificate-directory lookup.
 * @param x Certificate whose subject name is hashed.
 * @return Hash value used by the classic "c_rehash" subject hash naming scheme.
 */
unsigned long X509_subject_name_hash(X509 *x);""",
    "X509_subject_name_cmp/hash",
)

patch_both(
    "x509.h",
    """int X509_NAME_get_index_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj,
    int lastpos);""",
    """/**
 * @brief Find the next name entry whose attribute type matches an ASN1_OBJECT.
 * @param name Distinguished name to search.
 * @param obj Attribute type OID to match (for example NID_commonName's object).
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Index of the next matching entry, or -1 if none remains.
 */
int X509_NAME_get_index_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj,
    int lastpos);""",
    "X509_NAME_get_index_by_OBJ",
)

patch_both(
    "x509.h",
    """void *X509at_get0_data_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *x,
    const ASN1_OBJECT *obj, int lastpos, int type);""",
    """/**
 * @brief Return attribute data matching an OID from a stack of X509_ATTRIBUTE values.
 * @param x Attribute stack to search.
 * @param obj Attribute type OID to locate.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @param type Expected ASN.1 type of the attribute value (for example V_ASN1_OCTET_STRING).
 * @return Internal pointer to the attribute data (do not free), or NULL if not found / type mismatch.
 */
void *X509at_get0_data_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *x,
    const ASN1_OBJECT *obj, int lastpos, int type);""",
    "X509at_get0_data_by_OBJ",
)

patch_both(
    "x509.h",
    "PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(const EVP_PKEY *pkey);",
    """/**
 * @brief Convert an EVP_PKEY into a PKCS#8 PrivateKeyInfo structure.
 * @param pkey Private key to encode.
 * @return Newly allocated PKCS8_PRIV_KEY_INFO, or NULL on error; free with PKCS8_PRIV_KEY_INFO_free().
 */
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(const EVP_PKEY *pkey);""",
    "EVP_PKEY2PKCS8",
)

# ----- x509_vfy.h -----
patch_both(
    "x509_vfy.h",
    """typedef enum {
    X509_LU_NONE = 0,
    X509_LU_X509,
    X509_LU_CRL
} X509_LOOKUP_TYPE;""",
    """/**
 * @brief Kind of object returned by an X509_LOOKUP.
 */
typedef enum {
    /** No lookup object / empty result. */
    X509_LU_NONE = 0,
    /** Lookup result is an X509 certificate. */
    X509_LU_X509,
    /** Lookup result is an X509_CRL. */
    X509_LU_CRL
} X509_LOOKUP_TYPE;""",
    "X509_LOOKUP_TYPE",
)

patch_both(
    "x509_vfy.h",
    "int X509_STORE_add_cert(X509_STORE *xs, X509 *x);",
    """/**
 * @brief Add a certificate to an X509_STORE's trusted-certificate cache.
 * @param xs Store that will retain @p x.
 * @param x Certificate to add; the store increments its reference count on success.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_add_cert(X509_STORE *xs, X509 *x);""",
    "X509_STORE_add_cert",
)

patch_both(
    "x509_vfy.h",
    "int X509_STORE_load_locations(X509_STORE *s, const char *file, const char *dir);",
    """/**
 * @brief Load trusted certificates from a PEM file and/or a hashed certificate directory.
 * @param s Store that receives the loaded trust anchors.
 * @param file Optional PEM file of certificates, or NULL.
 * @param dir Optional directory of hashed certificate files, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_load_locations(X509_STORE *s, const char *file, const char *dir);""",
    "X509_STORE_load_locations",
)

patch_both(
    "x509_vfy.h",
    "X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);",
    """/**
 * @brief Allocate a new certificate-verification parameter object with default settings.
 * @return New X509_VERIFY_PARAM, or NULL on allocation failure; free with X509_VERIFY_PARAM_free().
 */
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);""",
    "X509_VERIFY_PARAM_new",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509_POLICY_NODE)
*X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);""",
    """/**
 * @brief Return the user-policy nodes from a certificate policy tree.
 * @param tree Policy tree produced by policy evaluation.
 * @return Internal STACK_OF(X509_POLICY_NODE) of user policies (do not free), or NULL if none.
 */
STACK_OF(X509_POLICY_NODE)
*X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);""",
    "X509_policy_tree_get0_user_policies",
)

# ----- x509v3.h -----
patch_both(
    "x509v3.h",
    """    X509 *subject_cert;
    X509_REQ *subject_req;
    X509_CRL *crl;
    /** Callbacks used to read configuration sections while building extensions. */""",
    """    X509 *subject_cert;
    /** Certificate request used when constructing request-related extensions. */
    X509_REQ *subject_req;
    /** CRL used when constructing CRL-related extensions. */
    X509_CRL *crl;
    /** Callbacks used to read configuration sections while building extensions. */""",
    "v3_ext_ctx.crl",
)

print(f"\nDone: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print("  missing:", m)
