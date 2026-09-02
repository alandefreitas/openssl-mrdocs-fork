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

# engine
patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_meths(ENGINE *e);",
"""/**
 * @brief Register @p e's EVP_PKEY_METHOD implementations with the global table (deprecated).
 * @param e ENGINE providing public-key methods to register.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_pkey_meths(ENGINE *e);""",
"ENGINE_register_pkey_meths")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
    int cmd_optional);""",
"""/**
 * @brief Run a named ENGINE control command whose argument is a string (deprecated).
 * @param e ENGINE that receives the command.
 * @param cmd_name Command name as advertised by the ENGINE.
 * @param arg String argument for the command, or NULL.
 * @param cmd_optional Non-zero to treat an unknown command as success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
    int cmd_optional);""",
"ENGINE_ctrl_cmd_string")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);",
"""/**
 * @brief Attach a DH_METHOD implementation to an ENGINE (deprecated).
 * @param e ENGINE whose DH method pointer is replaced.
 * @param dh_meth DH method table to use, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);""",
"ENGINE_set_DH")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);""",
"""/**
 * @brief Set the ctrl callback used by ENGINE_ctrl() for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param ctrl_f Control function, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);""",
"ENGINE_set_ctrl_function")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_DSA(ENGINE *e);",
"""/**
 * @brief Register @p e as the default ENGINE for DSA operations (deprecated).
 * @param e ENGINE to install as the DSA default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_DSA(ENGINE *e);""",
"ENGINE_set_default_DSA")

# err
patch_both("err.h",
"""static ossl_unused ossl_inline int ERR_COMMON_ERROR(unsigned long errcode)
{
    return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_COMMON) != 0;
}""",
"""/**
 * @brief Return whether an error code is a system-independent common ERR reason.
 * @param errcode Packed OpenSSL error code.
 * @return Non-zero if ERR_RFLAG_COMMON is set on @p errcode, otherwise 0.
 */
static ossl_unused ossl_inline int ERR_COMMON_ERROR(unsigned long errcode)
{
    return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_COMMON) != 0;
}""",
"ERR_COMMON_ERROR")

patch_both("err.h",
"int ERR_count_to_mark(void);",
"""/**
 * @brief Count error-stack entries above the most recently set mark.
 * @return Number of errors pushed since ERR_set_mark(), or 0 if no mark is active.
 */
int ERR_count_to_mark(void);""",
"ERR_count_to_mark")

# hmac / kdf / lhash / objects / params
patch_both("hmac.h",
"""OSSL_DEPRECATEDIN_3_0 int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data,
    size_t len);""",
"""/**
 * @brief Absorb more message bytes into an HMAC context (deprecated; prefer EVP_MAC_update).
 * @param ctx HMAC context initialized with HMAC_Init_ex().
 * @param data Next chunk of message bytes.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data,
    size_t len);""",
"HMAC_Update")

patch_both("kdf.h",
"int EVP_KDF_up_ref(EVP_KDF *kdf);",
"""/**
 * @brief Increment the reference count on a fetched EVP_KDF method.
 * @param kdf KDF method returned by EVP_KDF_fetch().
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_up_ref(EVP_KDF *kdf);""",
"EVP_KDF_up_ref")

patch_both("kdf.h",
"EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src);",
"""/**
 * @brief Duplicate a KDF context, copying algorithm state where supported.
 * @param src Source context to copy.
 * @return New EVP_KDF_CTX, or NULL on failure.
 */
EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src);""",
"EVP_KDF_CTX_dup")

patch_both("lhash.h",
"OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out);",
"""/**
 * @brief Print summary statistics for a hash table to a BIO (deprecated).
 * @param lh Hash table to describe.
 * @param out BIO that receives the human-readable report.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out);""",
"OPENSSL_LH_stats_bio")

patch_both("objects.h",
"int OBJ_create(const char *oid, const char *sn, const char *ln);",
"""/**
 * @brief Register a new ASN.1 object identifier with short and long names.
 * @param oid Numeric OID string (for example "1.2.3.4").
 * @param sn Short name to associate with the OID.
 * @param ln Long name to associate with the OID.
 * @return New NID on success, or NID_undef on error.
 */
int OBJ_create(const char *oid, const char *sn, const char *ln);""",
"OBJ_create")

patch_both("objects.h",
"int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);",
"""/**
 * @brief Look up the composite signature NID for a digest and public-key algorithm pair.
 * @param psignid On success, receives the signature algorithm NID.
 * @param dig_nid Digest algorithm NID (may be NID_undef for pure signatures).
 * @param pkey_nid Public-key algorithm NID.
 * @return 1 if a mapping was found, or 0 otherwise.
 */
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);""",
"OBJ_find_sigid_by_algs")

patch_both("params.h",
"int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val);",
"""/**
 * @brief Read an OSSL_PARAM value as a size_t.
 * @param p Parameter locating the value.
 * @param val Receives the converted integer on success.
 * @return 1 on success, or 0 if the parameter is missing or has an incompatible type.
 */
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val);""",
"OSSL_PARAM_get_size_t")

patch_both("params.h",
"""int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
    size_t *used_len);""",
"""/**
 * @brief Copy an OSSL_PARAM octet-string value into a caller buffer.
 * @param p Parameter locating the octet string.
 * @param val Address of a buffer pointer that receives up to @p max_len bytes; may allocate when *@p val is NULL depending on call pattern.
 * @param max_len Capacity of the destination buffer in bytes.
 * @param used_len Optional output set to the number of bytes copied or required.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
    size_t *used_len);""",
"OSSL_PARAM_get_octet_string")

patch_both("params.h",
"void OSSL_PARAM_free(OSSL_PARAM *p);",
"""/**
 * @brief Free an OSSL_PARAM array allocated by OSSL_PARAM_dup() or OSSL_PARAM_merge().
 * @param p Parameter array to free, or NULL.
 */
void OSSL_PARAM_free(OSSL_PARAM *p);""",
"OSSL_PARAM_free")

# pkcs7
patch_both("pkcs7.h",
"""typedef struct pkcs7_issuer_and_serial_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
} PKCS7_ISSUER_AND_SERIAL;""",
"""/**
 * @brief Issuer name and certificate serial number identifying a PKCS#7 signer or recipient.
 */
typedef struct pkcs7_issuer_and_serial_st {
    /** Distinguished name of the certificate issuer. */
    X509_NAME *issuer;
    /** Certificate serial number issued by @c issuer. */
    ASN1_INTEGER *serial;
} PKCS7_ISSUER_AND_SERIAL;""",
"PKCS7_ISSUER_AND_SERIAL")

patch_both("pkcs7.h",
"""    int state; /* used during processing */
    int detached;
    ASN1_OBJECT *type;""",
"""    int state; /* used during processing */
    /** Non-zero when the PKCS#7 content is detached from the signedData structure. */
    int detached;
    ASN1_OBJECT *type;""",
"pkcs7_st::detached")

patch_both("pkcs7.h",
"""int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
    BIO *indata, BIO *out, int flags);""",
"""/**
 * @brief Verify a PKCS#7 signedData structure and optionally write the content.
 * @param p7 Signed PKCS#7 object to verify.
 * @param certs Optional untrusted certificates that may complete signer chains.
 * @param store Trusted certificate store used for chain verification.
 * @param indata BIO supplying detached content when the signature does not embed it.
 * @param out Optional BIO that receives the verified content.
 * @param flags PKCS7_* verification flags (for example PKCS7_NOVERIFY, PKCS7_DETACHED).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
    BIO *indata, BIO *out, int flags);""",
"PKCS7_verify")

patch_both("pkcs7.h",
"""STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
    int flags);""",
"""/**
 * @brief Return the signer certificates used by PKCS7_verify() without duplicating them.
 * @param p7 Signed PKCS#7 object whose signers are located.
 * @param certs Optional certificates searched in addition to those embedded in @p p7.
 * @param flags PKCS7_* flags controlling signer lookup (for example PKCS7_NOINTERN).
 * @return Stack of X509 pointers owned by @p p7 / @p certs (do not free elements), or NULL on error.
 */
STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
    int flags);""",
"PKCS7_get0_signers")

patch_both("pkcs7.h",
"""PKCS7 *PKCS7_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
    const EVP_CIPHER *cipher, int flags,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"""/**
 * @brief Create a PKCS#7 envelopedData encrypting @p in for each recipient in @p certs.
 * @param certs Recipient certificates whose public keys encrypt the content-encryption key.
 * @param in BIO supplying the plaintext content.
 * @param cipher Content-encryption cipher (for example AES-256-CBC).
 * @param flags PKCS7_* encryption flags.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return New PKCS7 envelopedData object, or NULL on error.
 */
PKCS7 *PKCS7_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
    const EVP_CIPHER *cipher, int flags,
    OSSL_LIB_CTX *libctx, const char *propq);""",
"PKCS7_encrypt_ex")

patch_both("pkcs7.h",
"int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t);",
"""/**
 * @brief Add a signing-time authenticated attribute, taking ownership of @p t.
 * @param si SignerInfo to update.
 * @param t Signing time to attach, or NULL to use the current time (allocated internally).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t);""",
"PKCS7_add0_attrib_signing_time")

# rsa / sha
patch_both("rsa.h",
"""OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int sLen);""",
"""/**
 * @brief Verify a PKCS#1 PSS-encoded digest using an explicit MGF1 hash (deprecated).
 * @param rsa RSA key whose modulus length defines the encoded message size.
 * @param mHash Message digest that was signed.
 * @param Hash Hash algorithm that produced @p mHash and labels the PSS encoding.
 * @param mgf1Hash Hash algorithm used by MGF1, or NULL to use @p Hash.
 * @param EM Encoded message to verify (typically RSA_size(rsa) bytes).
 * @param sLen Salt length in bytes, or a special RSA_PSS_SALTLEN_* value.
 * @return 1 if the encoding is valid, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int sLen);""",
"RSA_verify_PKCS1_PSS_mgf1")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_new(const char *name, int flags);",
"""/**
 * @brief Allocate a new RSA_METHOD with the given name and flags (deprecated).
 * @param name Human-readable method name copied into the object.
 * @param flags Method flags such as RSA_METHOD_FLAG_NO_CHECK.
 * @return New RSA_METHOD, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 RSA_METHOD *RSA_meth_new(const char *name, int flags);""",
"RSA_meth_new")

patch_both("sha.h",
"OSSL_DEPRECATEDIN_3_0 int SHA224_Init(SHA256_CTX *c);",
"""/**
 * @brief Initialize a SHA-224 digest context (deprecated; prefer EVP_DigestInit_ex).
 * @param c Context to initialize (uses the SHA256_CTX layout).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Init(SHA256_CTX *c);""",
"SHA224_Init")

# types.h
patch_both("types.h",
"typedef struct asn1_string_st ASN1_OCTET_STRING;",
"""/**
 * @brief ASN.1 OCTET STRING stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_OCTET_STRING;""",
"ASN1_OCTET_STRING")

patch_both("types.h",
"typedef struct asn1_string_table_st ASN1_STRING_TABLE;",
"""/**
 * @brief Table entry describing size limits and encoding masks for an ASN.1 string NID.
 */
typedef struct asn1_string_table_st ASN1_STRING_TABLE;""",
"ASN1_STRING_TABLE")

patch_both("types.h",
"typedef struct hmac_ctx_st HMAC_CTX;",
"""/**
 * @brief Opaque HMAC computation context (legacy HMAC_* API).
 */
typedef struct hmac_ctx_st HMAC_CTX;""",
"HMAC_CTX")

patch_both("types.h",
"typedef struct ec_key_st EC_KEY;",
"""/**
 * @brief Opaque elliptic-curve key containing group parameters and public/private points.
 */
typedef struct ec_key_st EC_KEY;""",
"EC_KEY")

patch_both("types.h",
"typedef struct ossl_store_info_st OSSL_STORE_INFO;",
"""/**
 * @brief Opaque object returned by OSSL_STORE describing a loaded key, cert, or CRL.
 */
typedef struct ossl_store_info_st OSSL_STORE_INFO;""",
"OSSL_STORE_INFO")

patch_both("types.h",
"typedef struct ossl_decoder_st OSSL_DECODER;",
"""/**
 * @brief Opaque decoder method that converts external key/cert encodings into OpenSSL objects.
 */
typedef struct ossl_decoder_st OSSL_DECODER;""",
"OSSL_DECODER")

print(f"done ok={len(ok)} miss={len(missing)}")
if missing:
    print("MISSING:", *missing, sep="\n  ")
