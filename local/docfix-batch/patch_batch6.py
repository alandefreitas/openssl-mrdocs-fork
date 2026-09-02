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

# ----- asn1.h -----
patch_both("asn1.h",
"unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p);",
"""/**
 * @brief Return the OID print flags currently set on an ASN.1 print context.
 * @param p Print context to query.
 * @return ASN1_STRFLGS_* style flags controlling OID formatting.
 */
unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p);""",
"ASN1_PCTX_get_oid_flags")

patch_both("asn1.h",
"int ASN1_str2mask(const char *str, unsigned long *pmask);",
"""/**
 * @brief Parse a pipe-separated list of ASN1_STRFLGS_* flag names into a mask.
 * @param str Flag names such as "utf8|esc_ctrl" (case-insensitive).
 * @param pmask Receives the combined flag mask on success.
 * @return 1 on success, or 0 if @p str contains an unknown name.
 */
int ASN1_str2mask(const char *str, unsigned long *pmask);""",
"ASN1_str2mask")

patch_both("asn1.h",
"int ASN1_STRING_set_default_mask_asc(const char *p);",
"""/**
 * @brief Set the default ASN.1 string type mask from an ASCII name or mask expression.
 * @param p Mask description such as "utf8only", "default", or a numeric bitmask string.
 * @return 1 on success, or 0 if @p p is not recognized.
 */
int ASN1_STRING_set_default_mask_asc(const char *p);""",
"ASN1_STRING_set_default_mask_asc")

patch_both("asn1.h",
"int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm);",
"""/**
 * @brief Convert an ASN.1 time value to a broken-down UTC struct tm.
 * @param s ASN1_TIME (UTCTime or GeneralizedTime) to convert.
 * @param tm Destination calendar time in UTC; may be NULL to only validate @p s.
 * @return 1 on success, or 0 if @p s is invalid.
 */
int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm);""",
"ASN1_TIME_to_tm")

patch_both("asn1.h",
"int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);",
"""/**
 * @brief Set an ASN1_TIME from a string, preferring the X.509 UTCTime/GeneralizedTime rules.
 * @param s Destination time object to update.
 * @param str NUL-terminated time string in ASN.1 UTCTime or GeneralizedTime form.
 * @return 1 on success, or 0 if @p str is not a valid X.509 time encoding.
 */
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);""",
"ASN1_TIME_set_string_X509")

patch_both("asn1.h",
"DECLARE_ASN1_FUNCTIONS(ASN1_TIME)",
asn1_funcs("ASN1_TIME", "ASN.1 time value (UTCTime or GeneralizedTime)"),
"ASN1_TIME_asn1_funcs")

patch_both("asn1.h",
"void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);",
"""/**
 * @brief Assign an ASN.1 string ownership of an existing data buffer.
 * @param str String whose content pointer and length are replaced.
 * @param data Buffer that @p str will own (freed by ASN1_STRING_free); may be NULL when @p len is 0.
 * @param len Length of @p data in bytes.
 */
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);""",
"ASN1_STRING_set0")

patch_both("asn1.h",
"""typedef void *d2i_of_void(void **, const unsigned char **, long);
typedef int i2d_of_void(const void *, unsigned char **);""",
"""/**
 * @brief Function-pointer type for a type-erased ASN.1 DER decoder (d2i_*).
 * @param a Optional destination pointer updated to the decoded object, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded object pointer, or NULL on error.
 */
typedef void *d2i_of_void(void **, const unsigned char **, long);
/**
 * @brief Function-pointer type for a type-erased ASN.1 DER encoder (i2d_*).
 * @param a Object to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
typedef int i2d_of_void(const void *, unsigned char **);""",
"d2i_of_void")

# ----- async.h -----
patch_both("async.h",
"int ASYNC_pause_job(void);",
"""/**
 * @brief Pause the current ASYNC_JOB and return control to ASYNC_start_job().
 * @return 1 if the job paused successfully, or 0 if pausing is blocked or no job is running.
 */
int ASYNC_pause_job(void);""",
"ASYNC_pause_job")

patch_both("async.h",
"""int ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx,
    ASYNC_callback_fn *callback,
    void **callback_arg);""",
"""/**
 * @brief Retrieve the completion callback previously set on an async wait context.
 * @param ctx Wait context to query.
 * @param callback Receives the registered callback function pointer.
 * @param callback_arg Receives the callback user argument.
 * @return 1 if a callback is set, or 0 if none was registered.
 */
int ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx,
    ASYNC_callback_fn *callback,
    void **callback_arg);""",
"ASYNC_WAIT_CTX_get_callback")

# ----- bio.h -----
patch_both("bio.h",
"""int BIO_meth_set_recvmmsg(BIO_METHOD *biom,
    int (*f)(BIO *, BIO_MSG *, size_t, size_t,
        uint64_t, size_t *));""",
"""/**
 * @brief Install the multi-message receive callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param f Callback implementing recvmmsg-style reception into BIO_MSG entries.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_recvmmsg(BIO_METHOD *biom,
    int (*f)(BIO *, BIO_MSG *, size_t, size_t,
        uint64_t, size_t *));""",
"BIO_meth_set_recvmmsg")

patch_both("bio.h",
"int BIO_err_is_non_fatal(unsigned int errcode);",
"""/**
 * @brief Report whether a system or socket error code is a non-fatal retryable I/O condition.
 * @param errcode Error code such as a value from errno / WSAGetLastError().
 * @return 1 if the error is considered non-fatal for BIO I/O, or 0 otherwise.
 */
int BIO_err_is_non_fatal(unsigned int errcode);""",
"BIO_err_is_non_fatal")

patch_both("bio.h",
"int BIO_ctrl_reset_read_request(BIO *b);",
"""/**
 * @brief Clear the pending read-request size tracked by a buffering BIO.
 * @param b BIO whose read-request state is reset.
 * @return 1 on success, or 0 on failure.
 */
int BIO_ctrl_reset_read_request(BIO *b);""",
"BIO_ctrl_reset_read_request")

patch_both("bio.h",
"size_t BIO_ctrl_get_write_guarantee(BIO *b);",
"""/**
 * @brief Return how many bytes can currently be written without blocking or growing buffers.
 * @param b Buffering BIO to query.
 * @return Guaranteed writable byte count.
 */
size_t BIO_ctrl_get_write_guarantee(BIO *b);""",
"BIO_ctrl_get_write_guarantee")

patch_both("bio.h",
"    BIO_ADDR *peer, *local;",
"""    /** Peer socket address associated with this message, or NULL if unused. */
    BIO_ADDR *peer;
    /** Local socket address associated with this message, or NULL if unused. */
    BIO_ADDR *local;""",
"BIO_MSG::peer_local")

patch_both("bio.h",
"int BIO_test_flags(const BIO *b, int flags);",
"""/**
 * @brief Test whether any of the given flag bits are set on a BIO.
 * @param b BIO whose flags are examined.
 * @param flags Bitmask of BIO_FLAGS_* values to test.
 * @return Bitwise AND of the BIO's flags with @p flags.
 */
int BIO_test_flags(const BIO *b, int flags);""",
"BIO_test_flags")

# ----- blowfish.h -----
patch_both("blowfish.h",
"""typedef struct bf_key_st {
    BF_LONG P[BF_ROUNDS + 2];
    BF_LONG S[4 * 256];
} BF_KEY;""",
"""/**
 * @brief Legacy Blowfish expanded key schedule (P-array and S-boxes).
 */
typedef struct bf_key_st {
    /** Blowfish P-array including the two extra subkeys. */
    BF_LONG P[BF_ROUNDS + 2];
    /** Blowfish S-boxes (four boxes of 256 entries). */
    BF_LONG S[4 * 256];
} BF_KEY;""",
"BF_KEY")

# ----- bn.h -----
patch_both("bn.h",
"""int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);""",
"""/**
 * @brief Compute r = (a ^ b) mod p for binary polynomial-field (GF(2^m)) values.
 * @param r Result BIGNUM.
 * @param a Base.
 * @param b Exponent.
 * @param p Irreducible field polynomial.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);""",
"BN_GF2m_mod_exp")

patch_both("bn.h",
"""OSSL_DEPRECATEDIN_0_9_8
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem,
    void (*callback)(int, int, void *),
    void *cb_arg);""",
"""/**
 * @brief Generate a prime of approximately @p bits (deprecated; prefer BN_generate_prime_ex).
 * @param ret Destination BIGNUM, or NULL to allocate a new one.
 * @param bits Desired bit length of the prime.
 * @param safe Nonzero to require a safe prime ((p-1)/2 also prime).
 * @param add Optional congruence modulus constraint, or NULL.
 * @param rem Optional remainder for the @p add constraint, or NULL.
 * @param callback Progress callback, or NULL.
 * @param cb_arg User argument passed to @p callback.
 * @return Generated prime BIGNUM, or NULL on error.
 */
OSSL_DEPRECATEDIN_0_9_8
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem,
    void (*callback)(int, int, void *),
    void *cb_arg);""",
"BN_generate_prime")

patch_both("bn.h",
"""int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
    BN_CTX *ctx);""",
"""/**
 * @brief Divide @p m by @p d, writing quotient and/or remainder.
 * @param dv Receives the quotient, or NULL if not required.
 * @param rem Receives the remainder, or NULL if not required.
 * @param m Dividend.
 * @param d Divisor (must be non-zero).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
    BN_CTX *ctx);""",
"BN_div")

patch_both("bn.h",
"void BN_clear_free(BIGNUM *a);",
"""/**
 * @brief Clear sensitive digits of a BIGNUM and free it.
 * @param a BIGNUM to wipe and free, or NULL.
 */
void BN_clear_free(BIGNUM *a);""",
"BN_clear_free")


# ----- cms.h -----
patch_both("cms.h",
"""int CMS_RecipientInfo_kari_get0_orig_id(CMS_RecipientInfo *ri,
    X509_ALGOR **pubalg,
    ASN1_BIT_STRING **pubkey,
    ASN1_OCTET_STRING **keyid,
    X509_NAME **issuer,
    ASN1_INTEGER **sno);""",
"""/**
 * @brief Get the originator identifier from a key-agreement RecipientInfo.
 * @param ri Recipient info of type CMS_RECIPINFO_AGREE.
 * @param pubalg Receives the originator public-key algorithm, or NULL if not requested.
 * @param pubkey Receives the originator public key BIT STRING, or NULL if not requested.
 * @param keyid Receives the originator subject key identifier, or NULL if not requested.
 * @param issuer Receives the originator issuer name, or NULL if not requested.
 * @param sno Receives the originator serial number, or NULL if not requested.
 * @return 1 on success, or 0 if @p ri is not a key-agreement recipient.
 */
int CMS_RecipientInfo_kari_get0_orig_id(CMS_RecipientInfo *ri,
    X509_ALGOR **pubalg,
    ASN1_BIT_STRING **pubkey,
    ASN1_OCTET_STRING **keyid,
    X509_NAME **issuer,
    ASN1_INTEGER **sno);""",
"CMS_RecipientInfo_kari_get0_orig_id")

patch_both("cms.h",
"int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr);",
"""/**
 * @brief Extract a CMS ReceiptRequest attribute from a SignerInfo.
 * @param si SignerInfo whose signed attributes are searched.
 * @param prr Receives a newly allocated ReceiptRequest on success; set to NULL if absent.
 * @return 1 if found, 0 if not present, or -1 on decode error.
 */
int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr);""",
"CMS_get1_ReceiptRequest")

patch_both("cms.h",
"""int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si,
    const ASN1_OBJECT *obj, int lastpos);""",
"""/**
 * @brief Find an unsigned attribute by ASN.1 object in a CMS SignerInfo.
 * @param si SignerInfo whose unsignedAttrs are searched.
 * @param obj Attribute type OID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Attribute index, or -1 if not found.
 */
int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si,
    const ASN1_OBJECT *obj, int lastpos);""",
"CMS_unsigned_get_attr_by_OBJ")

patch_both("cms.h",
"""int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
    int lastpos);""",
"""/**
 * @brief Find an unsigned attribute by NID in a CMS SignerInfo.
 * @param si SignerInfo whose unsignedAttrs are searched.
 * @param nid Attribute type NID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Attribute index, or -1 if not found.
 */
int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
    int lastpos);""",
"CMS_unsigned_get_attr_by_NID")

patch_both("cms.h",
"""void *CMS_signed_get0_data_by_OBJ(const CMS_SignerInfo *si,
    const ASN1_OBJECT *oid,
    int lastpos, int type);""",
"""/**
 * @brief Return the first matching signed-attribute value of a given ASN.1 type.
 * @param si SignerInfo whose signedAttrs are searched.
 * @param oid Attribute type OID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @param type Expected ASN.1 type of the attribute value (for example V_ASN1_OCTET_STRING).
 * @return Pointer to the attribute value data, or NULL if not found / type mismatch.
 */
void *CMS_signed_get0_data_by_OBJ(const CMS_SignerInfo *si,
    const ASN1_OBJECT *oid,
    int lastpos, int type);""",
"CMS_signed_get0_data_by_OBJ")

patch_both("cms.h",
"int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);",
"""/**
 * @brief Append a copy of an X509_ATTRIBUTE to a CMS SignerInfo's signed attributes.
 * @param si SignerInfo whose signedAttrs set is extended.
 * @param attr Attribute to duplicate and append.
 * @return 1 on success, or 0 on failure.
 */
int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr);""",
"CMS_signed_add1_attr")

patch_both("cms.h",
"""void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
    X509 **signer, X509_ALGOR **pdig,
    X509_ALGOR **psig);""",
"""/**
 * @brief Retrieve algorithm and key pointers from a CMS SignerInfo.
 * @param si SignerInfo to query.
 * @param pk Receives the signer's public key if available, or NULL if not requested.
 * @param signer Receives the signer certificate if available, or NULL if not requested.
 * @param pdig Receives the digest algorithm, or NULL if not requested.
 * @param psig Receives the signature algorithm, or NULL if not requested.
 */
void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
    X509 **signer, X509_ALGOR **pdig,
    X509_ALGOR **psig);""",
"CMS_SignerInfo_get0_algs")

patch_both("cms.h",
"void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer);",
"""/**
 * @brief Associate a signer certificate with a CMS SignerInfo (increments the cert reference).
 * @param si SignerInfo to update.
 * @param signer Signer certificate to attach.
 */
void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer);""",
"CMS_SignerInfo_set1_signer_cert")

patch_both("cms.h",
"STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);",
"""/**
 * @brief Return a newly allocated stack of CRLs embedded in a CMS ContentInfo.
 * @param cms CMS structure that may contain certificates/CRLs (typically SignedData).
 * @return New STACK_OF(X509_CRL) with up-referenced CRLs, or NULL if none / on error.
 */
STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms);""",
"CMS_get1_crls")

patch_both("cms.h",
"""int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
    unsigned char *pass,
    ossl_ssize_t passlen);""",
"""/**
 * @brief Supply the password used to derive the KEK for a PasswordRecipientInfo.
 * @param ri Recipient info of type CMS_RECIPINFO_PASS.
 * @param pass Password bytes; ownership transfers to @p ri (may be cleared on free).
 * @param passlen Length of @p pass in bytes, or -1 if NUL-terminated.
 * @return 1 on success, or 0 on failure.
 */
int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
    unsigned char *pass,
    ossl_ssize_t passlen);""",
"CMS_RecipientInfo_set0_password")

patch_both("cms.h",
"""int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
    EVP_PKEY **pk, X509 **recip,
    X509_ALGOR **palg);""",
"""/**
 * @brief Retrieve key-transport algorithms and related objects from a RecipientInfo.
 * @param ri Recipient info of type CMS_RECIPINFO_TRANS.
 * @param pk Receives the recipient public key if available, or NULL if not requested.
 * @param recip Receives the recipient certificate if available, or NULL if not requested.
 * @param palg Receives the key-encryption algorithm, or NULL if not requested.
 * @return 1 on success, or 0 on failure.
 */
int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
    EVP_PKEY **pk, X509 **recip,
    X509_ALGOR **palg);""",
"CMS_RecipientInfo_ktri_get0_algs")

patch_both("cms.h",
"int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);",
"""/**
 * @brief Compare a certificate against the recipient identifier in a key-transport RecipientInfo.
 * @param ri Recipient info of type CMS_RECIPINFO_TRANS.
 * @param cert Certificate whose issuer/serial or subject key id is compared.
 * @return 0 if @p cert matches the recipient id, or non-zero otherwise.
 */
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);""",
"CMS_RecipientInfo_ktri_cert_cmp")

patch_both("cms.h",
"""CMS_ContentInfo *CMS_EnvelopedData_create_ex(const EVP_CIPHER *cipher,
    OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Create an empty CMS EnvelopedData ContentInfo using a library context.
 * @param cipher Content-encryption cipher whose ASN.1 parameters will be encoded.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New EnvelopedData ContentInfo, or NULL on error.
 */
CMS_ContentInfo *CMS_EnvelopedData_create_ex(const EVP_CIPHER *cipher,
    OSSL_LIB_CTX *libctx,
    const char *propq);""",
"CMS_EnvelopedData_create_ex")

patch_both("cms.h",
"""CMS_ContentInfo *
CMS_AuthEnvelopedData_create_ex(const EVP_CIPHER *cipher, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Create an empty CMS AuthEnvelopedData ContentInfo using a library context.
 * @param cipher Symmetric AEAD cipher to use (for example AES-GCM); must encode ASN.1 parameters.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New AuthEnvelopedData ContentInfo, or NULL on error.
 */
CMS_ContentInfo *
CMS_AuthEnvelopedData_create_ex(const EVP_CIPHER *cipher, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"CMS_AuthEnvelopedData_create_ex")

patch_both("cms.h",
"""int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
    X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);""",
"""/**
 * @brief Verify CMS SignedData signatures and write the content to @p out when requested.
 * @param cms SignedData ContentInfo to verify.
 * @param certs Optional untrusted certificates to aid signer location, or NULL.
 * @param store Trusted certificate store used to build and validate signer chains, or NULL.
 * @param dcont Detached content BIO when the payload is not embedded; otherwise NULL.
 * @param out Optional BIO that receives the verified content, or NULL.
 * @param flags CMS verify flags (for example CMS_NO_SIGNER_CERT_VERIFY).
 * @return 1 on success, or 0 on failure.
 */
int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
    X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);""",
"CMS_verify")

patch_both("cms.h",
"""CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey,
    STACK_OF(X509) *certs, BIO *data,
    unsigned int flags, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Create a CMS SignedData structure using a library context.
 * @param signcert Signer certificate corresponding to @p pkey, or NULL for certificates-only.
 * @param pkey Signer private key, or NULL when only embedding certificates.
 * @param certs Optional intermediate certificates to include, or NULL.
 * @param data Content BIO to sign (read fully unless CMS_STREAM / CMS_PARTIAL flags apply).
 * @param flags CMS signing flags (for example CMS_DETACHED, CMS_BINARY).
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New SignedData ContentInfo, or NULL on error.
 */
CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey,
    STACK_OF(X509) *certs, BIO *data,
    unsigned int flags, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"CMS_sign_ex")

patch_both("cms.h",
"""CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
    STACK_OF(X509) *certs, BIO *data,
    unsigned int flags);""",
"""/**
 * @brief Create a CMS SignedData structure with the default library context.
 * @param signcert Signer certificate corresponding to @p pkey, or NULL for certificates-only.
 * @param pkey Signer private key, or NULL when only embedding certificates.
 * @param certs Optional intermediate certificates to include, or NULL.
 * @param data Content BIO to sign.
 * @param flags CMS signing flags (for example CMS_DETACHED, CMS_BINARY).
 * @return New SignedData ContentInfo, or NULL on error.
 */
CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
    STACK_OF(X509) *certs, BIO *data,
    unsigned int flags);""",
"CMS_sign")

patch_both("cms.h",
"""int CMS_final_digest(CMS_ContentInfo *cms,
    const unsigned char *md, unsigned int mdlen, BIO *dcont,
    unsigned int flags);""",
"""/**
 * @brief Finalize a partially built CMS SignedData using a precomputed content digest.
 * @param cms Partial CMS structure created with CMS_PARTIAL (or streaming) flags.
 * @param md Precomputed message digest of the content.
 * @param mdlen Length of @p md in bytes.
 * @param dcont Detached content BIO when applicable, or NULL.
 * @param flags CMS finalization flags.
 * @return 1 on success, or 0 on failure.
 */
int CMS_final_digest(CMS_ContentInfo *cms,
    const unsigned char *md, unsigned int mdlen, BIO *dcont,
    unsigned int flags);""",
"CMS_final_digest")

patch_both("cms.h",
"int CMS_set_detached(CMS_ContentInfo *cms, int detached);",
"""/**
 * @brief Mark CMS content as detached (external) or embedded.
 * @param cms ContentInfo whose eContent embedding is updated.
 * @param detached Nonzero for detached content; zero to keep content inside SignedData.
 * @return 1 on success, or 0 on failure.
 */
int CMS_set_detached(CMS_ContentInfo *cms, int detached);""",
"CMS_set_detached")

patch_both("cms.h",
"typedef struct CMS_SignerInfo_st CMS_SignerInfo;",
"""/**
 * @brief Opaque CMS SignerInfo: per-signer algorithms, sid, signed/unsigned attrs, and signature.
 */
typedef struct CMS_SignerInfo_st CMS_SignerInfo;""",
"CMS_SignerInfo")

patch_both("cms.h",
"typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;",
"""/**
 * @brief Opaque CMS EnvelopedData: recipient infos and encrypted content info.
 */
typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;""",
"CMS_EnvelopedData")


# ----- conf.h -----
patch_both("conf.h",
"void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags);",
"""/**
 * @brief Set control flags on a loaded configuration module instance.
 * @param md Module instance to update.
 * @param flags Bitmask of CONF_MFLAGS_* values.
 */
void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags);""",
"CONF_imodule_set_flags")

patch_both("conf.h",
"int NCONF_dump_fp(const CONF *conf, FILE *out);",
"""/**
 * @brief Write the contents of a CONF object to a FILE in name=value form.
 * @param conf Configuration to dump.
 * @param out Destination stdio stream.
 * @return 1 on success, or 0 on failure.
 */
int NCONF_dump_fp(const CONF *conf, FILE *out);""",
"NCONF_dump_fp")

patch_both("conf.h",
"int NCONF_load_fp(CONF *conf, FILE *fp, long *eline);",
"""/**
 * @brief Load configuration name/value pairs from an open FILE.
 * @param conf Destination configuration object.
 * @param fp Input stream positioned at the start of the config text.
 * @param eline Optional output for the line number of a parse error, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int NCONF_load_fp(CONF *conf, FILE *fp, long *eline);""",
"NCONF_load_fp")

patch_both("conf.h",
"OSSL_DEPRECATEDIN_3_0 CONF_METHOD *NCONF_WIN32(void);",
"""/**
 * @brief Return the legacy Win32 CONF_METHOD (deprecated).
 * @return Pointer to the Win32 configuration method table.
 */
OSSL_DEPRECATEDIN_3_0 CONF_METHOD *NCONF_WIN32(void);""",
"NCONF_WIN32")

patch_both("conf.h",
"""typedef int conf_init_func(CONF_IMODULE *md, const CONF *cnf);
typedef void conf_finish_func(CONF_IMODULE *md);""",
"""/**
 * @brief DSO module initializer called when a CONF module is loaded.
 * @param md Module instance being initialized.
 * @param cnf Configuration object that triggered the load.
 * @return 1 on success, or 0 on failure.
 */
typedef int conf_init_func(CONF_IMODULE *md, const CONF *cnf);
/**
 * @brief DSO module finalizer called when a CONF module is unloaded.
 * @param md Module instance being finished.
 */
typedef void conf_finish_func(CONF_IMODULE *md);""",
"conf_init_finish_func")

# ----- core.h -----
patch_both("core.h",
"    const char *property_definition; /* key */",
"""    /** Property query string that further identifies this algorithm (provider key). */
    const char *property_definition;""",
"property_definition")

# ----- crypto.h -----
patch_both("crypto.h",
"""/*
 * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the
 * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
 * into a defined order as the return value when a != b is undefined, other
 * than to be non-zero.
 */
int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len);""",
"""/**
 * @brief Compare two memory regions in constant time with respect to their contents.
 * @param in_a First buffer.
 * @param in_b Second buffer.
 * @param len Number of bytes to compare.
 * @return 0 if the @p len bytes are equal; non-zero otherwise (ordering is undefined).
 *
 * Runtime depends on @p len but not on the data at @p in_a / @p in_b. Unlike memcmp,
 * the non-zero return value must not be used to sort elements.
 */
int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len);""",
"CRYPTO_memcmp")

patch_both("crypto.h",
"OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_child(void);",
"""/**
 * @brief Rebuild per-process cryptographic state in a freshly forked child (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_child(void);""",
"OPENSSL_fork_child")

patch_both("crypto.h",
"""int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
    const CRYPTO_EX_DATA *from);""",
"""/**
 * @brief Duplicate CRYPTO_EX_DATA entries from @p from into @p to for a class.
 * @param class_index CRYPTO_EX_INDEX_* identifying the object class.
 * @param to Destination ex_data container (typically freshly initialized).
 * @param from Source ex_data to copy.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
    const CRYPTO_EX_DATA *from);""",
"CRYPTO_dup_ex_data")

patch_both("crypto.h",
"CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);",
"""/**
 * @brief Allocate a new read/write lock for CRYPTO_THREAD_* locking helpers.
 * @return New CRYPTO_RWLOCK, or NULL on allocation failure.
 */
CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);""",
"CRYPTO_THREAD_lock_new")

# ----- ct.h -----
patch_both("ct.h",
"""/*
 * Pretty-prints an |sct| to |out|.
 * It will be indented by the number of spaces specified by |indent|.
 * If |logs| is not NULL, it will be used to lookup the CT log that the SCT came
 * from, so that the log name can be printed.
 */
void SCT_print(const SCT *sct, BIO *out, int indent, const CTLOG_STORE *logs);""",
"""/**
 * @brief Pretty-print a single Signed Certificate Timestamp to a BIO.
 * @param sct SCT to print.
 * @param out Destination BIO.
 * @param indent Number of leading spaces for each line.
 * @param logs Optional CT log store used to resolve the log name, or NULL.
 */
void SCT_print(const SCT *sct, BIO *out, int indent, const CTLOG_STORE *logs);""",
"SCT_print")

patch_both("ct.h",
"""/*
 * The same as CT_POLICY_EVAL_CTX_new_ex() but the default library
 * context and property query string is used.
 */
CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void);""",
"""/**
 * @brief Create an empty CT policy evaluation context with the default library context.
 * @return New context, or NULL on error; free with CT_POLICY_EVAL_CTX_free().
 */
CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void);""",
"CT_POLICY_EVAL_CTX_new")

# ----- dh.h -----
patch_both("dh.h",
"""OSSL_DEPRECATEDIN_3_0 int DH_compute_key(unsigned char *key,
    const BIGNUM *pub_key, DH *dh);""",
"""/**
 * @brief Derive the DH shared secret from a peer public key (deprecated).
 * @param key Output buffer of at least DH_size(@p dh) bytes.
 * @param pub_key Peer public value.
 * @param dh DH object holding the private key and domain parameters.
 * @return Number of bytes written, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_compute_key(unsigned char *key,
    const BIGNUM *pub_key, DH *dh);""",
"DH_compute_key")

patch_both("dh.h",
"int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len);",
"""/**
 * @brief Set the DH KDF User Keying Material, transferring ownership of @p ukm.
 * @param ctx Key-exchange context configured for DH KDF.
 * @param ukm UKM bytes that @p ctx will own and free; may be NULL when @p len is 0.
 * @param len Length of @p ukm in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len);""",
"EVP_PKEY_CTX_set0_dh_kdf_ukm")

# ----- dsa.h -----
patch_both("dsa.h",
"""OSSL_DEPRECATEDIN_3_0 int DSA_generate_parameters_ex(DSA *dsa, int bits,
    const unsigned char *seed,
    int seed_len,
    int *counter_ret,
    unsigned long *h_ret,
    BN_GENCB *cb);""",
"""/**
 * @brief Generate DSA domain parameters into an existing DSA object (deprecated).
 * @param dsa Destination DSA that receives p, q, and g.
 * @param bits Desired length of the prime p in bits.
 * @param seed Optional seed for deterministic generation, or NULL.
 * @param seed_len Length of @p seed in bytes.
 * @param counter_ret Optional output for the generation counter, or NULL.
 * @param h_ret Optional output for the generator counter h, or NULL.
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_generate_parameters_ex(DSA *dsa, int bits,
    const unsigned char *seed,
    int seed_len,
    int *counter_ret,
    unsigned long *h_ret,
    BN_GENCB *cb);""",
"DSA_generate_parameters_ex")

patch_both("dsa.h",
"""DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(OSSL_DEPRECATEDIN_3_0,
    DSA, DSAPrivateKey)""",
"""/**
 * @brief Decode a DSA private key from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAPrivateKey(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode a DSA private key to DER (deprecated).
 * @param a DSA key to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAPrivateKey(const DSA *a, unsigned char **out);""",
"i2d_DSAPrivateKey")

# ----- ec.h -----
patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_OpenSSL(void);",
"""/**
 * @brief Return the built-in OpenSSL EC_KEY_METHOD (deprecated).
 * @return Pointer to the default OpenSSL EC_KEY_METHOD.
 */
OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_OpenSSL(void);""",
"EC_KEY_OpenSSL")

patch_both("ec.h",
"int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);",
"""/**
 * @brief Return the trinomial basis degree k for a characteristic-2 curve group.
 * @param group EC_GROUP defined over GF(2^m) with a trinomial field polynomial.
 * @param k Receives the middle term degree of x^m + x^k + 1.
 * @return 1 on success, or 0 if @p group does not use a trinomial basis.
 */
int EC_GROUP_get_trinomial_basis(const EC_GROUP *group, unsigned int *k);""",
"EC_GROUP_get_trinomial_basis")

patch_both("ec.h",
"typedef struct ec_parameters_st ECPARAMETERS;",
"""/**
 * @brief Opaque ASN.1 EcpkParameters / ECParameters encoding helper type.
 */
typedef struct ec_parameters_st ECPARAMETERS;""",
"ECPARAMETERS")

patch_both("ec.h",
"int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);",
"""/**
 * @brief Select the ECDH key-derivation function type on a key-exchange context.
 * @param ctx Key context prepared for ECDH.
 * @param kdf KDF identifier such as EVP_PKEY_ECDH_KDF_NONE or EVP_PKEY_ECDH_KDF_X9_63.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);""",
"EVP_PKEY_CTX_set_ecdh_kdf_type")

# ----- engine.h -----
patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);""",
"""/**
 * @brief Set the callback used by ENGINE_load_private_key() to load private keys.
 * @param e ENGINE whose private-key loader is replaced.
 * @param loadpriv_f Loader callback, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);""",
"ENGINE_set_load_privkey_function")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_EC(void);",
"""/**
 * @brief Register every loaded ENGINE that provides an EC method.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_register_all_EC(void);""",
"ENGINE_register_all_EC")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 unsigned int ENGINE_get_table_flags(void);",
"""/**
 * @brief Return the global ENGINE algorithm-table flags.
 * @return Bitmask of ENGINE_TABLE_FLAG_* values.
 */
OSSL_DEPRECATEDIN_3_0 unsigned int ENGINE_get_table_flags(void);""",
"ENGINE_get_table_flags")

patch_both("engine.h",
"""typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
    STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **pkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method,
    void *callback_data);""",
"""/**
 * @brief ENGINE callback that supplies a client certificate and key for an SSL connection.
 * @param ssl SSL connection requesting a client certificate.
 * @param ca_dn Acceptable CA distinguished names from the server, or NULL.
 * @param pcert Receives the selected client certificate.
 * @param pkey Receives the matching private key.
 * @param pother Optional chain certificates to send, or NULL if unused.
 * @param ui_method UI method for interactive PIN/passphrase prompts, or NULL.
 * @param callback_data User pointer associated with the ENGINE load operation.
 * @return 1 on success, 0 on failure, or a negative value on fatal error.
 */
typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
    STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **pkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method,
    void *callback_data);""",
"ENGINE_SSL_CLIENT_CERT_PTR")

# ----- err.h -----
patch_both("err.h",
"void ERR_error_string_n(unsigned long e, char *buf, size_t len);",
"""/**
 * @brief Format an OpenSSL error code into a caller-provided buffer.
 * @param e Packed error code from ERR_get_error() or similar.
 * @param buf Destination buffer that receives a NUL-terminated description.
 * @param len Capacity of @p buf in bytes.
 */
void ERR_error_string_n(unsigned long e, char *buf, size_t len);""",
"ERR_error_string_n")

# ----- evp.h -----
patch_both("evp.h",
"const char *EVP_KEYEXCH_get0_name(const EVP_KEYEXCH *keyexch);",
"""/**
 * @brief Return the primary name of a fetched key-exchange algorithm.
 * @param keyexch Key-exchange implementation from EVP_KEYEXCH_fetch().
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEYEXCH_get0_name(const EVP_KEYEXCH *keyexch);""",
"EVP_KEYEXCH_get0_name")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth, int (*derive_init)(EVP_PKEY_CTX *ctx),
    int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));""",
"""/**
 * @brief Install key-derivation init/derive callbacks on a legacy EVP_PKEY_METHOD.
 * @param pmeth Method table to update.
 * @param derive_init Optional initializer invoked by EVP_PKEY_derive_init(), or NULL.
 * @param derive Callback that writes the shared secret / derived key.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth, int (*derive_init)(EVP_PKEY_CTX *ctx),
    int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));""",
"EVP_PKEY_meth_set_derive")

patch_both("evp.h",
"int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Validate the public key associated with a key context.
 * @param ctx Context whose key is checked (from EVP_PKEY_CTX_new or similar).
 * @return 1 if the public key is valid, 0 if invalid, or a negative value on error.
 */
int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_public_check")

patch_both("evp.h",
"""int EVP_PKEY_verify_recover_init_ex(EVP_PKEY_CTX *ctx,
    const OSSL_PARAM params[]);""",
"""/**
 * @brief Initialize @p ctx for signature recovery and apply algorithm parameters.
 * @param ctx Key context prepared for verify-recover (typically RSA).
 * @param params Optional OSSL_PARAM array of algorithm parameters, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_verify_recover_init_ex(EVP_PKEY_CTX *ctx,
    const OSSL_PARAM params[]);""",
"EVP_PKEY_verify_recover_init_ex")

patch_both("evp.h",
"const char *EVP_KEM_get0_name(const EVP_KEM *wrap);",
"""/**
 * @brief Return the primary name of a fetched KEM algorithm.
 * @param wrap KEM implementation from EVP_KEM_fetch().
 * @return Internal algorithm name string; do not free.
 */
const char *EVP_KEM_get0_name(const EVP_KEM *wrap);""",
"EVP_KEM_get0_name")

patch_both("evp.h",
"void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);",
"""/**
 * @brief Attach implementation-private data to a key context.
 * @param ctx Key context to update.
 * @param data Opaque pointer stored on @p ctx (not freed by OpenSSL).
 */
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);""",
"EVP_PKEY_CTX_set_data")

patch_both("evp.h",
"int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey);",
"""/**
 * @brief Return the estimated security strength of a key in bits.
 * @param pkey Key to query.
 * @return Security bits (for example 128), or 0 if unavailable.
 */
int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey);""",
"EVP_PKEY_get_security_bits")

patch_both("evp.h",
"const EVP_CIPHER *EVP_get_cipherbyname(const char *name);",
"""/**
 * @brief Look up a cipher algorithm by name (for example "AES-256-GCM").
 * @param name Cipher name or alias known to OpenSSL.
 * @return Matching EVP_CIPHER, or NULL if @p name is unknown.
 */
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);""",
"EVP_get_cipherbyname")

patch_both("evp.h",
"const EVP_CIPHER *EVP_aria_128_gcm(void);",
"""/**
 * @brief Return the ARIA-128 cipher in GCM mode.
 * @return EVP_CIPHER for aria-128-gcm, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aria_128_gcm(void);""",
"EVP_aria_128_gcm")

patch_both("evp.h",
"const EVP_CIPHER *EVP_aes_192_ctr(void);",
"""/**
 * @brief Return the AES-192 cipher in CTR mode.
 * @return EVP_CIPHER for aes-192-ctr, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_ctr(void);""",
"EVP_aes_192_ctr")

patch_both("evp.h",
"const EVP_CIPHER *EVP_aes_192_cbc(void);",
"""/**
 * @brief Return the AES-192 cipher in CBC mode.
 * @return EVP_CIPHER for aes-192-cbc, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_aes_192_cbc(void);""",
"EVP_aes_192_cbc")

patch_both("evp.h",
"const EVP_CIPHER *EVP_des_ede3_wrap(void);",
"""/**
 * @brief Return the Triple-DES key-wrap cipher (RFC 3217).
 * @return EVP_CIPHER for DES-EDE3-WRAP, or NULL if unavailable.
 */
const EVP_CIPHER *EVP_des_ede3_wrap(void);""",
"EVP_des_ede3_wrap")

patch_both("evp.h",
"const BIO_METHOD *BIO_f_cipher(void);",
"""/**
 * @brief Return the filter BIO_METHOD that encrypts or decrypts data with an EVP_CIPHER.
 * @return Pointer to the cipher filter BIO method.
 */
const BIO_METHOD *BIO_f_cipher(void);""",
"BIO_f_cipher")

patch_both("evp.h",
"int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);",
"""/**
 * @brief Enable or disable standard block-cipher padding on a cipher context.
 * @param c Cipher context to update.
 * @param pad Nonzero to enable PKCS-style padding; zero to disable.
 * @return 1 on success.
 */
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);""",
"EVP_CIPHER_CTX_set_padding")

patch_both("evp.h",
"int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);",
"""/**
 * @brief Send a legacy control request to a digest context.
 * @param ctx Digest context to control.
 * @param cmd Control command (algorithm-specific).
 * @param p1 Integer control argument.
 * @param p2 Pointer control argument, or NULL.
 * @return 1 on success, or a command-specific status / 0 on failure.
 */
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);""",
"EVP_MD_CTX_ctrl")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);",
"""/**
 * @brief Return a mutable pointer to the current IV in a cipher context (deprecated).
 * @param ctx Cipher context whose IV buffer is accessed.
 * @return Pointer to the IV bytes, or NULL if unavailable.
 */
OSSL_DEPRECATEDIN_3_0 unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);""",
"EVP_CIPHER_CTX_iv_noconst")

patch_both("evp.h",
"""int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
    void (*fn)(const char *name, void *data),
    void *data);""",
"""/**
 * @brief Invoke a callback for every name synonym associated with a cipher.
 * @param cipher Cipher algorithm to enumerate names for.
 * @param fn Callback receiving each name and @p data.
 * @param data User pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
    void (*fn)(const char *name, void *data),
    void *data);""",
"EVP_CIPHER_names_do_all")

patch_both("evp.h",
"const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher);",
"""/**
 * @brief Return the primary name of a cipher algorithm.
 * @param cipher Cipher method to query.
 * @return Internal name string; do not free.
 */
const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher);""",
"EVP_CIPHER_get0_name")

patch_both("evp.h",
"""    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;""",
"""    /** Pointer to the plaintext or ciphertext input for a TLS 1.1 multiblock operation. */
    const unsigned char *inp;
    /** Length in bytes of the buffer at @c inp / @c out for the multiblock operation. */
    size_t len;
    unsigned int interleave;""",
"EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM::len")

# ----- kdf.h -----
patch_both("kdf.h",
"""int EVP_PKEY_CTX_set1_scrypt_salt(EVP_PKEY_CTX *ctx,
    const unsigned char *salt, int saltlen);""",
"""/**
 * @brief Set the scrypt salt on a KDF key context (copies @p salt).
 * @param ctx Context configured for the scrypt algorithm.
 * @param salt Salt octets to copy.
 * @param saltlen Length of @p salt in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set1_scrypt_salt(EVP_PKEY_CTX *ctx,
    const unsigned char *salt, int saltlen);""",
"EVP_PKEY_CTX_set1_scrypt_salt")

patch_both("kdf.h",
"""int EVP_PKEY_CTX_add1_tls1_prf_seed(EVP_PKEY_CTX *pctx,
    const unsigned char *seed, int seedlen);""",
"""/**
 * @brief Append seed bytes to the TLS1-PRF seed on a key context.
 * @param pctx Context configured for TLS1-PRF.
 * @param seed Additional seed octets to append (copied).
 * @param seedlen Length of @p seed in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_add1_tls1_prf_seed(EVP_PKEY_CTX *pctx,
    const unsigned char *seed, int seedlen);""",
"EVP_PKEY_CTX_add1_tls1_prf_seed")

patch_both("kdf.h",
"""int EVP_PKEY_CTX_set1_tls1_prf_secret(EVP_PKEY_CTX *pctx,
    const unsigned char *sec, int seclen);""",
"""/**
 * @brief Set the TLS1-PRF secret on a key context (copies @p sec).
 * @param pctx Context configured for TLS1-PRF.
 * @param sec Secret octets to copy.
 * @param seclen Length of @p sec in bytes.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set1_tls1_prf_secret(EVP_PKEY_CTX *pctx,
    const unsigned char *sec, int seclen);""",
"EVP_PKEY_CTX_set1_tls1_prf_secret")

patch_both("kdf.h",
"void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);",
"""/**
 * @brief Free a KDF context and its associated state.
 * @param ctx Context to free, or NULL.
 */
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);""",
"EVP_KDF_CTX_free")

# ----- params.h -----
patch_both("params.h",
"""int OSSL_PARAM_set_octet_ptr(OSSL_PARAM *p, const void *val,
    size_t used_len);""",
"""/**
 * @brief Set an OSSL_PARAM that references an existing octet buffer without copying.
 * @param p Parameter of type OSSL_PARAM_OCTET_PTR to update.
 * @param val Address of the caller-owned octet data.
 * @param used_len Number of meaningful bytes at @p val.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_octet_ptr(OSSL_PARAM *p, const void *val,
    size_t used_len);""",
"OSSL_PARAM_set_octet_ptr")

patch_both("params.h",
"""OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
    size_t bsize);""",
"""/**
 * @brief Construct an OSSL_PARAM describing a pointer to a UTF-8 string buffer.
 * @param key Parameter name.
 * @param buf Address of a char* that locates the UTF-8 string.
 * @param bsize Maximum string capacity in bytes, or 0 if unknown.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
    size_t bsize);""",
"OSSL_PARAM_construct_utf8_ptr")

patch_both("params.h",
"OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf);",
"""/**
 * @brief Construct an OSSL_PARAM that locates an unsigned int value.
 * @param key Parameter name.
 * @param buf Address of the unsigned int to read or write.
 * @return Initialized OSSL_PARAM value (by value).
 */
OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf);""",
"OSSL_PARAM_construct_uint")

# ----- pkcs7.h -----
patch_both("pkcs7.h",
"STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info(PKCS7 *p7);",
"""/**
 * @brief Return the signer infos from a signed or signed-and-enveloped PKCS#7 structure.
 * @param p7 PKCS#7 object of type signedData or signedAndEnvelopedData.
 * @return Internal STACK_OF(PKCS7_SIGNER_INFO), or NULL if unavailable; do not free.
 */
STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info(PKCS7 *p7);""",
"PKCS7_get_signer_info")

patch_both("pkcs7.h",
"""    /*
     * The following is non NULL if it contains ASN1 encoding of this
     * structure
     */
    unsigned char *asn1;""",
"""    /**
     * Cached DER encoding of this PKCS#7 structure when non-NULL.
     */
    unsigned char *asn1;""",
"PKCS7::asn1")

patch_both("pkcs7.h",
"    STACK_OF(X509) *cert; /* [ 0 ] */ /* name should be 'certificates' */",
"""    /** Optional certificates included with the signed-and-enveloped data ([0]). */
    STACK_OF(X509) *cert; /* [ 0 ] */ /* name should be 'certificates' */""",
"PKCS7_SIGN_ENVELOPE::cert")

patch_both("pkcs7.h",
"    X509 *cert; /* get the pub-key from this */",
"""    /** Recipient certificate used to obtain the public key for this RecipientInfo. */
    X509 *cert;""",
"PKCS7_RECIP_INFO::cert")

# ----- quic.h -----
patch_both("quic.h",
"""/*
 * Method used for thread-assisted QUIC client operation.
 */
__owur const SSL_METHOD *OSSL_QUIC_client_thread_method(void);""",
"""/**
 * @brief Return the SSL_METHOD for thread-assisted QUIC client use.
 * @return Pointer to the constant thread-assisted QUIC client method.
 */
__owur const SSL_METHOD *OSSL_QUIC_client_thread_method(void);""",
"OSSL_QUIC_client_thread_method")

# ----- rand.h -----
patch_both("rand.h",
"OSSL_DEPRECATEDIN_3_0 RAND_METHOD *RAND_OpenSSL(void);",
"""/**
 * @brief Return the built-in OpenSSL legacy RAND_METHOD (deprecated).
 * @return Pointer to the default OpenSSL RAND_METHOD.
 */
OSSL_DEPRECATEDIN_3_0 RAND_METHOD *RAND_OpenSSL(void);""",
"RAND_OpenSSL")

patch_both("rand.h",
"OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_method(const RAND_METHOD *meth);",
"""/**
 * @brief Install the legacy RAND_METHOD used by RAND_bytes and related APIs (deprecated).
 * @param meth Method table to make current, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_method(const RAND_METHOD *meth);""",
"RAND_set_rand_method")

# ----- rsa.h -----
patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 void *RSA_meth_get0_app_data(const RSA_METHOD *meth);",
"""/**
 * @brief Return the application pointer previously attached to an RSA_METHOD.
 * @param meth Method to query.
 * @return App-data pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *RSA_meth_get0_app_data(const RSA_METHOD *meth);""",
"RSA_meth_get0_app_data")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_method(const RSA *rsa);",
"""/**
 * @brief Return the RSA_METHOD currently associated with an RSA key (deprecated).
 * @param rsa Key to query.
 * @return Pointer to the active RSA_METHOD.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_get_method(const RSA *rsa);""",
"RSA_get_method")

# ----- ssl.h -----
patch_both("ssl.h",
"SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);",
"""/**
 * @brief Replace the SSL_CTX associated with an existing SSL connection object.
 * @param ssl SSL object whose context is changed.
 * @param ctx New SSL_CTX to associate; certificates and some settings are inherited.
 * @return Previous SSL_CTX associated with @p ssl.
 */
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);""",
"SSL_set_SSL_CTX")

patch_both("ssl.h",
"void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb);",
"""/**
 * @brief Set the default PEM password callback used when loading keys on an SSL.
 * @param s SSL connection to update.
 * @param cb Password callback, or NULL to clear.
 */
void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb);""",
"SSL_set_default_passwd_cb")

patch_both("ssl.h",
"""__owur int SSL_SESSION_set1_id_context(SSL_SESSION *s,
    const unsigned char *sid_ctx,
    unsigned int sid_ctx_len);""",
"""/**
 * @brief Set the session ID context used to restrict session reuse.
 * @param s Session to update.
 * @param sid_ctx Context bytes that must match SSL_CTX_set_session_id_context().
 * @param sid_ctx_len Length of @p sid_ctx (at most SSL_MAX_SID_CTX_LENGTH).
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_SESSION_set1_id_context(SSL_SESSION *s,
    const unsigned char *sid_ctx,
    unsigned int sid_ctx_len);""",
"SSL_SESSION_set1_id_context")

patch_both("ssl.h",
"__owur const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s);",
"""/**
 * @brief Return the cipher suite stored on an SSL_SESSION.
 * @param s Session to query.
 * @return Pointer to the SSL_CIPHER, or NULL if unset; do not free.
 */
__owur const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s);""",
"SSL_SESSION_get0_cipher")

patch_both("ssl.h",
"__owur BIO *BIO_new_ssl_connect(SSL_CTX *ctx);",
"""/**
 * @brief Create a BIO chain of an SSL BIO and a connect BIO.
 * @param ctx SSL context used by the SSL BIO.
 * @return New BIO chain on success, or NULL on failure.
 */
__owur BIO *BIO_new_ssl_connect(SSL_CTX *ctx);""",
"BIO_new_ssl_connect")

patch_both("ssl.h",
"""void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
    int (*client_cert_cb)(SSL *ssl, X509 **x509,
        EVP_PKEY **pkey));""",
"""/**
 * @brief Install a callback that supplies a client certificate during handshake.
 * @param ctx SSL context whose connections inherit @p client_cert_cb.
 * @param client_cert_cb Callback that sets *@p x509 and *@p pkey, or NULL to clear.
 */
void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
    int (*client_cert_cb)(SSL *ssl, X509 **x509,
        EVP_PKEY **pkey));""",
"SSL_CTX_set_client_cert_cb")

patch_both("ssl.h",
"""void SSL_set_msg_callback(SSL *ssl,
    void (*cb)(int write_p, int version,
        int content_type, const void *buf,
        size_t len, SSL *ssl, void *arg));""",
"""/**
 * @brief Install a callback that observes SSL/TLS/QUIC protocol messages on one connection.
 * @param ssl SSL connection to instrument.
 * @param cb Message callback, or NULL to disable; arguments mirror SSL_CTX_set_msg_callback().
 */
void SSL_set_msg_callback(SSL *ssl,
    void (*cb)(int write_p, int version,
        int content_type, const void *buf,
        size_t len, SSL *ssl, void *arg));""",
"SSL_set_msg_callback")

# ----- stack.h -----
patch_both("stack.h",
"int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);",
"""/**
 * @brief Find the first stack element that compares equal to @p data.
 * @param st Stack to search (uses its comparison function when set).
 * @param data Value to locate.
 * @return Zero-based index of the match, or -1 if not found.
 */
int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);""",
"OPENSSL_sk_find")

# ----- types.h -----
patch_both("types.h",
"typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;",
"""/**
 * @brief Opaque library context that scopes providers, properties, and algorithm fetches.
 */
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;""",
"OSSL_LIB_CTX")

patch_both("types.h",
"typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;",
"""/**
 * @brief Opaque Issuing Distribution Point extension value (CRL IDP).
 */
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;""",
"ISSUING_DIST_POINT")

patch_both("types.h",
"typedef struct x509_revoked_st X509_REVOKED;",
"""/**
 * @brief Opaque single revoked-certificate entry within an X509_CRL.
 */
typedef struct x509_revoked_st X509_REVOKED;""",
"X509_REVOKED")

patch_both("types.h",
"typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;",
"""/**
 * @brief Opaque context for EVP_Encode*/EVP_Decode* base64 streaming.
 */
typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;""",
"EVP_ENCODE_CTX")

patch_both("types.h",
"typedef struct evp_pkey_st EVP_PKEY;",
"""/**
 * @brief Opaque public/private key handle used throughout the EVP and X.509 APIs.
 */
typedef struct evp_pkey_st EVP_PKEY;""",
"EVP_PKEY")

patch_both("types.h",
"typedef struct asn1_pctx_st ASN1_PCTX;",
"""/**
 * @brief Opaque ASN.1 print context controlling formatting flags for item printers.
 */
typedef struct asn1_pctx_st ASN1_PCTX;""",
"ASN1_PCTX")

patch_both("types.h",
"typedef struct ossl_provider_st OSSL_PROVIDER; /* Provider Object */",
"""/**
 * @brief Opaque provider object representing a loaded algorithm implementation module.
 */
typedef struct ossl_provider_st OSSL_PROVIDER;""",
"OSSL_PROVIDER")

# ----- ui.h -----
patch_both("ui.h",
"const void *UI_method_get_ex_data(const UI_METHOD *method, int idx);",
"""/**
 * @brief Return application ex_data previously stored on a UI_METHOD.
 * @param method Method to query.
 * @param idx Ex_data index from UI_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
const void *UI_method_get_ex_data(const UI_METHOD *method, int idx);""",
"UI_method_get_ex_data")

patch_both("ui.h",
"char *(*UI_method_get_prompt_constructor(const UI_METHOD *method))(UI *, const char *, const char *);",
"""/**
 * @brief Return the prompt-constructor callback previously set on a UI_METHOD.
 * @param method Method to query.
 * @return Prompt constructor function pointer, or NULL if unset.
 */
char *(*UI_method_get_prompt_constructor(const UI_METHOD *method))(UI *, const char *, const char *);""",
"UI_method_get_prompt_constructor")

patch_both("ui.h",
"int (*UI_method_get_writer(const UI_METHOD *method))(UI *, UI_STRING *);",
"""/**
 * @brief Return the writer callback previously set on a UI_METHOD.
 * @param method Method to query.
 * @return Writer function pointer, or NULL if unset.
 */
int (*UI_method_get_writer(const UI_METHOD *method))(UI *, UI_STRING *);""",
"UI_method_get_writer")

patch_both("ui.h",
"const UI_METHOD *UI_get_method(UI *ui);",
"""/**
 * @brief Return the UI_METHOD currently associated with a UI instance.
 * @param ui UI to query.
 * @return Pointer to the active UI_METHOD.
 */
const UI_METHOD *UI_get_method(UI *ui);""",
"UI_get_method")

# ----- x509.h -----
patch_both("x509.h",
"X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);",
"""/**
 * @brief Remove and return an attribute from an EVP_PKEY by index.
 * @param key Key whose attribute stack is modified.
 * @param loc Zero-based attribute index.
 * @return Removed X509_ATTRIBUTE (caller frees), or NULL if @p loc is invalid.
 */
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);""",
"EVP_PKEY_delete_attr")

patch_both("x509.h",
"""int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype,
    const void *data, int len);""",
"""/**
 * @brief Set the attribute value from typed bytes (copies @p data).
 * @param attr Attribute whose value set is replaced/extended.
 * @param attrtype ASN.1 type of @p data (for example V_ASN1_OCTET_STRING).
 * @param data Value bytes to copy; interpretation depends on @p attrtype.
 * @param len Length of @p data in bytes, or a type-specific sentinel.
 * @return 1 on success, or 0 on failure.
 */
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype,
    const void *data, int len);""",
"X509_ATTRIBUTE_set1_data")

patch_both("x509.h",
"""int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
    unsigned long flags);""",
"""/**
 * @brief Encode an extension value and add it to a revoked-certificate entry.
 * @param x Revoked entry to extend.
 * @param nid Extension NID.
 * @param value Extension-specific structure to encode with i2d.
 * @param crit Nonzero to mark the extension critical.
 * @param flags X509V3_ADD_* behavior flags.
 * @return 1 on success, 0 on failure, or -1 on duplicate when rejected by @p flags.
 */
int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
    unsigned long flags);""",
"X509_REVOKED_add1_ext_i2d")

patch_both("x509.h",
"""int X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
    int nid, int lastpos);""",
"""/**
 * @brief Find an extension by NID in a stack of X509_EXTENSION.
 * @param x Extension stack to search.
 * @param nid Extension NID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Extension index, or -1 if not found.
 */
int X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
    int nid, int lastpos);""",
"X509v3_get_ext_by_NID")

patch_both("x509.h",
"""int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflag,
    unsigned long cflag);""",
"""/**
 * @brief Print an X.509 certificate to a BIO with name and content flags.
 * @param bp Destination BIO.
 * @param x Certificate to print.
 * @param nmflag XN_FLAG_* flags controlling name formatting.
 * @param cflag X509_FLAG_* flags selecting which certificate fields to include.
 * @return 1 on success, or 0 on failure.
 */
int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflag,
    unsigned long cflag);""",
"X509_print_ex")

patch_both("x509.h",
"""int X509_REQ_add1_attr_by_NID(X509_REQ *req,
    int nid, int type,
    const unsigned char *bytes, int len);""",
"""/**
 * @brief Append an attribute identified by NID to a certificate request.
 * @param req Request whose attributes are extended.
 * @param nid Attribute type NID.
 * @param type ASN.1 string type of @p bytes.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_add1_attr_by_NID(X509_REQ *req,
    int nid, int type,
    const unsigned char *bytes, int len);""",
"X509_REQ_add1_attr_by_NID")

patch_both("x509.h",
"const char *X509_get_default_cert_area(void);",
"""/**
 * @brief Return the default OpenSSL certificates area directory path.
 * @return Static path string for the certificates installation area.
 */
const char *X509_get_default_cert_area(void);""",
"X509_get_default_cert_area")

patch_both("x509.h",
"ASN1_TIME *X509_time_adj(ASN1_TIME *s, long adj, time_t *t);",
"""/**
 * @brief Adjust an ASN1_TIME by a second offset relative to @p t (or the current time).
 * @param s Existing ASN1_TIME to update, or NULL to allocate a new one.
 * @param adj Seconds to add (may be negative).
 * @param t Base time, or NULL to use the current time.
 * @return Adjusted ASN1_TIME, or NULL on error.
 */
ASN1_TIME *X509_time_adj(ASN1_TIME *s, long adj, time_t *t);""",
"X509_time_adj")

patch_both("x509.h",
"void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);",
"""/**
 * @brief Set an X509_ALGOR to identify a message digest algorithm.
 * @param alg AlgorithmIdentifier to update.
 * @param md Digest whose OID (and typically NULL parameters) are stored.
 */
void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);""",
"X509_ALGOR_set_md")

patch_both("x509.h",
"OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);",
"""/**
 * @brief Read a DSA public key in SubjectPublicKeyInfo form from a BIO (deprecated).
 * @param bp BIO positioned at the DER/PEM public key.
 * @param dsa Optional destination pointer updated to the result, or NULL.
 * @return Decoded DSA key, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);""",
"d2i_DSA_PUBKEY_bio")

patch_both("x509.h",
"""    /* When decrypted, the following will not be NULL */
    EVP_PKEY *dec_pkey;""",
"""    /** Decrypted private key corresponding to @c enc_pkey when available. */
    EVP_PKEY *dec_pkey;""",
"dec_pkey")

patch_both("x509.h",
"typedef struct X509_crl_info_st X509_CRL_INFO;",
"""/**
 * @brief Opaque TBSCertList / CRL info structure inside an X509_CRL.
 */
typedef struct X509_crl_info_st X509_CRL_INFO;""",
"X509_CRL_INFO")

patch_both("x509.h",
"typedef STACK_OF(X509_ALGOR) X509_ALGORS;",
"""/**
 * @brief Stack of X509_ALGOR AlgorithmIdentifier values.
 */
typedef STACK_OF(X509_ALGOR) X509_ALGORS;""",
"X509_ALGORS")

patch_both("x509.h",
"""struct X509_algor_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
} /* X509_ALGOR */;""",
"""struct X509_algor_st {
    /** Object identifier naming the algorithm. */
    ASN1_OBJECT *algorithm;
    /** Optional algorithm parameters, or NULL when parameters are absent/NULL. */
    ASN1_TYPE *parameter;
} /* X509_ALGOR */;""",
"X509_ALGOR::parameter")

# ----- x509_vfy.h -----
patch_both("x509_vfy.h",
"const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);",
"""/**
 * @brief Look up a built-in named X509_VERIFY_PARAM by name.
 * @param name Parameter set name such as "default", "pkcs7", or "smime_sign".
 * @return Pointer to the named parameter object, or NULL if unknown; do not free.
 */
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);""",
"X509_VERIFY_PARAM_lookup")

patch_both("x509_vfy.h",
"int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);",
"""/**
 * @brief Find a candidate issuer certificate for @p x using the store context.
 * @param issuer Receives an up-referenced issuer certificate on success.
 * @param ctx Verification context providing the trusted store and callbacks.
 * @param x Certificate whose issuer is sought.
 * @return 1 if an issuer was found, 0 if not, or a negative value on error.
 */
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);""",
"X509_STORE_CTX_get1_issuer")

patch_both("x509_vfy.h",
"int X509_STORE_set_depth(X509_STORE *store, int depth);",
"""/**
 * @brief Set the maximum untrusted chain depth for verifications using @p store.
 * @param store Certificate store whose default verify parameters are updated.
 * @param depth Maximum number of untrusted intermediate CA certificates.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set_depth(X509_STORE *store, int depth);""",
"X509_STORE_set_depth")

patch_both("x509_vfy.h",
"void X509_TRUST_cleanup(void);",
"""/**
 * @brief Free all dynamically registered X509_TRUST table entries.
 */
void X509_TRUST_cleanup(void);""",
"X509_TRUST_cleanup")

# ----- x509v3.h -----
patch_both("x509v3.h",
"""void PROFESSION_INFO_set0_professionOIDs(
    PROFESSION_INFO *pi, STACK_OF(ASN1_OBJECT) *po);""",
"""/**
 * @brief Set the profession OIDs on a PROFESSION_INFO, taking ownership of @p po.
 * @param pi Profession info to update.
 * @param po Stack of profession OID values, or NULL to clear; frees any previous stack.
 */
void PROFESSION_INFO_set0_professionOIDs(
    PROFESSION_INFO *pi, STACK_OF(ASN1_OBJECT) *po);""",
"PROFESSION_INFO_set0_professionOIDs")

patch_both("x509v3.h",
"""const GENERAL_NAME *ADMISSION_SYNTAX_get0_admissionAuthority(
    const ADMISSION_SYNTAX *as);""",
"""/**
 * @brief Return the admission authority GeneralName from an ADMISSION_SYNTAX.
 * @param as Admission syntax to query.
 * @return Internal GENERAL_NAME pointer, or NULL if absent; do not free.
 */
const GENERAL_NAME *ADMISSION_SYNTAX_get0_admissionAuthority(
    const ADMISSION_SYNTAX *as);""",
"ADMISSION_SYNTAX_get0_admissionAuthority")

patch_both("x509v3.h",
"""void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY *n,
    ASN1_OBJECT *namingAuthorityId);""",
"""/**
 * @brief Set the naming authority OID, taking ownership of @p namingAuthorityId.
 * @param n Naming authority to update.
 * @param namingAuthorityId New authority identifier OID, or NULL to clear.
 */
void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY *n,
    ASN1_OBJECT *namingAuthorityId);""",
"NAMING_AUTHORITY_set0_authorityId")

patch_both("x509v3.h",
"""const ASN1_STRING *NAMING_AUTHORITY_get0_authorityText(
    const NAMING_AUTHORITY *n);""",
"""/**
 * @brief Return the human-readable naming authority text.
 * @param n Naming authority to query.
 * @return Internal ASN1_STRING, or NULL if absent; do not free.
 */
const ASN1_STRING *NAMING_AUTHORITY_get0_authorityText(
    const NAMING_AUTHORITY *n);""",
"NAMING_AUTHORITY_get0_authorityText")

patch_both("x509v3.h",
"""const ASN1_IA5STRING *NAMING_AUTHORITY_get0_authorityURL(
    const NAMING_AUTHORITY *n);""",
"""/**
 * @brief Return the naming authority URL (IA5String).
 * @param n Naming authority to query.
 * @return Internal ASN1_IA5STRING, or NULL if absent; do not free.
 */
const ASN1_IA5STRING *NAMING_AUTHORITY_get0_authorityURL(
    const NAMING_AUTHORITY *n);""",
"NAMING_AUTHORITY_get0_authorityURL")

patch_both("x509v3.h",
"int X509v3_addr_validate_path(X509_STORE_CTX *);",
"""/**
 * @brief Validate RFC 3779 IP address blocks along the certification path in @p ctx.
 * @param ctx Store context whose chain is checked for consistent IPAddrBlocks inheritance.
 * @return 1 if valid, or 0 on failure (sets verify error on @p ctx).
 */
int X509v3_addr_validate_path(X509_STORE_CTX *ctx);""",
"X509v3_addr_validate_path")

patch_both("x509v3.h",
"int X509v3_asid_canonize(ASIdentifiers *asid);",
"""/**
 * @brief Sort and merge an ASIdentifiers value into RFC 3779 canonical form.
 * @param asid Extension value to rewrite in place.
 * @return 1 on success, or 0 on failure.
 */
int X509v3_asid_canonize(ASIdentifiers *asid);""",
"X509v3_asid_canonize")

patch_both("x509v3.h",
"""int X509v3_addr_add_range(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi,
    unsigned char *min, unsigned char *max);""",
"""/**
 * @brief Add an inclusive IP address range to an IPAddrBlocks value.
 * @param addr Extension value to modify.
 * @param afi Address Family Identifier (IANA AFI).
 * @param safi Optional Subsequent Address Family Identifier, or NULL.
 * @param min Lowest address in network byte order (length implied by @p afi).
 * @param max Highest address in network byte order (same length as @p min).
 * @return 1 on success, or 0 on failure.
 */
int X509v3_addr_add_range(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi,
    unsigned char *min, unsigned char *max);""",
"X509v3_addr_add_range")

patch_both("x509v3.h",
"int X509v3_asid_add_inherit(ASIdentifiers *asid, int which);",
"""/**
 * @brief Mark an ASIdentifiers choice as inheriting from the issuer.
 * @param asid Extension value to modify.
 * @param which V3_ASID_ASNUM or V3_ASID_RDI selecting which choice inherits.
 * @return 1 on success, or 0 on failure.
 */
int X509v3_asid_add_inherit(ASIdentifiers *asid, int which);""",
"X509v3_asid_add_inherit")

patch_both("x509v3.h",
"DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)",
asn1_funcs("IPAddressOrRange", "IP address or address range (RFC 3779)"),
"IPAddressOrRange_asn1_funcs")

patch_both("x509v3.h",
"ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);",
"""/**
 * @brief Convert an ASCII IP address or CIDR prefix to an OCTET STRING for name constraints.
 * @param ipasc Address or prefix text (for example "192.0.2.0/24" or "2001:db8::/32").
 * @return Newly allocated ASN1_OCTET_STRING, or NULL on failure.
 */
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);""",
"a2i_IPADDRESS_NC")

patch_both("x509v3.h",
"int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags);",
"""/**
 * @brief Check whether a certificate's subjectAltName contains an IP address given as text.
 * @param x Certificate to check.
 * @param ipasc ASCII IPv4 or IPv6 address.
 * @param flags X509_CHECK_FLAG_* controlling matching behaviour.
 * @return 1 on match, 0 on no match, or -1 on malformed input / error.
 */
int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags);""",
"X509_check_ip_asc")

patch_both("x509v3.h",
"""int X509_check_host(X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername);""",
"""/**
 * @brief Check whether a certificate matches a DNS host name.
 * @param x Certificate whose subjectAltName / subject CN are examined.
 * @param chk Host name bytes (not necessarily NUL-terminated when @p chklen is set).
 * @param chklen Length of @p chk, or 0 to use strlen(@p chk).
 * @param flags X509_CHECK_FLAG_* controlling matching behaviour.
 * @param peername Optional output for a newly allocated matched name string, or NULL.
 * @return 1 on match, 0 on no match, or -1 on malformed input / error.
 */
int X509_check_host(X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername);""",
"X509_check_host")

patch_both("x509v3.h",
"STACK_OF(OPENSSL_STRING) *X509_get1_email(X509 *x);",
"""/**
 * @brief Collect email addresses from a certificate's subject and subjectAltName.
 * @param x Certificate to query.
 * @return Newly allocated stack of email strings, or NULL on failure; free with X509_email_free.
 */
STACK_OF(OPENSSL_STRING) *X509_get1_email(X509 *x);""",
"X509_get1_email")

patch_both("x509v3.h",
"char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp);",
"""/**
 * @brief Return the long human-readable name of a purpose table entry.
 * @param xp Purpose entry to query.
 * @return Internal name string; do not free.
 */
char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp);""",
"X509_PURPOSE_get0_name")

patch_both("x509v3.h",
"int X509_PURPOSE_get_count(void);",
"""/**
 * @brief Return how many entries are in the X509_PURPOSE table.
 * @return Number of registered purpose definitions.
 */
int X509_PURPOSE_get_count(void);""",
"X509_PURPOSE_get_count")

patch_both("x509v3.h",
"int X509_check_ca(X509 *x);",
"""/**
 * @brief Report whether a certificate appears to be a CA certificate.
 * @param x Certificate whose basicConstraints / keyUsage / self-signed status are examined.
 * @return Nonzero CA-likelihood code (see X509_check_ca(3)), or 0 if not a CA.
 */
int X509_check_ca(X509 *x);""",
"X509_check_ca")

patch_both("x509v3.h",
"int X509V3_EXT_add_alias(int nid_to, int nid_from);",
"""/**
 * @brief Alias an existing X.509v3 extension method under a new NID.
 * @param nid_to NID that should reuse the method of @p nid_from.
 * @param nid_from NID of an already-registered extension method.
 * @return 1 on success, or 0 on failure.
 */
int X509V3_EXT_add_alias(int nid_to, int nid_from);""",
"X509V3_EXT_add_alias")

patch_both("x509v3.h",
"char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const ASN1_INTEGER *aint);",
"""/**
 * @brief Convert an ASN1_INTEGER to a newly allocated decimal string.
 * @param meth Extension method (unused; may be NULL).
 * @param aint Integer value to convert.
 * @return Newly allocated C string, or NULL on error; free with OPENSSL_free.
 */
char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const ASN1_INTEGER *aint);""",
"i2s_ASN1_INTEGER")

patch_both("x509v3.h",
"""int X509V3_add_value(const char *name, const char *value,
    STACK_OF(CONF_VALUE) **extlist);""",
"""/**
 * @brief Append a name/value pair to a CONF_VALUE stack used by X509v3 helpers.
 * @param name Name string for the new CONF_VALUE (duplicated).
 * @param value Value string (duplicated); may be NULL.
 * @param extlist Address of the stack to append to; allocated if NULL.
 * @return 1 on success, or 0 on error.
 */
int X509V3_add_value(const char *name, const char *value,
    STACK_OF(CONF_VALUE) **extlist);""",
"X509V3_add_value")

patch_both("x509v3.h",
"void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);",
"""/**
 * @brief Attach an NCONF configuration database to an extension context.
 * @param ctx Extension context whose @c db / @c db_meth are updated.
 * @param conf CONF object used for section lookups while building extensions.
 */
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);""",
"X509V3_set_nconf")

patch_both("x509v3.h",
"""GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, CONF_VALUE *cnf);""",
"""/**
 * @brief Parse a single configuration name/value into a GENERAL_NAME.
 * @param method Extension method describing how the name form is parsed.
 * @param ctx Extension construction context.
 * @param cnf Configuration entry whose name selects the GEN_* form and whose value is the text.
 * @return New GENERAL_NAME, or NULL on error.
 */
GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, CONF_VALUE *cnf);""",
"v2i_GENERAL_NAME")

patch_both("x509v3.h",
"int i2d_AUTHORITY_INFO_ACCESS(const AUTHORITY_INFO_ACCESS *a, unsigned char **out);",
"""/**
 * @brief Encode an AuthorityInfoAccess syntax value to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_AUTHORITY_INFO_ACCESS(const AUTHORITY_INFO_ACCESS *a, unsigned char **out);""",
"i2d_AUTHORITY_INFO_ACCESS")

patch_both("x509v3.h",
"int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname);",
"""/**
 * @brief Fill a relative distribution-point name using an issuer X509_NAME.
 * @param dpn Distribution point name of type relativename to complete.
 * @param iname Issuer name prefixed to each relative RDN.
 * @return 1 on success, or 0 on failure.
 */
int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname);""",
"DIST_POINT_set_dpname")

patch_both("x509v3.h",
"const ASN1_ITEM *DIST_POINT_it(void);",
"""/**
 * @brief Return the ASN.1 item descriptor for DIST_POINT.
 * @return Pointer to the static ASN1_ITEM for DIST_POINT.
 */
const ASN1_ITEM *DIST_POINT_it(void);""",
"DIST_POINT_it")

patch_both("x509v3.h",
"USERNOTICE *USERNOTICE_new(void);",
"""/**
 * @brief Allocate an empty user notice policy qualifier.
 * @return New USERNOTICE, or NULL on allocation failure.
 */
USERNOTICE *USERNOTICE_new(void);""",
"USERNOTICE_new")

patch_both("x509v3.h",
"POLICYINFO *d2i_POLICYINFO(POLICYINFO **a, const unsigned char **in, long len);",
"""/**
 * @brief Decode a certificate policy information value from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded POLICYINFO, or NULL on error.
 */
POLICYINFO *d2i_POLICYINFO(POLICYINFO **a, const unsigned char **in, long len);""",
"d2i_POLICYINFO")

patch_both("x509v3.h",
"const ASN1_ITEM *CERTIFICATEPOLICIES_it(void);",
"""/**
 * @brief Return the ASN.1 item descriptor for CERTIFICATEPOLICIES.
 * @return Pointer to the static ASN1_ITEM for CERTIFICATEPOLICIES.
 */
const ASN1_ITEM *CERTIFICATEPOLICIES_it(void);""",
"CERTIFICATEPOLICIES_it")

patch_both("x509v3.h",
"CERTIFICATEPOLICIES *CERTIFICATEPOLICIES_new(void);",
"""/**
 * @brief Allocate an empty Certificate Policies extension value.
 * @return New CERTIFICATEPOLICIES, or NULL on allocation failure.
 */
CERTIFICATEPOLICIES *CERTIFICATEPOLICIES_new(void);""",
"CERTIFICATEPOLICIES_new")

patch_both("x509v3.h",
"DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)",
"""/**
 * @brief Allocate an empty TLS Feature extension value (stack of feature integers).
 * @return New TLS_FEATURE, or NULL on allocation failure.
 */
TLS_FEATURE *TLS_FEATURE_new(void);
/**
 * @brief Free a TLS Feature extension value and its contents.
 * @param a Value to free, or NULL.
 */
void TLS_FEATURE_free(TLS_FEATURE *a);""",
"TLS_FEATURE_alloc")

patch_both("x509v3.h",
"""int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
    ASN1_OBJECT *oid, ASN1_TYPE *value);""",
"""/**
 * @brief Set a GeneralName to type otherName, taking ownership of @p oid and @p value.
 * @param gen GeneralName to update.
 * @param oid otherName type OID.
 * @param value otherName value as an ASN1_TYPE.
 * @return 1 on success, or 0 on failure.
 */
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
    ASN1_OBJECT *oid, ASN1_TYPE *value);""",
"GENERAL_NAME_set0_othername")

patch_both("x509v3.h",
"char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8);",
"""/**
 * @brief Convert an ASN1_UTF8STRING to a newly allocated C string.
 * @param method Extension method (unused; may be NULL).
 * @param utf8 UTF8String value to convert.
 * @return Newly allocated C string, or NULL on error; free with OPENSSL_free.
 */
char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8);""",
"i2s_ASN1_UTF8STRING")

patch_both("x509v3.h",
"""STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    ASN1_BIT_STRING *bits,
    STACK_OF(CONF_VALUE) *extlist);""",
"""/**
 * @brief Convert an ASN1_BIT_STRING into named CONF_VALUE entries using @p method bit names.
 * @param method Extension method whose @c usr_data lists BIT_STRING_BITNAME entries.
 * @param bits Bit string to convert.
 * @param extlist Existing stack to append to, or NULL to allocate a new one.
 * @return Stack of CONF_VALUE entries, or NULL on error.
 */
STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    ASN1_BIT_STRING *bits,
    STACK_OF(CONF_VALUE) *extlist);""",
"i2v_ASN1_BIT_STRING")

patch_both("x509v3.h",
"int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);",
"""/**
 * @brief Compare two GENERAL_NAME values for equality.
 * @param a First name.
 * @param b Second name.
 * @return 0 if equal, or non-zero if they differ / on error.
 */
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);""",
"GENERAL_NAME_cmp")

patch_both("x509v3.h",
"int i2d_ISSUER_SIGN_TOOL(const ISSUER_SIGN_TOOL *a, unsigned char **out);",
"""/**
 * @brief Encode an ISSUER_SIGN_TOOL value to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_ISSUER_SIGN_TOOL(const ISSUER_SIGN_TOOL *a, unsigned char **out);""",
"i2d_ISSUER_SIGN_TOOL")

patch_both("x509v3.h",
"int i2d_SXNETID(const SXNETID *a, unsigned char **out);",
"""/**
 * @brief Encode an SXNETID value to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_SXNETID(const SXNETID *a, unsigned char **out);""",
"i2d_SXNETID")

patch_both("x509v3.h",
"int i2d_SXNET(const SXNET *a, unsigned char **out);",
"""/**
 * @brief Encode an SXNET value to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_SXNET(const SXNET *a, unsigned char **out);""",
"i2d_SXNET")

patch_both("x509v3.h",
"""    /** Flags such as X509_PURPOSE_DYNAMIC or X509_PURPOSE_DYNAMIC_NAME. */
    int flags;
    int (*check_purpose)(const struct x509_purpose_st *, const X509 *, int);""",
"""    /** Flags such as X509_PURPOSE_DYNAMIC or X509_PURPOSE_DYNAMIC_NAME. */
    int flags;
    /** Callback that evaluates whether a certificate satisfies this purpose. */
    int (*check_purpose)(const struct x509_purpose_st *, const X509 *, int);""",
"check_purpose")

patch_both("x509v3.h",
"""    /** Distribution point name for this issuingDistributionPoint, or NULL if omitted. */
    DIST_POINT_NAME *distpoint;
    int onlyuser;
    int onlyCA;
    ASN1_BIT_STRING *onlysomereasons;
    int indirectCRL;
    int onlyattr;
};""",
"""    /** Distribution point name for this issuingDistributionPoint, or NULL if omitted. */
    DIST_POINT_NAME *distpoint;
    /** ASN.1 BOOLEAN: when set, the CRL covers end-entity certificates only. */
    int onlyuser;
    /** ASN.1 BOOLEAN: when set, the CRL covers CA certificates only. */
    int onlyCA;
    /** Optional ReasonFlags bit string limiting which revocation reasons are covered. */
    ASN1_BIT_STRING *onlysomereasons;
    /** ASN.1 BOOLEAN: when set, certificate issuer may differ from the CRL issuer. */
    int indirectCRL;
    int onlyattr;
};""",
"IDP_fields")

patch_both("x509v3.h",
"""typedef struct PROXY_POLICY_st {
    ASN1_OBJECT *policyLanguage;
    ASN1_OCTET_STRING *policy;
} PROXY_POLICY;""",
"""typedef struct PROXY_POLICY_st {
    /** OID identifying the proxy policy language. */
    ASN1_OBJECT *policyLanguage;
    /** Optional policy octets interpreted according to @c policyLanguage. */
    ASN1_OCTET_STRING *policy;
} PROXY_POLICY;""",
"PROXY_POLICY_fields")

patch_both("x509v3.h",
"""/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(GENERAL_NAMES, GENERAL_NAMES, GENERAL_NAMES)""",
"""/**
 * @brief Opaque STACK_OF(GENERAL_NAMES) container type.
 */
struct stack_st_GENERAL_NAMES;
/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(GENERAL_NAMES, GENERAL_NAMES, GENERAL_NAMES)""",
"stack_st_GENERAL_NAMES")

patch_both("x509v3.h",
"typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;",
"""/**
 * @brief Authority Information Access extension: stack of ACCESS_DESCRIPTION entries.
 */
typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;""",
"AUTHORITY_INFO_ACCESS")

patch_both("x509v3.h",
"""#define GEN_RID 8
    int type;""",
"""#define GEN_RID 8
    /** GEN_* discriminator selecting which @c d union arm is valid. */
    int type;""",
"GENERAL_NAME::type")

patch_both("x509v3.h",
"""/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(X509V3_EXT_METHOD, X509V3_EXT_METHOD, X509V3_EXT_METHOD)""",
"""/**
 * @brief Opaque STACK_OF(X509V3_EXT_METHOD) container type.
 */
struct stack_st_X509V3_EXT_METHOD;
/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(X509V3_EXT_METHOD, X509V3_EXT_METHOD, X509V3_EXT_METHOD)""",
"stack_st_X509V3_EXT_METHOD")

patch_both("x509v3.h",
"""    X509_CRL *crl;
    X509V3_CONF_METHOD *db_meth;""",
"""    X509_CRL *crl;
    /** Callbacks used to read configuration sections while building extensions. */
    X509V3_CONF_METHOD *db_meth;""",
"db_meth")

patch_both("x509v3.h",
"""    /* The following pair is used for multi-valued extensions */
    X509V3_EXT_I2V i2v;
    X509V3_EXT_V2I v2i;""",
"""    /* The following pair is used for multi-valued extensions */
    /** Convert an extension value to a stack of CONF_VALUE name/value pairs. */
    X509V3_EXT_I2V i2v;
    /** Parse a stack of CONF_VALUE entries into an extension-specific value. */
    X509V3_EXT_V2I v2i;""",
"v2i")

patch_both("x509v3.h",
"""struct v3_ext_method {
    int ext_nid;
    int ext_flags;""",
"""/**
 * @brief Method table describing encode/decode/print behaviour for one X.509v3 extension NID.
 */
struct v3_ext_method {
    /** NID of the extension OID this method implements. */
    int ext_nid;
    /** Flags such as X509V3_EXT_DYNAMIC, X509V3_EXT_CTX_DEP, or X509V3_EXT_MULTILINE. */
    int ext_flags;""",
"v3_ext_method")

patch_both("x509v3.h",
"""typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
    BIO *out, int indent);""",
"""typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx, const char *str);
/**
 * @brief Print an extension-specific value to a BIO.
 * @param method Extension method describing the conversion.
 * @param ext Extension-specific value to print.
 * @param out Destination BIO.
 * @param indent Number of leading spaces for each line.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
    BIO *out, int indent);""",
"X509V3_EXT_I2R")

patch_both("x509v3.h",
"""typedef STACK_OF(CONF_VALUE) *(*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
    STACK_OF(CONF_VALUE) *extlist);
typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx,
    STACK_OF(CONF_VALUE) *values);""",
"""typedef STACK_OF(CONF_VALUE) *(*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
    STACK_OF(CONF_VALUE) *extlist);
/**
 * @brief Parse configuration name/value pairs into an extension-specific value.
 * @param method Extension method describing the conversion.
 * @param ctx Extension context for the conversion.
 * @param values Stack of CONF_VALUE entries describing the extension.
 * @return Extension-specific value, or NULL on error.
 */
typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx,
    STACK_OF(CONF_VALUE) *values);""",
"X509V3_EXT_V2I")


# .in files use generate_stack_macros() instead of SKM_DEFINE_STACK_OF_INTERNAL
patch_both("x509v3.h.in",
"""/* clang-format off */
{-
    generate_stack_macros("GENERAL_NAMES");
-}""",
"""/**
 * @brief Opaque STACK_OF(GENERAL_NAMES) container type.
 */
struct stack_st_GENERAL_NAMES;
/* clang-format off */
{-
    generate_stack_macros("GENERAL_NAMES");
-}""",
"stack_st_GENERAL_NAMES")

patch_both("x509v3.h.in",
"""/* clang-format off */
{-
    generate_stack_macros("X509V3_EXT_METHOD");
-}""",
"""/**
 * @brief Opaque STACK_OF(X509V3_EXT_METHOD) container type.
 */
struct stack_st_X509V3_EXT_METHOD;
/* clang-format off */
{-
    generate_stack_macros("X509V3_EXT_METHOD");
-}""",
"stack_st_X509V3_EXT_METHOD")

print(f"done ok={len(ok)} miss={len(missing)}")
if missing:
    print("MISSING:", *missing, sep="\n  ")
