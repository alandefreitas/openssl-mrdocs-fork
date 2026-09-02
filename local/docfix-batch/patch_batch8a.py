#!/usr/bin/env python3
"""Documentation repair batch 8a: asn1, buffer, cms, comp, ct, dh, ec, engine."""
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


def asn1_funcs_name(ctype, name, brief):
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {ctype} used as a {name}, or NULL on allocation failure.
 */
{ctype} *{name}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {name}_free({ctype} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {name}, or NULL on error.
 */
{ctype} *d2i_{name}({ctype} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{name}(const {ctype} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {name}.
 * @return Pointer to the static ASN1_ITEM for {name}.
 */
const ASN1_ITEM *{name}_it(void);"""


# ----- asn1.h -----
patch_both("asn1.h",
"typedef const ASN1_ITEM *ASN1_ITEM_EXP(void);",
"""/**
 * @brief Function type that returns a pointer to a static ASN1_ITEM descriptor.
 *
 * Used with ASN1_ITEM_ptr() so ASN.1 items can be referenced as function
 * exports rather than as data symbols on platforms that require that form.
 */
typedef const ASN1_ITEM *ASN1_ITEM_EXP(void);""",
"ASN1_ITEM_EXP")

patch_both("asn1.h",
"""        ASN1_BOOLEAN boolean;
        /** Generic ASN.1 string when type is an ASN1_STRING-compatible tag. */""",
"""        /** BOOLEAN value when type is V_ASN1_BOOLEAN. */
        ASN1_BOOLEAN boolean;
        /** Generic ASN.1 string when type is an ASN1_STRING-compatible tag. */""",
"boolean")

patch_both("asn1.h",
"""        ASN1_UTCTIME *utctime;
        ASN1_GENERALIZEDTIME *generalizedtime;""",
"""        /** UTCTime value when type is V_ASN1_UTCTIME. */
        ASN1_UTCTIME *utctime;
        /** GeneralizedTime value when type is V_ASN1_GENERALIZEDTIME. */
        ASN1_GENERALIZEDTIME *generalizedtime;""",
"utctime")

patch_both("asn1.h",
"""ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
    int offset_day, long offset_sec);""",
"""/**
 * @brief Set an ASN1_UTCTIME from @p t adjusted by a day/second offset.
 * @param s Existing UTCTIME to reuse, or NULL to allocate a new one.
 * @param t Base calendar time (seconds since the Epoch).
 * @param offset_day Days to add to @p t (may be negative).
 * @param offset_sec Seconds to add after the day offset (may be negative).
 * @return The UTCTIME on success (possibly newly allocated), or NULL on error.
 */
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
    int offset_day, long offset_sec);""",
"ASN1_UTCTIME_adj")

patch_both("asn1.h",
"""int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a,
    const ASN1_OCTET_STRING *b);""",
"""/**
 * @brief Compare two ASN.1 OCTET STRING values lexicographically by content.
 * @param a First octet string.
 * @param b Second octet string.
 * @return Negative, zero, or positive like memcmp according to the content bytes.
 */
int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a,
    const ASN1_OCTET_STRING *b);""",
"ASN1_OCTET_STRING_cmp")

patch_both("asn1.h",
"DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)",
asn1_funcs_name("ASN1_STRING", "DISPLAYTEXT", "DisplayText (ASN.1 string CHOICE)"),
"DISPLAYTEXT")

patch_both("asn1.h",
"unsigned long ASN1_tag2bit(int tag);",
"""/**
 * @brief Map an ASN.1 universal tag number to the corresponding B_ASN1_* bit mask.
 * @param tag ASN.1 tag number such as V_ASN1_UTF8STRING.
 * @return Matching B_ASN1_* bit, or 0 if @p tag has no string-type bit mapping.
 */
unsigned long ASN1_tag2bit(int tag);""",
"ASN1_tag2bit")

patch_both("asn1.h",
"void *ASN1_item_dup(const ASN1_ITEM *it, const void *x);",
"""/**
 * @brief Deep-copy an ASN.1 value described by @p it.
 * @param it ASN.1 item describing the type of @p x.
 * @param x Value to duplicate.
 * @return Newly allocated copy, or NULL on error; free with ASN1_item_free.
 */
void *ASN1_item_dup(const ASN1_ITEM *it, const void *x);""",
"ASN1_item_dup")

patch_both("asn1.h",
"""int ASN1_item_sign_ex(const ASN1_ITEM *it, X509_ALGOR *algor1,
    X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
    const void *data, const ASN1_OCTET_STRING *id,
    EVP_PKEY *pkey, const EVP_MD *md, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Sign the DER encoding of @p data using @p it and write AlgorithmIdentifier(s) plus the signature.
 * @param it ASN.1 item describing @p data.
 * @param algor1 First AlgorithmIdentifier to fill (for example signatureAlgorithm), or NULL.
 * @param algor2 Optional second AlgorithmIdentifier to fill, or NULL.
 * @param signature BIT STRING that receives the signature bytes.
 * @param data Object whose DER encoding is signed.
 * @param id Optional ASN.1 OCTET STRING identity / SM2-id parameter, or NULL.
 * @param pkey Private key used to create the signature.
 * @param md Digest method, or NULL to use the key-type default.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_item_sign_ex(const ASN1_ITEM *it, X509_ALGOR *algor1,
    X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
    const void *data, const ASN1_OCTET_STRING *id,
    EVP_PKEY *pkey, const EVP_MD *md, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"ASN1_item_sign_ex")

patch_both("asn1.h",
"void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *pval);",
"""/**
 * @brief Decode an ASN.1 value described by @p it from a BIO (default library context).
 * @param it ASN.1 item describing the type to decode.
 * @param in BIO positioned at DER input.
 * @param pval Optional existing object to reuse, or NULL to allocate.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *pval);""",
"ASN1_item_d2i_bio")

patch_both("asn1.h",
"const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p);",
"""/**
 * @brief Return the ASN1_ITEM currently being scanned by an ASN.1 scan context.
 * @param p Scan context created for a custom ASN.1 item scan/callback.
 * @return ASN.1 item associated with @p p, or NULL if none is set.
 */
const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p);""",
"ASN1_SCTX_get_item")

# ----- buffer.h -----
patch_both("buffer.h",
"size_t BUF_MEM_grow(BUF_MEM *str, size_t len);",
"""/**
 * @brief Grow or shrink a BUF_MEM so its valid length is @p len.
 * @param str Buffer to resize.
 * @param len Desired length in bytes; expands capacity when needed.
 * @return New length on success, or 0 on allocation failure.
 *
 * Newly allocated capacity beyond the previous length is left uninitialized;
 * use BUF_MEM_grow_clean() when cleared growth is required.
 */
size_t BUF_MEM_grow(BUF_MEM *str, size_t len);""",
"BUF_MEM_grow")

# ----- cms.h -----
patch_both("cms.h",
"CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher);",
"""/**
 * @brief Create an empty CMS EnvelopedData ContentInfo for @p cipher (default library context).
 * @param cipher Content-encryption cipher whose ASN.1 parameters will be encoded.
 * @return New EnvelopedData ContentInfo, or NULL on error; free with CMS_ContentInfo_free.
 */
CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher);""",
"CMS_EnvelopedData_create")

patch_both("cms.h",
"X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc);",
"""/**
 * @brief Remove and return the signed attribute at index @p loc from a CMS SignerInfo.
 * @param si SignerInfo whose signedAttrs set is modified.
 * @param loc Zero-based index of the attribute to delete.
 * @return Removed attribute (caller frees with X509_ATTRIBUTE_free), or NULL on error.
 */
X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc);""",
"CMS_signed_delete_attr")

patch_both("cms.h",
"""int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si,
    int nid, int type,
    const void *bytes, int len);""",
"""/**
 * @brief Append an unsigned attribute identified by NID to a CMS SignerInfo.
 * @param si SignerInfo whose unsignedAttrs set is extended.
 * @param nid Attribute type NID (for example NID_pkcs9_signingTime).
 * @param type ASN.1 string type for @p bytes (for example V_ASN1_OCTET_STRING).
 * @param bytes Attribute value bytes, or NULL when @p len is 0.
 * @param len Length of @p bytes in octets.
 * @return 1 on success, or 0 on failure.
 */
int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si,
    int nid, int type,
    const void *bytes, int len);""",
"CMS_unsigned_add1_attr_by_NID")

# ----- comp.h -----
patch_both("comp.h",
"""int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
    unsigned char *in, int ilen);""",
"""/**
 * @brief Decompress @p ilen bytes from @p in into @p out using a COMP_CTX.
 * @param ctx Compression context (for example zlib) that performs expansion.
 * @param out Destination buffer for expanded data.
 * @param olen Capacity of @p out in bytes.
 * @param in Compressed input bytes.
 * @param ilen Number of compressed bytes at @p in.
 * @return Number of bytes written to @p out, or a negative value on error.
 */
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
    unsigned char *in, int ilen);""",
"COMP_expand_block")

# ----- ct.h -----
patch_both("ct.h",
"__owur int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len);",
"""/**
 * @brief Set the CT log ID on an SCT, transferring ownership of @p log_id.
 * @param sct SCT whose log_id field is replaced.
 * @param log_id Log ID bytes that @p sct will own (freed by SCT_free); may be NULL when @p log_id_len is 0.
 * @param log_id_len Length of @p log_id in bytes (typically CT_V1_HASHLEN for v1).
 * @return 1 on success, or 0 on failure.
 */
__owur int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len);""",
"SCT_set0_log_id")

patch_both("ct.h",
"void CTLOG_free(CTLOG *log);",
"""/**
 * @brief Free a Certificate Transparency log entry and its owned fields.
 * @param log Log to free, or NULL.
 */
void CTLOG_free(CTLOG *log);""",
"CTLOG_free")

# ----- dh.h -----
patch_both("dh.h",
"int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);",
"""/**
 * @brief Get the message digest used for DH key-derivation (KDF) on a key context.
 * @param ctx Key context configured for a DH KDF operation.
 * @param md Receives a pointer to the digest method (do not free).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **md);""",
"EVP_PKEY_CTX_get_dh_kdf_md")

patch_both("dh.h",
"""OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_key(DH_METHOD *dhm,
    int (*generate_key)(DH *));""",
"""/**
 * @brief Set the key-generation callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param generate_key Callback that fills a DH object's public/private values, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_key(DH_METHOD *dhm,
    int (*generate_key)(DH *));""",
"DH_meth_set_generate_key")

# ----- ec.h -----
patch_both("ec.h",
"int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx);",
"""/**
 * @brief Get the ECDH cofactor mode from a key context.
 * @param ctx Key context configured for ECDH.
 * @return Cofactor mode (0 = disable, 1 = enable, -1 = use key default), or a negative error code.
 */
int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx);""",
"EVP_PKEY_CTX_get_ecdh_cofactor_mode")

patch_both("ec.h",
"size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);",
"""/**
 * @brief Copy built-in elliptic-curve descriptors into @p r.
 * @param r Array of EC_builtin_curve that receives up to @p nitems entries, or NULL to query only the count.
 * @param nitems Capacity of @p r in elements; ignored when @p r is NULL.
 * @return Total number of built-in curves (may exceed @p nitems).
 */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);""",
"EC_get_builtin_curves")

patch_both("ec.h",
"const char *EC_curve_nid2nist(int nid);",
"""/**
 * @brief Map an OpenSSL curve NID to its NIST curve name string.
 * @param nid Curve NID such as NID_X9_62_prime256v1.
 * @return NIST name (for example "P-256"), or NULL if @p nid has no NIST mapping.
 */
const char *EC_curve_nid2nist(int nid);""",
"EC_curve_nid2nist")

patch_both("ec.h",
"""EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
    EC_POINT *, BN_CTX *);""",
"""/**
 * @brief Decode an EC point from a hex-encoded octet string.
 * @param group Curve that defines the point encoding.
 * @param hex NUL-terminated hexadecimal encoding of the point octets.
 * @param point Existing point to overwrite, or NULL to allocate a new one.
 * @param ctx BN_CTX for temporary BIGNUMs, or NULL to allocate internally.
 * @return The resulting EC_POINT, or NULL on error.
 */
EC_POINT *EC_POINT_hex2point(const EC_GROUP *group, const char *hex,
    EC_POINT *point, BN_CTX *ctx);""",
"EC_POINT_hex2point")

patch_both("ec.h",
"""OSSL_DEPRECATEDIN_3_0 int EC_POINT_make_affine(const EC_GROUP *group,
    EC_POINT *point, BN_CTX *ctx);""",
"""/**
 * @brief Convert @p point to affine coordinates in @p group (deprecated).
 * @param group Curve that owns @p point.
 * @param point Point to convert in place.
 * @param ctx BN_CTX for temporary BIGNUMs, or NULL to allocate internally.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int EC_POINT_make_affine(const EC_GROUP *group,
    EC_POINT *point, BN_CTX *ctx);""",
"EC_POINT_make_affine")

patch_both("ec.h",
"""OSSL_DEPRECATEDIN_3_0 int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x,
    int off);""",
"""/**
 * @brief Print EC public-key parameters from @p x to a FILE (deprecated).
 * @param fp Output stream.
 * @param x Group whose parameters are printed.
 * @param off Indentation width in spaces.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x,
    int off);""",
"ECPKParameters_print_fp")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 int EC_KEY_decoded_from_explicit_params(const EC_KEY *key);",
"""/**
 * @brief Report whether @p key's group was decoded from explicit curve parameters (deprecated).
 * @param key EC key to query.
 * @return 1 if parameters were explicit, 0 if named/implicit, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int EC_KEY_decoded_from_explicit_params(const EC_KEY *key);""",
"EC_KEY_decoded_from_explicit_params")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);",
"""/**
 * @brief Store application data on an EC_KEY at CRYPTO_EX index @p idx (deprecated).
 * @param key Key receiving the data.
 * @param idx Index from CRYPTO_get_ex_new_index() for EC_KEY.
 * @param arg Pointer to store; ownership rules follow CRYPTO_EX_DATA.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);""",
"EC_KEY_set_ex_data")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);",
"""/**
 * @brief Set ASN.1 encoding flags on the EC_GROUP inside @p eckey (deprecated).
 * @param eckey Key whose group encoding flags are updated.
 * @param asn1_flag Flag such as OPENSSL_EC_NAMED_CURVE or OPENSSL_EC_EXPLICIT_CURVE.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);""",
"EC_KEY_set_asn1_flag")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key);",
"""/**
 * @brief Return the EC_KEY_METHOD currently used by @p key (deprecated).
 * @param key EC key to query.
 * @return Method table pointer (do not free).
 */
OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key);""",
"EC_KEY_get_method")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth);",
"""/**
 * @brief Attach an EC_KEY_METHOD to @p key (deprecated).
 * @param key Key whose method table is replaced.
 * @param meth Method table to use; must outlive @p key unless replaced again.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth);""",
"EC_KEY_set_method")

patch_both("ec.h",
"OSSL_DEPRECATEDIN_3_0 EC_KEY *EC_KEY_new_method(ENGINE *engine);",
"""/**
 * @brief Allocate an EC_KEY using the EC method from @p engine (deprecated).
 * @param engine ENGINE supplying an EC_KEY_METHOD, or NULL for the default method.
 * @return New empty EC_KEY, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *EC_KEY_new_method(ENGINE *engine);""",
"EC_KEY_new_method")

patch_both("ec.h",
"typedef struct ECDSA_SIG_st ECDSA_SIG;",
"""/**
 * @brief Opaque ECDSA signature holding the integers r and s.
 */
typedef struct ECDSA_SIG_st ECDSA_SIG;""",
"ECDSA_SIG_st")

patch_both("ec.h",
"""OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
    int (*ckey)(unsigned char **psec, size_t *pseclen,
        const EC_POINT *pub_key, const EC_KEY *ecdh));""",
"""/**
 * @brief Set the ECDH shared-secret callback on an EC_KEY_METHOD (deprecated).
 * @param meth Method table to update.
 * @param ckey Callback that computes the shared secret into *@p psec / *@p pseclen, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
    int (*ckey)(unsigned char **psec, size_t *pseclen,
        const EC_POINT *pub_key, const EC_KEY *ecdh));""",
"EC_KEY_METHOD_set_compute_key")

patch_both("ec.h",
"""OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth,
    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf,
        int sig_len, EC_KEY *eckey),
    int (*verify_sig)(const unsigned char *dgst,
        int dgst_len, const ECDSA_SIG *sig,
        EC_KEY *eckey));""",
"""/**
 * @brief Set ECDSA verify callbacks on an EC_KEY_METHOD (deprecated).
 * @param meth Method table to update.
 * @param verify Callback that verifies a DER/raw signature buffer, or NULL to clear.
 * @param verify_sig Callback that verifies an ECDSA_SIG structure, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth,
    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf,
        int sig_len, EC_KEY *eckey),
    int (*verify_sig)(const unsigned char *dgst,
        int dgst_len, const ECDSA_SIG *sig,
        EC_KEY *eckey));""",
"EC_KEY_METHOD_set_verify")

# ----- engine.h -----
patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_last(void);",
"""/**
 * @brief Return the last ENGINE in the global ENGINE list (deprecated).
 * @return ENGINE with an incremented structural reference, or NULL if the list is empty.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_last(void);""",
"ENGINE_get_last")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_register_RAND(ENGINE *e);",
"""/**
 * @brief Register @p e's RAND implementation with the global RAND table (deprecated).
 * @param e ENGINE whose RAND method should be registered.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_RAND(ENGINE *e);""",
"ENGINE_register_RAND")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_register_ciphers(ENGINE *e);",
"""/**
 * @brief Register @p e's cipher implementations with the global cipher table (deprecated).
 * @param e ENGINE whose ciphers should be registered.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_ciphers(ENGINE *e);""",
"ENGINE_register_ciphers")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_meths(ENGINE *e);",
"""/**
 * @brief Unregister @p e's EVP_PKEY_METHOD implementations from the global table (deprecated).
 * @param e ENGINE whose pkey methods should be removed.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_pkey_meths(ENGINE *e);""",
"ENGINE_unregister_pkey_meths")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0 int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p,
    void (*f)(void));""",
"""/**
 * @brief Dispatch a control command to an ENGINE (deprecated).
 * @param e ENGINE receiving the command.
 * @param cmd Control command (ENGINE_CTRL_* or ENGINE-specific).
 * @param i Integer argument for @p cmd.
 * @param p Pointer argument for @p cmd, or NULL when unused.
 * @param f Optional function-pointer argument for @p cmd, or NULL.
 * @return Command-specific positive value on success, or non-positive on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p,
    void (*f)(void));""",
"ENGINE_ctrl")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_name(ENGINE *e, const char *name);",
"""/**
 * @brief Set the human-readable name string for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param name NUL-terminated display name; must remain valid for the life of @p e.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_name(ENGINE *e, const char *name);""",
"ENGINE_set_name")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);",
"""/**
 * @brief Attach an RSA_METHOD to an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param rsa_meth RSA method table, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);""",
"ENGINE_set_RSA")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);""",
"""/**
 * @brief Set the cipher enumeration callback for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param f Callback that lists or fetches EVP_CIPHER implementations, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);""",
"ENGINE_set_ciphers")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 const char *ENGINE_get_id(const ENGINE *e);",
"""/**
 * @brief Return the unique identifier string of an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return NUL-terminated id (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const char *ENGINE_get_id(const ENGINE *e);""",
"ENGINE_get_id")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);",
"""/**
 * @brief Return the RSA_METHOD currently attached to an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return RSA method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);""",
"ENGINE_get_RSA")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *ENGINE_get_EC(const ENGINE *e);",
"""/**
 * @brief Return the EC_KEY_METHOD currently attached to an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return EC key method pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *ENGINE_get_EC(const ENGINE *e);""",
"ENGINE_get_EC")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);""",
"""/**
 * @brief Return the ctrl callback registered on an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return Ctrl function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);""",
"ENGINE_get_ctrl_function")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe,
    const char *str, int len);""",
"""/**
 * @brief Find an EVP_PKEY_ASN1_METHOD by PEM/string name across ENGINEs (deprecated).
 * @param pe Optional address that receives the ENGINE that provided the method (structurally referenced), or NULL.
 * @param str Method name bytes (not necessarily NUL-terminated).
 * @param len Length of @p str in bytes.
 * @return Matching ASN.1 method, or NULL if none is found.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe,
    const char *str, int len);""",
"ENGINE_pkey_asn1_find_str")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_init(ENGINE *e);",
"""/**
 * @brief Initialise an ENGINE for functional use (deprecated).
 * @param e ENGINE to initialise; takes a functional reference on success.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_init(ENGINE *e);""",
"ENGINE_init")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data);""",
"""/**
 * @brief Load a private key from an ENGINE by key identifier (deprecated).
 * @param e Initialised ENGINE that implements key loading.
 * @param key_id ENGINE-specific key identifier string.
 * @param ui_method UI method for PIN/passphrase prompts, or NULL.
 * @param callback_data Application pointer passed to @p ui_method.
 * @return Loaded EVP_PKEY, or NULL on failure.
 */
OSSL_DEPRECATEDIN_3_0
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data);""",
"ENGINE_load_private_key")

patch_both("engine.h",
"""OSSL_DEPRECATEDIN_3_0
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **ppkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method, void *callback_data);""",
"""/**
 * @brief Load an SSL client certificate and key via an ENGINE (deprecated).
 * @param e Initialised ENGINE that implements SSL client-cert loading.
 * @param s SSL connection requesting a client certificate.
 * @param ca_dn Acceptable CA names from the server, or NULL.
 * @param pcert Receives the selected client certificate.
 * @param ppkey Receives the matching private key.
 * @param pother Optional stack receiving additional chain certificates, or NULL.
 * @param ui_method UI method for PIN/passphrase prompts, or NULL.
 * @param callback_data Application pointer passed to @p ui_method.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn,
    X509 **pcert, EVP_PKEY **ppkey,
    STACK_OF(X509) **pother,
    UI_METHOD *ui_method, void *callback_data);""",
"ENGINE_load_ssl_client_cert")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RSA(ENGINE *e);",
"""/**
 * @brief Register @p e as the default ENGINE for RSA operations (deprecated).
 * @param e ENGINE to install as the RSA default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RSA(ENGINE *e);""",
"ENGINE_set_default_RSA")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_EC(ENGINE *e);",
"""/**
 * @brief Register @p e as the default ENGINE for EC operations (deprecated).
 * @param e ENGINE to install as the EC default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_EC(ENGINE *e);""",
"ENGINE_set_default_EC")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_digests(ENGINE *e);",
"""/**
 * @brief Register @p e as the default ENGINE for digest algorithms (deprecated).
 * @param e ENGINE to install as the digests default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_digests(ENGINE *e);""",
"ENGINE_set_default_digests")

patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_pkey_asn1_meths(ENGINE *e);",
"""/**
 * @brief Register @p e as the default ENGINE for EVP_PKEY ASN.1 methods (deprecated).
 * @param e ENGINE to install as the pkey ASN.1-method default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_pkey_asn1_meths(ENGINE *e);""",
"ENGINE_set_default_pkey_asn1_meths")

print(f"\nDone 8a: {len(ok)} ok, {len(missing)} missing")
if missing:
    print("MISSING:", *missing, sep="\n  ")
