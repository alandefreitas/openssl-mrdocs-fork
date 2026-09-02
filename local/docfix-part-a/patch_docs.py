#!/usr/bin/env python3
"""Patch OpenSSL public headers with MrDocs documentation (part A).
Tries both path and path+'.in' for each replacement.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # openssl/
INC = ROOT / "include" / "openssl"

ok = []
missing = []
partial = []


def patch_both(rel: str, old: str, new: str, label: str) -> None:
    """Apply the same substitution to rel and rel+'.in' when present."""
    paths = [INC / rel]
    if not rel.endswith(".in"):
        paths.append(INC / (rel + ".in"))
    any_found = False
    any_changed = False
    for path in paths:
        if not path.exists():
            continue
        any_found = True
        text = path.read_text(encoding="utf-8")
        if old not in text:
            # Already patched?
            if new.strip() in text or (new in text):
                print(f"  SKIP (already): {path.name} :: {label}")
                any_changed = True
                continue
            print(f"  MISS old text: {path.name} :: {label}")
            missing.append(f"{path.name}:{label}")
            continue
        count = text.count(old)
        if count != 1:
            print(f"  WARN count={count}: {path.name} :: {label}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        any_changed = True
        ok.append(f"{path.name}:{label}")
    if not any_found:
        missing.append(f"{rel}:{label}:no-file")
    elif not any_changed:
        partial.append(label)


# ---------------------------------------------------------------------------
# asn1.h / asn1.h.in
# ---------------------------------------------------------------------------
patch_both(
    "asn1.h",
    "int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);",
    """/**
 * @brief Copy type, data, and flags from @p str into @p dst.
 * @param dst Destination string; must already be allocated.
 * @param src Source string to copy from (parameter name in API is @c str).
 * @param str Source ASN1_STRING whose contents are copied into @p dst.
 * @return 1 on success, or 0 on failure (including when @p str is NULL).
 *
 * Preserves any ASN1_STRING_FLAG_EMBED bit already set on @p dst.
 */
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);""".replace(
        " * @param src Source string to copy from (parameter name in API is @c str).\n",
        "",
    ),
    "ASN1_STRING_copy",
)

# Fix - I accidentally left a replace; rewrite cleanly below if needed
# Actually the replace removed the bad line. Good.

patch_both(
    "asn1.h",
    """int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a,
    const unsigned char *flags, int flags_len);""",
    """/**
 * @brief Verify that every set bit in @p a is allowed by the @p flags mask.
 * @param a Bit string to check; NULL or empty is treated as valid.
 * @param flags Byte mask of permitted bits (1 = allowed).
 * @param flags_len Length of @p flags in bytes.
 * @return 1 if all set bits are allowed (or @p a is empty), or 0 if any disallowed bit is set.
 */
int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a,
    const unsigned char *flags, int flags_len);""",
    "ASN1_BIT_STRING_check",
)

# ---------------------------------------------------------------------------
# async.h
# ---------------------------------------------------------------------------
patch_both(
    "async.h",
    "ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void);",
    """/**
 * @brief Allocate a new asynchronous wait context.
 * @return New ASYNC_WAIT_CTX, or NULL on allocation failure.
 *
 * Create one before ASYNC_start_job(); a context is associated with at most one
 * ASYNC_JOB at a time but may be reused after that job finishes.
 */
ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void);""",
    "ASYNC_WAIT_CTX_new",
)

# ---------------------------------------------------------------------------
# bio.h / bio.h.in
# ---------------------------------------------------------------------------
patch_both(
    "bio.h",
    "int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);",
    """/**
 * @brief Attempt to read up to @p dlen bytes from BIO @p b into @p data.
 * @param b BIO to read from.
 * @param data Destination buffer for the bytes read.
 * @param dlen Maximum number of bytes to read.
 * @param readbytes On success, receives the number of bytes actually read.
 * @return 1 if any data was successfully read, or 0 otherwise.
 */
int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);""",
    "BIO_read_ex",
)

# ---------------------------------------------------------------------------
# buffer.h
# ---------------------------------------------------------------------------
patch_both(
    "buffer.h",
    "    size_t max; /* size of buffer */",
    "    /** Allocated capacity of @c data in bytes. */\n    size_t max;",
    "buf_mem_st.max",
)

patch_both(
    "buffer.h",
    "BUF_MEM *BUF_MEM_new_ex(unsigned long flags);",
    """/**
 * @brief Allocate a new BUF_MEM with the given allocation flags.
 * @param flags Allocation flags such as BUF_MEM_FLAG_SECURE for secure-heap @c data.
 * @return New zero-length BUF_MEM, or NULL on allocation failure.
 */
BUF_MEM *BUF_MEM_new_ex(unsigned long flags);""",
    "BUF_MEM_new_ex",
)

# ---------------------------------------------------------------------------
# cms.h / cms.h.in
# ---------------------------------------------------------------------------
patch_both(
    "cms.h",
    "DECLARE_ASN1_PRINT_FUNCTION(CMS_ContentInfo)",
    """/**
 * @brief Print a CMS_ContentInfo structure to a BIO.
 * @param out BIO to write human-readable output to.
 * @param x CMS ContentInfo to print.
 * @param indent Indentation depth in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int CMS_ContentInfo_print_ctx(BIO *out, const CMS_ContentInfo *x, int indent,
    const ASN1_PCTX *pctx);""",
    "CMS_ContentInfo_print_ctx",
)

patch_both(
    "cms.h",
    "CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags);",
    """/**
 * @brief Create a CMS Data ContentInfo from bytes read from @p in.
 * @param in BIO supplying the content octets.
 * @param flags CMS flags; CMS_STREAM defers CMS_final() for streaming.
 * @return New CMS_ContentInfo of type NID_pkcs7_data, or NULL on error.
 *
 * Equivalent to CMS_data_create_ex() with a NULL library context and property query.
 */
CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags);""",
    "CMS_data_create",
)

patch_both(
    "cms.h",
    """int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,
    const char *attrname, int type,
    const void *bytes, int len);""",
    """/**
 * @brief Append an unsigned attribute identified by name to a CMS SignerInfo.
 * @param si SignerInfo whose unsignedAttrs set is extended.
 * @param attrname Attribute type name (short or long name from obj_mac.h).
 * @param type ASN.1 string type of @p bytes (for example V_ASN1_OCTET_STRING).
 * @param bytes Attribute value bytes to copy into the new X509_ATTRIBUTE.
 * @param len Length of @p bytes in octets.
 * @return 1 on success, or 0 on failure.
 */
int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,
    const char *attrname, int type,
    const void *bytes, int len);""",
    "CMS_unsigned_add1_attr_by_txt",
)

# ---------------------------------------------------------------------------
# comp.h
# ---------------------------------------------------------------------------
patch_both(
    "comp.h",
    "COMP_METHOD *COMP_brotli(void);",
    """/**
 * @brief Return the stream-based brotli compression method.
 * @return brotli COMP_METHOD on success, or NULL on failure (or if brotli is unavailable).
 */
COMP_METHOD *COMP_brotli(void);""",
    "COMP_brotli",
)

# ---------------------------------------------------------------------------
# ct.h / ct.h.in
# ---------------------------------------------------------------------------
patch_both(
    "ct.h",
    "/* Gets the peer certificate that the SCTs are for */\nX509 *CT_POLICY_EVAL_CTX_get0_cert(const CT_POLICY_EVAL_CTX *ctx);",
    """/**
 * @brief Return the peer certificate associated with SCTs in a policy context.
 * @param ctx Policy evaluation context to query.
 * @return Certificate the SCTs were issued for, or NULL if unset.
 */
X509 *CT_POLICY_EVAL_CTX_get0_cert(const CT_POLICY_EVAL_CTX *ctx);""",
    "CT_POLICY_EVAL_CTX_get0_cert",
)

patch_both(
    "ct.h",
    """/*
 * Set the version of an SCT.
 * Returns 1 on success, 0 if the version is unrecognized.
 */
__owur int SCT_set_version(SCT *sct, sct_version_t version);""",
    """/**
 * @brief Set the Certificate Transparency version of an SCT.
 * @param sct SCT to update.
 * @param version SCT version to set; only SCT_VERSION_V1 is currently supported.
 * @return 1 if @p version is supported, or 0 otherwise.
 */
__owur int SCT_set_version(SCT *sct, sct_version_t version);""",
    "SCT_set_version",
)

# ---------------------------------------------------------------------------
# dh.h
# ---------------------------------------------------------------------------
patch_both(
    "dh.h",
    "int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);",
    """/**
 * @brief Set the DH key-derivation function type on an EVP_PKEY_CTX.
 * @param ctx Key derivation / encapsulate context for a DH key.
 * @param kdf KDF type such as EVP_PKEY_DH_KDF_NONE or EVP_PKEY_DH_KDF_X9_42.
 * @return 1 on success, or a negative value for unsupported / failure.
 *
 * When using EVP_PKEY_DH_KDF_X9_42, also set the KDF OID, digest, and output length.
 */
int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf);""",
    "EVP_PKEY_CTX_set_dh_kdf_type",
)

patch_both(
    "dh.h",
    "DECLARE_ASN1_ITEM(DHparams)",
    """/**
 * @brief Return the ASN.1 item descriptor for Diffie-Hellman domain parameters.
 * @return Pointer to the static ASN1_ITEM for DHparams.
 */
const ASN1_ITEM *DHparams_it(void);""",
    "DHparams_it",
)

patch_both(
    "dh.h",
    "OSSL_DEPRECATEDIN_3_0 DH *DH_new_method(ENGINE *engine);",
    """/**
 * @brief Allocate a DH object that uses @p engine for DH operations (deprecated).
 * @param engine ENGINE to use, or NULL for the default DH ENGINE / method.
 * @return New DH, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_new_method(ENGINE *engine);""",
    "DH_new_method",
)

patch_both(
    "dh.h",
    "DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(OSSL_DEPRECATEDIN_3_0, DH, DHparams)",
    """/**
 * @brief Decode Diffie-Hellman domain parameters from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded DH parameters, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DH *d2i_DHparams(DH **a, const unsigned char **in, long len);
/**
 * @brief Encode Diffie-Hellman domain parameters to DER (deprecated).
 * @param a DH object whose parameters are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DHparams(const DH *a, unsigned char **out);""",
    "d2i/i2d_DHparams",
)

# ---------------------------------------------------------------------------
# dsa.h
# ---------------------------------------------------------------------------
patch_both(
    "dsa.h",
    "int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);",
    """/**
 * @brief Set the digest used for DSA parameter generation on an EVP_PKEY_CTX.
 * @param ctx Parameter-generation context for a DSA key.
 * @param md Message digest to use; if unset, SHA-1/224/256 is chosen to match q.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_set_dsa_paramgen_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);""",
    "EVP_PKEY_CTX_set_dsa_paramgen_md",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_default_method(void);",
    """/**
 * @brief Return the current default DSA_METHOD (deprecated).
 * @return Pointer to the default DSA_METHOD.
 *
 * Meaningfulness depends on whether the ENGINE API is in use; prefer providers.
 */
OSSL_DEPRECATEDIN_3_0 const DSA_METHOD *DSA_get_default_method(void);""",
    "DSA_get_default_method",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int DSA_set_method(DSA *dsa, const DSA_METHOD *);",
    """/**
 * @brief Select the DSA_METHOD used for operations on @p dsa (deprecated).
 * @param dsa DSA key whose method is replaced.
 * @param meth Method implementation to attach; releases any prior ENGINE method.
 * @return Non-zero on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set_method(DSA *dsa, const DSA_METHOD *meth);""",
    "DSA_set_method",
)

patch_both(
    "dsa.h",
    "OSSL_DEPRECATEDIN_3_0 int DSAparams_print_fp(FILE *fp, const DSA *x);",
    """/**
 * @brief Print DSA domain parameters to a FILE (deprecated).
 * @param fp Output FILE.
 * @param x DSA object whose parameters are printed.
 * @return 1 on success, or 0 or a negative value on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSAparams_print_fp(FILE *fp, const DSA *x);""",
    "DSAparams_print_fp",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam,
    int (*bn_mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, BN_CTX *, BN_MONT_CTX *));""",
    """/**
 * @brief Set the modular-exponentiation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param bn_mod_exp Callback computing r = a^p mod m (with optional Montgomery ctx), or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam,
    int (*bn_mod_exp)(DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
        const BIGNUM *, BN_CTX *, BN_MONT_CTX *));""",
    "DSA_meth_set_bn_mod_exp",
)

# ---------------------------------------------------------------------------
# ec.h
# ---------------------------------------------------------------------------
patch_both(
    "ec.h",
    "OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_get_default_method(void);",
    """/**
 * @brief Return the current default EC_KEY_METHOD (deprecated).
 * @return Pointer to the default EC_KEY_METHOD.
 */
OSSL_DEPRECATEDIN_3_0 const EC_KEY_METHOD *EC_KEY_get_default_method(void);""",
    "EC_KEY_get_default_method",
)

# ---------------------------------------------------------------------------
# engine.h
# ---------------------------------------------------------------------------
patch_both(
    "engine.h",
    "OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_EC(ENGINE *e);",
    """/**
 * @brief Remove @p e's EC method from the ENGINE EC implementation table.
 * @param e ENGINE previously registered for EC.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_EC(ENGINE *e);""",
    "ENGINE_unregister_EC",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);""",
    """/**
 * @brief Set the callback invoked by ENGINE_finish() to shut down an ENGINE.
 * @param e ENGINE whose finish hook is replaced.
 * @param finish_f Function called to release functional state of @p e, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);""",
    "ENGINE_set_finish_function",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);""",
    """/**
 * @brief Return the finish callback registered on an ENGINE.
 * @param e ENGINE to query.
 * @return Finish function pointer, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);""",
    "ENGINE_get_finish_function",
)

# ---------------------------------------------------------------------------
# err.h / err.h.in
# ---------------------------------------------------------------------------
patch_both(
    "err.h",
    """typedef struct ERR_string_data_st {
    unsigned long error;
    const char *string;
} ERR_STRING_DATA;""",
    """/**
 * @brief Mapping from a packed OpenSSL error code to a human-readable string.
 */
typedef struct ERR_string_data_st {
    /** Packed error code as produced by ERR_PACK(lib, func, reason). */
    unsigned long error;
    /** NUL-terminated description corresponding to @c error. */
    const char *string;
} ERR_STRING_DATA;""",
    "ERR_STRING_DATA",
)

patch_both(
    "err.h",
    "void ERR_add_error_vdata(int num, va_list args);",
    """/**
 * @brief Append additional string data to the most recent error, from a va_list.
 * @param num Number of @c char * arguments in @p args to concatenate.
 * @param args va_list of @p num C strings associated with the last error code.
 *
 * Like ERR_add_error_data() but takes a va_list; total extra data per error is capped at 4096 characters.
 */
void ERR_add_error_vdata(int num, va_list args);""",
    "ERR_add_error_vdata",
)

# ---------------------------------------------------------------------------
# hmac.h
# ---------------------------------------------------------------------------
patch_both(
    "hmac.h",
    "OSSL_DEPRECATEDIN_3_0 size_t HMAC_size(const HMAC_CTX *e);",
    """/**
 * @brief Return the output length in bytes of the digest used by an HMAC context (deprecated).
 * @param e HMAC context whose underlying hash size is queried.
 * @return Digest output size in bytes, or 0 if @p e has no digest set.
 */
OSSL_DEPRECATEDIN_3_0 size_t HMAC_size(const HMAC_CTX *e);""",
    "HMAC_size",
)

# ---------------------------------------------------------------------------
# objects.h
# ---------------------------------------------------------------------------
patch_both(
    "objects.h",
    """void OBJ_NAME_do_all(int type, void (*fn)(const OBJ_NAME *, void *arg),
    void *arg);""",
    """/**
 * @brief Invoke a callback for every OBJ_NAME of the given type (unsorted).
 * @param type Name table type to iterate (for example OBJ_NAME_TYPE_MD_METH).
 * @param fn Callback receiving each OBJ_NAME entry and @p arg.
 * @param arg User pointer passed through to @p fn.
 */
void OBJ_NAME_do_all(int type, void (*fn)(const OBJ_NAME *, void *arg),
    void *arg);""",
    "OBJ_NAME_do_all",
)

patch_both(
    "objects.h",
    "int OBJ_obj2nid(const ASN1_OBJECT *o);",
    """/**
 * @brief Return the NID for an ASN1_OBJECT.
 * @param o Object identifier to look up.
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_obj2nid(const ASN1_OBJECT *o);""",
    "OBJ_obj2nid",
)

patch_both(
    "objects.h",
    "int OBJ_txt2nid(const char *s);",
    """/**
 * @brief Return the NID for a text object identifier.
 * @param s Long name, short name, or numerical OID string.
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_txt2nid(const char *s);""",
    "OBJ_txt2nid",
)

patch_both(
    "objects.h",
    "int OBJ_ln2nid(const char *s);",
    """/**
 * @brief Return the NID for an object long name.
 * @param s Long name to look up (for example "commonName").
 * @return Corresponding NID, or NID_undef on error.
 */
int OBJ_ln2nid(const char *s);""",
    "OBJ_ln2nid",
)

patch_both(
    "objects.h",
    "int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);",
    """/**
 * @brief Compare two ASN1_OBJECT values.
 * @param a First object identifier.
 * @param b Second object identifier.
 * @return 0 if @p a and @p b are identical; non-zero otherwise.
 */
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);""",
    "OBJ_cmp",
)

patch_both(
    "objects.h",
    "int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);",
    """/**
 * @brief Look up the digest and public-key NIDs that compose a signature algorithm.
 * @param signid NID of the composite signature algorithm.
 * @param pdig_nid Optional out-parameter for the digest algorithm NID, or NULL.
 * @param ppkey_nid Optional out-parameter for the public-key algorithm NID, or NULL.
 * @return 1 if @p signid is found, or 0 otherwise.
 */
int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);""",
    "OBJ_find_sigid_algs",
)

# ---------------------------------------------------------------------------
# params.h
# ---------------------------------------------------------------------------
patch_both(
    "params.h",
    "OSSL_PARAM OSSL_PARAM_construct_time_t(const char *key, time_t *buf);",
    """/**
 * @brief Construct an OSSL_PARAM describing a time_t integer buffer.
 * @param key Parameter name stored in the returned descriptor.
 * @param buf Address of the time_t value associated with @p key.
 * @return OSSL_PARAM of type OSSL_PARAM_INTEGER sized for time_t.
 */
OSSL_PARAM OSSL_PARAM_construct_time_t(const char *key, time_t *buf);""",
    "OSSL_PARAM_construct_time_t",
)

patch_both(
    "params.h",
    "int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val);",
    """/**
 * @brief Read a floating-point value from an OSSL_PARAM into @p val.
 * @param p Parameter of floating-point type to read.
 * @param val Receives the converted double value on success.
 * @return 1 on success, or 0 on type/size mismatch or other failure.
 */
int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val);""",
    "OSSL_PARAM_get_double",
)

# ---------------------------------------------------------------------------
# pem.h
# ---------------------------------------------------------------------------
patch_both(
    "pem.h",
    """void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
    pem_password_cb *cb, void *u);""",
    """/**
 * @brief Read a named PEM object from a FILE and decode it with @p d2i.
 * @param d2i ASN.1 decode callback for the expected type.
 * @param name PEM type label expected on the BEGIN line (e.g. "CERTIFICATE").
 * @param fp FILE to read from.
 * @param x Optional address of an object pointer to reuse, or NULL.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return Decoded object on success, or NULL on failure.
 */
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
    pem_password_cb *cb, void *u);""",
    "PEM_ASN1_read",
)

# ---------------------------------------------------------------------------
# rsa.h
# ---------------------------------------------------------------------------
patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen);",
    """/**
 * @brief Get the RSA-PSS salt length configured on an EVP_PKEY_CTX.
 * @param ctx Context whose padding mode must already be RSA_PKCS1_PSS_PADDING.
 * @param saltlen Receives the salt length (or a special RSA_PSS_SALTLEN_* value).
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen);""",
    "EVP_PKEY_CTX_get_rsa_pss_saltlen",
)

patch_both(
    "rsa.h",
    "int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen);",
    """/**
 * @brief Set the RSA-OAEP label on an EVP_PKEY_CTX, transferring ownership of @p label.
 * @param ctx Context whose padding mode must be RSA_PKCS1_OAEP_PADDING.
 * @param label Label bytes to adopt, or NULL (with @p llen 0) to clear the label.
 * @param llen Length of @p label in bytes.
 * @return 1 on success, or a negative value for unsupported / failure.
 *
 * The library takes ownership of @p label; the caller must not free it afterwards.
 */
int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen);""",
    "EVP_PKEY_CTX_set0_rsa_oaep_label",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_set0_crt_params(RSA *r,
    BIGNUM *dmp1, BIGNUM *dmq1,
    BIGNUM *iqmp);""",
    """/**
 * @brief Set the CRT parameters on an RSA key, transferring ownership (deprecated).
 * @param r RSA key to update.
 * @param dmp1 d mod (p-1), or NULL to leave unchanged (once set, may not clear).
 * @param dmq1 d mod (q-1), or NULL to leave unchanged.
 * @param iqmp q^-1 mod p, or NULL to leave unchanged.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_set0_crt_params(RSA *r,
    BIGNUM *dmp1, BIGNUM *dmq1,
    BIGNUM *iqmp);""",
    "RSA_set0_crt_params",
)

patch_both(
    "rsa.h",
    "OSSL_DEPRECATEDIN_3_0 const RSA_PSS_PARAMS *RSA_get0_pss_params(const RSA *r);",
    """/**
 * @brief Return the RSA-PSS parameters associated with an RSA key (deprecated).
 * @param r RSA key to query.
 * @return Internal RSA_PSS_PARAMS pointer, or NULL if none are set.
 */
OSSL_DEPRECATEDIN_3_0 const RSA_PSS_PARAMS *RSA_get0_pss_params(const RSA *r);""",
    "RSA_get0_pss_params",
)

patch_both(
    "rsa.h",
    "OSSL_DEPRECATEDIN_3_0 ENGINE *RSA_get0_engine(const RSA *r);",
    """/**
 * @brief Return the ENGINE set on an RSA key (deprecated).
 * @param r RSA key to query.
 * @return ENGINE handle, or NULL if none is set.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *RSA_get0_engine(const RSA *r);""",
    "RSA_get0_engine",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
    """/**
 * @brief Encode a message with PKCS #1 v1.5 encryption padding (type 2) (deprecated).
 * @param to Destination buffer of size @p tlen for the padded encoding.
 * @param tlen Size of @p to in bytes (typically RSA_size()).
 * @param f Message bytes to encode.
 * @param fl Length of @p f in bytes.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *f, int fl);""",
    "RSA_padding_add_PKCS1_type_2",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int PKCS1_MGF1(unsigned char *mask, long len,
    const unsigned char *seed, long seedlen,
    const EVP_MD *dgst);""",
    """/**
 * @brief Generate a PKCS #1 mask using MGF1 with digest @p dgst (deprecated).
 * @param mask Output buffer that receives @p len mask bytes.
 * @param len Desired mask length in bytes.
 * @param seed MGF seed (mgfSeed).
 * @param seedlen Length of @p seed in bytes.
 * @param dgst Hash function used by MGF1.
 * @return 0 on success, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int PKCS1_MGF1(unsigned char *mask, long len,
    const unsigned char *seed, long seedlen,
    const EVP_MD *dgst);""",
    "PKCS1_MGF1",
)

patch_both(
    "rsa.h",
    "DECLARE_ASN1_DUP_FUNCTION_name_attr(OSSL_DEPRECATEDIN_3_0, RSA, RSAPublicKey)",
    """/**
 * @brief Duplicate an RSA public key via ASN.1 encode/decode (deprecated).
 * @param a RSA key whose public components are duplicated.
 * @return Newly allocated RSA copy, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 RSA *RSAPublicKey_dup(const RSA *a);""",
    "RSAPublicKey_dup",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_mod_exp(RSA_METHOD *rsa,
    int (*mod_exp)(BIGNUM *r0, const BIGNUM *i, RSA *rsa,
        BN_CTX *ctx));""",
    """/**
 * @brief Set the CRT modular-exponentiation callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param mod_exp Callback used for CRT computations, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_mod_exp(RSA_METHOD *rsa,
    int (*mod_exp)(BIGNUM *r0, const BIGNUM *i, RSA *rsa,
        BN_CTX *ctx));""",
    "RSA_meth_set_mod_exp",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_verify(RSA_METHOD *rsa,
    int (*verify)(int dtype, const unsigned char *m,
        unsigned int m_length,
        const unsigned char *sigbuf,
        unsigned int siglen, const RSA *rsa));""",
    """/**
 * @brief Set the signature-verification callback on a custom RSA_METHOD (deprecated).
 * @param rsa Method object to update.
 * @param verify Callback invoked by RSA_verify(), with the same parameters, or NULL.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_verify(RSA_METHOD *rsa,
    int (*verify)(int dtype, const unsigned char *m,
        unsigned int m_length,
        const unsigned char *sigbuf,
        unsigned int siglen, const RSA *rsa));""",
    "RSA_meth_set_verify",
)

# Need exact text for RSA_meth_set_verify - check signature
# RSA_meth_get_keygen
patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_keygen(const RSA_METHOD *meth))(RSA *rsa, int bits,
    BIGNUM *e, BN_GENCB *cb);""",
    """/**
 * @brief Return the key-generation callback from a custom RSA_METHOD (deprecated).
 * @param meth Method object to query.
 * @return Keygen function pointer used by RSA_generate_key_ex(), or NULL.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_keygen(const RSA_METHOD *meth))(RSA *rsa, int bits,
    BIGNUM *e, BN_GENCB *cb);""",
    "RSA_meth_get_keygen",
)

print("\n=== SUMMARY ===")
print(f"OK: {len(ok)}")
print(f"MISSING: {len(missing)}")
for m in missing:
    print("  -", m)
print(f"PARTIAL: {partial}")
sys.exit(1 if missing else 0)
