#!/usr/bin/env python3
"""Documentation repair batch 19e: types, ui, x509, x509_vfy, x509v3."""
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


print("=== batch 19e: types/ui/x509/x509_vfy/x509v3 ===")

# ----- types.h -----

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
""",
    """typedef struct asn1_string_st ASN1_INTEGER;
/**
 * @brief ASN.1 ENUMERATED stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_ENUMERATED;
""",
    "ASN1_ENUMERATED",
)

patch_one(
    "types.h",
    """typedef struct rsa_pss_params_st RSA_PSS_PARAMS;
""",
    """/**
 * @brief Opaque RSASSA-PSS parameter structure (hashAlg / maskGenAlg / saltLength / trailerField).
 */
struct rsa_pss_params_st;
/**
 * @brief Opaque RSASSA-PSS parameter structure (hashAlg / maskGenAlg / saltLength / trailerField).
 */
typedef struct rsa_pss_params_st RSA_PSS_PARAMS;
""",
    "rsa_pss_params_st/RSA_PSS_PARAMS",
)

# ----- ui.h -----

patch_both(
    "ui.h",
    """UI *UI_new(void);
""",
    """/**
 * @brief Allocate a new UI that uses the process-wide default UI_METHOD.
 * @return New UI, or NULL on error; free with UI_free().
 */
UI *UI_new(void);
""",
    "UI_new",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx);
""",
    """/**
 * @brief Sign certificate request @p x using an already-initialized digest/signing context.
 * @param x Certificate request whose signature is computed and stored.
 * @param ctx EVP_MD_CTX prepared for signing (digest + private key).
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx);
""",
    "X509_REQ_sign_ctx",
)

patch_both(
    "x509.h",
    """int i2d_X509_REQ_bio(BIO *bp, const X509_REQ *req);
""",
    """/**
 * @brief Write a certificate request to a BIO in DER form.
 * @param bp Output BIO.
 * @param req Certificate request to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_X509_REQ_bio(BIO *bp, const X509_REQ *req);
""",
    "i2d_X509_REQ_bio",
)

patch_both(
    "x509.h",
    """X509_PUBKEY *d2i_X509_PUBKEY_bio(BIO *bp, X509_PUBKEY **xpk);
""",
    """/**
 * @brief Decode an X509_PUBKEY (SubjectPublicKeyInfo) in DER form from a BIO.
 * @param bp BIO positioned at the DER encoding.
 * @param xpk Optional destination pointer updated to the result, or NULL.
 * @return Decoded X509_PUBKEY, or NULL on error; free with X509_PUBKEY_free().
 */
X509_PUBKEY *d2i_X509_PUBKEY_bio(BIO *bp, X509_PUBKEY **xpk);
""",
    "d2i_X509_PUBKEY_bio",
)

patch_both(
    "x509.h",
    """void X509_get0_signature(const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg, const X509 *x);
""",
    """/**
 * @brief Return internal pointers to a certificate's signature value and AlgorithmIdentifier.
 * @param psig Receives the signature BIT STRING, or NULL to skip; do not free.
 * @param palg Receives the signature AlgorithmIdentifier, or NULL to skip; do not free.
 * @param x Certificate to query.
 */
void X509_get0_signature(const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg, const X509 *x);
""",
    "X509_get0_signature",
)

patch_both(
    "x509.h",
    """unsigned char *X509_keyid_get0(X509 *x, int *len);
""",
    """/**
 * @brief Return the subject key identifier attached to a certificate, if any.
 * @param x Certificate whose auxiliary key id is queried.
 * @param len Optional out-parameter receiving the key id length in bytes; may be NULL.
 * @return Internal pointer to key id bytes, or NULL if none; do not free.
 */
unsigned char *X509_keyid_get0(X509 *x, int *len);
""",
    "X509_keyid_get0",
)

patch_both(
    "x509.h",
    """EVP_PKEY *X509_get0_pubkey(const X509 *x);
""",
    """/**
 * @brief Return the certificate subject public key without incrementing its reference count.
 * @param x Certificate to query.
 * @return Internal EVP_PKEY pointer (do not free), or NULL on error.
 */
EVP_PKEY *X509_get0_pubkey(const X509 *x);
""",
    "X509_get0_pubkey",
)

patch_both(
    "x509.h",
    """void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg);
""",
    """/**
 * @brief Return internal pointers to a request's signature value and AlgorithmIdentifier.
 * @param req Certificate request to query.
 * @param psig Receives the signature BIT STRING, or NULL to skip; do not free.
 * @param palg Receives the signature AlgorithmIdentifier, or NULL to skip; do not free.
 */
void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg);
""",
    "X509_REQ_get0_signature",
)

patch_both(
    "x509.h",
    """int X509_REQ_get_signature_nid(const X509_REQ *req);
""",
    """/**
 * @brief Return the NID of the digest used in a request's signature AlgorithmIdentifier.
 * @param req Certificate request to query.
 * @return Digest NID, or NID_undef if the algorithm is unknown / has no digest.
 */
int X509_REQ_get_signature_nid(const X509_REQ *req);
""",
    "X509_REQ_get_signature_nid",
)

patch_both(
    "x509.h",
    """EVP_PKEY *X509_REQ_get0_pubkey(const X509_REQ *req);
""",
    """/**
 * @brief Return the request subject public key without incrementing its reference count.
 * @param req Certificate request to query.
 * @return Internal EVP_PKEY pointer (do not free), or NULL on error.
 */
EVP_PKEY *X509_REQ_get0_pubkey(const X509_REQ *req);
""",
    "X509_REQ_get0_pubkey",
)

patch_both(
    "x509.h",
    """int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
""",
    """/**
 * @brief Append a duplicate of @p attr to a certificate request's attribute list.
 * @param req Certificate request that receives the attribute.
 * @param attr Attribute to duplicate and append.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
""",
    "X509_REQ_add1_attr",
)

patch_both(
    "x509.h",
    """const STACK_OF(X509_EXTENSION) *X509_CRL_get0_extensions(const X509_CRL *crl);
""",
    """/**
 * @brief Return the stack of extensions on a CRL (crlExtensions), if any.
 * @param crl CRL to query.
 * @return Internal STACK_OF(X509_EXTENSION) pointer, or NULL if none; do not free.
 */
const STACK_OF(X509_EXTENSION) *X509_CRL_get0_extensions(const X509_CRL *crl);
""",
    "X509_CRL_get0_extensions",
)

patch_both(
    "x509.h",
    """const STACK_OF(X509_EXTENSION) *
X509_REVOKED_get0_extensions(const X509_REVOKED *r);
""",
    """/**
 * @brief Return the stack of extensions on a CRL revoked-entry, if any.
 * @param r Revoked entry to query.
 * @return Internal STACK_OF(X509_EXTENSION) pointer, or NULL if none; do not free.
 */
const STACK_OF(X509_EXTENSION) *
X509_REVOKED_get0_extensions(const X509_REVOKED *r);
""",
    "X509_REVOKED_get0_extensions",
)

patch_both(
    "x509.h",
    """unsigned long X509_subject_name_hash_old(X509 *x);
""",
    """/**
 * @brief Return the legacy MD5-based hash of a certificate's subject name.
 * @param x Certificate whose subject name is hashed.
 * @return 32-bit old-style subject name hash.
 */
unsigned long X509_subject_name_hash_old(X509 *x);
""",
    "X509_subject_name_hash_old",
)

patch_both(
    "x509.h",
    """int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
""",
    """/**
 * @brief Compare two X.509 distinguished names for equality.
 * @param a First name.
 * @param b Second name.
 * @return 0 if equal, or a non-zero value if they differ (including on error).
 */
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
""",
    "X509_NAME_cmp",
)

patch_both(
    "x509.h",
    """int X509_NAME_entry_count(const X509_NAME *name);
""",
    """/**
 * @brief Return the number of X509_NAME_ENTRY values in a distinguished name.
 * @param name Name to query.
 * @return Entry count (>= 0).
 */
int X509_NAME_entry_count(const X509_NAME *name);
""",
    "X509_NAME_entry_count",
)

patch_both(
    "x509.h",
    """int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos);
""",
    """/**
 * @brief Find the next extension on a certificate matching NID @p nid.
 * @param x Certificate whose extensions are searched.
 * @param nid Extension type NID to match.
 * @param lastpos Index after which to continue searching (-1 to start from the beginning).
 * @return Extension index, or -1 if not found.
 */
int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos);
""",
    "X509_get_ext_by_NID",
)

patch_both(
    "x509.h",
    """int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
""",
    """/**
 * @brief Insert a duplicate of extension @p ex into a certificate at @p loc.
 * @param x Certificate that receives the extension.
 * @param ex Extension to duplicate and insert.
 * @param loc Insertion index (-1 appends).
 * @return 1 on success, or 0 on failure.
 */
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
""",
    "X509_add_ext",
)

patch_both(
    "x509.h",
    """void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
""",
    """/**
 * @brief Decode the first (or next) certificate extension with NID @p nid into its ASN.1 type.
 * @param x Certificate whose extensions are searched.
 * @param nid Extension type NID to decode.
 * @param crit Optional out-parameter set to 1 if critical, 0 if not, -1/-2 on error; may be NULL.
 * @param idx Optional in/out index for multi-occurrence search; may be NULL for the first match.
 * @return Newly allocated decoded extension value (type depends on @p nid), or NULL if not found / on error.
 */
void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
""",
    "X509_get_ext_d2i",
)

patch_both(
    "x509.h",
    """int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
""",
    """/**
 * @brief Insert a duplicate of extension @p ex into a CRL at @p loc.
 * @param x CRL that receives the extension.
 * @param ex Extension to duplicate and insert.
 * @param loc Insertion index (-1 appends).
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
""",
    "X509_CRL_add_ext",
)

patch_both(
    "x509.h",
    """int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
""",
    """/**
 * @brief Set whether an X.509v3 extension is marked critical.
 * @param ex Extension to update.
 * @param crit Non-zero for critical, zero for non-critical.
 * @return 1 on success, or 0 on failure.
 */
int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
""",
    "X509_EXTENSION_set_critical",
)

patch_both(
    "x509.h",
    """ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex);
""",
    """/**
 * @brief Return the OID identifying an X.509v3 extension's type.
 * @param ex Extension to query.
 * @return Internal ASN1_OBJECT pointer, or NULL; do not free.
 */
ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex);
""",
    "X509_EXTENSION_get_object",
)

patch_both(
    "x509.h",
    """STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    int nid, int type,
    const unsigned char *bytes,
    int len);
""",
    """/**
 * @brief Create an attribute by NID and append a copy to a STACK_OF(X509_ATTRIBUTE).
 * @param x Address of the attribute stack pointer; allocated if NULL.
 * @param nid Attribute type NID.
 * @param type ASN.1 type of the attribute data.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return The (possibly newly allocated) attribute stack, or NULL on error.
 */
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    int nid, int type,
    const unsigned char *bytes,
    int len);
""",
    "X509at_add1_attr_by_NID",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
    const ASN1_OBJECT *obj,
    int atrtype, const void *data,
    int len);
""",
    """/**
 * @brief Create or reuse an X.509 Attribute identified by OID with typed data.
 * @param attr Optional address of an X509_ATTRIBUTE pointer to reuse or receive the result; may be NULL.
 * @param obj Attribute type OID.
 * @param atrtype ASN.1 / multibyte string type for @p data.
 * @param data Attribute value octets.
 * @param len Length of @p data in bytes.
 * @return New or reused X509_ATTRIBUTE, or NULL on error.
 */
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
    const ASN1_OBJECT *obj,
    int atrtype, const void *data,
    int len);
""",
    "X509_ATTRIBUTE_create_by_OBJ",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
""",
    """/**
 * @brief Return an attribute attached to an EVP_PKEY by index.
 * @param key Key whose attribute stack is queried.
 * @param loc Zero-based attribute index.
 * @return Internal X509_ATTRIBUTE pointer (do not free), or NULL if @p loc is out of range.
 */
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
""",
    "EVP_PKEY_get_attr",
)

patch_both(
    "x509.h",
    """EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8);
""",
    """/**
 * @brief Convert PKCS#8 private key info into an EVP_PKEY using the default library context.
 * @param p8 PKCS#8 PrivateKeyInfo to decode.
 * @return New EVP_PKEY, or NULL on error; free with EVP_PKEY_free().
 */
EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8);
""",
    "EVP_PKCS82PKEY",
)

patch_both(
    "x509.h",
    """int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO *p8, int nid, int type,
    const unsigned char *bytes, int len);
""",
    """/**
 * @brief Append an attribute identified by NID @p nid to a PKCS#8 private key info.
 * @param p8 PKCS#8 structure receiving the attribute.
 * @param nid Attribute type NID.
 * @param type ASN.1 type of the attribute data.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return 1 on success, or 0 on failure.
 */
int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO *p8, int nid, int type,
    const unsigned char *bytes, int len);
""",
    "PKCS8_pkey_add1_attr_by_NID",
)

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj);
""",
    """/**
 * @brief Store a certificate in an X509_OBJECT, taking a reference to @p obj.
 * @param a Object that will hold type X509_LU_X509.
 * @param obj Certificate to reference; its reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj);
""",
    "X509_OBJECT_set1_X509",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags);
""",
    """/**
 * @brief Set verification behaviour flags on an X509_STORE (OR of X509_V_FLAG_*).
 * @param xs Store whose default verify flags are replaced.
 * @param flags Flag bits applied to new X509_STORE_CTX instances from this store.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags);
""",
    "X509_STORE_set_flags",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_lookup_certs(X509_STORE *xs,
    X509_STORE_CTX_lookup_certs_fn lookup_certs);
""",
    """/**
 * @brief Install the certificate-by-name lookup callback used by verifications from this store.
 * @param xs Store whose certificate lookup function pointer is replaced.
 * @param lookup_certs Callback that returns a stack of matching certificates for a name, or NULL on failure; NULL selects the default.
 */
void X509_STORE_set_lookup_certs(X509_STORE *xs,
    X509_STORE_CTX_lookup_certs_fn lookup_certs);
""",
    "X509_STORE_set_lookup_certs",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name);
""",
    """/**
 * @brief Allocate a new custom X509_LOOKUP_METHOD with the given method name.
 * @param name Short name stored on the method (for diagnostics); duplicated internally.
 * @return New X509_LOOKUP_METHOD, or NULL on error; free with X509_LOOKUP_meth_free().
 */
X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name);
""",
    "X509_LOOKUP_meth_new",
)

patch_both(
    "x509_vfy.h",
    """X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *vs,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name);
""",
    """/**
 * @brief Look up a certificate or CRL by subject name and return a new X509_OBJECT wrapper.
 * @param vs Store context providing the X509_STORE and lookup state.
 * @param type X509_LU_X509 or X509_LU_CRL.
 * @param name Subject (or issuer for CRLs) name to match.
 * @return Newly allocated X509_OBJECT holding a reference to the match, or NULL if not found / on error; free with X509_OBJECT_free().
 */
X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *vs,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name);
""",
    "X509_STORE_CTX_get_obj_by_subject",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509) *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the verified certificate chain built for @p ctx without transferring ownership.
 * @param ctx Store context after successful (or partial) chain building.
 * @return Internal STACK_OF(X509) (leaf first), or NULL if none; do not free.
 */
STACK_OF(X509) *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_chain",
)

# ----- x509v3.h -----

patch_both(
    "x509v3.h",
    """typedef void *(*X509V3_EXT_NEW)(void);
""",
    """/**
 * @brief Callback that allocates a fresh extension-specific value for an X.509v3 method.
 * @return Newly allocated extension value, or NULL on allocation failure.
 */
typedef void *(*X509V3_EXT_NEW)(void);
""",
    "X509V3_EXT_NEW",
)

patch_both(
    "x509v3.h",
    """typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
""",
    """/**
 * @brief Stack of GeneralName values (SubjectAltName, IssuerAltName, distribution points, etc.).
 */
typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
""",
    "GENERAL_NAMES",
)

patch_both(
    "x509v3.h",
    """DECLARE_ASN1_ITEM(PROXY_CERT_INFO_EXTENSION)
""",
    """/**
 * @brief Return the ASN.1 item descriptor for PROXY_CERT_INFO_EXTENSION.
 * @return Pointer to the static ASN1_ITEM for PROXY_CERT_INFO_EXTENSION.
 */
const ASN1_ITEM *PROXY_CERT_INFO_EXTENSION_it(void);
""",
    "PROXY_CERT_INFO_EXTENSION_it",
)

patch_both(
    "x509v3.h",
    """    /** ASN.1 BOOLEAN: when set, certificate issuer may differ from the CRL issuer. */
    int indirectCRL;
    int onlyattr;
""",
    """    /** ASN.1 BOOLEAN: when set, certificate issuer may differ from the CRL issuer. */
    int indirectCRL;
    /** ASN.1 BOOLEAN: when set, the CRL covers attribute certificates only. */
    int onlyattr;
""",
    "onlyattr",
)

patch_both(
    "x509v3.h",
    """SXNET *d2i_SXNET(SXNET **a, const unsigned char **in, long len);
""",
    """/**
 * @brief Decode an SXNET (Strong Extranet) value from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded SXNET, or NULL on error.
 */
SXNET *d2i_SXNET(SXNET **a, const unsigned char **in, long len);
""",
    "d2i_SXNET",
)

patch_both(
    "x509v3.h",
    """void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype);
""",
    """/**
 * @brief Return the typed payload pointer stored in a GeneralName.
 * @param a GeneralName to query.
 * @param ptype Optional out-parameter receiving the name form (GEN_*), or NULL to skip.
 * @return Internal value pointer for the current type (do not free), or NULL if unset.
 */
void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype);
""",
    "GENERAL_NAME_get0_value",
)

patch_both(
    "x509v3.h",
    """POLICYINFO *POLICYINFO_new(void);
""",
    """/**
 * @brief Allocate an empty certificate policy information (POLICYINFO) value.
 * @return New POLICYINFO, or NULL on allocation failure; free with POLICYINFO_free().
 */
POLICYINFO *POLICYINFO_new(void);
""",
    "POLICYINFO_new",
)

patch_both(
    "x509v3.h",
    """void X509V3_conf_free(CONF_VALUE *val);
""",
    """/**
 * @brief Free a CONF_VALUE previously produced for X.509v3 configuration helpers.
 * @param val Configuration value to free, or NULL (no-op).
 */
void X509V3_conf_free(CONF_VALUE *val);
""",
    "X509V3_conf_free",
)

patch_both(
    "x509v3.h",
    """int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
    X509_REQ *req);
""",
    """/**
 * @brief Add all extensions from a configuration section to a certificate request.
 * @param conf Configuration object containing @p section.
 * @param ctx Extension construction context.
 * @param section Name of the configuration section listing extensions.
 * @param req Certificate request that receives the extensions.
 * @return 1 on success, or 0 on error.
 */
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
    X509_REQ *req);
""",
    "X509V3_EXT_REQ_add_nconf",
)

patch_both(
    "x509v3.h",
    """ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const char *value);
""",
    """/**
 * @brief Parse a decimal (or 0x-prefixed hex) string into a newly allocated ASN1_INTEGER.
 * @param meth Extension method (unused; may be NULL).
 * @param value Numeric string to parse.
 * @return Newly allocated ASN1_INTEGER, or NULL on error; free with ASN1_INTEGER_free().
 */
ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const char *value);
""",
    "s2i_ASN1_INTEGER",
)

patch_one(
    "x509v3.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ASIdOrRange, ASIdOrRange, ASIdOrRange)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASIdOrRange) container type.
 */
struct stack_st_ASIdOrRange;
SKM_DEFINE_STACK_OF_INTERNAL(ASIdOrRange, ASIdOrRange, ASIdOrRange)
""",
    "stack_st_ASIdOrRange",
)

patch_one(
    "x509v3.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("ASIdOrRange");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASIdOrRange) container type.
 */
struct stack_st_ASIdOrRange;
{-
    generate_stack_macros("ASIdOrRange");
-}
""",
    "stack_st_ASIdOrRange",
)

patch_both(
    "x509v3.h",
    """int X509v3_addr_get_range(IPAddressOrRange *aor, const unsigned afi,
    unsigned char *min, unsigned char *max,
    const int length);
""",
    """/**
 * @brief Expand an IPAddressOrRange into inclusive @p min/@p max address bytes for @p afi.
 * @param aor Address or range choice to expand.
 * @param afi Address family (IANA_AFI_IPV4 or IANA_AFI_IPV6).
 * @param min Output buffer receiving the low address bytes.
 * @param max Output buffer receiving the high address bytes.
 * @param length Capacity of @p min and @p max in bytes (4 for IPv4, 16 for IPv6).
 * @return Address length written on success, or 0 on failure.
 */
int X509v3_addr_get_range(IPAddressOrRange *aor, const unsigned afi,
    unsigned char *min, unsigned char *max,
    const int length);
""",
    "X509v3_addr_get_range",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
