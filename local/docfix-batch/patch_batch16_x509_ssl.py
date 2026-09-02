#!/usr/bin/env python3
"""Documentation repair batch 16: ssl.h + x509.h + x509_vfy.h + x509v3.h."""
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


print("=== batch 16: ssl.h + x509.h + x509_vfy.h + x509v3.h ===")

# ----- ssl.h -----

patch_both(
    "ssl.h",
    """/* Gets the SCTs received from a connection */
const STACK_OF(SCT) *SSL_get0_peer_scts(SSL *s);
""",
    """/**
 * @brief Return the signed certificate timestamps (SCTs) received on this connection.
 * @param s SSL connection to query.
 * @return Internal STACK_OF(SCT) of found SCTs (do not free), or NULL on error.
 */
const STACK_OF(SCT) *SSL_get0_peer_scts(SSL *s);
""",
    "SSL_get0_peer_scts",
)

patch_both(
    "ssl.h",
    """int SSL_set_block_padding(SSL *ssl, size_t block_size);
""",
    """/**
 * @brief Pad TLS 1.3 application records for @p ssl to a multiple of @p block_size.
 * @param ssl SSL object to configure (not supported for QUIC).
 * @param block_size Padding block size; 0 or 1 disables block padding; must not exceed SSL3_RT_MAX_PLAIN_LENGTH.
 * @return 1 on success, or 0 if @p block_size is too large or the call is invalid for @p ssl.
 */
int SSL_set_block_padding(SSL *ssl, size_t block_size);
""",
    "SSL_set_block_padding",
)

patch_both(
    "ssl.h",
    """__owur STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
        *meths);
""",
    """/**
 * @brief Replace the global stack of SSL/TLS compression methods, transferring ownership of @p meths.
 * @param meths New STACK_OF(SSL_COMP) to install, or NULL to clear.
 * @return Previous compression-method stack (caller may free), or NULL if none was set.
 */
__owur STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
        *meths);
""",
    "SSL_COMP_set0_compression_methods",
)

patch_both(
    "ssl.h",
    """STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
""",
    """/**
 * @brief Return the global stack of available SSL/TLS integrated compression methods.
 * @return Internal STACK_OF(SSL_COMP) of compression methods, or NULL on error.
 */
STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
""",
    "SSL_COMP_get_compression_methods",
)

patch_both(
    "ssl.h",
    """unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags);
""",
    """/**
 * @brief Clear DANE authentication feature flags on an SSL connection.
 * @param ssl SSL object whose DANE flags are updated.
 * @param flags Bit-mask of DANE feature flags to clear.
 * @return Flags in effect before this call.
 */
unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags);
""",
    "SSL_dane_clear_flags",
)

patch_both(
    "ssl.h",
    """__owur int SSL_dane_enable(SSL *s, const char *basedomain);
""",
    """/**
 * @brief Enable DANE TLSA authentication for a connection (must be called before the handshake).
 * @param s SSL connection associated with a DANE-enabled SSL_CTX.
 * @param basedomain Base domain name used for DANE name checks / TLSA lookup context.
 * @return Positive value on success, 0 on invalid usage, or a negative value on resource failure.
 */
__owur int SSL_dane_enable(SSL *s, const char *basedomain);
""",
    "SSL_dane_enable",
)

patch_both(
    "ssl.h",
    """int SSL_is_dtls(const SSL *s);
""",
    """/**
 * @brief Test whether an SSL object is using the DTLS protocol.
 * @param s SSL connection to query.
 * @return 1 if the connection uses DTLS, or 0 otherwise.
 */
int SSL_is_dtls(const SSL *s);
""",
    "SSL_is_dtls",
)

patch_both(
    "ssl.h",
    """const char *SSL_group_to_name(SSL *s, int id);
""",
    """/**
 * @brief Return the TLS group name registered for a group identifier on this connection.
 * @param s SSL object whose providers/group registry are consulted.
 * @param id TLS group ID as returned by APIs such as SSL_get1_groups().
 * @return NUL-terminated group name string, or NULL if no matching name is registered.
 */
const char *SSL_group_to_name(SSL *s, int id);
""",
    "SSL_group_to_name",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """const STACK_OF(X509_ATTRIBUTE) *
PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
""",
    """/**
 * @brief Return the attribute stack embedded in a PKCS#8 PrivateKeyInfo.
 * @param p8 PKCS#8 structure to query.
 * @return Internal const STACK_OF(X509_ATTRIBUTE) (do not free), or NULL if none.
 */
const STACK_OF(X509_ATTRIBUTE) *
PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
""",
    "PKCS8_pkey_get0_attrs",
)

patch_both(
    "x509.h",
    """int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
    int version, int ptype, void *pval,
    unsigned char *penc, int penclen);
""",
    """/**
 * @brief Set the algorithm, version, parameters, and encoded private key on a PKCS#8 PrivateKeyInfo.
 * @param priv PKCS#8 structure to update.
 * @param aobj Algorithm OID to assign (ownership transferred as implemented).
 * @param version PKCS#8 version field value.
 * @param ptype ASN.1 type of @p pval (V_ASN1_*).
 * @param pval Algorithm parameters value matching @p ptype, or NULL.
 * @param penc Encoded private-key octets; ownership transferred on success.
 * @param penclen Length of @p penc in bytes.
 * @return 1 on success, or 0 on failure.
 */
int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
    int version, int ptype, void *pval,
    unsigned char *penc, int penclen);
""",
    "PKCS8_pkey_set0",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
    int prf_nid, int keylen);
""",
    """/**
 * @brief Build an X509_ALGOR describing PBKDF2 key-derivation parameters.
 * @param iter PBKDF2 iteration count.
 * @param salt Salt bytes, or NULL to generate/omit as implemented.
 * @param saltlen Length of @p salt in bytes.
 * @param prf_nid NID of the PRF digest (e.g. NID_hmacWithSHA256), or 0 for the default.
 * @param keylen Derived key length in bytes, or 0 if omitted from the parameters.
 * @return Newly allocated X509_ALGOR, or NULL on error.
 */
X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
    int prf_nid, int keylen);
""",
    "PKCS5_pbkdf2_set",
)

patch_both(
    "x509.h",
    """X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen,
    unsigned char *aiv, int prf_nid);
""",
    """/**
 * @brief Build a PKCS#5 PBES2 AlgorithmIdentifier for @p cipher with optional IV and PBKDF2 PRF.
 * @param cipher Cipher that defines the encryption scheme.
 * @param iter PBKDF2 iteration count.
 * @param salt Salt bytes, or NULL as implemented.
 * @param saltlen Length of @p salt in bytes.
 * @param aiv Explicit IV bytes, or NULL to generate one.
 * @param prf_nid NID of the PBKDF2 PRF, or 0 for the default.
 * @return Newly allocated X509_ALGOR, or NULL on error.
 */
X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
    unsigned char *salt, int saltlen,
    unsigned char *aiv, int prf_nid);
""",
    "PKCS5_pbe2_set_iv",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
    const char *attrname, int type,
    const unsigned char *bytes, int len);
""",
    """/**
 * @brief Append an X509_ATTRIBUTE named by @p attrname to an EVP_PKEY attribute list.
 * @param key Key whose attribute stack is updated.
 * @param attrname Short or long attribute name (see obj_mac.h SN_* / LN_*).
 * @param type ASN.1 value type for the attribute data (V_ASN1_*).
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes, or -1 if @p bytes is a NUL-terminated string when applicable.
 * @return 1 on success, or 0 on failure (including duplicate attributes).
 */
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
    const char *attrname, int type,
    const unsigned char *bytes, int len);
""",
    "EVP_PKEY_add1_attr_by_txt",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
""",
    """/**
 * @brief Append a copy of @p attr to an EVP_PKEY attribute list, creating the list if needed.
 * @param key Key whose attribute stack is updated.
 * @param attr Attribute to copy onto the key; must be non-NULL and not already present.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
""",
    "EVP_PKEY_add1_attr",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
""",
    """/**
 * @brief Return how many X509_ATTRIBUTE entries are attached to a key.
 * @param key Key to query.
 * @return Attribute count, or 0 if none.
 */
int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
""",
    "EVP_PKEY_get_attr_count",
)

patch_both(
    "x509.h",
    """ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);
""",
    """/**
 * @brief Return the ASN.1 value at index @p idx within a multi-valued X509_ATTRIBUTE.
 * @param attr Attribute to query.
 * @param idx Zero-based value index.
 * @return Internal ASN1_TYPE pointer (do not free), or NULL if @p idx is out of range.
 */
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);
""",
    "X509_ATTRIBUTE_get0_type",
)

patch_both(
    "x509.h",
    """ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
""",
    """/**
 * @brief Return the object identifier that names an X509_ATTRIBUTE.
 * @param attr Attribute to query.
 * @return Internal ASN1_OBJECT pointer (do not free), or NULL on error.
 */
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
""",
    "X509_ATTRIBUTE_get0_object",
)

patch_both(
    "x509.h",
    """int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr);
""",
    """/**
 * @brief Return the number of values held by an X509_ATTRIBUTE.
 * @param attr Attribute to query.
 * @return Value count, or 0 if empty/unavailable.
 */
int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr);
""",
    "X509_ATTRIBUTE_count",
)

patch_both(
    "x509.h",
    """STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    const char *attrname,
    int type,
    const unsigned char *bytes,
    int len);
""",
    """/**
 * @brief Create an attribute by name and append a copy to a STACK_OF(X509_ATTRIBUTE).
 * @param x Address of the attribute stack pointer; allocated if NULL.
 * @param attrname Attribute name (SN/LN) used to resolve the OID.
 * @param type ASN.1 type of the attribute data.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return The (possibly newly allocated) attribute stack, or NULL on error.
 */
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    const char *attrname,
    int type,
    const unsigned char *bytes,
    int len);
""",
    "X509at_add1_attr_by_txt",
)

patch_both(
    "x509.h",
    """STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    const ASN1_OBJECT *obj,
    int type,
    const unsigned char *bytes,
    int len);
""",
    """/**
 * @brief Create an attribute by OID and append a copy to a STACK_OF(X509_ATTRIBUTE).
 * @param x Address of the attribute stack pointer; allocated if NULL.
 * @param obj Attribute object identifier.
 * @param type ASN.1 type of the attribute data.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return The (possibly newly allocated) attribute stack, or NULL on error.
 */
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
                                                      **x,
    const ASN1_OBJECT *obj,
    int type,
    const unsigned char *bytes,
    int len);
""",
    "X509at_add1_attr_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
    const ASN1_OBJECT *obj, int lastpos);
""",
    """/**
 * @brief Find the next attribute in a stack whose OID equals @p obj.
 * @param sk Attribute stack to search, or NULL.
 * @param obj Object identifier to match.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Index of the matching attribute, or -1 if not found.
 */
int X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
    const ASN1_OBJECT *obj, int lastpos);
""",
    "X509at_get_attr_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj);
""",
    """/**
 * @brief Set the extension OID on an X509_EXTENSION, copying @p obj.
 * @param ex Extension to update.
 * @param obj Object identifier to assign.
 * @return 1 on success, or 0 on failure.
 */
int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj);
""",
    "X509_EXTENSION_set_object",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
""",
    """/**
 * @brief Insert a copy of extension @p ex into a revoked-entry extension stack.
 * @param x Revoked entry to update.
 * @param ex Extension to duplicate into @p x.
 * @param loc Insertion index, or -1 to append.
 * @return 1 on success, or 0 on failure.
 */
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
""",
    "X509_REVOKED_add_ext",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_REVOKED_get_ext(const X509_REVOKED *x, int loc);
""",
    """/**
 * @brief Return the extension at index @p loc on a revoked entry.
 * @param x Revoked entry to query.
 * @param loc Zero-based extension index.
 * @return Internal X509_EXTENSION pointer (do not free), or NULL if out of range.
 */
X509_EXTENSION *X509_REVOKED_get_ext(const X509_REVOKED *x, int loc);
""",
    "X509_REVOKED_get_ext",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *x, int crit,
    int lastpos);
""",
    """/**
 * @brief Find the next revoked-entry extension with criticality @p crit.
 * @param x Revoked entry to search.
 * @param crit 1 to match critical extensions, or 0 for non-critical.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Matching extension index, or -1 if not found.
 */
int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *x, int crit,
    int lastpos);
""",
    "X509_REVOKED_get_ext_by_critical",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    """/**
 * @brief Find the next revoked-entry extension whose OID equals @p obj.
 * @param x Revoked entry to search.
 * @param obj Extension object identifier to match.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Matching extension index, or -1 if not found.
 */
int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    "X509_REVOKED_get_ext_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos);
""",
    """/**
 * @brief Find the next revoked-entry extension whose NID equals @p nid.
 * @param x Revoked entry to search.
 * @param nid Extension NID to match.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Matching extension index, or -1 if not found.
 */
int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos);
""",
    "X509_REVOKED_get_ext_by_NID",
)

patch_both(
    "x509.h",
    """void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);
""",
    """/**
 * @brief Decode the first (or next) CRL extension with NID @p nid into its ASN.1 type.
 * @param x CRL to query.
 * @param nid Extension NID to decode.
 * @param crit Optional out-parameter set to 1/0/-1 for critical/non-critical/not found.
 * @param idx Optional in/out index for repeated searches; NULL returns the first match only.
 * @return Newly allocated decoded extension value (caller frees), or NULL if absent/error.
 */
void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);
""",
    "X509_CRL_get_ext_d2i",
)

patch_both(
    "x509.h",
    """int X509_CRL_get_ext_by_OBJ(const X509_CRL *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    """/**
 * @brief Find the next CRL extension whose OID equals @p obj.
 * @param x CRL to search.
 * @param obj Extension object identifier to match.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Matching extension index, or -1 if not found.
 */
int X509_CRL_get_ext_by_OBJ(const X509_CRL *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    "X509_CRL_get_ext_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_CRL_get_ext_count(const X509_CRL *x);
""",
    """/**
 * @brief Return the number of extensions on a CRL.
 * @param x CRL to query.
 * @return Extension count, or 0 if none.
 */
int X509_CRL_get_ext_count(const X509_CRL *x);
""",
    "X509_CRL_get_ext_count",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
""",
    """/**
 * @brief Remove and return the certificate extension at index @p loc.
 * @param x Certificate to update.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is invalid.
 */
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
""",
    "X509_delete_ext",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc);
""",
    """/**
 * @brief Remove and return the extension at index @p loc from an extension stack.
 * @param x Extension stack to update.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is invalid.
 */
X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc);
""",
    "X509v3_delete_ext",
)

patch_both(
    "x509.h",
    """int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
""",
    """/**
 * @brief Add a name entry identified by field name @p field to an X509_NAME.
 * @param name Name to update.
 * @param field Attribute field name (SN/LN) such as "CN".
 * @param type ASN.1 string type for the value (MBSTRING_* / V_ASN1_*).
 * @param bytes Field value bytes.
 * @param len Length of @p bytes, or -1 for NUL-terminated text when applicable.
 * @param loc Insertion index, or -1 to append.
 * @param set -1/0/1 control whether to join the previous RDN set, start a new set, or add after.
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
    const unsigned char *bytes, int len, int loc,
    int set);
""",
    "X509_NAME_add_entry_by_txt",
)

patch_both(
    "x509.h",
    """X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc);
""",
    """/**
 * @brief Return the name entry at index @p loc in an X509_NAME.
 * @param name Name to query.
 * @param loc Zero-based entry index.
 * @return Internal X509_NAME_ENTRY pointer (do not free), or NULL if out of range.
 */
X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc);
""",
    "X509_NAME_get_entry",
)

patch_both(
    "x509.h",
    """int X509_NAME_get_text_by_NID(const X509_NAME *name, int nid,
    char *buf, int len);
""",
    """/**
 * @brief Copy the UTF-8/text value of the first name entry with NID @p nid into @p buf.
 * @param name Name to query.
 * @param nid Attribute NID to locate.
 * @param buf Output buffer, or NULL to query the required length only.
 * @param len Size of @p buf in bytes.
 * @return Length of the text (excluding NUL) copied or required, or -1 on error/not found.
 */
int X509_NAME_get_text_by_NID(const X509_NAME *name, int nid,
    char *buf, int len);
""",
    "X509_NAME_get_text_by_NID",
)

patch_both(
    "x509.h",
    """int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag,
    unsigned long cflag);
""",
    """/**
 * @brief Print a certificate request to a BIO with name and content formatting flags.
 * @param bp Destination BIO.
 * @param x Certificate request to print.
 * @param nmflag Name-printing flags (XN_FLAG_*).
 * @param cflag Content flags controlling which request fields are shown (X509_FLAG_*).
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag,
    unsigned long cflag);
""",
    "X509_REQ_print_ex",
)

patch_both(
    "x509.h",
    """int X509_print(BIO *bp, X509 *x);
""",
    """/**
 * @brief Print an X.509 certificate to a BIO using default formatting.
 * @param bp Destination BIO.
 * @param x Certificate to print.
 * @return 1 on success, or 0 on failure.
 */
int X509_print(BIO *bp, X509 *x);
""",
    "X509_print",
)

patch_both(
    "x509.h",
    """int X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, int indent,
    unsigned long flags);
""",
    """/**
 * @brief Print an X509_NAME to a FILE with indentation and XN_FLAG_* formatting.
 * @param fp Destination stdio file.
 * @param nm Name to print.
 * @param indent Indentation width in spaces.
 * @param flags Name-printing flags (XN_FLAG_*).
 * @return 1 on success, or 0 on failure (or -1 on some legacy error paths).
 */
int X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, int indent,
    unsigned long flags);
""",
    "X509_NAME_print_ex_fp",
)

patch_both(
    "x509.h",
    """int X509_REQ_print_fp(FILE *bp, X509_REQ *req);
""",
    """/**
 * @brief Print a certificate request to a FILE using default formatting.
 * @param bp Destination stdio file.
 * @param req Certificate request to print.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_print_fp(FILE *bp, X509_REQ *req);
""",
    "X509_REQ_print_fp",
)

patch_both(
    "x509.h",
    """int X509_CRL_print_fp(FILE *bp, X509_CRL *x);
""",
    """/**
 * @brief Print a CRL to a FILE using default formatting.
 * @param bp Destination stdio file.
 * @param x CRL to print.
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_print_fp(FILE *bp, X509_CRL *x);
""",
    "X509_CRL_print_fp",
)

patch_both(
    "x509.h",
    """unsigned long X509_NAME_hash_old(const X509_NAME *x);
""",
    """/**
 * @brief Return the legacy MD5-based hash of an X509_NAME (old subject_hash algorithm).
 * @param x Name to hash.
 * @return 32-bit name hash used by historical certificate-directory layouts.
 */
unsigned long X509_NAME_hash_old(const X509_NAME *x);
""",
    "X509_NAME_hash_old",
)

patch_both(
    "x509.h",
    """int X509_add_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs, int flags);
""",
    """/**
 * @brief Append certificates from @p certs onto stack @p sk according to @p flags.
 * @param sk Destination certificate stack (must be non-NULL).
 * @param certs Source stack to add from; may be NULL (no-op success).
 * @param flags Combination of X509_ADD_FLAG_* (up-ref, prepend, no-dup, no-ss).
 * @return 1 on success, or 0 on failure.
 */
int X509_add_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs, int flags);
""",
    "X509_add_certs",
)

patch_both(
    "x509.h",
    """unsigned long X509_issuer_name_hash_old(X509 *a);
""",
    """/**
 * @brief Return the legacy MD5-based hash of a certificate's issuer name.
 * @param a Certificate whose issuer name is hashed.
 * @return 32-bit old-style issuer name hash.
 */
unsigned long X509_issuer_name_hash_old(X509 *a);
""",
    "X509_issuer_name_hash_old",
)

patch_both(
    "x509.h",
    """unsigned long X509_issuer_and_serial_hash(X509 *a);
""",
    """/**
 * @brief Hash a certificate's issuer name and serial number into a 32-bit value.
 * @param a Certificate to hash.
 * @return Hash derived from issuer name and serial number.
 */
unsigned long X509_issuer_and_serial_hash(X509 *a);
""",
    "X509_issuer_and_serial_hash",
)

patch_both(
    "x509.h",
    """void OSSL_STACK_OF_X509_free(STACK_OF(X509) *certs);
""",
    """/**
 * @brief Free a STACK_OF(X509) and the certificates it owns (sk_X509_pop_free).
 * @param certs Certificate stack to free, or NULL.
 */
void OSSL_STACK_OF_X509_free(STACK_OF(X509) *certs);
""",
    "OSSL_STACK_OF_X509_free",
)

patch_both(
    "x509.h",
    """int X509_REQ_check_private_key(const X509_REQ *req, EVP_PKEY *pkey);
""",
    """/**
 * @brief Check that @p pkey matches the public key in a certificate request.
 * @param req Certificate request containing the public key.
 * @param pkey Private (or public) key to compare.
 * @return 1 if the keys match, or 0 if they do not / on error.
 */
int X509_REQ_check_private_key(const X509_REQ *req, EVP_PKEY *pkey);
""",
    "X509_REQ_check_private_key",
)

patch_both(
    "x509.h",
    """X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer,
    EVP_PKEY *skey, const EVP_MD *md, unsigned int flags);
""",
    """/**
 * @brief Construct a delta CRL listing revocations in @p newer that are absent from @p base.
 * @param base Base CRL.
 * @param newer Newer CRL from the same issuer.
 * @param skey Issuer private key used to sign the delta CRL, or NULL to leave unsigned.
 * @param md Digest used when signing, or NULL for the default.
 * @param flags Reserved; typically 0.
 * @return Newly allocated delta X509_CRL, or NULL on error.
 */
X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer,
    EVP_PKEY *skey, const EVP_MD *md, unsigned int flags);
""",
    "X509_CRL_diff",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);
""",
    """/**
 * @brief Set the revocation time on a revoked-entry object, copying @p tm.
 * @param r Revoked entry to update.
 * @param tm Revocation time to assign.
 * @return 1 on success, or 0 on failure.
 */
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);
""",
    "X509_REVOKED_set_revocationDate",
)

patch_both(
    "x509.h",
    """int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
""",
    """/**
 * @brief Set the certificate serial number on a revoked-entry object, copying @p serial.
 * @param x Revoked entry to update.
 * @param serial Serial number to assign.
 * @return 1 on success, or 0 on failure.
 */
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
""",
    "X509_REVOKED_set_serialNumber",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_1_1_0 ASN1_TIME *X509_CRL_get_lastUpdate(X509_CRL *crl);
""",
    """/**
 * @brief Return the CRL thisUpdate time (deprecated alias of X509_CRL_get0_lastUpdate).
 * @param crl CRL to query.
 * @return Internal ASN1_TIME pointer (do not free), or NULL if unset.
 */
OSSL_DEPRECATEDIN_1_1_0 ASN1_TIME *X509_CRL_get_lastUpdate(X509_CRL *crl);
""",
    "X509_CRL_get_lastUpdate",
)

patch_both(
    "x509.h",
    """int X509_CRL_up_ref(X509_CRL *crl);
""",
    """/**
 * @brief Increment the reference count on a CRL.
 * @param crl CRL to retain.
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_up_ref(X509_CRL *crl);
""",
    "X509_CRL_up_ref",
)

patch_both(
    "x509.h",
    """int X509_REQ_add1_attr_by_txt(X509_REQ *req,
    const char *attrname, int type,
    const unsigned char *bytes, int len);
""",
    """/**
 * @brief Add an attribute named by @p attrname to a certificate request.
 * @param req Certificate request to update.
 * @param attrname Attribute name (SN/LN).
 * @param type ASN.1 type of the attribute data.
 * @param bytes Attribute value bytes.
 * @param len Length of @p bytes.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_add1_attr_by_txt(X509_REQ *req,
    const char *attrname, int type,
    const unsigned char *bytes, int len);
""",
    "X509_REQ_add1_attr_by_txt",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
""",
    """/**
 * @brief Remove and return the attribute at index @p loc from a certificate request.
 * @param req Certificate request to update.
 * @param loc Zero-based attribute index.
 * @return Detached X509_ATTRIBUTE (caller frees), or NULL if @p loc is invalid.
 */
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
""",
    "X509_REQ_delete_attr",
)

patch_both(
    "x509.h",
    """int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, const ASN1_OBJECT *obj,
    int lastpos);
""",
    """/**
 * @brief Find the next certificate-request attribute whose OID equals @p obj.
 * @param req Certificate request to search.
 * @param obj Attribute object identifier to match.
 * @param lastpos Index after which to search (-1 to start from the beginning).
 * @return Matching attribute index, or -1 if not found.
 */
int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, const ASN1_OBJECT *obj,
    int lastpos);
""",
    "X509_REQ_get_attr_by_OBJ",
)

patch_both(
    "x509.h",
    """int X509_REQ_add_extensions(X509_REQ *req, const STACK_OF(X509_EXTENSION) *ext);
""",
    """/**
 * @brief Embed a copy of extension stack @p ext as request attributes on @p req.
 * @param req Certificate request to update.
 * @param ext Extensions to add (typically under the extensionRequest attribute).
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_add_extensions(X509_REQ *req, const STACK_OF(X509_EXTENSION) *ext);
""",
    "X509_REQ_add_extensions",
)

patch_both(
    "x509.h",
    """int *X509_REQ_get_extension_nids(void);
""",
    """/**
 * @brief Return the NID list used when locating extensions embedded in a certificate request.
 * @return Pointer to a NID array terminated by NID_undef (do not free); may be set via X509_REQ_set_extension_nids().
 */
int *X509_REQ_get_extension_nids(void);
""",
    "X509_REQ_get_extension_nids",
)

patch_both(
    "x509.h",
    """X509_PUBKEY *X509_REQ_get_X509_PUBKEY(X509_REQ *req);
""",
    """/**
 * @brief Return the X509_PUBKEY structure holding the request's subject public key.
 * @param req Certificate request to query.
 * @return Internal X509_PUBKEY pointer (do not free), or NULL on error.
 */
X509_PUBKEY *X509_REQ_get_X509_PUBKEY(X509_REQ *req);
""",
    "X509_REQ_get_X509_PUBKEY",
)

patch_both(
    "x509.h",
    """void X509_REQ_set0_signature(X509_REQ *req, ASN1_BIT_STRING *psig);
""",
    """/**
 * @brief Set the request signature bit string, transferring ownership of @p psig.
 * @param req Certificate request to update.
 * @param psig Signature value to install; frees any previous signature.
 */
void X509_REQ_set0_signature(X509_REQ *req, ASN1_BIT_STRING *psig);
""",
    "X509_REQ_set0_signature",
)

patch_both(
    "x509.h",
    """ASN1_BIT_STRING *X509_get0_pubkey_bitstr(const X509 *x);
""",
    """/**
 * @brief Return the subject public key BIT STRING from a certificate.
 * @param x Certificate to query.
 * @return Internal ASN1_BIT_STRING pointer (do not free), or NULL on error.
 */
ASN1_BIT_STRING *X509_get0_pubkey_bitstr(const X509 *x);
""",
    "X509_get0_pubkey_bitstr",
)

patch_both(
    "x509.h",
    """int X509_get_signature_type(const X509 *x);
""",
    """/**
 * @brief Return the EVP public-key type implied by a certificate's signature algorithm.
 * @param x Certificate to query.
 * @return EVP_PKEY type constant (EVP_PKEY_*), or NID_undef / 0 on failure.
 */
int X509_get_signature_type(const X509 *x);
""",
    "X509_get_signature_type",
)

patch_both(
    "x509.h",
    """X509_NAME *X509_get_subject_name(const X509 *a);
""",
    """/**
 * @brief Return the subject name of a certificate.
 * @param a Certificate to query.
 * @return Internal X509_NAME pointer (do not free), or NULL on error.
 */
X509_NAME *X509_get_subject_name(const X509 *a);
""",
    "X509_get_subject_name",
)

patch_both(
    "x509.h",
    """int X509_set_issuer_name(X509 *x, const X509_NAME *name);
""",
    """/**
 * @brief Set a certificate's issuer name by copying @p name.
 * @param x Certificate to update.
 * @param name Issuer distinguished name to assign.
 * @return 1 on success, or 0 on failure.
 */
int X509_set_issuer_name(X509 *x, const X509_NAME *name);
""",
    "X509_set_issuer_name",
)

patch_both(
    "x509.h",
    """char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
""",
    """/**
 * @brief Format an X509_NAME as a legacy one-line slash-separated string.
 * @param a Name to format.
 * @param buf Optional caller buffer of @p size bytes; if NULL, a new buffer is allocated.
 * @param size Size of @p buf when non-NULL.
 * @return Pointer to the formatted string (@p buf or allocated memory the caller must OPENSSL_free), or NULL on error.
 */
char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
""",
    "X509_NAME_oneline",
)

patch_both(
    "x509.h",
    """void X509_set0_distinguishing_id(X509 *x, ASN1_OCTET_STRING *d_id);
""",
    """/**
 * @brief Attach a SMIME/CMS distinguishing identifier to a certificate, transferring ownership of @p d_id.
 * @param x Certificate to update.
 * @param d_id Distinguishing id octets, or NULL to clear; frees any previous value.
 */
void X509_set0_distinguishing_id(X509 *x, ASN1_OCTET_STRING *d_id);
""",
    "X509_set0_distinguishing_id",
)

patch_both(
    "x509.h",
    """void *X509_get_ex_data(const X509 *r, int idx);
""",
    """/**
 * @brief Retrieve application ex_data previously stored on a certificate.
 * @param r Certificate to query.
 * @param idx Index obtained from X509_get_ex_new_index() / CRYPTO_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
void *X509_get_ex_data(const X509 *r, int idx);
""",
    "X509_get_ex_data",
)

patch_both(
    "x509.h",
    """int X509_set_ex_data(X509 *r, int idx, void *arg);
""",
    """/**
 * @brief Store application ex_data on a certificate at index @p idx.
 * @param r Certificate to update.
 * @param idx Index obtained from X509_get_ex_new_index() / CRYPTO_get_ex_new_index().
 * @param arg Opaque pointer to store (may be NULL).
 * @return 1 on success, or 0 on failure.
 */
int X509_set_ex_data(X509 *r, int idx, void *arg);
""",
    "X509_set_ex_data",
)

patch_both(
    "x509.h",
    """X509_REQ *X509_REQ_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Allocate an empty X509_REQ associated with a library context and property query.
 * @param libctx OpenSSL library context, or NULL for the default.
 * @param propq Property query string for algorithm fetches, or NULL.
 * @return Newly allocated certificate request, or NULL on allocation failure.
 */
X509_REQ *X509_REQ_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_REQ_new_ex",
)

patch_both(
    "x509.h",
    """X509_PUBKEY *X509_PUBKEY_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Allocate an empty X509_PUBKEY associated with a library context and property query.
 * @param libctx OpenSSL library context, or NULL for the default.
 * @param propq Property query string for algorithm fetches, or NULL.
 * @return Newly allocated X509_PUBKEY, or NULL on allocation failure.
 */
X509_PUBKEY *X509_PUBKEY_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_PUBKEY_new_ex",
)

patch_both(
    "x509.h",
    """const char *X509_get_default_cert_file_env(void);
""",
    """/**
 * @brief Return the environment-variable name that overrides the default certificate file path.
 * @return Static string naming the cert-file environment variable (e.g. SSL_CERT_FILE).
 */
const char *X509_get_default_cert_file_env(void);
""",
    "X509_get_default_cert_file_env",
)

patch_both(
    "x509.h",
    """X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req);
""",
    """/**
 * @brief Decode a DER-encoded certificate request from a BIO.
 * @param bp BIO positioned at the DER input.
 * @param req Optional destination pointer; if non-NULL and *@p req is non-NULL, reuse/replace that object.
 * @return Decoded X509_REQ, or NULL on error.
 */
X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req);
""",
    "d2i_X509_REQ_bio",
)

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id);
""",
    """/**
 * @brief Return a built-in X509_VERIFY_PARAM by table index.
 * @param id Zero-based index into the built-in verify-parameter table (see X509_VERIFY_PARAM_get_count()).
 * @return Internal const X509_VERIFY_PARAM pointer (do not free), or NULL if @p id is out of range.
 */
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id);
""",
    "X509_VERIFY_PARAM_get0",
)

patch_both(
    "x509_vfy.h",
    """void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
""",
    """/**
 * @brief Set the maximum depth of untrusted CA certificates allowed above the leaf.
 * @param param Verification parameters to update.
 * @param depth Maximum number of untrusted intermediate CAs (0 = leaf only / peer cert alone).
 */
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
""",
    "X509_VERIFY_PARAM_set_depth",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Shut down a lookup object, releasing method-specific resources via its shutdown callback.
 * @param ctx Lookup to shut down.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_shutdown",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(
    const X509_LOOKUP_METHOD *method);
""",
    """/**
 * @brief Return the get-by-fingerprint function pointer installed on a lookup method.
 * @param method Lookup method to query.
 * @return Function pointer previously set with X509_LOOKUP_meth_set_get_by_fingerprint(), or NULL.
 */
X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(
    const X509_LOOKUP_METHOD *method);
""",
    "X509_LOOKUP_meth_get_get_by_fingerprint",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
""",
    """/**
 * @brief Return the built-in lookup method that loads certificates and CRLs from PEM/DER files.
 * @return Pointer to the static X509_LOOKUP_METHOD for file lookups.
 */
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
""",
    "X509_LOOKUP_file",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_get_crl(X509_STORE *xs,
    X509_STORE_CTX_get_crl_fn get_crl);
""",
    """/**
 * @brief Install the CRL-retrieval callback inherited by contexts created from this store.
 * @param xs Certificate store to configure.
 * @param get_crl Function that locates a CRL for a given certificate, or NULL for the default.
 */
void X509_STORE_set_get_crl(X509_STORE *xs,
    X509_STORE_CTX_get_crl_fn get_crl);
""",
    "X509_STORE_set_get_crl",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_verify_fn X509_STORE_get_verify(const X509_STORE *xs);
""",
    """/**
 * @brief Return the chain-verify callback installed on a certificate store.
 * @param xs Certificate store to query.
 * @return Function pointer previously set with X509_STORE_set_verify(), or NULL for the default.
 */
X509_STORE_CTX_verify_fn X509_STORE_get_verify(const X509_STORE *xs);
""",
    "X509_STORE_get_verify",
)

# ----- x509v3.h -----

patch_both(
    "x509v3.h",
    """char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section);
""",
    """/**
 * @brief Look up a configuration string via the X509V3_CTX database method.
 * @param ctx Extension context providing @c db / @c db_meth for CONF access.
 * @param name Value name to retrieve.
 * @param section Configuration section name, or NULL for the method default.
 * @return Newly allocated string (free with X509V3_string_free()), or NULL if absent/error.
 */
char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section);
""",
    "X509V3_get_string",
)

patch_both(
    "x509v3.h",
    """typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;
""",
    """/**
 * @brief Stack of POLICY_MAPPING entries used by the policy-mappings certificate extension.
 */
typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;
""",
    "POLICY_MAPPINGS",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
