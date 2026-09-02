#!/usr/bin/env python3
"""Documentation repair batch 20d: types, ui, x509, x509_vfy, x509v3."""
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


print("=== batch 20d: types/ui/x509* ===")

# ----- types.h -----
patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
""",
    """typedef struct asn1_string_st ASN1_UTF8STRING;
/**
 * @brief Generic ASN.1 string container (length, type, and data bytes).
 */
typedef struct asn1_string_st ASN1_STRING;
""",
    "ASN1_STRING",
)

patch_one(
    "types.h",
    """typedef struct asn1_pctx_st ASN1_PCTX;
typedef struct asn1_sctx_st ASN1_SCTX;
""",
    """typedef struct asn1_pctx_st ASN1_PCTX;
/**
 * @brief Opaque ASN.1 scan context used while decoding constructed types.
 */
struct asn1_sctx_st;
/**
 * @brief Opaque ASN.1 scan context used while decoding constructed types.
 */
typedef struct asn1_sctx_st ASN1_SCTX;
""",
    "asn1_sctx_st/ASN1_SCTX",
)

patch_one(
    "types.h",
    """typedef struct bn_blinding_st BN_BLINDING;
""",
    """/**
 * @brief Opaque RSA/modular blinding state (BN_BLINDING_*).
 */
struct bn_blinding_st;
/**
 * @brief Opaque RSA/modular blinding state (BN_BLINDING_*).
 */
typedef struct bn_blinding_st BN_BLINDING;
""",
    "bn_blinding_st/BN_BLINDING",
)

patch_one(
    "types.h",
    """typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_mac_st EVP_MAC;
""",
    """/**
 * @brief Opaque message-digest operation context (EVP_Digest* / EVP_DigestSign*).
 */
struct evp_md_ctx_st;
/**
 * @brief Opaque message-digest operation context (EVP_Digest* / EVP_DigestSign*).
 */
typedef struct evp_md_ctx_st EVP_MD_CTX;
/**
 * @brief Opaque MAC algorithm (EVP_MAC_fetch / EVP_Q_mac).
 */
struct evp_mac_st;
/**
 * @brief Opaque MAC algorithm (EVP_MAC_fetch / EVP_Q_mac).
 */
typedef struct evp_mac_st EVP_MAC;
""",
    "evp_md_ctx_st/evp_mac_st",
)

patch_one(
    "types.h",
    """typedef struct evp_keymgmt_st EVP_KEYMGMT;
""",
    """/**
 * @brief Opaque key-management algorithm implementation (provider keymgmt).
 */
struct evp_keymgmt_st;
/**
 * @brief Opaque key-management algorithm implementation (provider keymgmt).
 */
typedef struct evp_keymgmt_st EVP_KEYMGMT;
""",
    "evp_keymgmt_st/EVP_KEYMGMT",
)

patch_one(
    "types.h",
    """typedef struct evp_kem_st EVP_KEM;
""",
    """/**
 * @brief Opaque key-encapsulation mechanism algorithm (EVP_KEM_*).
 */
struct evp_kem_st;
/**
 * @brief Opaque key-encapsulation mechanism algorithm (EVP_KEM_*).
 */
typedef struct evp_kem_st EVP_KEM;
""",
    "evp_kem_st/EVP_KEM",
)

patch_one(
    "types.h",
    """typedef struct dh_method DH_METHOD;
""",
    """/**
 * @brief Opaque DH method table (deprecated engine-style DH_METHOD_*).
 */
struct dh_method;
/**
 * @brief Opaque DH method table (deprecated engine-style DH_METHOD_*).
 */
typedef struct dh_method DH_METHOD;
""",
    "dh_method/DH_METHOD",
)

patch_one(
    "types.h",
    """typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
""",
    """/**
 * @brief Opaque X.509 certificate revocation list.
 */
struct X509_crl_st;
/**
 * @brief Opaque X.509 certificate revocation list.
 */
typedef struct X509_crl_st X509_CRL;
/**
 * @brief Opaque method table customizing CRL lookup/verification behaviour.
 */
struct x509_crl_method_st;
/**
 * @brief Opaque method table customizing CRL lookup/verification behaviour.
 */
typedef struct x509_crl_method_st X509_CRL_METHOD;
""",
    "X509_CRL/X509_CRL_METHOD",
)

patch_one(
    "types.h",
    """typedef struct x509_store_st X509_STORE;
""",
    """/**
 * @brief Opaque trust store of certificates and CRLs used during verification.
 */
struct x509_store_st;
/**
 * @brief Opaque trust store of certificates and CRLs used during verification.
 */
typedef struct x509_store_st X509_STORE;
""",
    "x509_store_st/X509_STORE",
)

patch_one(
    "types.h",
    """typedef struct x509_sig_info_st X509_SIG_INFO;
""",
    """/**
 * @brief Opaque signature metadata (security bits / TLS usage flags) for an X.509 signature.
 */
struct x509_sig_info_st;
/**
 * @brief Opaque signature metadata (security bits / TLS usage flags) for an X.509 signature.
 */
typedef struct x509_sig_info_st X509_SIG_INFO;
""",
    "x509_sig_info_st/X509_SIG_INFO",
)

patch_one(
    "types.h",
    """typedef struct ossl_http_req_ctx_st OSSL_HTTP_REQ_CTX;
""",
    """/**
 * @brief Opaque HTTP request context used by OSSL_HTTP_* client helpers.
 */
typedef struct ossl_http_req_ctx_st OSSL_HTTP_REQ_CTX;
""",
    "OSSL_HTTP_REQ_CTX",
)

patch_one(
    "types.h",
    """typedef struct ctlog_st CTLOG;
""",
    """/**
 * @brief Opaque Certificate Transparency log identity (public key + description).
 */
struct ctlog_st;
/**
 * @brief Opaque Certificate Transparency log identity (public key + description).
 */
typedef struct ctlog_st CTLOG;
""",
    "ctlog_st/CTLOG",
)

patch_one(
    "types.h",
    """typedef struct ossl_algorithm_st OSSL_ALGORITHM;
""",
    """/**
 * @brief Opaque provider algorithm description (name, property, implementation).
 */
struct ossl_algorithm_st;
/**
 * @brief Opaque provider algorithm description (name, property, implementation).
 */
typedef struct ossl_algorithm_st OSSL_ALGORITHM;
""",
    "ossl_algorithm_st/OSSL_ALGORITHM",
)

patch_one(
    "types.h",
    """typedef struct ossl_encoder_st OSSL_ENCODER;
""",
    """/**
 * @brief Opaque encoder method that serializes keys and related objects.
 */
struct ossl_encoder_st;
/**
 * @brief Opaque encoder method that serializes keys and related objects.
 */
typedef struct ossl_encoder_st OSSL_ENCODER;
""",
    "ossl_encoder_st/OSSL_ENCODER",
)

# ----- ui -----
patch_both(
    "ui.h",
    """/* When all strings have been added, process the whole thing. */
int UI_process(UI *ui);
""",
    """/**
 * @brief Run the UI method to present prompts and collect answers for all added strings.
 * @param ui UI previously populated with UI_add_*() / UI_dup_*() strings.
 * @return 0 on success, a negative value on error, or -2 if the user cancelled.
 */
int UI_process(UI *ui);
""",
    "UI_process",
)

# ----- x509 -----
patch_both(
    "x509.h",
    """int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, const EVP_PKEY *key);
""",
    """/**
 * @brief Write @p key to a FILE as a PKCS#8 PrivateKeyInfo DER encoding.
 * @param fp Output file opened for writing.
 * @param key Private key to encode.
 * @return Number of bytes written, or a non-positive value on error.
 */
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, const EVP_PKEY *key);
""",
    "i2d_PKCS8PrivateKeyInfo_fp",
)

patch_both(
    "x509.h",
    """int X509_cmp_time(const ASN1_TIME *s, time_t *t);
""",
    """/**
 * @brief Compare an ASN.1 Time against time_t @p t (or the current time if @p t is NULL).
 * @param s Time value in UTCTime or GeneralizedTime form (RFC 5280).
 * @param t Instant to compare against, or NULL to use the current time.
 * @return -1 if @p s is earlier than or equal to *@p t, 1 if later, or 0 on error.
 */
int X509_cmp_time(const ASN1_TIME *s, time_t *t);
""",
    "X509_cmp_time",
)

patch_both(
    "x509.h",
    """const char *X509_get_default_cert_file(void);
""",
    """/**
 * @brief Return the default path of the trusted CA certificate file (SSL_CERT_FILE default).
 * @return Static path string; do not free.
 */
const char *X509_get_default_cert_file(void);
""",
    "X509_get_default_cert_file",
)

patch_both(
    "x509.h",
    """int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
""",
    """/**
 * @brief Append revoked-certificate entry @p rev to CRL @p crl, transferring ownership.
 * @param crl CRL that takes ownership of @p rev.
 * @param rev Revoked entry to add (must not be freed by the caller on success).
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
""",
    "X509_CRL_add0_revoked",
)

patch_both(
    "x509.h",
    """X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
""",
    """/**
 * @brief Return the issuer X509_NAME of a certificate revocation list.
 * @param crl CRL to query.
 * @return Internal issuer name pointer (do not free), or NULL if unset.
 */
X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
""",
    "X509_CRL_get_issuer",
)

patch_both(
    "x509.h",
    """int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags);
""",
    """/**
 * @brief Check that a CRL satisfies Suite B signature/algorithm constraints.
 * @param crl CRL to check.
 * @param pk Issuer public key used to verify algorithm consistency.
 * @param flags Suite B checking flags (same family as X509_chain_check_suiteb()).
 * @return X509_V_OK on success, or an X509_V_ERR_* Suite B failure code.
 */
int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags);
""",
    "X509_CRL_check_suiteb",
)

patch_both(
    "x509.h",
    """X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
""",
    """/**
 * @brief Remove and return the extension at index @p loc from a CRL.
 * @param x CRL to modify.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees with X509_EXTENSION_free()), or NULL on error.
 */
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
""",
    "X509_CRL_delete_ext",
)

patch_both(
    "x509.h",
    """X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc);
""",
    """/**
 * @brief Remove and return the attribute at index @p loc from an attribute stack.
 * @param x Attribute stack to modify.
 * @param loc Zero-based attribute index.
 * @return Detached X509_ATTRIBUTE (caller frees), or NULL on error.
 */
X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc);
""",
    "X509at_delete_attr",
)

# ----- x509_vfy -----
patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_check_crl_fn)(X509_STORE_CTX *ctx, X509_CRL *crl);
""",
    """/**
 * @brief Callback type that verifies the signature/validity of a CRL in context @p ctx.
 * @param ctx Verification context performing the check.
 * @param crl CRL whose authenticity is checked.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_check_crl_fn)(X509_STORE_CTX *ctx, X509_CRL *crl);
""",
    "X509_STORE_CTX_check_crl_fn",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_ctrl(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_ctrl_fn ctrl_fn);
""",
    """/**
 * @brief Install the control callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method to update.
 * @param ctrl_fn Callback implementing X509_LOOKUP_ctrl()-style commands.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_ctrl(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_ctrl_fn ctrl_fn);
""",
    "X509_LOOKUP_meth_set_ctrl",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_set_default_paths(X509_STORE *xs);
""",
    """/**
 * @brief Load the default system CA file and directory into certificate store @p xs.
 * @param xs Certificate store to update.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set_default_paths(X509_STORE *xs);
""",
    "X509_STORE_set_default_paths",
)

patch_both(
    "x509_vfy.h",
    """char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return a newly allocated ASCII form of the expected IP address for name checks.
 * @param param Verification parameters to query.
 * @return Heap string such as "192.0.2.1" or an IPv6 textual address (free with OPENSSL_free()), or NULL if unset.
 */
char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get1_ip_asc",
)

patch_both(
    "x509_vfy.h",
    """int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
""",
    """/**
 * @brief Return how many policy nodes are present at a policy-tree level.
 * @param level Policy level from X509_policy_tree_get0_level().
 * @return Number of nodes in @p level.
 */
int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
""",
    "X509_policy_level_node_count",
)

# ----- x509v3 -----
patch_both(
    "x509v3.h",
    """void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x, int nid, int *crit,
    int *idx);
""",
    """/**
 * @brief Decode the first (or next) extension of type @p nid from a stack into its native structure.
 * @param x Extension stack to search.
 * @param nid NID of the extension type to decode.
 * @param crit Optional out-parameter receiving 1 if critical, -1 if not found, or may be NULL.
 * @param idx Optional in/out index to resume search after a previous match, or NULL for the first.
 * @return Newly allocated extension-specific object (caller frees), or NULL if not found / on error.
 */
void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x, int nid, int *crit,
    int *idx);
""",
    "X509V3_get_d2i",
)

print(f"\nOK {len(ok)}, MISS {len(missing)}")
for m in missing:
    print(" ", m)
