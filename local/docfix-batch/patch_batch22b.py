#!/usr/bin/env python3
"""Documentation repair batch 22b: cmp.h symbols from ITAV through get1_caCerts."""
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


print("=== batch 22b ===")

patch_both(
    "cmp.h",
    """typedef struct ossl_cmp_msg_st OSSL_CMP_MSG;
DECLARE_ASN1_DUP_FUNCTION(OSSL_CMP_MSG)
DECLARE_ASN1_ENCODE_FUNCTIONS(OSSL_CMP_MSG, OSSL_CMP_MSG, OSSL_CMP_MSG)
""",
    """/**
 * @brief Opaque PKIMessage structure (PKIHeader and body) from RFC 4210.
 */
typedef struct ossl_cmp_msg_st OSSL_CMP_MSG;
/**
 * @brief Allocate an empty OSSL_CMP_MSG structure.
 * @return New OSSL_CMP_MSG, or NULL on allocation failure.
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_new(void);
/**
 * @brief Free an OSSL_CMP_MSG structure and its contents.
 * @param a Value to free, or NULL.
 */
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *a);
/**
 * @brief Decode an OSSL_CMP_MSG from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded OSSL_CMP_MSG, or NULL on error.
 */
OSSL_CMP_MSG *d2i_OSSL_CMP_MSG(OSSL_CMP_MSG **a, const unsigned char **in, long len);
/**
 * @brief Encode an OSSL_CMP_MSG to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_OSSL_CMP_MSG(const OSSL_CMP_MSG *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for OSSL_CMP_MSG.
 * @return Pointer to the static ASN1_ITEM for OSSL_CMP_MSG.
 */
const ASN1_ITEM *OSSL_CMP_MSG_it(void);
/**
 * @brief Duplicate an OSSL_CMP_MSG structure.
 * @param a Value to duplicate.
 * @return Copy of @p a, or NULL on error.
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_dup(const OSSL_CMP_MSG *a);
""",
    "OSSL_CMP_MSG",
)

patch_both(
    "cmp.h",
    """typedef struct ossl_cmp_certstatus_st OSSL_CMP_CERTSTATUS;
""",
    """/**
 * @brief CertStatus from RFC 4210 section 5.3.18: certHash and certReqId for certConf.
 */
typedef struct ossl_cmp_certstatus_st OSSL_CMP_CERTSTATUS;
""",
    "OSSL_CMP_CERTSTATUS",
)

patch_both(
    "cmp.h",
    """typedef struct ossl_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;
""",
    """/**
 * @brief RevRepContent from RFC 4210 section 5.3.4: status for each certReqId in an RR.
 */
typedef struct ossl_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;
""",
    "OSSL_CMP_REVREPCONTENT",
)

patch_both(
    "cmp.h",
    """typedef struct ossl_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;
""",
    """/**
 * @brief CertRepMessage from RFC 4210 section 5.3.3: CA Pubs and certResponse sequence.
 */
typedef struct ossl_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;
""",
    "OSSL_CMP_CERTREPMESSAGE",
)

patch_both(
    "cmp.h",
    """typedef struct ossl_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;
""",
    """/**
 * @brief CertResponse from RFC 4210 section 5.3.3: certReqId, status, and optional cert/key.
 */
typedef struct ossl_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;
""",
    "OSSL_CMP_CERTRESPONSE",
)

patch_both(
    "cmp.h",
    """typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;
""",
    """/**
 * @brief Sequence of UTF8String status or error detail text in PKIStatusInfo (RFC 4210).
 */
typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;
""",
    "OSSL_CMP_PKIFREETEXT",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_ITAV *OSSL_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value);
""",
    """/**
 * @brief Allocate an ITAV with the given infoType and infoValue, taking ownership of both.
 * @param type infoType OID; ownership transfers to the ITAV.
 * @param value infoValue as a generic ASN1_TYPE; ownership transfers to the ITAV.
 * @return New ITAV on success, or NULL on error.
 */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value);
""",
    "OSSL_CMP_ITAV_create",
)

patch_both(
    "cmp.h",
    """ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav);
""",
    """/**
 * @brief Return the infoType OID from an ITAV.
 * @param itav ITAV to query.
 * @return Internal infoType pointer, or NULL if unavailable.
 */
ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav);
""",
    "OSSL_CMP_ITAV_get0_type",
)

patch_both(
    "cmp.h",
    """ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav);
""",
    """/**
 * @brief Return the infoValue from an ITAV.
 * @param itav ITAV to query.
 * @return Internal infoValue pointer, or NULL if unavailable.
 */
ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav);
""",
    "OSSL_CMP_ITAV_get0_value",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_ITAV *OSSL_CMP_ITAV_new0_certProfile(STACK_OF(ASN1_UTF8STRING)
        *certProfile);
""",
    """/**
 * @brief Create a certProfile ITAV from a stack of profile name strings.
 * @param certProfile Profile names to include; ownership transfers to the ITAV.
 * @return New ITAV on success, or NULL on error.
 */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_new0_certProfile(STACK_OF(ASN1_UTF8STRING)
        *certProfile);
""",
    "OSSL_CMP_ITAV_new0_certProfile",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_caCerts(const STACK_OF(X509) *caCerts);
""",
    """/**
 * @brief Create a caCerts ITAV containing a copy of the given CA certificate stack.
 * @param caCerts CA certificates to embed in the ITAV.
 * @return New ITAV on success, or NULL on error.
 */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_caCerts(const STACK_OF(X509) *caCerts);
""",
    "OSSL_CMP_ITAV_new_caCerts",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_ITAV_get0_caCerts(const OSSL_CMP_ITAV *itav, STACK_OF(X509) **out);
""",
    """/**
 * @brief Extract the CA certificate stack from a caCerts ITAV.
 * @param itav ITAV with infoType caCerts.
 * @param out Address of a pointer set to the internal certificate stack, or NULL if none.
 * @return 1 on success, 0 if @p itav is not a caCerts ITAV or on error.
 */
int OSSL_CMP_ITAV_get0_caCerts(const OSSL_CMP_ITAV *itav, STACK_OF(X509) **out);
""",
    "OSSL_CMP_ITAV_get0_caCerts",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_ITAV_get0_rootCaCert(const OSSL_CMP_ITAV *itav, X509 **out);
""",
    """/**
 * @brief Extract the root CA certificate from a rootCaCert ITAV.
 * @param itav ITAV with infoType rootCaCert.
 * @param out Receives the internal certificate pointer, or NULL if absent.
 * @return 1 on success, 0 if @p itav is not a rootCaCert ITAV or on error.
 */
int OSSL_CMP_ITAV_get0_rootCaCert(const OSSL_CMP_ITAV *itav, X509 **out);
""",
    "OSSL_CMP_ITAV_get0_rootCaCert",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_rootCaKeyUpdate(const X509 *newWithNew,
    const X509 *newWithOld,
    const X509 *oldWithNew);
""",
    """/**
 * @brief Create a rootCaKeyUpdate ITAV with optional transition certificates.
 * @param newWithNew New root CA certificate signed with the new key, or NULL.
 * @param newWithOld New root CA certificate signed with the old key, or NULL.
 * @param oldWithNew Old root CA certificate signed with the new key, or NULL.
 * @return New ITAV on success, or NULL on error.
 */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_rootCaKeyUpdate(const X509 *newWithNew,
    const X509 *newWithOld,
    const X509 *oldWithNew);
""",
    "OSSL_CMP_ITAV_new_rootCaKeyUpdate",
)

patch_both(
    "cmp.h",
    """void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Free an OSSL_CMP_MSG structure and its contents.
 * @param msg Message to free, or NULL.
 */
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_MSG_free_standalone",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Reset a CMP context to its initial state while retaining configuration.
 * @param ctx CMP context to reinitialize.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_reinit",
)

patch_both(
    "cmp.h",
    """OSSL_LIB_CTX *OSSL_CMP_CTX_get0_libctx(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the library context associated with a CMP context.
 * @param ctx CMP context.
 * @return Library context pointer, or NULL if unset.
 */
OSSL_LIB_CTX *OSSL_CMP_CTX_get0_libctx(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_libctx",
)

patch_both(
    "cmp.h",
    """const char *OSSL_CMP_CTX_get0_propq(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the property query string used for algorithm fetching.
 * @param ctx CMP context.
 * @return Property query string, or NULL if unset.
 */
const char *OSSL_CMP_CTX_get0_propq(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_propq",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val);
""",
    """/**
 * @brief Set a CMP context option (OSSL_CMP_OPT_*).
 * @param ctx CMP context.
 * @param opt Option identifier.
 * @param val Option value.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val);
""",
    "OSSL_CMP_CTX_set_option",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt);
""",
    """/**
 * @brief Read a CMP context option (OSSL_CMP_OPT_*).
 * @param ctx CMP context.
 * @param opt Option identifier.
 * @return Current option value, or -1 on error.
 */
int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt);
""",
    "OSSL_CMP_CTX_get_option",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_log_cb_t cb);
""",
    """/**
 * @brief Register a CMP logging callback for this context.
 * @param ctx CMP context.
 * @param cb Callback invoked for CMP log messages, or NULL for the default logger.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_log_cb_t cb);
""",
    "OSSL_CMP_CTX_set_log_cb",
)

patch_both(
    "cmp.h",
    """void OSSL_CMP_CTX_print_errors(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Print the OpenSSL error queue using the context logging callback.
 * @param ctx CMP context whose log callback receives error-queue entries.
 */
void OSSL_CMP_CTX_print_errors(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_print_errors",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path);
""",
    """/**
 * @brief Set the HTTP path component for CMP server requests.
 * @param ctx CMP context.
 * @param path URL path (for example "/cmp"), or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path);
""",
    "OSSL_CMP_CTX_set1_serverPath",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port);
""",
    """/**
 * @brief Set the TCP port used for CMP HTTP(S) transfer.
 * @param ctx CMP context.
 * @param port Server port number.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port);
""",
    "OSSL_CMP_CTX_set_serverPort",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_proxy(OSSL_CMP_CTX *ctx, const char *name);
""",
    """/**
 * @brief Set an HTTP proxy hostname for CMP transfer.
 * @param ctx CMP context.
 * @param name Proxy hostname or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_proxy(OSSL_CMP_CTX *ctx, const char *name);
""",
    "OSSL_CMP_CTX_set1_proxy",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_no_proxy(OSSL_CMP_CTX *ctx, const char *names);
""",
    """/**
 * @brief Set a comma-separated list of hosts that bypass the HTTP proxy.
 * @param ctx CMP context.
 * @param names Host list in no-proxy format, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_no_proxy(OSSL_CMP_CTX *ctx, const char *names);
""",
    "OSSL_CMP_CTX_set1_no_proxy",
)

patch_both(
    "cmp.h",
    """typedef OSSL_CMP_MSG *(*OSSL_CMP_transfer_cb_t)(OSSL_CMP_CTX *ctx,
    const OSSL_CMP_MSG *req);
""",
    """/**
 * @brief Callback type for sending a CMP request and returning the response message.
 * @param ctx CMP context with transfer settings.
 * @param req Outgoing CMP request message.
 * @return Server response message on success, or NULL on error.
 */
typedef OSSL_CMP_MSG *(*OSSL_CMP_transfer_cb_t)(OSSL_CMP_CTX *ctx,
    const OSSL_CMP_MSG *req);
""",
    "OSSL_CMP_transfer_cb_t",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_transfer_cb_t cb);
""",
    """/**
 * @brief Replace the message transfer callback used by the CMP client.
 * @param ctx CMP context.
 * @param cb Transfer callback, or NULL to restore the default HTTP transfer.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_transfer_cb_t cb);
""",
    "OSSL_CMP_CTX_set_transfer_cb",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    """/**
 * @brief Set the opaque argument passed to the message transfer callback.
 * @param ctx CMP context.
 * @param arg Callback argument pointer.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    "OSSL_CMP_CTX_set_transfer_cb_arg",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    """/**
 * @brief Pin the expected sender DN for incoming CMP response verification.
 * @param ctx CMP context.
 * @param name Expected sender X509_NAME, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    "OSSL_CMP_CTX_set1_expected_sender",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_untrusted(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs);
""",
    """/**
 * @brief Set untrusted certificates used when validating CMP server messages.
 * @param ctx CMP context.
 * @param certs Intermediate certificate stack, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_untrusted(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs);
""",
    "OSSL_CMP_CTX_set1_untrusted",
)

patch_both(
    "cmp.h",
    """STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the untrusted certificate stack configured on the context.
 * @param ctx CMP context.
 * @return Internal untrusted stack, or NULL if unset.
 */
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_untrusted",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_cert(OSSL_CMP_CTX *ctx, X509 *cert);
""",
    """/**
 * @brief Set the client CMP signer certificate on the context.
 * @param ctx CMP context.
 * @param cert Client certificate used to protect outgoing messages, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_cert(OSSL_CMP_CTX *ctx, X509 *cert);
""",
    "OSSL_CMP_CTX_set1_cert",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey);
""",
    """/**
 * @brief Set the private key used to protect outgoing CMP messages.
 * @param ctx CMP context.
 * @param pkey Private key matching the client certificate, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey);
""",
    "OSSL_CMP_CTX_set1_pkey",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
    const unsigned char *ref, int len);
""",
    """/**
 * @brief Set the reference value used for password-based CMP message protection.
 * @param ctx CMP context.
 * @param ref Reference octets copied into the context.
 * @param len Length of @p ref in bytes.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
    const unsigned char *ref, int len);
""",
    "OSSL_CMP_CTX_set1_referenceValue",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx,
    const unsigned char *sec, int len);
""",
    """/**
 * @brief Set the shared secret used for MAC-based CMP message protection.
 * @param ctx CMP context.
 * @param sec Secret octets copied into the context.
 * @param len Length of @p sec in bytes.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx,
    const unsigned char *sec, int len);
""",
    "OSSL_CMP_CTX_set1_secretValue",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    """/**
 * @brief Set the intended recipient DN placed in outgoing CMP PKIHeader fields.
 * @param ctx CMP context.
 * @param name Recipient X509_NAME, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    "OSSL_CMP_CTX_set1_recipient",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_push0_geninfo_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
""",
    """/**
 * @brief Append an ITAV to the geninfo field of outgoing CMP messages.
 * @param ctx CMP context.
 * @param itav ITAV to push; ownership transfers to the context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_push0_geninfo_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
""",
    "OSSL_CMP_CTX_push0_geninfo_ITAV",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_reset_geninfo_ITAVs(OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Clear all geninfo ITAVs stored on the CMP context.
 * @param ctx CMP context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_reset_geninfo_ITAVs(OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_reset_geninfo_ITAVs",
)

patch_both(
    "cmp.h",
    """STACK_OF(OSSL_CMP_ITAV)
*OSSL_CMP_CTX_get0_geninfo_ITAVs(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the geninfo ITAV stack configured on the context.
 * @param ctx CMP context.
 * @return Internal ITAV stack, or NULL if empty or unset.
 */
STACK_OF(OSSL_CMP_ITAV)
*OSSL_CMP_CTX_get0_geninfo_ITAVs(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_geninfo_ITAVs",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, int priv, EVP_PKEY *pkey);
""",
    """/**
 * @brief Set the new key pair used in certificate-request templates.
 * @param ctx CMP context.
 * @param priv Non-zero to store the private key, zero for the public key only.
 * @param pkey Key to install; ownership transfers to the context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, int priv, EVP_PKEY *pkey);
""",
    "OSSL_CMP_CTX_set0_newPkey",
)

patch_both(
    "cmp.h",
    """EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx, int priv);
""",
    """/**
 * @brief Return the new public or private key stored on the context.
 * @param ctx CMP context.
 * @param priv Non-zero to return the private key, zero for the public key.
 * @return Internal key pointer, or NULL if unset.
 */
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx, int priv);
""",
    "OSSL_CMP_CTX_get0_newPkey",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_serialNumber(OSSL_CMP_CTX *ctx, const ASN1_INTEGER *sn);
""",
    """/**
 * @brief Set the serial number field in the certificate template.
 * @param ctx CMP context.
 * @param sn Serial number to copy, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_serialNumber(OSSL_CMP_CTX *ctx, const ASN1_INTEGER *sn);
""",
    "OSSL_CMP_CTX_set1_serialNumber",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    """/**
 * @brief Set the subject DN in the certificate template.
 * @param ctx CMP context.
 * @param name Subject X509_NAME to copy, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name);
""",
    "OSSL_CMP_CTX_set1_subjectName",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_push1_subjectAltName(OSSL_CMP_CTX *ctx,
    const GENERAL_NAME *name);
""",
    """/**
 * @brief Append a Subject Alternative Name to the certificate template.
 * @param ctx CMP context.
 * @param name GeneralName copied into the template SAN extension.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_push1_subjectAltName(OSSL_CMP_CTX *ctx,
    const GENERAL_NAME *name);
""",
    "OSSL_CMP_CTX_push1_subjectAltName",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
""",
    """/**
 * @brief Replace request extensions in the certificate template.
 * @param ctx CMP context.
 * @param exts Extensions stack; ownership transfers to the context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
""",
    "OSSL_CMP_CTX_set0_reqExtensions",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_push0_policy(OSSL_CMP_CTX *ctx, POLICYINFO *pinfo);
""",
    """/**
 * @brief Append a certificate policy to the template policy extension.
 * @param ctx CMP context.
 * @param pinfo PolicyInformation to append; ownership transfers to the context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_push0_policy(OSSL_CMP_CTX *ctx, POLICYINFO *pinfo);
""",
    "OSSL_CMP_CTX_push0_policy",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_oldCert(OSSL_CMP_CTX *ctx, X509 *cert);
""",
    """/**
 * @brief Set the old certificate referenced by a key-update request.
 * @param ctx CMP context.
 * @param cert Old certificate to copy into the context, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_oldCert(OSSL_CMP_CTX *ctx, X509 *cert);
""",
    "OSSL_CMP_CTX_set1_oldCert",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr);
""",
    """/**
 * @brief Set a PKCS#10 CSR used for P10CR certificate requests.
 * @param ctx CMP context.
 * @param csr PKCS#10 request to copy, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr);
""",
    "OSSL_CMP_CTX_set1_p10CSR",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_push0_genm_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
""",
    """/**
 * @brief Append an ITAV to the body of an outgoing General Message (genm).
 * @param ctx CMP context.
 * @param itav ITAV to push; ownership transfers to the context.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_push0_genm_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
""",
    "OSSL_CMP_CTX_push0_genm_ITAV",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_certConf_cb_t cb);
""",
    """/**
 * @brief Register the certificate-confirmation callback for the CMP client.
 * @param ctx CMP context.
 * @param cb Callback invoked before sending certConf, or NULL for the default.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_certConf_cb_t cb);
""",
    "OSSL_CMP_CTX_set_certConf_cb",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    """/**
 * @brief Set the opaque argument passed to the certConf callback.
 * @param ctx CMP context.
 * @param arg Callback argument pointer.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    "OSSL_CMP_CTX_set_certConf_cb_arg",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_get_status(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the PKIStatus from the last CMP transaction stored on the context.
 * @param ctx CMP context.
 * @return PKIStatus value, or -1 if unavailable.
 */
int OSSL_CMP_CTX_get_status(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get_status",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_get0_statusString(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the statusString text from the last CMP transaction.
 * @param ctx CMP context.
 * @return Internal statusString stack, or NULL if absent.
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_get0_statusString(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_statusString",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_get_failInfoCode(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the failInfo bit field from the last CMP transaction.
 * @param ctx CMP context.
 * @return failInfo integer, or -1 if unavailable.
 */
int OSSL_CMP_CTX_get_failInfoCode(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get_failInfoCode",
)

patch_both(
    "cmp.h",
    """X509 *OSSL_CMP_CTX_get0_validatedSrvCert(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the validated CMP server certificate from the last transaction.
 * @param ctx CMP context.
 * @return Server certificate pointer owned by @p ctx, or NULL if unavailable.
 */
X509 *OSSL_CMP_CTX_get0_validatedSrvCert(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get0_validatedSrvCert",
)

patch_both(
    "cmp.h",
    """STACK_OF(X509) *OSSL_CMP_CTX_get1_newChain(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return a copy of the newly obtained certificate chain from the last transaction.
 * @param ctx CMP context.
 * @return Newly allocated certificate stack, or NULL if unavailable; caller must free.
 */
STACK_OF(X509) *OSSL_CMP_CTX_get1_newChain(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get1_newChain",
)

patch_both(
    "cmp.h",
    """STACK_OF(X509) *OSSL_CMP_CTX_get1_caPubs(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return a copy of CA certificates (caPubs) from the last certRep.
 * @param ctx CMP context.
 * @return Newly allocated certificate stack, or NULL if unavailable; caller must free.
 */
STACK_OF(X509) *OSSL_CMP_CTX_get1_caPubs(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get1_caPubs",
)

patch_both(
    "cmp.h",
    """STACK_OF(X509) *OSSL_CMP_CTX_get1_extraCertsIn(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return a copy of extraCerts received in the last CMP message.
 * @param ctx CMP context.
 * @return Newly allocated certificate stack, or NULL if unavailable; caller must free.
 */
STACK_OF(X509) *OSSL_CMP_CTX_get1_extraCertsIn(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get1_extraCertsIn",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
    const ASN1_OCTET_STRING *id);
""",
    """/**
 * @brief Set the transactionID placed in outgoing CMP PKIHeader fields.
 * @param ctx CMP context.
 * @param id Transaction ID octet string to copy, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
    const ASN1_OCTET_STRING *id);
""",
    "OSSL_CMP_CTX_set1_transactionID",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set1_senderNonce(OSSL_CMP_CTX *ctx,
    const ASN1_OCTET_STRING *nonce);
""",
    """/**
 * @brief Set the senderNonce placed in outgoing CMP PKIHeader fields.
 * @param ctx CMP context.
 * @param nonce Sender nonce octet string to copy, or NULL to clear.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set1_senderNonce(OSSL_CMP_CTX *ctx,
    const ASN1_OCTET_STRING *nonce);
""",
    "OSSL_CMP_CTX_set1_senderNonce",
)

patch_both(
    "cmp.h",
    """char *OSSL_CMP_snprint_PKIStatusInfo(const OSSL_CMP_PKISI *statusInfo,
    char *buf, size_t bufsize);
""",
    """/**
 * @brief Format a PKIStatusInfo structure into a human-readable string.
 * @param statusInfo PKIStatusInfo to format.
 * @param buf Destination buffer.
 * @param bufsize Size of @p buf.
 * @return @p buf on success, or NULL on error.
 */
char *OSSL_CMP_snprint_PKIStatusInfo(const OSSL_CMP_PKISI *statusInfo,
    char *buf, size_t bufsize);
""",
    "OSSL_CMP_snprint_PKIStatusInfo",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_PKISI *
OSSL_CMP_STATUSINFO_new(int status, int fail_info, const char *text);
""",
    """/**
 * @brief Allocate a PKIStatusInfo with status, optional failInfo, and statusString text.
 * @param status PKIStatus value (OSSL_CMP_PKISTATUS_*).
 * @param fail_info PKIFailureInfo bit field, or 0 if none.
 * @param text Optional status detail string copied into statusString, or NULL.
 * @return New PKIStatusInfo, or NULL on error.
 */
OSSL_CMP_PKISI *
OSSL_CMP_STATUSINFO_new(int status, int fail_info, const char *text);
""",
    "OSSL_CMP_STATUSINFO_new",
)

patch_both(
    "cmp.h",
    """ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr);
""",
    """/**
 * @brief Return the transactionID from a CMP PKIHeader.
 * @param hdr PKIHeader to query.
 * @return Internal transactionID octet string, or NULL if absent.
 */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr);
""",
    "OSSL_CMP_HDR_get0_transactionID",
)

patch_both(
    "cmp.h",
    """ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr);
""",
    """/**
 * @brief Return the recipNonce from a CMP PKIHeader.
 * @param hdr PKIHeader to query.
 * @return Internal recipNonce octet string, or NULL if absent.
 */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr);
""",
    "OSSL_CMP_HDR_get0_recipNonce",
)

patch_both(
    "cmp.h",
    """STACK_OF(OSSL_CMP_ITAV)
*OSSL_CMP_HDR_get0_geninfo_ITAVs(const OSSL_CMP_PKIHEADER *hdr);
""",
    """/**
 * @brief Return the geninfo ITAV stack from a CMP PKIHeader.
 * @param hdr PKIHeader to query.
 * @return Internal ITAV stack, or NULL if absent.
 */
STACK_OF(OSSL_CMP_ITAV)
*OSSL_CMP_HDR_get0_geninfo_ITAVs(const OSSL_CMP_PKIHEADER *hdr);
""",
    "OSSL_CMP_HDR_get0_geninfo_ITAVs",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Return the PKIHeader from a CMP message.
 * @param msg CMP message to query.
 * @return Internal PKIHeader pointer, or NULL on error.
 */
OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_MSG_get0_header",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_MSG_get_bodytype(const OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Return the PKIBody choice id of a CMP message.
 * @param msg CMP message to query.
 * @return Body type (OSSL_CMP_* constant), or -1 on error.
 */
int OSSL_CMP_MSG_get_bodytype(const OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_MSG_get_bodytype",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_MSG_update_transactionID(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Copy the context transactionID into a CMP message header.
 * @param ctx CMP context supplying the transactionID.
 * @param msg Outgoing CMP message whose header is updated.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_MSG_update_transactionID(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_MSG_update_transactionID",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_MSG_update_recipNonce(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Copy the context senderNonce into a CMP message recipNonce field.
 * @param ctx CMP context supplying the nonce.
 * @param msg Outgoing CMP message whose header is updated.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_MSG_update_recipNonce(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_MSG_update_recipNonce",
)

patch_both(
    "cmp.h",
    """OSSL_CRMF_MSG *OSSL_CMP_CTX_setup_CRM(OSSL_CMP_CTX *ctx, int for_KUR, int rid);
""",
    """/**
 * @brief Build a CRMF CertReqMsg from fields stored on the CMP context.
 * @param ctx CMP context with template and POPO settings.
 * @param for_KUR Non-zero when building a Key Update Request message.
 * @param rid Certificate request ID to assign.
 * @return New CRMF message on success, or NULL on error; caller must free.
 */
OSSL_CRMF_MSG *OSSL_CMP_CTX_setup_CRM(OSSL_CMP_CTX *ctx, int for_KUR, int rid);
""",
    "OSSL_CMP_CTX_setup_CRM",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_MSG *d2i_OSSL_CMP_MSG_bio(BIO *bio, OSSL_CMP_MSG **msg);
""",
    """/**
 * @brief Decode a DER-encoded CMP message from a BIO.
 * @param bio BIO supplying DER bytes.
 * @param msg Optional destination pointer updated to the result.
 * @return Decoded CMP message, or NULL on error.
 */
OSSL_CMP_MSG *d2i_OSSL_CMP_MSG_bio(BIO *bio, OSSL_CMP_MSG **msg);
""",
    "d2i_OSSL_CMP_MSG_bio",
)

patch_both(
    "cmp.h",
    """int i2d_OSSL_CMP_MSG_bio(BIO *bio, const OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Encode a CMP message to DER and write it to a BIO.
 * @param bio Destination BIO.
 * @param msg CMP message to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_OSSL_CMP_MSG_bio(BIO *bio, const OSSL_CMP_MSG *msg);
""",
    "i2d_OSSL_CMP_MSG_bio",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg);
""",
    """/**
 * @brief Verify protection and header fields of an incoming CMP message.
 * @param ctx CMP context with trust and protection settings.
 * @param msg CMP message to validate.
 * @return 1 if valid, 0 if invalid, or -1 on error.
 */
int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg);
""",
    "OSSL_CMP_validate_msg",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
    X509_STORE *trusted_store, X509 *cert);
""",
    """/**
 * @brief Validate that @p cert chains to a trust anchor in @p trusted_store.
 * @param ctx CMP context (used for untrusted intermediates and callbacks).
 * @param trusted_store Trust store containing acceptable anchors.
 * @param cert Certificate to validate.
 * @return 1 if the path validates, 0 if not, or -1 on error.
 */
int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
    X509_STORE *trusted_store, X509 *cert);
""",
    "OSSL_CMP_validate_cert_path",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_MSG *OSSL_CMP_CTX_server_perform(OSSL_CMP_CTX *client_ctx,
    const OSSL_CMP_MSG *req);
""",
    """/**
 * @brief Process a CMP request locally using the server callbacks on the context.
 * @param client_ctx CMP context configured with server-side callbacks.
 * @param req Incoming CMP request message.
 * @return Response CMP message on success, or NULL on error.
 */
OSSL_CMP_MSG *OSSL_CMP_CTX_server_perform(OSSL_CMP_CTX *client_ctx,
    const OSSL_CMP_MSG *req);
""",
    "OSSL_CMP_CTX_server_perform",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_new(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Allocate a CMP server context with default options.
 * @param libctx Library context, or NULL for the default.
 * @param propq Property query string for algorithm fetching, or NULL.
 * @return New server context, or NULL on allocation failure.
 */
OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_new(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "OSSL_CMP_SRV_CTX_new",
)

patch_both(
    "cmp.h",
    """void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx);
""",
    """/**
 * @brief Free a CMP server context and its resources.
 * @param srv_ctx Server context to free, or NULL.
 */
void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx);
""",
    "OSSL_CMP_SRV_CTX_free",
)

patch_both(
    "cmp.h",
    """typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_cert_request_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
    const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr,
    X509 **certOut, STACK_OF(X509) **chainOut, STACK_OF(X509) **caPubs);
""",
    """/**
 * @brief Server callback type for processing IR/CR/KUR/P10CR certificate requests.
 * @param srv_ctx CMP server context.
 * @param req Incoming request message.
 * @param certReqId Certificate request ID from the message body.
 * @param crm CRMF CertReqMsg, if present.
 * @param p10cr PKCS#10 request, if present.
 * @param certOut Receives the issued certificate allocated by the callback.
 * @param chainOut Receives an optional chain allocated by the callback.
 * @param caPubs Receives optional caPubs allocated by the callback.
 * @return PKIStatusInfo for the certResponse, allocated by the callback.
 */
typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_cert_request_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
    const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr,
    X509 **certOut, STACK_OF(X509) **chainOut, STACK_OF(X509) **caPubs);
""",
    "OSSL_CMP_SRV_cert_request_cb_t",
)

patch_both(
    "cmp.h",
    """typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_rr_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    const X509_NAME *issuer,
    const ASN1_INTEGER *serial);
""",
    """/**
 * @brief Server callback type for processing Revocation Request (RR) messages.
 * @param srv_ctx CMP server context.
 * @param req Incoming RR message.
 * @param issuer Issuer name of the certificate to revoke.
 * @param serial Serial number of the certificate to revoke.
 * @return PKIStatusInfo for the revocation response, allocated by the callback.
 */
typedef OSSL_CMP_PKISI *(*OSSL_CMP_SRV_rr_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    const X509_NAME *issuer,
    const ASN1_INTEGER *serial);
""",
    "OSSL_CMP_SRV_rr_cb_t",
)

patch_both(
    "cmp.h",
    """typedef void (*OSSL_CMP_SRV_error_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    const OSSL_CMP_PKISI *statusInfo,
    const ASN1_INTEGER *errorCode,
    const OSSL_CMP_PKIFREETEXT *errDetails);
""",
    """/**
 * @brief Server callback invoked when constructing an error message response.
 * @param srv_ctx CMP server context.
 * @param req Request that triggered the error, if available.
 * @param statusInfo PKIStatusInfo being sent.
 * @param errorCode Optional error code integer from the error message body.
 * @param errDetails Optional free-text error details.
 */
typedef void (*OSSL_CMP_SRV_error_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    const OSSL_CMP_PKISI *statusInfo,
    const ASN1_INTEGER *errorCode,
    const OSSL_CMP_PKIFREETEXT *errDetails);
""",
    "OSSL_CMP_SRV_error_cb_t",
)

patch_both(
    "cmp.h",
    """typedef int (*OSSL_CMP_SRV_certConf_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    int certReqId,
    const ASN1_OCTET_STRING *certHash,
    const OSSL_CMP_PKISI *si);
""",
    """/**
 * @brief Server callback type for processing incoming certConf messages.
 * @param srv_ctx CMP server context.
 * @param req Incoming certConf message.
 * @param certReqId Certificate request ID from the certStatus entry.
 * @param certHash certHash from the certStatus entry.
 * @param si PKIStatusInfo from the certStatus entry.
 * @return 1 on success, 0 on rejection, or -1 on error.
 */
typedef int (*OSSL_CMP_SRV_certConf_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req,
    int certReqId,
    const ASN1_OCTET_STRING *certHash,
    const OSSL_CMP_PKISI *si);
""",
    "OSSL_CMP_SRV_certConf_cb_t",
)

patch_both(
    "cmp.h",
    """typedef int (*OSSL_CMP_SRV_pollReq_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req, int certReqId,
    OSSL_CMP_MSG **certReq,
    int64_t *check_after);
""",
    """/**
 * @brief Server callback type for processing pollReq messages.
 * @param srv_ctx CMP server context.
 * @param req Incoming pollReq message.
 * @param certReqId Certificate request ID being polled.
 * @param certReq Receives a pending certRep message when ready, or NULL.
 * @param check_after Receives suggested poll interval in seconds when not ready.
 * @return 1 on success, 0 on error.
 */
typedef int (*OSSL_CMP_SRV_pollReq_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req, int certReqId,
    OSSL_CMP_MSG **certReq,
    int64_t *check_after);
""",
    "OSSL_CMP_SRV_pollReq_cb_t",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_SRV_CTX_init(OSSL_CMP_SRV_CTX *srv_ctx, void *custom_ctx,
    OSSL_CMP_SRV_cert_request_cb_t process_cert_request,
    OSSL_CMP_SRV_rr_cb_t process_rr,
    OSSL_CMP_SRV_genm_cb_t process_genm,
    OSSL_CMP_SRV_error_cb_t process_error,
    OSSL_CMP_SRV_certConf_cb_t process_certConf,
    OSSL_CMP_SRV_pollReq_cb_t process_pollReq);
""",
    """/**
 * @brief Register server-side CMP message processing callbacks.
 * @param srv_ctx Server context to initialize.
 * @param custom_ctx Application pointer returned by OSSL_CMP_SRV_CTX_get0_custom_ctx().
 * @param process_cert_request Callback for certificate requests, or NULL.
 * @param process_rr Callback for revocation requests, or NULL.
 * @param process_genm Callback for general messages, or NULL.
 * @param process_error Callback invoked when sending error messages, or NULL.
 * @param process_certConf Callback for certConf messages, or NULL.
 * @param process_pollReq Callback for pollReq messages, or NULL.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_SRV_CTX_init(OSSL_CMP_SRV_CTX *srv_ctx, void *custom_ctx,
    OSSL_CMP_SRV_cert_request_cb_t process_cert_request,
    OSSL_CMP_SRV_rr_cb_t process_rr,
    OSSL_CMP_SRV_genm_cb_t process_genm,
    OSSL_CMP_SRV_error_cb_t process_error,
    OSSL_CMP_SRV_certConf_cb_t process_certConf,
    OSSL_CMP_SRV_pollReq_cb_t process_pollReq);
""",
    "OSSL_CMP_SRV_CTX_init",
)

patch_both(
    "cmp.h",
    """typedef int (*OSSL_CMP_SRV_clean_transaction_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const ASN1_OCTET_STRING *id);
""",
    """/**
 * @brief Callback type for cleaning up server state after a transaction completes.
 * @param srv_ctx CMP server context.
 * @param id transactionID of the finished transaction.
 * @return 1 on success, 0 on error.
 */
typedef int (*OSSL_CMP_SRV_clean_transaction_cb_t)(OSSL_CMP_SRV_CTX *srv_ctx,
    const ASN1_OCTET_STRING *id);
""",
    "OSSL_CMP_SRV_clean_transaction_cb_t",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_SRV_CTX_init_trans(OSSL_CMP_SRV_CTX *srv_ctx,
    OSSL_CMP_SRV_delayed_delivery_cb_t delay,
    OSSL_CMP_SRV_clean_transaction_cb_t clean);
""",
    """/**
 * @brief Register delayed-delivery and transaction-cleanup callbacks on a server context.
 * @param srv_ctx Server context.
 * @param delay Optional callback deciding whether to delay response delivery.
 * @param clean Optional callback invoked when a transaction is finished.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_SRV_CTX_init_trans(OSSL_CMP_SRV_CTX *srv_ctx,
    OSSL_CMP_SRV_delayed_delivery_cb_t delay,
    OSSL_CMP_SRV_clean_transaction_cb_t clean);
""",
    "OSSL_CMP_SRV_CTX_init_trans",
)

patch_both(
    "cmp.h",
    """OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_cmp_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
""",
    """/**
 * @brief Return the embedded CMP context from a server context.
 * @param srv_ctx Server context.
 * @return Internal OSSL_CMP_CTX pointer.
 */
OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_cmp_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
""",
    "OSSL_CMP_SRV_CTX_get0_cmp_ctx",
)

patch_both(
    "cmp.h",
    """void *OSSL_CMP_SRV_CTX_get0_custom_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
""",
    """/**
 * @brief Return the application custom context pointer from a server context.
 * @param srv_ctx Server context.
 * @return Pointer supplied to OSSL_CMP_SRV_CTX_init(), or NULL if unset.
 */
void *OSSL_CMP_SRV_CTX_get0_custom_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
""",
    "OSSL_CMP_SRV_CTX_get0_custom_ctx",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx,
    int val);
""",
    """/**
 * @brief Enable or disable granting implicitConfirm in certRep messages.
 * @param srv_ctx CMP server context.
 * @param val Non-zero to enable, 0 to disable.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx,
    int val);
""",
    "OSSL_CMP_SRV_CTX_set_grant_implicit_confirm",
)

patch_both(
    "cmp.h",
    """X509 *OSSL_CMP_exec_certreq(OSSL_CMP_CTX *ctx, int req_type,
    const OSSL_CRMF_MSG *crm);
""",
    """/**
 * @brief Execute a CMP certificate request transaction (IR/CR/KUR/P10CR).
 * @param ctx CMP client context.
 * @param req_type Body type (OSSL_CMP_IR, OSSL_CMP_CR, OSSL_CMP_KUR, or OSSL_CMP_P10CR).
 * @param crm Optional CRMF message for IR/CR/KUR; NULL to build from context fields.
 * @return Newly enrolled certificate on success, or NULL on error.
 */
X509 *OSSL_CMP_exec_certreq(OSSL_CMP_CTX *ctx, int req_type,
    const OSSL_CRMF_MSG *crm);
""",
    "OSSL_CMP_exec_certreq",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_try_certreq(OSSL_CMP_CTX *ctx, int req_type,
    const OSSL_CRMF_MSG *crm, int *checkAfter);
""",
    """/**
 * @brief Start or continue a deferred CMP certificate request (pollReq flow).
 * @param ctx CMP client context.
 * @param req_type Body type (OSSL_CMP_IR, OSSL_CMP_CR, OSSL_CMP_KUR, or OSSL_CMP_P10CR).
 * @param crm Optional CRMF message for IR/CR/KUR.
 * @param checkAfter Receives server-suggested poll interval when the request is pending.
 * @return 1 if the certificate is ready, 0 if polling should continue, or -1 on error.
 */
int OSSL_CMP_try_certreq(OSSL_CMP_CTX *ctx, int req_type,
    const OSSL_CRMF_MSG *crm, int *checkAfter);
""",
    "OSSL_CMP_try_certreq",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Execute a CMP Revocation Request (RR) transaction using context fields.
 * @param ctx CMP client context with oldCert and revocation reason configured.
 * @return 1 on success, 0 on failure, or -1 on error.
 */
int OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_exec_RR_ses",
)

patch_both(
    "cmp.h",
    """STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Execute a CMP General Message (genm) transaction and return response ITAVs.
 * @param ctx CMP client context with genm ITAVs configured.
 * @return Stack of response ITAVs on success, or NULL on error; caller must free contents.
 */
STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_exec_GENM_ses",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_get1_caCerts(OSSL_CMP_CTX *ctx, STACK_OF(X509) **out);
""",
    """/**
 * @brief Request CA certificates from the CMP server via genm/genp and verify the response.
 * @param ctx CMP context referencing the CMP server.
 * @param out Receives a newly allocated stack of CA certificates; caller must free.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_get1_caCerts(OSSL_CMP_CTX *ctx, STACK_OF(X509) **out);
""",
    "OSSL_CMP_get1_caCerts",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_HTTP_bio_cb_t cb);
""",
    """/**
 * @brief Set the HTTP BIO callback used for CMP message transfer.
 * @param ctx CMP context.
 * @param cb HTTP callback that performs the request/response exchange.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_HTTP_bio_cb_t cb);
""",
    "OSSL_CMP_CTX_set_http_cb",
)

patch_both(
    "cmp.h",
    """int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    """/**
 * @brief Set the opaque argument passed to the HTTP transfer callback.
 * @param ctx CMP context.
 * @param arg Callback argument pointer.
 * @return 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
""",
    "OSSL_CMP_CTX_set_http_cb_arg",
)

patch_both(
    "cmp.h",
    """void *OSSL_CMP_CTX_get_http_cb_arg(const OSSL_CMP_CTX *ctx);
""",
    """/**
 * @brief Return the argument previously set for the HTTP transfer callback.
 * @param ctx CMP context.
 * @return HTTP callback argument, or NULL if unset.
 */
void *OSSL_CMP_CTX_get_http_cb_arg(const OSSL_CMP_CTX *ctx);
""",
    "OSSL_CMP_CTX_get_http_cb_arg",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
