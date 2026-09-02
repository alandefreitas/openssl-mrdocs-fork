#!/usr/bin/env python3
"""Documentation repair batch 23e: ts.h symbols."""
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


print("=== batch 23e (ts.h) ===")

# ts.h has no .h.in counterpart; patch the include MrDocs reads.

patch_one(
    "ts.h",
    """int TS_REQ_set_version(TS_REQ *a, long version);
""",
    """/**
 * @brief Set the version field of a time-stamp request (typically 1).
 * @param a Request to update.
 * @param version Version number to store.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_version(TS_REQ *a, long version);
""",
    "TS_REQ_set_version",
)

patch_one(
    "ts.h",
    """int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy);
""",
    """/**
 * @brief Set the optional TSA policy OID requested in a time-stamp request.
 * @param a Request to update.
 * @param policy Policy object identifier to copy into the request.
 * @return 1 on success, or 0 on failure.
 */
int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy);
""",
    "TS_REQ_set_policy_id",
)

patch_one(
    "ts.h",
    """int TS_REQ_get_cert_req(const TS_REQ *a);
""",
    """/**
 * @brief Return whether the request asks the TSA to include certificates.
 * @param a Request to query.
 * @return Nonzero if certReq is TRUE, otherwise 0.
 */
int TS_REQ_get_cert_req(const TS_REQ *a);
""",
    "TS_REQ_get_cert_req",
)

patch_one(
    "ts.h",
    """int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
""",
    """/**
 * @brief Set the TSA policy OID in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param policy_id Policy object identifier to copy.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id);
""",
    "TS_TST_INFO_set_policy_id",
)

patch_one(
    "ts.h",
    """ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);
""",
    """/**
 * @brief Return the TSA policy OID from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal ASN1_OBJECT pointer, or NULL if unset.
 */
ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a);
""",
    "TS_TST_INFO_get_policy_id",
)

patch_one(
    "ts.h",
    """TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);
""",
    """/**
 * @brief Return the optional accuracy field from a TSTInfo structure.
 * @param a TSTInfo to query.
 * @return Internal TS_ACCURACY pointer, or NULL if absent.
 */
TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a);
""",
    "TS_TST_INFO_get_accuracy",
)

patch_one(
    "ts.h",
    """const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);
""",
    """/**
 * @brief Return the seconds component of a time-stamp accuracy structure.
 * @param a Accuracy structure to query.
 * @return Internal ASN1_INTEGER pointer, or NULL if unset.
 */
const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a);
""",
    "TS_ACCURACY_get_seconds",
)

patch_one(
    "ts.h",
    """int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
""",
    """/**
 * @brief Set the optional milliseconds component of a time-stamp accuracy.
 * @param a Accuracy structure to update.
 * @param millis Milliseconds value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis);
""",
    "TS_ACCURACY_set_millis",
)

patch_one(
    "ts.h",
    """int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
""",
    """/**
 * @brief Set the optional nonce echoed from the request in a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param nonce Nonce value to copy, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce);
""",
    "TS_TST_INFO_set_nonce",
)

patch_one(
    "ts.h",
    """X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc);
""",
    """/**
 * @brief Remove and return the TSTInfo extension at index @p loc.
 * @param a TSTInfo to update.
 * @param loc Zero-based extension index.
 * @return Detached X509_EXTENSION (caller frees), or NULL if @p loc is invalid.
 */
X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc);
""",
    "TS_TST_INFO_delete_ext",
)

patch_one(
    "ts.h",
    """int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
""",
    """/**
 * @brief Insert an extension into a TSTInfo structure.
 * @param a TSTInfo to update.
 * @param ex Extension to add (duplicated into the TSTInfo).
 * @param loc Insertion index, or -1 to append.
 * @return 1 on success, or 0 on failure.
 */
int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc);
""",
    "TS_TST_INFO_add_ext",
)

patch_one(
    "ts.h",
    """void TS_RESP_CTX_free(TS_RESP_CTX *ctx);
""",
    """/**
 * @brief Free a time-stamp response context and associated resources.
 * @param ctx Context to free, or NULL.
 */
void TS_RESP_CTX_free(TS_RESP_CTX *ctx);
""",
    "TS_RESP_CTX_free",
)

patch_one(
    "ts.h",
    """int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);
""",
    """/**
 * @brief Set additional certificates included with generated time-stamp responses.
 * @param ctx Response context to configure.
 * @param certs Certificate chain to include (referenced), or NULL to clear; none are included by default.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);
""",
    "TS_RESP_CTX_set_certs",
)

patch_one(
    "ts.h",
    """int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);
""",
    """/**
 * @brief Verify a PKCS#7 time-stamp token against the criteria in @p ctx.
 * @param ctx Verification context with TS_VFY_* flags and expected imprint/data/store.
 * @param token PKCS#7 ContentInfo containing a TimeStampToken.
 * @return 1 on success, or 0 on failure.
 */
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token);
""",
    "TS_RESP_verify_token",
)

patch_one(
    "ts.h",
    """X509_STORE *TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s);
""",
    """/**
 * @brief Set the trusted certificate store used when verifying a time-stamp token.
 * @param ctx Verification context to update.
 * @param s Certificate store taken over by the context (freed on cleanup), or NULL.
 * @return The store pointer now stored in @p ctx.
 */
X509_STORE *TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s);
""",
    "TS_VERIFY_CTX_set_store",
)

patch_one(
    "ts.h",
    """STACK_OF(X509) *TS_VERIFY_CTX_set_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) *certs);
""",
    """/**
 * @brief Set the untrusted certificate stack used when verifying a time-stamp token.
 * @param ctx Verification context to update.
 * @param certs Certificate stack taken over by the context (freed on cleanup), or NULL.
 * @return The certificate stack now stored in @p ctx.
 */
STACK_OF(X509) *TS_VERIFY_CTX_set_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) *certs);
""",
    "TS_VERIFY_CTX_set_certs",
)

patch_one(
    "ts.h",
    """int TS_CONF_set_signer_digest(CONF *conf, const char *section,
    const char *md, TS_RESP_CTX *ctx);
""",
    """/**
 * @brief Set the TSA signer digest on a response context from CONF.
 * @param conf Configuration object.
 * @param section TSA configuration section name.
 * @param md Optional digest name override, or NULL to read from @p conf.
 * @param ctx Response context to update.
 * @return 1 on success, or 0 on failure.
 */
int TS_CONF_set_signer_digest(CONF *conf, const char *section,
    const char *md, TS_RESP_CTX *ctx);
""",
    "TS_CONF_set_signer_digest",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
