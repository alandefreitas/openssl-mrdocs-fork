#!/usr/bin/env python3
"""Documentation repair batch 23d: ocsp.h symbols."""
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


print("=== batch 23d (ocsp.h) ===")

patch_both(
    "ocsp.h",
    """OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req);
""",
    """/**
 * @brief Send an OCSP request over HTTP via @p b and return the decoded response.
 * @param b BIO connected to the OCSP responder (typically a connected socket BIO).
 * @param path HTTP request-URI path for the OCSP service (for example "/").
 * @param req OCSP request to POST as application/ocsp-request.
 * @return Newly allocated OCSP_RESPONSE, or NULL on error; free with OCSP_RESPONSE_free().
 */
OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req);
""",
    "OCSP_sendreq_bio",
)

patch_both(
    "ocsp.h",
    """OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx);
""",
    """/**
 * @brief Return the SingleResponse at index @p idx in a basic OCSP response.
 * @param bs Basic OCSP response to query.
 * @param idx Zero-based index into the responses sequence.
 * @return Internal OCSP_SINGLERESP pointer, or NULL if @p bs is NULL or @p idx is out of range.
 */
OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx);
""",
    "OCSP_resp_get0",
)

patch_both(
    "ocsp.h",
    """int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last);
""",
    """/**
 * @brief Find the next SingleResponse whose CertID matches @p id.
 * @param bs Basic OCSP response to search.
 * @param id CertID identifying the certificate of interest.
 * @param last Index after which to search, or -1 to start from the beginning.
 * @return Index of the matching SingleResponse, or -1 if not found.
 */
int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last);
""",
    "OCSP_resp_find",
)

patch_both(
    "ocsp.h",
    """int OCSP_request_onereq_count(OCSP_REQUEST *req);
""",
    """/**
 * @brief Return the number of single-request entries in an OCSP request.
 * @param req OCSP request to query.
 * @return Number of OCSP_ONEREQ entries in the requestList.
 */
int OCSP_request_onereq_count(OCSP_REQUEST *req);
""",
    "OCSP_request_onereq_count",
)

patch_both(
    "ocsp.h",
    """OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one);
""",
    """/**
 * @brief Return the CertID from a single OCSP request entry.
 * @param one Single-request entry to query.
 * @return Internal OCSP_CERTID pointer (reqCert), or NULL if unset.
 */
OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one);
""",
    "OCSP_onereq_get0_id",
)

patch_both(
    "ocsp.h",
    """OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs);
""",
    """/**
 * @brief Create an OCSP response with the given status and optional basic response.
 * @param status OCSPResponseStatus value such as OCSP_RESPONSE_STATUS_SUCCESSFUL.
 * @param bs Optional BasicOCSPResponse to embed as responseBytes, or NULL for status-only.
 * @return Newly allocated OCSP_RESPONSE, or NULL on error; free with OCSP_RESPONSE_free().
 */
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs);
""",
    "OCSP_response_create",
)

patch_both(
    "ocsp.h",
    """int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos);
""",
    """/**
 * @brief Find the next OCSP request extension with criticality @p crit.
 * @param x OCSP request whose extensions are searched.
 * @param crit Nonzero to match critical extensions, zero for non-critical.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos);
""",
    "OCSP_REQUEST_get_ext_by_critical",
)

patch_both(
    "ocsp.h",
    """int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x);
""",
    """/**
 * @brief Return the number of extensions on a single OCSP request entry.
 * @param x Single OCSP request entry to query.
 * @return Extension count, or 0 if none.
 */
int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x);
""",
    "OCSP_ONEREQ_get_ext_count",
)

patch_both(
    "ocsp.h",
    """int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    """/**
 * @brief Find the next basic-response extension with object identifier @p obj.
 * @param x Basic OCSP response whose extensions are searched.
 * @param obj ASN.1 object identifier to match.
 * @param lastpos Index after which to search, or -1 to start from the beginning.
 * @return Extension index, or -1 if not found.
 */
int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, const ASN1_OBJECT *obj,
    int lastpos);
""",
    "OCSP_BASICRESP_get_ext_by_OBJ",
)

patch_both(
    "ocsp.h",
    """int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value,
    int crit, unsigned long flags);
""",
    """/**
 * @brief Encode @p value as a basic-response extension of type @p nid and append it.
 * @param x Basic OCSP response to update.
 * @param nid NID of the extension type to add.
 * @param value Native extension structure encoded via i2d.
 * @param crit Nonzero to mark the extension critical.
 * @param flags X509V3_ADD_* flags controlling replacement behaviour.
 * @return 1 on success, 0 on error, or -1 on a fatal error.
 */
int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value,
    int crit, unsigned long flags);
""",
    "OCSP_BASICRESP_add1_ext_i2d",
)

patch_both(
    "ocsp.h",
    """void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit,
    int *idx);
""",
    """/**
 * @brief Decode the first SingleResponse extension of type @p nid into its native structure.
 * @param x SingleResponse to query.
 * @param nid NID of the extension type to extract.
 * @param crit Optional output set to 1 if critical, 0 if not, or -1 on error; may be NULL.
 * @param idx Optional in/out extension index for X509V3_get_d2i-style iteration; may be NULL.
 * @return Newly allocated decoded extension value, or NULL if absent or on error.
 */
void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit,
    int *idx);
""",
    "OCSP_SINGLERESP_get1_ext_d2i",
)

patch_both(
    "ocsp.h",
    """const char *OCSP_cert_status_str(long s);
""",
    """/**
 * @brief Return a human-readable string for an OCSP CertStatus value.
 * @param s Status value such as V_OCSP_CERTSTATUS_GOOD, REVOKED, or UNKNOWN.
 * @return Static NUL-terminated description string (for example "good").
 */
const char *OCSP_cert_status_str(long s);
""",
    "OCSP_cert_status_str",
)

patch_both(
    "ocsp.h",
    """int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
    X509_STORE *st, unsigned long flags);
""",
    """/**
 * @brief Verify the signature and optional certificate path of a basic OCSP response.
 * @param bs Basic OCSP response to verify.
 * @param certs Optional untrusted certificates used to locate or build the signer path, or NULL.
 * @param st Trusted certificate store used for path validation.
 * @param flags OCSP_* / X509 verify flags controlling verification behaviour.
 * @return 1 on successful verification, or 0 on failure.
 */
int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
    X509_STORE *st, unsigned long flags);
""",
    "OCSP_basic_verify",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
