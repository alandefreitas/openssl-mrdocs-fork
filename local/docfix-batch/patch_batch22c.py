#!/usr/bin/env python3
"""Documentation repair batch 22c: crmf.h symbols."""
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


print("=== batch 22c ===")

patch_both(
    "crmf.h",
    """DECLARE_ASN1_DUP_FUNCTION(OSSL_CRMF_MSG)
""",
    """/**
 * @brief Duplicate an OSSL_CRMF_MSG structure.
 * @param a Value to duplicate.
 * @return Copy of @p a, or NULL on error.
 */
OSSL_CRMF_MSG *OSSL_CRMF_MSG_dup(const OSSL_CRMF_MSG *a);
""",
    "OSSL_CRMF_MSG_dup",
)

patch_both(
    "crmf.h",
    """DECLARE_ASN1_DUP_FUNCTION(OSSL_CRMF_CERTID)
""",
    """/**
 * @brief Duplicate an OSSL_CRMF_CERTID structure.
 * @param a Value to duplicate.
 * @return Copy of @p a, or NULL on error.
 */
OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_dup(const OSSL_CRMF_CERTID *a);
""",
    "OSSL_CRMF_CERTID_dup",
)

patch_both(
    "crmf.h",
    """typedef struct ossl_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;
""",
    """/**
 * @brief OptionalValidity from RFC 4211: optional notBefore and notAfter times in a certTemplate.
 */
typedef struct ossl_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;
""",
    "OSSL_CRMF_OPTIONALVALIDITY",
)

patch_both(
    "crmf.h",
    """OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(OSSL_LIB_CTX *libctx, size_t slen,
    int owfnid, size_t itercnt,
    int macnid);
""",
    """/**
 * @brief Create a PBMParameter for password-based MAC POPO (RFC 4211 section 4.4).
 * @param libctx Library context for algorithm fetching, or NULL for the default.
 * @param slen Length of the random salt in bytes.
 * @param owfnid NID of the one-way function digest.
 * @param itercnt OWF iteration count.
 * @param macnid NID of the MAC algorithm.
 * @return New PBMParameter, or NULL on error.
 */
OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(OSSL_LIB_CTX *libctx, size_t slen,
    int owfnid, size_t itercnt,
    int macnid);
""",
    "OSSL_CRMF_pbmp_new",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSG_set1_regCtrl_regToken(OSSL_CRMF_MSG *msg,
    const ASN1_UTF8STRING *tok);
""",
    """/**
 * @brief Set the regToken regCtrl in a CRMF CertReqMsg.
 * @param msg CertReqMsg to update.
 * @param tok Registration token value to copy; see RFC 4211 section 6.1.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CRMF_MSG_set1_regCtrl_regToken(OSSL_CRMF_MSG *msg,
    const ASN1_UTF8STRING *tok);
""",
    "OSSL_CRMF_MSG_set1_regCtrl_regToken",
)

patch_both(
    "crmf.h",
    """ASN1_UTF8STRING
*OSSL_CRMF_MSG_get0_regCtrl_regToken(const OSSL_CRMF_MSG *msg);
""",
    """/**
 * @brief Return the regToken regCtrl from a CRMF CertReqMsg, if present.
 * @param msg CertReqMsg to query.
 * @return Internal regToken pointer, or NULL if absent.
 */
ASN1_UTF8STRING
*OSSL_CRMF_MSG_get0_regCtrl_regToken(const OSSL_CRMF_MSG *msg);
""",
    "OSSL_CRMF_MSG_get0_regCtrl_regToken",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSG_set1_regCtrl_oldCertID(OSSL_CRMF_MSG *msg,
    const OSSL_CRMF_CERTID *cid);
""",
    """/**
 * @brief Set the oldCertID regCtrl in a CRMF CertReqMsg.
 * @param msg CertReqMsg to update.
 * @param cid CertId identifying the certificate being renewed; copied into the message.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CRMF_MSG_set1_regCtrl_oldCertID(OSSL_CRMF_MSG *msg,
    const OSSL_CRMF_CERTID *cid);
""",
    "OSSL_CRMF_MSG_set1_regCtrl_oldCertID",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(OSSL_CRMF_MSG *msg,
    const ASN1_UTF8STRING *utf8pairs);
""",
    """/**
 * @brief Set the utf8Pairs regInfo in a CRMF CertReqMsg.
 * @param msg CertReqMsg to update.
 * @param utf8pairs UTF-8 string value to copy into regInfo.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(OSSL_CRMF_MSG *msg,
    const ASN1_UTF8STRING *utf8pairs);
""",
    "OSSL_CRMF_MSG_set1_regInfo_utf8Pairs",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSG_set0_validity(OSSL_CRMF_MSG *crm,
    ASN1_TIME *notBefore, ASN1_TIME *notAfter);
""",
    """/**
 * @brief Set optional validity times in the certTemplate of a CRMF CertReqMsg.
 * @param crm CertReqMsg to update.
 * @param notBefore Optional notBefore time; ownership transfers when non-NULL.
 * @param notAfter Optional notAfter time; ownership transfers when non-NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CRMF_MSG_set0_validity(OSSL_CRMF_MSG *crm,
    ASN1_TIME *notBefore, ASN1_TIME *notAfter);
""",
    "OSSL_CRMF_MSG_set0_validity",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid);
""",
    """/**
 * @brief Set the certReqId field in a CRMF CertReqMsg.
 * @param crm CertReqMsg to update.
 * @param rid Certificate request ID as a nonnegative integer.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid);
""",
    "OSSL_CRMF_MSG_set_certReqId",
)

patch_both(
    "crmf.h",
    """int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs,
    int rid, int acceptRAVerified,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Verify proof-of-possession on a CRMF CertReqMessages sequence.
 * @param reqs CertReqMessages to verify.
 * @param rid certReqId of the message to verify, or -1 to verify all messages.
 * @param acceptRAVerified Non-zero to accept POPO raVerified without further checks.
 * @param libctx Library context for algorithm fetching, or NULL for the default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return 1 if POPO verifies, 0 if not, or -1 on error.
 */
int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs,
    int rid, int acceptRAVerified,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "OSSL_CRMF_MSGS_verify_popo",
)

patch_both(
    "crmf.h",
    """const X509_NAME *OSSL_CRMF_CERTID_get0_issuer(const OSSL_CRMF_CERTID *cid);
""",
    """/**
 * @brief Return the issuer name from a CRMF CertId.
 * @param cid CertId to query.
 * @return Internal issuer name pointer, or NULL if absent or on error.
 */
const X509_NAME *OSSL_CRMF_CERTID_get0_issuer(const OSSL_CRMF_CERTID *cid);
""",
    "OSSL_CRMF_CERTID_get0_issuer",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
