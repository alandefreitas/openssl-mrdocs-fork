#!/usr/bin/env python3
"""Documentation repair batch 15e: x509_vfy.h + x509v3.h."""
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


print("=== batch 15e: x509_vfy.h + x509v3.h ===")

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """int X509_OBJECT_up_ref_count(X509_OBJECT *a);
""",
    """/**
 * @brief Increment the reference count on the certificate or CRL held by an X509_OBJECT.
 * @param a Object whose contained X509 or X509_CRL is retained.
 * @return 1 on success, or 0 on failure.
 */
int X509_OBJECT_up_ref_count(X509_OBJECT *a);
""",
    "X509_OBJECT_up_ref_count",
)

patch_both(
    "x509_vfy.h",
    """X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a);
""",
    """/**
 * @brief Return the certificate stored in an X509_OBJECT, if any.
 * @param a Object to query.
 * @return Internal X509 pointer (do not free), or NULL if @p a does not hold a certificate.
 */
X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a);
""",
    "X509_OBJECT_get0_X509",
)

patch_both(
    "x509_vfy.h",
    """X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a);
""",
    """/**
 * @brief Return the CRL stored in an X509_OBJECT, if any.
 * @param a Object to query.
 * @return Internal X509_CRL pointer (do not free), or NULL if @p a does not hold a CRL.
 */
X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a);
""",
    "X509_OBJECT_get0_X509_CRL",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(const X509_STORE *xs);
""",
    """/**
 * @brief Return the internal cache of certificates and CRLs held by a store.
 * @param xs Certificate store to query.
 * @return Internal STACK_OF(X509_OBJECT) (do not free or modify casually), or NULL if unavailable.
 */
STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(const X509_STORE *xs);
""",
    "X509_STORE_get0_objects",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_set_purpose(X509_STORE *xs, int purpose);
""",
    """/**
 * @brief Set the default certificate purpose applied when verifying with this store.
 * @param xs Store whose verification parameters are updated.
 * @param purpose Purpose identifier (see X509_PURPOSE_*).
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set_purpose(X509_STORE *xs, int purpose);
""",
    "X509_STORE_set_purpose",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_verify(X509_STORE *xs, X509_STORE_CTX_verify_fn verify);
""",
    """/**
 * @brief Install the chain-verify callback used by store contexts created from @p xs.
 * @param xs Certificate store to configure.
 * @param verify Function that verifies chain signatures and validity periods; NULL selects the default.
 */
void X509_STORE_set_verify(X509_STORE *xs, X509_STORE_CTX_verify_fn verify);
""",
    "X509_STORE_set_verify",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_verify_cb(X509_STORE *xs,
    X509_STORE_CTX_verify_cb verify_cb);
""",
    """/**
 * @brief Install the verify-result callback inherited by contexts created from this store.
 * @param xs Certificate store to configure.
 * @param verify_cb Callback invoked for each verification error/result, or NULL to clear.
 */
void X509_STORE_set_verify_cb(X509_STORE *xs,
    X509_STORE_CTX_verify_cb verify_cb);
""",
    "X509_STORE_set_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(const X509_STORE *xs);
""",
    """/**
 * @brief Return the verify-result callback installed on a certificate store.
 * @param xs Store to query.
 * @return Function pointer previously set with X509_STORE_set_verify_cb(), or NULL if unset.
 */
X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(const X509_STORE *xs);
""",
    "X509_STORE_get_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(const X509_STORE *s);
""",
    """/**
 * @brief Return the check-issued callback installed on a certificate store.
 * @param s Store to query.
 * @return Function pointer previously set with X509_STORE_set_check_issued(), or NULL for the default.
 */
X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(const X509_STORE *s);
""",
    "X509_STORE_get_check_issued",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(const X509_STORE *xs);
""",
    """/**
 * @brief Return the get-CRL callback installed on a certificate store.
 * @param xs Store to query.
 * @return Function pointer previously set with X509_STORE_set_get_crl(), or NULL for the default.
 */
X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(const X509_STORE *xs);
""",
    "X509_STORE_get_get_crl",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_cert_crl(X509_STORE *xs,
    X509_STORE_CTX_cert_crl_fn cert_crl);
""",
    """/**
 * @brief Install the cert-against-CRL check callback used by verifications from this store.
 * @param xs Store whose cert/CRL check function pointer is replaced.
 * @param cert_crl Callback that checks whether a certificate is listed on a CRL, or NULL for the default.
 */
void X509_STORE_set_cert_crl(X509_STORE *xs,
    X509_STORE_CTX_cert_crl_fn cert_crl);
""",
    "X509_STORE_set_cert_crl",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(const X509_STORE *xs);
""",
    """/**
 * @brief Return the cert-against-CRL check callback installed on a store.
 * @param xs Certificate store to query.
 * @return Function pointer previously set with X509_STORE_set_cert_crl(), or NULL for the default.
 */
X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(const X509_STORE *xs);
""",
    "X509_STORE_get_cert_crl",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_check_policy(X509_STORE *xs,
    X509_STORE_CTX_check_policy_fn check_policy);
""",
    """/**
 * @brief Install the certificate-policy check callback used by verifications from this store.
 * @param xs Store whose policy-check function pointer is replaced.
 * @param check_policy Callback that evaluates certificate policies, or NULL for the default.
 */
void X509_STORE_set_check_policy(X509_STORE *xs,
    X509_STORE_CTX_check_policy_fn check_policy);
""",
    "X509_STORE_set_check_policy",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE *s);
""",
    """/**
 * @brief Return the certificate-policy check callback installed on a store.
 * @param s Certificate store to query.
 * @return Function pointer previously set with X509_STORE_set_check_policy(), or NULL for the default.
 */
X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE *s);
""",
    "X509_STORE_get_check_policy",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_set_ex_data(X509_STORE *xs, int idx, void *data);
""",
    """/**
 * @brief Store application ex_data on an X509_STORE at index @p idx.
 * @param xs Certificate store to update.
 * @param idx Index from X509_STORE_get_ex_new_index() / CRYPTO_get_ex_new_index().
 * @param data Pointer to store.
 * @return 1 on success, or 0 on error.
 */
int X509_STORE_set_ex_data(X509_STORE *xs, int idx, void *data);
""",
    "X509_STORE_set_ex_data",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX *X509_STORE_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Allocate an empty X509_STORE_CTX using an explicit library context.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New verification context, or NULL on allocation failure.
 *
 * Call X509_STORE_CTX_init() (or X509_STORE_CTX_init_rpk()) before verifying.
 */
X509_STORE_CTX *X509_STORE_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_STORE_CTX_new_ex",
)

patch_both(
    "x509_vfy.h",
    """EVP_PKEY *X509_STORE_CTX_get0_rpk(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the raw public key being verified, if any.
 * @param ctx Verification store context to query.
 * @return Internal EVP_PKEY pointer (do not free), or NULL when verifying a certificate instead.
 */
EVP_PKEY *X509_STORE_CTX_get0_rpk(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_rpk",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_get_crl(X509_STORE_CTX *ctx,
    X509_STORE_CTX_get_crl_fn get_crl);
""",
    """/**
 * @brief Override the get-CRL callback on a verification context.
 * @param ctx Store context whose get_crl function is replaced.
 * @param get_crl Callback that locates a CRL for a certificate, or NULL for the default.
 */
void X509_STORE_CTX_set_get_crl(X509_STORE_CTX *ctx,
    X509_STORE_CTX_get_crl_fn get_crl);
""",
    "X509_STORE_CTX_set_get_crl",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *xs, X509_LOOKUP_METHOD *m);
""",
    """/**
 * @brief Attach a new X509_LOOKUP of method @p m to a certificate store.
 * @param xs Store that will own the returned lookup.
 * @param m Lookup method such as X509_LOOKUP_file() or X509_LOOKUP_hash_dir().
 * @return New X509_LOOKUP bound to @p xs, or NULL on error.
 */
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *xs, X509_LOOKUP_METHOD *m);
""",
    "X509_STORE_add_lookup",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_LOOKUP_get_by_fingerprint_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const unsigned char *bytes,
    int len,
    X509_OBJECT *ret);
""",
    """/**
 * @brief Callback type that looks up a certificate or CRL by fingerprint.
 * @param ctx Lookup instance to query.
 * @param type X509_LU_X509 or X509_LU_CRL selecting the object kind.
 * @param bytes Fingerprint octets to match.
 * @param len Length of @p bytes.
 * @param ret Receives the found object on success.
 * @return 1 on success, or 0 on failure / not found.
 */
typedef int (*X509_LOOKUP_get_by_fingerprint_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const unsigned char *bytes,
    int len,
    X509_OBJECT *ret);
""",
    "X509_LOOKUP_get_by_fingerprint_fn",
)

patch_both(
    "x509_vfy.h",
    """void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Return the free callback registered on an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Function that frees per-lookup method state, or NULL if unset.
 */
void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_meth_get_free",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_issuer_serial_fn fn);
""",
    """/**
 * @brief Set the get-by-issuer-and-serial callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param fn Callback that finds objects by issuer name and serial, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_issuer_serial_fn fn);
""",
    "X509_LOOKUP_meth_set_get_by_issuer_serial",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_fingerprint_fn fn);
""",
    """/**
 * @brief Set the get-by-fingerprint callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param fn Callback that finds an X509_OBJECT by fingerprint, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_fingerprint_fn fn);
""",
    "X509_LOOKUP_meth_set_get_by_fingerprint",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    const ASN1_INTEGER *serial,
    X509_OBJECT *ret);
""",
    """/**
 * @brief Look up a certificate in a lookup method by issuer name and serial number.
 * @param ctx Lookup instance to query.
 * @param type Object kind (typically X509_LU_X509).
 * @param name Issuer distinguished name.
 * @param serial Certificate serial number.
 * @param ret Receives the found object on success (cached in the store; do not free casually).
 * @return 1 if found, or 0 on failure / not found.
 */
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    const ASN1_INTEGER *serial,
    X509_OBJECT *ret);
""",
    "X509_LOOKUP_by_issuer_serial",
)

patch_both(
    "x509_vfy.h",
    """void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx);
""",
    """/**
 * @brief Return the method-specific opaque data attached to an X509_LOOKUP.
 * @param ctx Lookup object to query.
 * @return Pointer previously set with X509_LOOKUP_set_method_data(), or NULL if unset.
 */
void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_get_method_data",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx);
""",
    """/**
 * @brief Return the X509_STORE that owns a lookup object.
 * @param ctx Lookup to query.
 * @return Owning store pointer (do not free via this reference), or NULL if unset.
 */
X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_get_store",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_load_file(X509_STORE *xs, const char *file);
""",
    """/**
 * @brief Load trusted certificates from a PEM/DER file into a store.
 * @param xs Certificate store to update.
 * @param file Path to a file containing one or more certificates.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_load_file(X509_STORE *xs, const char *file);
""",
    "X509_STORE_load_file",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_load_store(X509_STORE *xs, const char *store);
""",
    """/**
 * @brief Load trusted certificates from an OSSL_STORE URI into a store.
 * @param xs Certificate store to update.
 * @param store URI understood by OSSL_STORE (for example a file: or pkcs11: URI).
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_load_store(X509_STORE *xs, const char *store);
""",
    "X509_STORE_load_store",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_load_store_ex(X509_STORE *xs, const char *store,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Load trusted certificates from an OSSL_STORE URI, with provider selection.
 * @param xs Certificate store to update.
 * @param store URI understood by OSSL_STORE.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_load_store_ex(X509_STORE *xs, const char *store,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_STORE_load_store_ex",
)

patch_both(
    "x509_vfy.h",
    """STACK_OF(X509) *X509_STORE_CTX_get1_chain(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return a new reference to the verified certificate chain built for @p ctx.
 * @param ctx Store context after successful (or partial) chain building.
 * @return New STACK_OF(X509) with up-reffed certificates; free with OSSL_STACK_OF_X509_free(), or NULL if none.
 */
STACK_OF(X509) *X509_STORE_CTX_get1_chain(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get1_chain",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
""",
    """/**
 * @brief Set the trust setting used when verifying with a store context.
 * @param ctx Store context whose verify parameters are updated.
 * @param trust Trust identifier (see X509_TRUST_*).
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
""",
    "X509_STORE_CTX_set_trust",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
    int purpose, int trust);
""",
    """/**
 * @brief Inherit purpose and trust onto a store context, falling back to defaults when unset.
 * @param ctx Store context whose X509_VERIFY_PARAM is updated.
 * @param def_purpose Default purpose used when @p purpose is 0 / unset.
 * @param purpose Desired purpose id (X509_PURPOSE_*), or 0 to keep/inherit.
 * @param trust Desired trust id (X509_TRUST_*), or 0 to derive from purpose.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
    int purpose, int trust);
""",
    "X509_STORE_CTX_purpose_inherit",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
""",
    """/**
 * @brief Apply a named built-in X509_VERIFY_PARAM set to a store context.
 * @param ctx Verification context whose parameters are updated.
 * @param name Parameter set name such as "default", "ssl_client", or "ssl_server".
 * @return 1 on success, or 0 if @p name is unknown or copy fails.
 */
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
""",
    "X509_STORE_CTX_set_default",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to,
    const X509_VERIFY_PARAM *from);
""",
    """/**
 * @brief Copy unset fields from @p from into @p to according to inheritance flags.
 * @param to Destination parameters that receive values only where not already set.
 * @param from Source parameters providing defaults to inherit.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to,
    const X509_VERIFY_PARAM *from);
""",
    "X509_VERIFY_PARAM_inherit",
)

patch_both(
    "x509_vfy.h",
    """void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level);
""",
    """/**
 * @brief Set the authentication security level required during verification.
 * @param param Verification parameters to update.
 * @param auth_level Security level (same scale as SSL_CTX_set_security_level); -1 clears / disables the check.
 */
void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level);
""",
    "X509_VERIFY_PARAM_set_auth_level",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
    STACK_OF(ASN1_OBJECT) *policies);
""",
    """/**
 * @brief Replace the user certificate-policy OID set on verification parameters.
 * @param param Verification parameters to update.
 * @param policies Stack of policy OIDs to copy, or NULL to clear the set.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
    STACK_OF(ASN1_OBJECT) *policies);
""",
    "X509_VERIFY_PARAM_set1_policies",
)

patch_both(
    "x509_vfy.h",
    """char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx);
""",
    """/**
 * @brief Return an expected hostname previously set for name checks.
 * @param param Verification parameters to query.
 * @param idx Zero-based index into the host list.
 * @return Internal host string (do not free), or NULL if @p idx is out of range.
 */
char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx);
""",
    "X509_VERIFY_PARAM_get0_host",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,
    const char *name, size_t namelen);
""",
    """/**
 * @brief Append an expected DNS/IP hostname for name checks without clearing existing hosts.
 * @param param Verification parameters to update.
 * @param name Hostname or IP literal to expect (copied).
 * @param namelen Length of @p name in bytes (0 means NUL-terminated).
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,
    const char *name, size_t namelen);
""",
    "X509_VERIFY_PARAM_add1_host",
)

patch_both(
    "x509_vfy.h",
    """unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the hostname-checking flags stored in verification parameters.
 * @param param Verification parameters to query.
 * @return X509_CHECK_FLAG_* bits previously set with X509_VERIFY_PARAM_set_hostflags().
 */
unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get_hostflags",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the authentication security level required by verification parameters.
 * @param param Verification parameters to query.
 * @return Security level previously set with X509_VERIFY_PARAM_set_auth_level(), or -1 if unset.
 */
int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get_auth_level",
)

patch_both(
    "x509_vfy.h",
    """const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the name associated with an X509_VERIFY_PARAM object.
 * @param param Verification parameters to query.
 * @return Internal name string (do not free), or NULL if unnamed.
 */
const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get0_name",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Register @p param in the global named X509_VERIFY_PARAM table (takes ownership).
 * @param param Named parameter object to add; freed on table cleanup or replacement of the same name.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_add0_table",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_get_count(void);
""",
    """/**
 * @brief Return how many named entries are in the global X509_VERIFY_PARAM table.
 * @return Count of built-in and dynamically registered named parameter sets.
 */
int X509_VERIFY_PARAM_get_count(void);
""",
    "X509_VERIFY_PARAM_get_count",
)

patch_both(
    "x509_vfy.h",
    """int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
""",
    """/**
 * @brief Return how many levels a certificate policy tree contains.
 * @param tree Policy tree from X509_policy_check().
 * @return Number of levels (typically one per certificate in the chain), or 0 if @p tree is NULL.
 */
int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
""",
    "X509_policy_tree_level_count",
)

# ----- x509v3.h -----

patch_one(
    "x509v3.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(SXNETID, SXNETID, SXNETID)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(SXNETID) container type.
 */
struct stack_st_SXNETID;
SKM_DEFINE_STACK_OF_INTERNAL(SXNETID, SXNETID, SXNETID)
""",
    "stack_st_SXNETID",
)

patch_one(
    "x509v3.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("SXNETID");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(SXNETID) container type.
 */
struct stack_st_SXNETID;
{-
    generate_stack_macros("SXNETID");
-}
""",
    "stack_st_SXNETID",
)

patch_both(
    "x509v3.h",
    """int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, const char *user,
    int userlen);
""",
    """/**
 * @brief Add a Strong Extranet zone/user id using an ASN.1 INTEGER zone number.
 * @param psx Address of an SXNET pointer; allocates a new SXNET when *@p psx is NULL.
 * @param izone Zone identifier; ownership transfers to the SXNET on success.
 * @param user User identifier octets (not necessarily NUL-terminated when @p userlen >= 0).
 * @param userlen Length of @p user in bytes, or -1 to use strlen(@p user); must be at most 64.
 * @return 1 on success, or 0 on error.
 */
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, const char *user,
    int userlen);
""",
    "SXNET_add_id_INTEGER",
)

patch_both(
    "x509v3.h",
    """char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5);
""",
    """/**
 * @brief Convert an ASN1_IA5STRING to a newly allocated C string.
 * @param method Extension method (unused; may be NULL).
 * @param ia5 IA5String value to convert.
 * @return Newly allocated C string, or NULL on error; free with OPENSSL_free.
 */
char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5);
""",
    "i2s_ASN1_IA5STRING",
)

patch_both(
    "x509v3.h",
    """CRL_DIST_POINTS *CRL_DIST_POINTS_new(void);
""",
    """/**
 * @brief Allocate a new CRL Distribution Points extension value.
 * @return New CRL_DIST_POINTS, or NULL on allocation failure.
 */
CRL_DIST_POINTS *CRL_DIST_POINTS_new(void);
""",
    "CRL_DIST_POINTS_new",
)

patch_both(
    "x509v3.h",
    """int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, const char *section,
    STACK_OF(X509_EXTENSION) **sk);
""",
    """/**
 * @brief Add all extensions from a configuration section to an extension stack.
 * @param conf Configuration object containing @p section.
 * @param ctx Extension construction context.
 * @param section Name of the configuration section listing extensions.
 * @param sk Address of a STACK_OF(X509_EXTENSION) to append to; allocated if *@p sk is NULL.
 * @return 1 on success, or 0 on error.
 */
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, const char *section,
    STACK_OF(X509_EXTENSION) **sk);
""",
    "X509V3_EXT_add_nconf_sk",
)

patch_both(
    "x509v3.h",
    """void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
""",
    """/**
 * @brief Free a CONF_VALUE section previously returned by X509V3_get_section().
 * @param ctx Extension context whose @c db_meth provides free_section, or NULL to free with X509V3_conf_free helpers.
 * @param section Stack of CONF_VALUE entries to free, or NULL.
 */
void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
""",
    "X509V3_section_free",
)

patch_both(
    "x509v3.h",
    """int X509V3_add_value_bool(const char *name, int asn1_bool,
    STACK_OF(CONF_VALUE) **extlist);
""",
    """/**
 * @brief Append a boolean CONF_VALUE named @p name with value "TRUE" or "FALSE".
 * @param name Extension value name to store.
 * @param asn1_bool Nonzero stores "TRUE"; zero stores "FALSE".
 * @param extlist Stack of CONF_VALUE entries to extend; allocated if *@p extlist is NULL.
 * @return 1 on success, or 0 on error.
 */
int X509V3_add_value_bool(const char *name, int asn1_bool,
    STACK_OF(CONF_VALUE) **extlist);
""",
    "X509V3_add_value_bool",
)

patch_both(
    "x509v3.h",
    """char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth,
    const ASN1_ENUMERATED *aint);
""",
    """/**
 * @brief Convert an ASN1_ENUMERATED to a name string using @p meth's ENUMERATED_NAMES table.
 * @param meth Extension method whose @c usr_data points to an ENUMERATED_NAMES list.
 * @param aint Enumerated value to convert.
 * @return Newly allocated name or decimal string, or NULL on error; free with OPENSSL_free.
 */
char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth,
    const ASN1_ENUMERATED *aint);
""",
    "i2s_ASN1_ENUMERATED_TABLE",
)

patch_both(
    "x509v3.h",
    """uint32_t X509_get_extension_flags(X509 *x);
""",
    """/**
 * @brief Return the cached X.509v3 extension summary flags for a certificate.
 * @param x Certificate whose extensions have been processed (for example via X509_check_purpose).
 * @return Bitmask of EXFLAG_* values describing presence and properties of common extensions.
 */
uint32_t X509_get_extension_flags(X509 *x);
""",
    "X509_get_extension_flags",
)

patch_both(
    "x509v3.h",
    """int X509v3_addr_add_inherit(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi);
""",
    """/**
 * @brief Mark an address family in an IPAddrBlocks value as inheriting from the issuer.
 * @param addr Extension value to modify.
 * @param afi Address Family Identifier (IANA AFI).
 * @param safi Optional Subsequent Address Family Identifier, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509v3_addr_add_inherit(IPAddrBlocks *addr,
    const unsigned afi, const unsigned *safi);
""",
    "X509v3_addr_add_inherit",
)

patch_both(
    "x509v3.h",
    """int X509v3_asid_validate_resource_set(STACK_OF(X509) *chain,
    ASIdentifiers *ext,
    int allow_inheritance);
""",
    """/**
 * @brief Validate that AS identifiers in @p ext are covered by ancestors in @p chain.
 * @param chain Certificate chain (leaf first) used to check nested ASIdentifiers extensions.
 * @param ext AS resource set claimed by the leaf (or NULL to treat as empty).
 * @param allow_inheritance Non-zero to permit inherit elements when validating.
 * @return 1 if @p ext is valid given @p chain, or 0 otherwise.
 */
int X509v3_asid_validate_resource_set(STACK_OF(X509) *chain,
    ASIdentifiers *ext,
    int allow_inheritance);
""",
    "X509v3_asid_validate_resource_set",
)

patch_one(
    "x509v3.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(PROFESSION_INFO, PROFESSION_INFO, PROFESSION_INFO)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PROFESSION_INFO) container type.
 */
struct stack_st_PROFESSION_INFO;
SKM_DEFINE_STACK_OF_INTERNAL(PROFESSION_INFO, PROFESSION_INFO, PROFESSION_INFO)
""",
    "stack_st_PROFESSION_INFO",
)

patch_one(
    "x509v3.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("PROFESSION_INFO");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PROFESSION_INFO) container type.
 */
struct stack_st_PROFESSION_INFO;
{-
    generate_stack_macros("PROFESSION_INFO");
-}
""",
    "stack_st_PROFESSION_INFO",
)

patch_both(
    "x509v3.h",
    """void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *n,
    ASN1_STRING *namingAuthorityText);
""",
    """/**
 * @brief Set the authority text on a NAMING_AUTHORITY, taking ownership of @p namingAuthorityText.
 * @param n Naming authority to update.
 * @param namingAuthorityText New descriptive text, or NULL to clear; frees any previous value.
 */
void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *n,
    ASN1_STRING *namingAuthorityText);
""",
    "NAMING_AUTHORITY_set0_authorityText",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
