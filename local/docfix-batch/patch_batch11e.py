#!/usr/bin/env python3
"""Documentation repair batch 11e: x509_vfy.h + x509v3.h."""
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


print("=== batch 11e: x509_vfy.h + x509v3.h ===")

# ----- stacks: .h uses SKM; .in uses generate_stack_macros -----
patch_one(
    "x509_vfy.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(X509_LOOKUP, X509_LOOKUP, X509_LOOKUP)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(X509_LOOKUP) container type.
 */
struct stack_st_X509_LOOKUP;
SKM_DEFINE_STACK_OF_INTERNAL(X509_LOOKUP, X509_LOOKUP, X509_LOOKUP)
""",
    "stack_st_X509_LOOKUP",
)

patch_one(
    "x509_vfy.h",
    """SKM_DEFINE_STACK_OF_INTERNAL(X509_VERIFY_PARAM, X509_VERIFY_PARAM, X509_VERIFY_PARAM)
""",
    """/**
 * @brief Opaque STACK_OF(X509_VERIFY_PARAM) container type.
 */
struct stack_st_X509_VERIFY_PARAM;
SKM_DEFINE_STACK_OF_INTERNAL(X509_VERIFY_PARAM, X509_VERIFY_PARAM, X509_VERIFY_PARAM)
""",
    "stack_st_X509_VERIFY_PARAM",
)

patch_one(
    "x509_vfy.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("X509_LOOKUP")
    .generate_stack_macros("X509_OBJECT")
    .generate_stack_macros("X509_VERIFY_PARAM");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(X509_LOOKUP) container type.
 */
struct stack_st_X509_LOOKUP;
/**
 * @brief Opaque STACK_OF(X509_VERIFY_PARAM) container type.
 */
struct stack_st_X509_VERIFY_PARAM;
{-
    generate_stack_macros("X509_LOOKUP")
    .generate_stack_macros("X509_OBJECT")
    .generate_stack_macros("X509_VERIFY_PARAM");
-}
""",
    "stack_st_X509_LOOKUP+VERIFY_PARAM",
)

patch_both(
    "x509_vfy.h",
    """int X509_TRUST_get_count(void);
""",
    """/**
 * @brief Return the number of entries in the global X509_TRUST table.
 * @return Count of built-in and dynamically registered trust types.
 */
int X509_TRUST_get_count(void);
""",
    "X509_TRUST_get_count",
)

patch_both(
    "x509_vfy.h",
    """int X509_TRUST_get_by_id(int id);
""",
    """/**
 * @brief Return the table index of the X509_TRUST entry with trust id @p id.
 * @param id Trust purpose identifier (X509_TRUST_*).
 * @return Index suitable for X509_TRUST_get0, or -1 if not found.
 */
int X509_TRUST_get_by_id(int id);
""",
    "X509_TRUST_get_by_id",
)

patch_both(
    "x509_vfy.h",
    """char *X509_TRUST_get0_name(const X509_TRUST *xp);
""",
    """/**
 * @brief Return the short name of an X509_TRUST table entry.
 * @param xp Trust entry to query.
 * @return Internal name string; do not free.
 */
char *X509_TRUST_get0_name(const X509_TRUST *xp);
""",
    "X509_TRUST_get0_name",
)

patch_both(
    "x509_vfy.h",
    """int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj);
""",
    """/**
 * @brief Append an OID to a certificate's auxiliary trust list.
 * @param x Certificate whose trust objects are extended (creates aux data if needed).
 * @param obj Purpose/OID that should cause the certificate to be trusted when matched.
 * @return 1 on success, or 0 on failure.
 */
int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj);
""",
    "X509_add1_trust_object",
)

patch_both(
    "x509_vfy.h",
    """void X509_reject_clear(X509 *x);
""",
    """/**
 * @brief Clear all auxiliary reject-object OIDs attached to a certificate.
 * @param x Certificate whose reject OID stack is freed and reset.
 */
void X509_reject_clear(X509 *x);
""",
    "X509_reject_clear",
)

patch_both(
    "x509_vfy.h",
    """int (*X509_TRUST_set_default(int (*trust)(int, X509 *, int)))(int, X509 *,
    int);
""",
    """/**
 * @brief Install a process-wide default trust-checking callback.
 * @param trust Callback of the form int trust(int id, X509 *x, int flags), or NULL to restore the built-in default.
 * @return Previous default trust callback.
 */
int (*X509_TRUST_set_default(int (*trust)(int, X509 *, int)))(int, X509 *,
    int);
""",
    "X509_TRUST_set_default",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
""",
    """/**
 * @brief Verify-result callback invoked for each certificate during chain verification.
 * @param ok Current verification result (1 if OK so far, 0 if an error was recorded).
 * @param ctx Store context describing the certificate under examination and any error.
 * @return Non-zero to continue/accept, or 0 to fail verification.
 */
typedef int (*X509_STORE_CTX_verify_cb)(int ok, X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
    X509 *x, X509 *issuer);
""",
    """/**
 * @brief Callback type that checks whether @p issuer appears to have issued @p x.
 * @param ctx Verification context performing the check.
 * @param x Candidate subject certificate.
 * @param issuer Candidate issuer certificate.
 * @return 1 if @p issuer issued @p x, or 0 otherwise.
 */
typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
    X509 *x, X509 *issuer);
""",
    "X509_STORE_CTX_check_issued_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_get_crl_fn)(X509_STORE_CTX *ctx,
    X509_CRL **crl, X509 *x);
""",
    """/**
 * @brief Callback type that locates a CRL for certificate @p x.
 * @param ctx Verification context performing the lookup.
 * @param crl On success, set to the found CRL (caller/context manages lifetime per OpenSSL rules).
 * @param x Certificate for which a CRL is needed.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_get_crl_fn)(X509_STORE_CTX *ctx,
    X509_CRL **crl, X509 *x);
""",
    "X509_STORE_CTX_get_crl_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef STACK_OF(X509_CRL)
    *(*X509_STORE_CTX_lookup_crls_fn)(const X509_STORE_CTX *ctx,
        const X509_NAME *nm);
""",
    """/**
 * @brief Callback type that returns CRLs matching issuer name @p nm.
 * @param ctx Verification context performing the lookup.
 * @param nm CRL issuer name to search for.
 * @return Newly allocated stack of X509_CRL, or NULL on failure; caller frees with sk_X509_CRL_pop_free.
 */
typedef STACK_OF(X509_CRL)
    *(*X509_STORE_CTX_lookup_crls_fn)(const X509_STORE_CTX *ctx,
        const X509_NAME *nm);
""",
    "X509_STORE_CTX_lookup_crls_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_cleanup_fn)(X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Callback type invoked to clean up application state associated with a store context.
 * @param ctx Verification context being cleaned up.
 * @return 1 on success, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_cleanup_fn)(X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_cleanup_fn",
)

patch_both(
    "x509_vfy.h",
    """X509_OBJECT *X509_OBJECT_new(void);
""",
    """/**
 * @brief Allocate an empty X509_OBJECT container for a certificate or CRL.
 * @return New X509_OBJECT, or NULL on allocation failure.
 */
X509_OBJECT *X509_OBJECT_new(void);
""",
    "X509_OBJECT_new",
)

patch_both(
    "x509_vfy.h",
    """int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj);
""",
    """/**
 * @brief Store a CRL in an X509_OBJECT, taking a reference to @p obj.
 * @param a Object that will hold type X509_LU_CRL.
 * @param obj CRL to reference; its reference count is incremented on success.
 * @return 1 on success, or 0 on failure.
 */
int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj);
""",
    "X509_OBJECT_set1_X509_CRL",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_free(X509_STORE *xs);
""",
    """/**
 * @brief Free an X509_STORE and release its references to certificates, CRLs, and lookups.
 * @param xs Store to free; NULL is ignored.
 */
void X509_STORE_free(X509_STORE *xs);
""",
    "X509_STORE_free",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_lock(X509_STORE *xs);
""",
    """/**
 * @brief Acquire a write lock on an X509_STORE for thread-safe mutation.
 * @param xs Store to lock.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_lock(X509_STORE *xs);
""",
    "X509_STORE_lock",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_set_trust(X509_STORE *xs, int trust);
""",
    """/**
 * @brief Set the default trust setting applied when verifying with this store.
 * @param xs Store whose verification parameters are updated.
 * @param trust Trust identifier (see X509_TRUST_*).
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_set_trust(X509_STORE *xs, int trust);
""",
    "X509_STORE_set_trust",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_check_crl(X509_STORE *xs,
    X509_STORE_CTX_check_crl_fn check_crl);
""",
    """/**
 * @brief Install a callback that verifies CRLs for a certificate store.
 * @param xs Store whose CRL-check callback is set.
 * @param check_crl Callback used to validate CRLs, or NULL for the default.
 */
void X509_STORE_set_check_crl(X509_STORE *xs,
    X509_STORE_CTX_check_crl_fn check_crl);
""",
    "X509_STORE_set_check_crl",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(const X509_STORE *xs);
""",
    """/**
 * @brief Return the CRL-lookup callback installed on a certificate store.
 * @param xs Store to query.
 * @return Callback used to find CRLs by issuer name, or NULL if the default is used.
 */
X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(const X509_STORE *xs);
""",
    "X509_STORE_get_lookup_crls",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_set_cleanup(X509_STORE *xs,
    X509_STORE_CTX_cleanup_fn cleanup);
""",
    """/**
 * @brief Install a cleanup callback inherited by X509_STORE_CTX objects from this store.
 * @param xs Store whose cleanup callback is set.
 * @param cleanup Callback invoked when a store context is cleaned up, or NULL to clear.
 */
void X509_STORE_set_cleanup(X509_STORE *xs,
    X509_STORE_CTX_cleanup_fn cleanup);
""",
    "X509_STORE_set_cleanup",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the verify-result callback installed on a store context.
 * @param ctx Store context to query.
 * @return Verify callback pointer, or NULL if unset.
 */
X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the cert-against-CRL check callback installed on a store context.
 * @param ctx Store context to query.
 * @return Function pointer cached from the corresponding X509_STORE, or NULL if unset.
 */
X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_cert_crl",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the certificate-policy check callback installed on a store context.
 * @param ctx Store context to query.
 * @return Function pointer cached from the corresponding X509_STORE, or NULL if unset.
 */
X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_check_policy",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the CRL-lookup callback installed on a store context.
 * @param ctx Store context to query.
 * @return Function pointer cached from the corresponding X509_STORE, or NULL if unset.
 */
X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_lookup_crls",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the cleanup callback installed on a store context.
 * @param ctx Store context to query.
 * @return Function pointer cached from the corresponding X509_STORE, or NULL if unset.
 */
X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_cleanup",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_LOOKUP_ctrl_fn)(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret);
""",
    """/**
 * @brief Control-command callback for an X509_LOOKUP_METHOD.
 * @param ctx Lookup object receiving the command.
 * @param cmd Control command such as X509_L_FILE_LOAD.
 * @param argc String argument for @p cmd, or NULL.
 * @param argl Integer argument for @p cmd.
 * @param ret Optional address receiving a result string, or NULL.
 * @return Positive value on success, or <=0 on failure (command-specific).
 */
typedef int (*X509_LOOKUP_ctrl_fn)(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret);
""",
    "X509_LOOKUP_ctrl_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_LOOKUP_get_by_subject_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    X509_OBJECT *ret);
""",
    """/**
 * @brief Callback type that looks up a certificate or CRL by subject name.
 * @param ctx Lookup instance to query.
 * @param type X509_LU_X509 or X509_LU_CRL selecting the object kind.
 * @param name Subject name to match.
 * @param ret Receives the found object on success.
 * @return 1 on success, or 0 on failure / not found.
 */
typedef int (*X509_LOOKUP_get_by_subject_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    X509_OBJECT *ret);
""",
    "X509_LOOKUP_get_by_subject_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_LOOKUP_get_by_issuer_serial_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    const ASN1_INTEGER *serial,
    X509_OBJECT *ret);
""",
    """/**
 * @brief Callback type that looks up a certificate by issuer name and serial number.
 * @param ctx Lookup instance to query.
 * @param type Object kind (typically X509_LU_X509).
 * @param name Issuer distinguished name.
 * @param serial Certificate serial number.
 * @param ret Receives the found object on success.
 * @return 1 on success, or 0 on failure / not found.
 */
typedef int (*X509_LOOKUP_get_by_issuer_serial_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name,
    const ASN1_INTEGER *serial,
    X509_OBJECT *ret);
""",
    "X509_LOOKUP_get_by_issuer_serial_fn",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_LOOKUP_get_by_alias_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const char *str,
    int len,
    X509_OBJECT *ret);
""",
    """/**
 * @brief Callback type that looks up a certificate or CRL by alias / friendly name.
 * @param ctx Lookup instance to query.
 * @param type X509_LU_X509 or X509_LU_CRL selecting the object kind.
 * @param str Alias bytes to match.
 * @param len Length of @p str in bytes.
 * @param ret Receives the found object on success.
 * @return 1 on success, or 0 on failure / not found.
 */
typedef int (*X509_LOOKUP_get_by_alias_fn)(X509_LOOKUP *ctx,
    X509_LOOKUP_TYPE type,
    const char *str,
    int len,
    X509_OBJECT *ret);
""",
    "X509_LOOKUP_get_by_alias_fn",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
    int (*init)(X509_LOOKUP *ctx));
""",
    """/**
 * @brief Set the initialization callback on an X509_LOOKUP_METHOD.
 * @param method Lookup method table to update.
 * @param init Callback invoked when an X509_LOOKUP using @p method is initialized, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
    int (*init)(X509_LOOKUP *ctx));
""",
    "X509_LOOKUP_meth_set_init",
)

patch_both(
    "x509_vfy.h",
    """int (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Return the shutdown callback registered on an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Shutdown function previously set with X509_LOOKUP_meth_set_shutdown(), or NULL if unset.
 */
int (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_meth_get_shutdown",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD *method);
""",
    """/**
 * @brief Return the control callback registered on an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Ctrl function previously set with X509_LOOKUP_meth_set_ctrl(), or NULL if unset.
 */
X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD *method);
""",
    "X509_LOOKUP_meth_get_ctrl",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(
    const X509_LOOKUP_METHOD *method);
""",
    """/**
 * @brief Return the get-by-subject callback from an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Function pointer previously set with X509_LOOKUP_meth_set_get_by_subject(), or NULL.
 */
X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(
    const X509_LOOKUP_METHOD *method);
""",
    "X509_LOOKUP_meth_get_get_by_subject",
)

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(
    const X509_LOOKUP_METHOD *method);
""",
    """/**
 * @brief Return the get-by-alias callback from an X509_LOOKUP_METHOD.
 * @param method Lookup method to query.
 * @return Function pointer previously set with X509_LOOKUP_meth_set_get_by_alias(), or NULL.
 */
X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(
    const X509_LOOKUP_METHOD *method);
""",
    "X509_LOOKUP_meth_get_get_by_alias",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x);
""",
    """/**
 * @brief Add a CRL to an X509_STORE's cache.
 * @param xs Store that will retain @p x.
 * @param x CRL to add; the store increments its reference count on success.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x);
""",
    "X509_STORE_add_crl",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret);
""",
    """/**
 * @brief Invoke the control method of an X509_LOOKUP (no explicit library context).
 * @param ctx Lookup object receiving the command.
 * @param cmd Control command such as X509_L_FILE_LOAD.
 * @param argc String argument for @p cmd, or NULL.
 * @param argl Integer argument for @p cmd.
 * @param ret Optional address receiving a result string, or NULL.
 * @return Positive value on success, or <=0 on failure (command-specific).
 */
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret);
""",
    "X509_LOOKUP_ctrl",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
    char **ret, OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Invoke the control method of an X509_LOOKUP with an explicit library context.
 * @param ctx Lookup object receiving the command.
 * @param cmd Control command such as X509_L_FILE_LOAD.
 * @param argc String argument for @p cmd, or NULL.
 * @param argl Integer argument for @p cmd.
 * @param ret Optional address receiving a result string, or NULL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Positive value on success, or <=0 on failure (command-specific).
 */
int X509_LOOKUP_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
    char **ret, OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_LOOKUP_ctrl_ex",
)

patch_both(
    "x509_vfy.h",
    """int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    """/**
 * @brief Load certificates from @p file into the store behind @p ctx.
 * @param ctx Lookup object associated with the destination X509_STORE.
 * @param file Path to a certificate file.
 * @param type File format such as X509_FILETYPE_PEM or X509_FILETYPE_ASN1.
 * @return Number of certificates loaded, or 0 on failure.
 */
int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    "X509_load_cert_file",
)

patch_both(
    "x509_vfy.h",
    """int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    """/**
 * @brief Load CRLs from @p file into the store behind @p ctx.
 * @param ctx Lookup object associated with the destination X509_STORE.
 * @param file Path to a CRL file.
 * @param type File format such as X509_FILETYPE_PEM or X509_FILETYPE_ASN1.
 * @return Number of CRLs loaded, or 0 on failure.
 */
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
""",
    "X509_load_crl_file",
)

patch_both(
    "x509_vfy.h",
    """int X509_load_cert_crl_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Load certificates and CRLs from a PEM @p file with an explicit library context.
 * @param ctx Lookup object associated with the destination X509_STORE.
 * @param file Path to a PEM file that may contain certificates and CRLs.
 * @param type File format; typically X509_FILETYPE_PEM for mixed content.
 * @param libctx Library context for decoding, or NULL for the default.
 * @param propq Property query string, or NULL.
 * @return Number of objects loaded, or 0 on failure.
 */
int X509_load_cert_crl_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_load_cert_crl_file_ex",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_init(X509_LOOKUP *ctx);
""",
    """/**
 * @brief Initialize an X509_LOOKUP by invoking its method's init callback.
 * @param ctx Lookup object to initialize.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_init(X509_LOOKUP *ctx);
""",
    "X509_LOOKUP_init",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret);
""",
    """/**
 * @brief Look up a certificate or CRL by subject name via a lookup method.
 * @param ctx Lookup instance to query.
 * @param type X509_LU_X509 or X509_LU_CRL selecting the object kind.
 * @param name Subject name to match.
 * @param ret Receives the found object on success.
 * @return 1 on success, or 0 on failure / not found.
 */
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret);
""",
    "X509_LOOKUP_by_subject",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data);
""",
    """/**
 * @brief Attach method-specific opaque data to an X509_LOOKUP.
 * @param ctx Lookup object that stores @p data for its method callbacks.
 * @param data Pointer owned/interpreted by the lookup method.
 * @return 1 on success, or 0 on failure.
 */
int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data);
""",
    "X509_LOOKUP_set_method_data",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
""",
    """/**
 * @brief Set the current verification error code on a store context.
 * @param ctx Verification context to update.
 * @param s X509_V_OK or an X509_V_ERR_* error code.
 */
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
""",
    "X509_STORE_CTX_set_error",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth);
""",
    """/**
 * @brief Set the certificate-chain depth associated with the current verification error.
 * @param ctx Verification context to update.
 * @param depth Depth of the certificate related to the error (0 = end-entity).
 */
void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth);
""",
    "X509_STORE_CTX_set_error_depth",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_get_explicit_policy(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return whether an explicit certificate policy was required/found during verification.
 * @param ctx Verification context after policy processing.
 * @return Non-zero if explicit policy applies, or 0 otherwise.
 */
int X509_STORE_CTX_get_explicit_policy(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_explicit_policy",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return how many certificates at the start of the chain were untrusted.
 * @param ctx Verification context after chain building.
 * @return Count of untrusted certificates leading the constructed chain.
 */
int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get_num_untrusted",
)

patch_both(
    "x509_vfy.h",
    """X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the verification parameters associated with a store context.
 * @param ctx Verification context to query.
 * @return Internal X509_VERIFY_PARAM pointer (do not free), or NULL if unset.
 */
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_param",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Transfer ownership of verification parameters to a store context.
 * @param ctx Verification context that takes ownership of @p param.
 * @param param Parameters to install; any previous parameters are freed.
 */
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
""",
    "X509_STORE_CTX_set0_param",
)

patch_both(
    "x509_vfy.h",
    """void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Free an X509_VERIFY_PARAM and any associated host/email/IP data.
 * @param param Parameters to free; NULL is ignored.
 */
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_free",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
    const X509_VERIFY_PARAM *from);
""",
    """/**
 * @brief Copy all verification settings from @p from into @p to.
 * @param to Destination parameters overwritten with a deep copy of @p from.
 * @param from Source parameters to copy.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
    const X509_VERIFY_PARAM *from);
""",
    "X509_VERIFY_PARAM_set1",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
""",
    """/**
 * @brief Set the name of an X509_VERIFY_PARAM (used when inheriting named defaults).
 * @param param Parameters to update.
 * @param name NUL-terminated name string copied into @p param.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
""",
    "X509_VERIFY_PARAM_set1_name",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param,
    unsigned long flags);
""",
    """/**
 * @brief OR additional X509_V_FLAG_* bits into verification parameters.
 * @param param Parameters to update.
 * @param flags Flag bits to set.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param,
    unsigned long flags);
""",
    "X509_VERIFY_PARAM_set_flags",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
    unsigned long flags);
""",
    """/**
 * @brief Clear X509_V_FLAG_* bits from verification parameters.
 * @param param Parameters to update.
 * @param flags Flag bits to clear.
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
    unsigned long flags);
""",
    "X509_VERIFY_PARAM_clear_flags",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
""",
    """/**
 * @brief Set the certificate purpose checked during verification.
 * @param param Verification parameters to update.
 * @param purpose Purpose identifier (see X509_PURPOSE_*).
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
""",
    "X509_VERIFY_PARAM_set_purpose",
)

patch_both(
    "x509_vfy.h",
    """uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param);
""",
    """/**
 * @brief Return the inheritance-control flags stored in @p param.
 * @param param Verification parameters to query.
 * @return Bitmask of X509_VP_FLAG_* inheritance flags.
 */
uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param);
""",
    "X509_VERIFY_PARAM_get_inh_flags",
)

patch_both(
    "x509_vfy.h",
    """int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,
    const char *email, size_t emaillen);
""",
    """/**
 * @brief Set the expected RFC822 mailbox for certificate name checks.
 * @param param Verification parameters to update.
 * @param email Email address bytes (need not be NUL-terminated if @p emaillen is set).
 * @param emaillen Length of @p email in bytes, or 0 to use strlen(@p email).
 * @return 1 on success, or 0 on failure.
 */
int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,
    const char *email, size_t emaillen);
""",
    "X509_VERIFY_PARAM_set1_email",
)

# ----- x509v3.h -----
patch_both(
    "x509v3.h",
    """    EVP_PKEY *issuer_pkey;
""",
    """    /** Issuer private key for signing constructed extensions. */
    EVP_PKEY *issuer_pkey;
""",
    "issuer_pkey",
)

patch_both(
    "x509v3.h",
    """    char *sname;
""",
    """    /** Short purpose name. */
    char *sname;
""",
    "sname",
)

patch_one(
    "x509v3.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ACCESS_DESCRIPTION, ACCESS_DESCRIPTION, ACCESS_DESCRIPTION)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ACCESS_DESCRIPTION) container type.
 */
struct stack_st_ACCESS_DESCRIPTION;
SKM_DEFINE_STACK_OF_INTERNAL(ACCESS_DESCRIPTION, ACCESS_DESCRIPTION, ACCESS_DESCRIPTION)
""",
    "stack_st_ACCESS_DESCRIPTION",
)

patch_one(
    "x509v3.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("ACCESS_DESCRIPTION");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ACCESS_DESCRIPTION) container type.
 */
struct stack_st_ACCESS_DESCRIPTION;
{-
    generate_stack_macros("ACCESS_DESCRIPTION");
-}
""",
    "stack_st_ACCESS_DESCRIPTION",
)

patch_one(
    "x509v3.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(POLICYINFO, POLICYINFO, POLICYINFO)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(POLICYINFO) container type.
 */
struct stack_st_POLICYINFO;
SKM_DEFINE_STACK_OF_INTERNAL(POLICYINFO, POLICYINFO, POLICYINFO)
""",
    "stack_st_POLICYINFO",
)

patch_one(
    "x509v3.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("POLICYINFO");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(POLICYINFO) container type.
 */
struct stack_st_POLICYINFO;
{-
    generate_stack_macros("POLICYINFO");
-}
""",
    "stack_st_POLICYINFO",
)

patch_both(
    "x509v3.h",
    """int X509_check_email(X509 *x, const char *chk, size_t chklen,
    unsigned int flags);
""",
    """/**
 * @brief Check whether a certificate's subjectAltName/subject email matches @p chk.
 * @param x Certificate to check.
 * @param chk Email address to compare (need not be NUL-terminated if @p chklen is set).
 * @param chklen Length of @p chk in bytes, or 0 to use strlen(@p chk).
 * @param flags X509_CHECK_FLAG_* controlling comparison behavior.
 * @return 1 on match, 0 on no match, or -1 on malformed input / error.
 */
int X509_check_email(X509 *x, const char *chk, size_t chklen,
    unsigned int flags);
""",
    "X509_check_email",
)

patch_both(
    "x509v3.h",
    """const GENERAL_NAME *ADMISSIONS_get0_admissionAuthority(const ADMISSIONS *a);
""",
    """/**
 * @brief Return the admission authority GENERAL_NAME from an ADMISSIONS entry.
 * @param a Admissions entry to query.
 * @return Internal pointer to the admission authority, or NULL if absent; must not be freed by the caller.
 */
const GENERAL_NAME *ADMISSIONS_get0_admissionAuthority(const ADMISSIONS *a);
""",
    "ADMISSIONS_get0_admissionAuthority",
)

patch_both(
    "x509v3.h",
    """const ASN1_OCTET_STRING *PROFESSION_INFO_get0_addProfessionInfo(
    const PROFESSION_INFO *pi);
""",
    """/**
 * @brief Return the additional profession info octet string from a PROFESSION_INFO.
 * @param pi Profession info to query.
 * @return Internal ASN1_OCTET_STRING pointer, or NULL if absent; must not be freed by the caller.
 */
const ASN1_OCTET_STRING *PROFESSION_INFO_get0_addProfessionInfo(
    const PROFESSION_INFO *pi);
""",
    "PROFESSION_INFO_get0_addProfessionInfo",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(" ", m)
    raise SystemExit(1)
