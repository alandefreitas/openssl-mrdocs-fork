#!/usr/bin/env python3
"""Documentation repair batch 18e: ssl, stack, types, x509*."""
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


print("=== batch 18e: ssl/stack/types/x509 ===")

# ----- ssl.h -----

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_3_0 __owur int SRP_Calc_A_param(SSL *s);
""",
    """/**
 * @brief Compute the SRP client public value A for @p s (deprecated).
 * @param s SSL connection configured for SRP authentication.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 __owur int SRP_Calc_A_param(SSL *s);
""",
    "SRP_Calc_A_param",
)

patch_both(
    "ssl.h",
    """int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl,
    SSL_SESSION *sess);
""",
    """/**
 * @brief Return the new-session callback previously set on @p ctx.
 * @param ctx SSL_CTX to query.
 * @return Pointer to the callback, or NULL if unset.
 */
int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl,
    SSL_SESSION *sess);
""",
    "SSL_CTX_sess_get_new_cb",
)

patch_both(
    "ssl.h",
    """__owur int SSL_set1_host(SSL *s, const char *hostname);
""",
    """/**
 * @brief Set the expected DNS hostname used for certificate name checks (and SNI).
 * @param s SSL connection.
 * @param hostname DNS name to verify against the peer certificate; clears prior names.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set1_host(SSL *s, const char *hostname);
""",
    "SSL_set1_host",
)

patch_both(
    "ssl.h",
    """size_t SSL_client_hello_get0_random(SSL *s, const unsigned char **out);
""",
    """/**
 * @brief Return the ClientHello Random field from a client-hello callback context.
 * @param s SSL object during a client-hello callback.
 * @param out Receives a pointer to the random bytes (typically 32 bytes); do not free.
 * @return Number of random bytes, or 0 if unavailable.
 */
size_t SSL_client_hello_get0_random(SSL *s, const unsigned char **out);
""",
    "SSL_client_hello_get0_random",
)

patch_both(
    "ssl.h",
    """void *SSL_CTX_get_ex_data(const SSL_CTX *ssl, int idx);
""",
    """/**
 * @brief Retrieve application-specific data previously stored on an SSL_CTX.
 * @param ssl SSL_CTX that owns the ex_data table.
 * @param idx Index from SSL_CTX_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
void *SSL_CTX_get_ex_data(const SSL_CTX *ssl, int idx);
""",
    "SSL_CTX_get_ex_data",
)

patch_both(
    "ssl.h",
    """__owur int SSL_get_rpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc);
""",
    """/**
 * @brief Fill @p desc with the poll descriptor used to wait for readable SSL/QUIC data.
 * @param s SSL (or QUIC) connection.
 * @param desc Receives the BIO_POLL_DESCRIPTOR for the read side.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_get_rpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc);
""",
    "SSL_get_rpoll_descriptor",
)

# ----- stack.h -----

patch_one(
    "stack.h",
    """typedef struct stack_st OPENSSL_STACK; /* Use STACK_OF(...) instead */
""",
    """/**
 * @brief Opaque generic pointer stack; prefer the typed STACK_OF(...) wrappers.
 */
typedef struct stack_st OPENSSL_STACK; /* Use STACK_OF(...) instead */
""",
    "OPENSSL_STACK",
)

patch_one(
    "stack.h",
    """typedef void (*OPENSSL_sk_freefunc)(void *);
""",
    """/**
 * @brief Callback that frees one element when OPENSSL_sk_pop_free() drains a stack.
 */
typedef void (*OPENSSL_sk_freefunc)(void *);
""",
    "OPENSSL_sk_freefunc",
)

patch_one(
    "stack.h",
    """int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
""",
    """/**
 * @brief Append @p data to the end of a generic OPENSSL_STACK.
 * @param st Stack to modify.
 * @param data Element pointer to store.
 * @return Number of elements after the push, or 0 on failure.
 */
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
""",
    "OPENSSL_sk_push",
)

# ----- types.h -----

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
""",
    """/**
 * @brief ASN.1 INTEGER stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
/**
 * @brief ASN.1 BIT STRING stored in the generic asn1_string_st representation.
 */
typedef struct asn1_string_st ASN1_BIT_STRING;
""",
    "ASN1_INTEGER/BIT_STRING",
)

patch_one(
    "types.h",
    """typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
""",
    """/**
 * @brief Opaque ASN.1 method table describing how an EVP_PKEY type is encoded.
 */
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
""",
    "EVP_PKEY_ASN1_METHOD",
)

patch_one(
    "types.h",
    """typedef struct evp_kdf_ctx_st EVP_KDF_CTX;
""",
    """/**
 * @brief Opaque key-derivation function context (EVP_KDF_CTX_*).
 */
typedef struct evp_kdf_ctx_st EVP_KDF_CTX;
""",
    "EVP_KDF_CTX",
)

patch_one(
    "types.h",
    """typedef struct rsa_oaep_params_st RSA_OAEP_PARAMS;
""",
    """/**
 * @brief Opaque RSAES-OAEP parameter structure (hashFunc / maskGenFunc / pSourceFunc).
 */
typedef struct rsa_oaep_params_st RSA_OAEP_PARAMS;
""",
    "RSA_OAEP_PARAMS",
)

patch_one(
    "types.h",
    """typedef struct ec_key_method_st EC_KEY_METHOD;
""",
    """/**
 * @brief Opaque method table customizing EC_KEY operations (deprecated ENGINE-style API).
 */
typedef struct ec_key_method_st EC_KEY_METHOD;
""",
    "EC_KEY_METHOD",
)

patch_one(
    "types.h",
    """typedef struct ssl_ctx_st SSL_CTX;
""",
    """/**
 * @brief Opaque TLS/DTLS/QUIC context holding shared configuration and certificates.
 */
typedef struct ssl_ctx_st SSL_CTX;
""",
    "SSL_CTX",
)

patch_one(
    "types.h",
    """typedef struct ocsp_responder_id_st OCSP_RESPID;
""",
    """/**
 * @brief Opaque OCSP ResponderID (byName or byKey).
 */
typedef struct ocsp_responder_id_st OCSP_RESPID;
""",
    "OCSP_RESPID",
)

patch_one(
    "types.h",
    """typedef struct sct_st SCT;
""",
    """/**
 * @brief Opaque Certificate Transparency Signed Certificate Timestamp.
 */
typedef struct sct_st SCT;
""",
    "SCT",
)

patch_one(
    "types.h",
    """typedef struct ossl_item_st OSSL_ITEM;
""",
    """/**
 * @brief Opaque provider item pairing an identifier with a pointer payload.
 */
typedef struct ossl_item_st OSSL_ITEM;
""",
    "OSSL_ITEM",
)

patch_one(
    "types.h",
    """typedef struct ossl_param_bld_st OSSL_PARAM_BLD;
""",
    """/**
 * @brief Opaque builder that assembles a dynamic OSSL_PARAM array.
 */
typedef struct ossl_param_bld_st OSSL_PARAM_BLD;
""",
    "OSSL_PARAM_BLD",
)

patch_one(
    "types.h",
    """typedef struct ossl_self_test_st OSSL_SELF_TEST;
""",
    """/**
 * @brief Opaque self-test event object used by provider FIPS self-test callbacks.
 */
typedef struct ossl_self_test_st OSSL_SELF_TEST;
""",
    "OSSL_SELF_TEST",
)

# For record diagnostics on typedef struct X Y - MrDocs sometimes wants the
# underlying tag documented. Add forward briefs where the tag is opaque.
# ossl_param_bld_st, ocsp_responder_id_st, rsa_oaep_params_st, evp_kdf_ctx_st,
# evp_pkey_asn1_method_st were flagged as records.

def patch_typedef_with_struct(rel, typedef_line, struct_tag, brief, label):
    old = typedef_line
    # After our previous patches, typedef may already have a brief above it.
    # Find the documented form.
    new = f"""/**
 * @brief {brief}
 */
struct {struct_tag};
/**
 * @brief {brief}
 */
{typedef_line}"""
    # Prefer replacing already-documented typedef (brief + typedef)
    path = INC / rel
    text = path.read_text(encoding="utf-8")
    # Try: existing brief we just added + typedef
    needle = f"""/**
 * @brief {brief}
 */
{typedef_line}"""
    if needle in text:
        path.write_text(text.replace(needle, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    elif old in text:
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    else:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(f"{path.name}:{label}")


patch_typedef_with_struct(
    "types.h",
    "typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;\n",
    "evp_pkey_asn1_method_st",
    "Opaque ASN.1 method table describing how an EVP_PKEY type is encoded.",
    "evp_pkey_asn1_method_st record",
)
patch_typedef_with_struct(
    "types.h",
    "typedef struct evp_kdf_ctx_st EVP_KDF_CTX;\n",
    "evp_kdf_ctx_st",
    "Opaque key-derivation function context (EVP_KDF_CTX_*).",
    "evp_kdf_ctx_st record",
)
patch_typedef_with_struct(
    "types.h",
    "typedef struct rsa_oaep_params_st RSA_OAEP_PARAMS;\n",
    "rsa_oaep_params_st",
    "Opaque RSAES-OAEP parameter structure (hashFunc / maskGenFunc / pSourceFunc).",
    "rsa_oaep_params_st record",
)
patch_typedef_with_struct(
    "types.h",
    "typedef struct ocsp_responder_id_st OCSP_RESPID;\n",
    "ocsp_responder_id_st",
    "Opaque OCSP ResponderID (byName or byKey).",
    "ocsp_responder_id_st record",
)
patch_typedef_with_struct(
    "types.h",
    "typedef struct ossl_param_bld_st OSSL_PARAM_BLD;\n",
    "ossl_param_bld_st",
    "Opaque builder that assembles a dynamic OSSL_PARAM array.",
    "ossl_param_bld_st record",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """    int enc_len;
""",
    """    /** Length in bytes of the encrypted private-key material at @c enc_data. */
    int enc_len;
""",
    "enc_len",
)

patch_both(
    "x509.h",
    """char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
""",
    """/**
 * @brief Base64-encode a Netscape Signed Public Key and Challenge structure.
 * @param x SPKI to encode.
 * @return Newly allocated Base64 string, or NULL on failure; free with OPENSSL_free().
 */
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
""",
    "NETSCAPE_SPKI_b64_encode",
)

patch_both(
    "x509.h",
    """int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx);
""",
    """/**
 * @brief Sign certificate @p x using an already-initialized digest/signing context.
 * @param x Certificate whose signature is computed and stored.
 * @param ctx EVP_MD_CTX prepared for signing (digest + private key).
 * @return 1 on success, or 0 on failure.
 */
int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx);
""",
    "X509_sign_ctx",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
""",
    """/**
 * @brief Decode an EC private key in SEC1 DER form from a FILE (deprecated).
 * @param fp Input stream positioned at the DER encoding.
 * @param eckey Optional destination pointer updated to the result, or NULL.
 * @return Decoded EC_KEY, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
""",
    "d2i_ECPrivateKey_fp",
)

patch_both(
    "x509.h",
    """PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
    PKCS8_PRIV_KEY_INFO **p8inf);
""",
    """/**
 * @brief Decode a PKCS#8 PrivateKeyInfo structure from a FILE.
 * @param fp Input stream positioned at the DER encoding.
 * @param p8inf Optional destination pointer updated to the result, or NULL.
 * @return Decoded PKCS8_PRIV_KEY_INFO, or NULL on error.
 */
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
    PKCS8_PRIV_KEY_INFO **p8inf);
""",
    "d2i_PKCS8_PRIV_KEY_INFO_fp",
)

patch_both(
    "x509.h",
    """const char *X509_get_default_private_dir(void);
""",
    """/**
 * @brief Return the default directory path used for private-key files.
 * @return Internal path string (often from X509_PRIVATE_DIR); do not free.
 */
const char *X509_get_default_private_dir(void);
""",
    "X509_get_default_private_dir",
)

patch_both(
    "x509.h",
    """ASN1_OCTET_STRING *X509_get0_distinguishing_id(X509 *x);
""",
    """/**
 * @brief Return the distinguishing id OCTET STRING attached to certificate @p x, if any.
 * @param x Certificate to query.
 * @return Internal ASN1_OCTET_STRING pointer, or NULL; do not free.
 */
ASN1_OCTET_STRING *X509_get0_distinguishing_id(X509 *x);
""",
    "X509_get0_distinguishing_id",
)

patch_both(
    "x509.h",
    """int X509_REQ_get_attr_count(const X509_REQ *req);
""",
    """/**
 * @brief Return the number of attributes in a certificate request.
 * @param req Certificate signing request to query.
 * @return Attribute count (>= 0).
 */
int X509_REQ_get_attr_count(const X509_REQ *req);
""",
    "X509_REQ_get_attr_count",
)

patch_both(
    "x509.h",
    """int X509_NAME_add_entry(X509_NAME *name, const X509_NAME_ENTRY *ne,
    int loc, int set);
""",
    """/**
 * @brief Insert a copy of name entry @p ne into @p name at the given location/set.
 * @param name Distinguished name to modify.
 * @param ne Entry to copy into @p name.
 * @param loc Insertion index (-1 appends).
 * @param set Relative Distinguished Name set index (-1 starts a new RDN).
 * @return 1 on success, or 0 on failure.
 */
int X509_NAME_add_entry(X509_NAME *name, const X509_NAME_ENTRY *ne,
    int loc, int set);
""",
    "X509_NAME_add_entry",
)

patch_both(
    "x509.h",
    """ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
""",
    """/**
 * @brief Return the OCTET STRING payload of an X.509 extension.
 * @param ne Extension to query.
 * @return Internal ASN1_OCTET_STRING pointer, or NULL; do not free.
 */
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
""",
    "X509_EXTENSION_get_data",
)

patch_both(
    "x509.h",
    """int PKCS8_pkey_get0(const ASN1_OBJECT **ppkalg,
    const unsigned char **pk, int *ppklen,
    const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8);
""",
    """/**
 * @brief Extract algorithm and private-key octets from a PKCS#8 PrivateKeyInfo.
 * @param ppkalg Receives the algorithm OID, or NULL to skip.
 * @param pk Receives a pointer to the private-key bit string octets, or NULL to skip.
 * @param ppklen Receives the length of *@p pk, or NULL to skip.
 * @param pa Receives the AlgorithmIdentifier, or NULL to skip.
 * @param p8 PKCS#8 structure to query.
 * @return 1 on success, or 0 on failure.
 */
int PKCS8_pkey_get0(const ASN1_OBJECT **ppkalg,
    const unsigned char **pk, int *ppklen,
    const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8);
""",
    "PKCS8_pkey_get0",
)

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(X509_TRUST, X509_TRUST, X509_TRUST)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(X509_TRUST) container type.
 */
struct stack_st_X509_TRUST;
SKM_DEFINE_STACK_OF_INTERNAL(X509_TRUST, X509_TRUST, X509_TRUST)
""",
    "stack_st_X509_TRUST",
)

patch_both(
    "x509_vfy.h",
    """int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
    const char *name, int arg1, void *arg2);
""",
    """/**
 * @brief Register a custom X509_TRUST checking method under @p id.
 * @param id Trust identifier (X509_TRUST_* or an application-defined id).
 * @param flags X509_TRUST_* flag bits controlling the entry.
 * @param ck Callback that evaluates trust for a candidate certificate.
 * @param name Short name for the trust setting.
 * @param arg1 Integer argument stored on the X509_TRUST object.
 * @param arg2 Pointer argument stored on the X509_TRUST object.
 * @return 1 on success, or 0 on failure.
 */
int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
    const char *name, int arg1, void *arg2);
""",
    "X509_TRUST_add",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_print_verify_cb(int ok, X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Default verify callback that prints diagnosis details when verification fails.
 * @param ok Current verification status (1 success, 0 failure).
 * @param ctx Store context describing the failure/success.
 * @return The (possibly unchanged) @p ok value after logging.
 */
int X509_STORE_CTX_print_verify_cb(int ok, X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_print_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Callback that checks revocation status for certificates in a store context.
 * @param ctx Verification context whose current chain should be revocation-checked.
 * @return 1 if revocation checks succeed, or 0 on failure.
 */
typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_check_revocation_fn",
)

patch_both(
    "x509_vfy.h",
    """X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
    X509_OBJECT *x);
""",
    """/**
 * @brief Find an X509_OBJECT in @p h that matches the type and identity of @p x.
 * @param h Stack of store objects to search.
 * @param x Probe object describing the desired certificate or CRL.
 * @return Matching X509_OBJECT from @p h, or NULL if not found.
 */
X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
    X509_OBJECT *x);
""",
    "X509_OBJECT_retrieve_match",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
    X509_STORE_CTX_verify_cb verify);
""",
    """/**
 * @brief Install a verify callback on a store context (overrides the store default).
 * @param ctx Verification context to update.
 * @param verify Callback invoked for each certificate check; may be NULL.
 */
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
    X509_STORE_CTX_verify_cb verify);
""",
    "X509_STORE_CTX_set_verify_cb",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_CTX_get_by_subject(const X509_STORE_CTX *vs,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret);
""",
    """/**
 * @brief Look up a certificate or CRL by subject name via the store of @p vs.
 * @param vs Store context providing the X509_STORE and lookup state.
 * @param type X509_LU_X509 or X509_LU_CRL.
 * @param name Subject (or issuer for CRLs) name to match.
 * @param ret Destination object that receives a reference to the match.
 * @return 1 on success, or 0 if not found / on error.
 */
int X509_STORE_CTX_get_by_subject(const X509_STORE_CTX *vs,
    X509_LOOKUP_TYPE type,
    const X509_NAME *name, X509_OBJECT *ret);
""",
    "X509_STORE_CTX_get_by_subject",
)

patch_both(
    "x509_vfy.h",
    """int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const char *str, int len, X509_OBJECT *ret);
""",
    """/**
 * @brief Look up a certificate or CRL by alias / friendly name through a lookup method.
 * @param ctx Lookup method instance.
 * @param type X509_LU_X509 or X509_LU_CRL.
 * @param str Alias bytes.
 * @param len Length of @p str.
 * @param ret Destination object that receives a reference to the match.
 * @return 1 on success, or 0 if not found / on error.
 */
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
    const char *str, int len, X509_OBJECT *ret);
""",
    "X509_LOOKUP_by_alias",
)

patch_both(
    "x509_vfy.h",
    """int X509_STORE_load_locations_ex(X509_STORE *xs,
    const char *file, const char *dir,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Load trusted certificates from @p file and/or hashed @p dir into a store.
 * @param xs Destination X509_STORE.
 * @param file Optional PEM/bundle file of trusted certs, or NULL.
 * @param dir Optional directory of hashed cert files, or NULL.
 * @param libctx Library context for loading, or NULL for the default.
 * @param propq Property query for provider fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int X509_STORE_load_locations_ex(X509_STORE *xs,
    const char *file, const char *dir,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "X509_STORE_load_locations_ex",
)

patch_both(
    "x509_vfy.h",
    """X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(const X509_STORE_CTX *ctx);
""",
    """/**
 * @brief Return the parent store context when @p ctx is used for a nested check (for example CRL).
 * @param ctx Child verification context.
 * @return Parent X509_STORE_CTX, or NULL if @p ctx is top-level.
 */
X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(const X509_STORE_CTX *ctx);
""",
    "X509_STORE_CTX_get0_parent_ctx",
)

patch_both(
    "x509_vfy.h",
    """void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
""",
    """/**
 * @brief Transfer ownership of a verified certificate chain into a store context.
 * @param c Verification context whose chain is replaced.
 * @param sk Stack of X509 certificates (leaf first); ownership transfers to @p c.
 */
void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
""",
    "X509_STORE_CTX_set0_verified_chain",
)

# ----- x509v3.h -----

patch_both(
    "x509v3.h",
    """typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx, const char *str);
""",
    """/**
 * @brief Callback that parses a configuration string into an extension-specific structure.
 * @param method Extension method describing the target type.
 * @param ctx Extension configuration context (issuer/subject certificates, etc.).
 * @param str Configuration value string to parse.
 * @return Newly allocated extension value, or NULL on error.
 */
typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
    struct v3_ext_ctx *ctx, const char *str);
""",
    "X509V3_EXT_S2I",
)

patch_both(
    "x509v3.h",
    """int X509V3_extensions_print(BIO *out, const char *title,
    const STACK_OF(X509_EXTENSION) *exts,
    unsigned long flag, int indent);
""",
    """/**
 * @brief Print a stack of X.509v3 extensions to a BIO with an optional section title.
 * @param out Destination BIO.
 * @param title Optional heading printed before the extensions, or NULL.
 * @param exts Extensions to print.
 * @param flag X509V3_EXT_* print flags.
 * @param indent Indentation in spaces.
 * @return 1 on success, or 0 on failure.
 */
int X509V3_extensions_print(BIO *out, const char *title,
    const STACK_OF(X509_EXTENSION) *exts,
    unsigned long flag, int indent);
""",
    "X509V3_extensions_print",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
