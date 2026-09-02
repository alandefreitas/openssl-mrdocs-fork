#!/usr/bin/env python3
"""Documentation repair batch 7b: ct, dh, dsa, ec, engine, err, evp, kdf, lhash, params, pem, pkcs7, rsa, sha, srtp."""
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


# ----- ct.h -----
patch_both("ct.h",
"int CT_POLICY_EVAL_CTX_set1_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer);",
"""/**
 * @brief Set the issuer certificate used when validating precertificate SCTs.
 * @param ctx Policy evaluation context to update.
 * @param issuer Issuer certificate; a reference is taken (caller retains ownership).
 * @return 1 on success, or 0 on error.
 */
int CT_POLICY_EVAL_CTX_set1_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer);""",
"CT_POLICY_EVAL_CTX_set1_issuer")

patch_both("ct.h",
"void CT_POLICY_EVAL_CTX_set_time(CT_POLICY_EVAL_CTX *ctx, uint64_t time_in_ms);",
"""/**
 * @brief Set the time used when evaluating SCT timestamps in a policy context.
 * @param ctx Policy evaluation context to update.
 * @param time_in_ms Time since the Unix epoch in milliseconds.
 */
void CT_POLICY_EVAL_CTX_set_time(CT_POLICY_EVAL_CTX *ctx, uint64_t time_in_ms);""",
"CT_POLICY_EVAL_CTX_set_time")

patch_both("ct.h",
"""SCT *SCT_new_from_base64(unsigned char version,
    const char *logid_base64,
    ct_log_entry_type_t entry_type,
    uint64_t timestamp,
    const char *extensions_base64,
    const char *signature_base64);""",
"""/**
 * @brief Create an SCT from base64-encoded log id, extensions, and signature fields.
 * @param version SCT version byte (typically SCT_VERSION_V1).
 * @param logid_base64 Base64-encoded CT log ID.
 * @param entry_type Log entry type (X.509 certificate or precertificate).
 * @param timestamp SCT timestamp in milliseconds since the Unix epoch.
 * @param extensions_base64 Base64-encoded SCT extensions, or empty/NULL for none.
 * @param signature_base64 Base64-encoded SCT signature.
 * @return New SCT, or NULL on error; free with SCT_free.
 */
SCT *SCT_new_from_base64(unsigned char version,
    const char *logid_base64,
    ct_log_entry_type_t entry_type,
    uint64_t timestamp,
    const char *extensions_base64,
    const char *signature_base64);""",
"SCT_new_from_base64")

patch_both("ct.h",
"""__owur int SCT_set1_log_id(SCT *sct, const unsigned char *log_id,
    size_t log_id_len);""",
"""/**
 * @brief Set the CT log ID on an SCT by copying @p log_id.
 * @param sct SCT to update.
 * @param log_id Log ID bytes to copy.
 * @param log_id_len Length of @p log_id in bytes.
 * @return 1 on success, or 0 on error.
 */
__owur int SCT_set1_log_id(SCT *sct, const unsigned char *log_id,
    size_t log_id_len);""",
"SCT_set1_log_id")

patch_both("ct.h",
"int SCT_get_signature_nid(const SCT *sct);",
"""/**
 * @brief Return the NID of the signature algorithm used by an SCT.
 * @param sct SCT to query.
 * @return An NID such as NID_sha256WithRSAEncryption or NID_ecdsa_with_SHA256, or NID_undef.
 */
int SCT_get_signature_nid(const SCT *sct);""",
"SCT_get_signature_nid")

patch_both("ct.h",
"""__owur int SCT_set1_extensions(SCT *sct, const unsigned char *ext,
    size_t ext_len);""",
"""/**
 * @brief Set the SCT extensions field by copying @p ext.
 * @param sct SCT to update.
 * @param ext Extension bytes to copy, or NULL when @p ext_len is 0.
 * @param ext_len Length of @p ext in bytes.
 * @return 1 on success, or 0 on error.
 */
__owur int SCT_set1_extensions(SCT *sct, const unsigned char *ext,
    size_t ext_len);""",
"SCT_set1_extensions")

patch_both("ct.h",
"""__owur int SCT_set1_signature(SCT *sct, const unsigned char *sig,
    size_t sig_len);""",
"""/**
 * @brief Set the SCT signature by copying @p sig.
 * @param sct SCT to update.
 * @param sig Signature bytes to copy.
 * @param sig_len Length of @p sig in bytes.
 * @return 1 on success, or 0 on error.
 */
__owur int SCT_set1_signature(SCT *sct, const unsigned char *sig,
    size_t sig_len);""",
"SCT_set1_signature")

patch_both("ct.h",
"__owur int SCT_set_source(SCT *sct, sct_source_t source);",
"""/**
 * @brief Record where an SCT was obtained (TLS extension, OCSP, X.509 extension, etc.).
 * @param sct SCT to update.
 * @param source Origin tag from sct_source_t.
 * @return 1 on success, or 0 on error.
 */
__owur int SCT_set_source(SCT *sct, sct_source_t source);""",
"SCT_set_source")

patch_both("ct.h",
"""STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
    size_t len);""",
"""/**
 * @brief Decode a TLS-format (not DER) list of SCTs from @p pp.
 * @param a Optional destination stack pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the TLS-encoded SCT list; advanced past the data.
 * @param len Number of bytes available at *@p pp.
 * @return Stack of SCTs, or NULL on error.
 */
STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
    size_t len);""",
"o2i_SCT_LIST")

patch_both("ct.h",
"CTLOG_STORE *CTLOG_STORE_new(void);",
"""/**
 * @brief Allocate an empty CT log store.
 * @return New CTLOG_STORE, or NULL on allocation failure; free with CTLOG_STORE_free.
 */
CTLOG_STORE *CTLOG_STORE_new(void);""",
"CTLOG_STORE_new")

# ----- dh.h -----
patch_both("dh.h",
"int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qlen);",
"""/**
 * @brief Set the DH parameter-generation subprime (q) length in bits.
 * @param ctx EVP_PKEY_CTX configured for DH parameter generation.
 * @param qlen Desired bit length of the subprime q.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qlen);""",
"EVP_PKEY_CTX_set_dh_paramgen_subprime_len")

patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 int DHparams_print_fp(FILE *fp, const DH *x);",
"""/**
 * @brief Print DH parameters to a FILE in human-readable form (deprecated).
 * @param fp Output FILE.
 * @param x DH object whose parameters are printed.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DHparams_print_fp(FILE *fp, const DH *x);""",
"DHparams_print_fp")

patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 int DH_set_length(DH *dh, long length);",
"""/**
 * @brief Set the optional private-value length hint on a DH object (deprecated).
 * @param dh DH object to update.
 * @param length Preferred length in bits of the secret exponent, or 0 for the default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_set_length(DH *dh, long length);""",
"DH_set_length")

# ----- dsa.h -----
patch_both("dsa.h",
"""OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign(DSA_METHOD *dsam,
    DSA_SIG *(*sign)(const unsigned char *, int, DSA *));""",
"""/**
 * @brief Install the DSA signing callback on a DSA_METHOD (deprecated).
 * @param dsam Method being configured.
 * @param sign Callback that signs a digest and returns a DSA_SIG, or NULL to clear.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_sign(DSA_METHOD *dsam,
    DSA_SIG *(*sign)(const unsigned char *, int, DSA *));""",
"DSA_meth_set_sign")

patch_both("dsa.h",
"OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_sign_setup(const DSA_METHOD *dsam))(DSA *, BN_CTX *, BIGNUM **, BIGNUM **);",
"""/**
 * @brief Return the sign-setup callback installed on a DSA_METHOD (deprecated).
 * @param dsam Method to query.
 * @return Sign-setup function pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_sign_setup(const DSA_METHOD *dsam))(DSA *, BN_CTX *, BIGNUM **, BIGNUM **);""",
"DSA_meth_get_sign_setup")

# ----- ec.h -----
patch_both("ec.h",
"unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);",
"""/**
 * @brief Return a pointer to the optional seed associated with an EC_GROUP.
 * @param x Group to query.
 * @return Pointer to the internal seed bytes, or NULL if no seed is set.
 */
unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);""",
"EC_GROUP_get0_seed")

patch_both("ec.h",
"int EC_curve_nist2nid(const char *name);",
"""/**
 * @brief Map a NIST curve name such as \"P-256\" to the corresponding OpenSSL NID.
 * @param name NIST short name (for example \"P-256\", \"B-571\").
 * @return Curve NID on success, or NID_undef if @p name is not recognized.
 */
int EC_curve_nist2nid(const char *name);""",
"EC_curve_nist2nid")

# ----- engine.h -----
patch_both("engine.h",
"OSSL_DEPRECATEDIN_3_0 int ENGINE_register_all_complete(void);",
"""/**
 * @brief Register all loaded ENGINEs for every algorithm they implement (deprecated).
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_all_complete(void);""",
"ENGINE_register_all_complete")

# ----- err.h -----
# Macro-generated LHASH record: exclude via mrdocs.yml rather than expanding DEFINE_LHASH_OF_INTERNAL.
patch_both("err.h",
"int ERR_load_strings_const(const ERR_STRING_DATA *str);",
"""/**
 * @brief Register a const ERR_STRING_DATA table whose last entry has error == 0.
 * @param str Array of error-code / string pairs terminated by a zero error code.
 * @return 1 on success, or 0 on error.
 */
int ERR_load_strings_const(const ERR_STRING_DATA *str);""",
"ERR_load_strings_const")

patch_both("err.h",
"OSSL_DEPRECATEDIN_1_0_0 void ERR_remove_state(unsigned long pid);",
"""/**
 * @brief Remove the error queue for a process id (deprecated; use ERR_remove_thread_state).
 * @param pid Ignored; historically identified the process whose state was cleared.
 */
OSSL_DEPRECATEDIN_1_0_0 void ERR_remove_state(unsigned long pid);""",
"ERR_remove_state")

# ----- evp.h -----
patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);""",
"""/**
 * @brief Set the input block size advertised by a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param blocksize Block size in bytes (for example 64 for SHA-1).
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);""",
"EVP_MD_meth_set_input_blocksize")

patch_both("evp.h",
"int EVP_MD_get_pkey_type(const EVP_MD *md);",
"""/**
 * @brief Return the legacy public-key NID associated with a digest method.
 * @param md Digest method to query.
 * @return NID of the traditional combined pkey+digest type, or NID_undef.
 */
int EVP_MD_get_pkey_type(const EVP_MD *md);""",
"EVP_MD_get_pkey_type")

patch_both("evp.h",
"unsigned long EVP_MD_get_flags(const EVP_MD *md);",
"""/**
 * @brief Return the flag bits associated with a digest method.
 * @param md Digest method to query.
 * @return Bitmask of EVP_MD_FLAG_* values.
 */
unsigned long EVP_MD_get_flags(const EVP_MD *md);""",
"EVP_MD_get_flags")

patch_both("evp.h",
"int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);",
"""/**
 * @brief Return the IV length in bytes required by a cipher.
 * @param cipher Cipher method to query.
 * @return IV length, or 0 if the cipher does not use an IV.
 */
int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);""",
"EVP_CIPHER_get_iv_length")

patch_both("evp.h",
"int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher);",
"""/**
 * @brief Return the cipher mode constant for a cipher method.
 * @param cipher Cipher method to query.
 * @return An EVP_CIPH_*_MODE value (for example EVP_CIPH_CBC_MODE).
 */
int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher);""",
"EVP_CIPHER_get_mode")

patch_both("evp.h",
"EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);",
"""/**
 * @brief Duplicate a cipher context, including its algorithm state.
 * @param in Context to copy.
 * @return Newly allocated copy, or NULL on error; free with EVP_CIPHER_CTX_free.
 */
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);""",
"EVP_CIPHER_CTX_dup")

patch_both("evp.h",
"""__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
"""/**
 * @brief Finish decryption and write any remaining plaintext (legacy wrapper).
 * @param ctx Decryption context previously updated with EVP_DecryptUpdate.
 * @param outm Buffer receiving the final plaintext block(s).
 * @param outl Receives the number of bytes written to @p outm.
 * @return 1 on success, 0 on padding/authentication failure, or a negative value on error.
 */
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);""",
"EVP_DecryptFinal")

patch_both("evp.h",
"""__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen);""",
"""/**
 * @brief Finalize a DigestSign operation and write the signature.
 * @param ctx Context initialized with EVP_DigestSignInit and updated with EVP_DigestSignUpdate.
 * @param sigret Buffer receiving the signature, or NULL to only query the required length.
 * @param siglen On entry, size of @p sigret; on exit, signature length (or required size).
 * @return 1 on success, or 0 / a negative value on error.
 */
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen);""",
"EVP_DigestSignFinal")

patch_both("evp.h",
"""__owur int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    const unsigned char *ek, int ekl,
    const unsigned char *iv, EVP_PKEY *priv);""",
"""/**
 * @brief Initialize envelope decryption: unwrap @p ek with @p priv and set up @p type.
 * @param ctx Cipher context to initialize for decryption.
 * @param type Content-encryption cipher, or NULL to defer until a later call.
 * @param ek Encrypted content-encryption key.
 * @param ekl Length of @p ek in bytes.
 * @param iv IV for @p type, or NULL if not required yet.
 * @param priv Recipient private key used to decrypt @p ek.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    const unsigned char *ek, int ekl,
    const unsigned char *iv, EVP_PKEY *priv);""",
"EVP_OpenInit")

patch_both("evp.h",
"const EVP_MD *EVP_md_null(void);",
"""/**
 * @brief Return the null digest method (zero-length digest, for testing/legacy use).
 * @return Pointer to the static null EVP_MD.
 */
const EVP_MD *EVP_md_null(void);""",
"EVP_md_null")

patch_both("evp.h",
"const EVP_MD *EVP_md5(void);",
"""/**
 * @brief Return the MD5 digest method (128-bit output).
 * @return Pointer to the static MD5 EVP_MD.
 */
const EVP_MD *EVP_md5(void);""",
"EVP_md5")

patch_both("evp.h",
"const EVP_MD *EVP_sha1(void);",
"""/**
 * @brief Return the SHA-1 digest method (160-bit output).
 * @return Pointer to the static SHA-1 EVP_MD.
 */
const EVP_MD *EVP_sha1(void);""",
"EVP_sha1")

patch_both("evp.h",
"""EVP_RAND *EVP_RAND_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);""",
"""/**
 * @brief Fetch a random-number generator implementation from providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as \"CTR-DRBG\" or \"HASH-DRBG\".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_RAND, or NULL on error; free with EVP_RAND_free.
 */
EVP_RAND *EVP_RAND_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);""",
"EVP_RAND_fetch")

patch_both("evp.h",
"void EVP_RAND_free(EVP_RAND *rand);",
"""/**
 * @brief Release a reference to an EVP_RAND obtained from EVP_RAND_fetch.
 * @param rand RNG method to free, or NULL.
 */
void EVP_RAND_free(EVP_RAND *rand);""",
"EVP_RAND_free")

patch_both("evp.h",
"""__owur int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr, size_t pstr_len,""",
"""/**
 * @brief Instantiate (seed) an EVP_RAND_CTX so it can generate random bytes.
 * @param ctx RNG context to instantiate.
 * @param strength Requested security strength in bits.
 * @param prediction_resistance Non-zero to force a reseed from live entropy.
 * @param pstr Optional personalization string, or NULL.
 * @param pstr_len Length of @p pstr in bytes.
 * @param params Optional OSSL_PARAM array of additional parameters, or NULL.
 * @return 1 on success, or 0 on error.
 */
__owur int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr, size_t pstr_len,""",
"EVP_RAND_instantiate")

patch_both("evp.h",
"""void EVP_PKEY_asn1_set_public_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_pub_check)(const EVP_PKEY *pk));""",
"""/**
 * @brief Install the public-key consistency check callback on an ASN.1 method.
 * @param ameth ASN.1 method being configured.
 * @param pkey_pub_check Callback that returns 1 if @p pk's public key is valid, or NULL to clear.
 */
void EVP_PKEY_asn1_set_public_check(EVP_PKEY_ASN1_METHOD *ameth,
    int (*pkey_pub_check)(const EVP_PKEY *pk));""",
"EVP_PKEY_asn1_set_public_check")

patch_both("evp.h",
"""void EVP_KEM_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEM *wrap, void *arg), void *arg);""",
"""/**
 * @brief Call @p fn for every KEM algorithm available from providers in @p libctx.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback invoked with each EVP_KEM and @p arg.
 * @param arg User argument forwarded to @p fn.
 */
void EVP_KEM_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KEM *wrap, void *arg), void *arg);""",
"EVP_KEM_do_all_provided")

patch_both("evp.h",
"""int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
    unsigned char *buf, size_t max_buf_sz,
    size_t *out_sz);""",
"""/**
 * @brief Read an octet-string parameter from a key by OSSL_PKEY_PARAM name.
 * @param pkey Key to query.
 * @param key_name Parameter name (for example OSSL_PKEY_PARAM_PUB_KEY).
 * @param buf Destination buffer, or NULL to only query the required size.
 * @param max_buf_sz Capacity of @p buf in bytes.
 * @param out_sz Receives the parameter length in bytes.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
    unsigned char *buf, size_t max_buf_sz,
    size_t *out_sz);""",
"EVP_PKEY_get_octet_string_param")

patch_both("evp.h",
"OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth, int (**pcopy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));",
"""/**
 * @brief Retrieve the context-copy callback from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pcopy Receives the copy callback pointer (may be set to NULL if unset).
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth, int (**pcopy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src));""",
"EVP_PKEY_meth_get_copy")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth, int (**pverify_init)(EVP_PKEY_CTX *ctx),
    int (**pverify)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs, size_t tbslen));""",
"""/**
 * @brief Retrieve the verify-init and verify callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pverify_init Receives the verify-init callback pointer.
 * @param pverify Receives the verify callback pointer.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth, int (**pverify_init)(EVP_PKEY_CTX *ctx),
    int (**pverify)(EVP_PKEY_CTX *ctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs, size_t tbslen));""",
"EVP_PKEY_meth_get_verify")

patch_both("evp.h",
"""OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth,
    int (**pverify_recover_init)(EVP_PKEY_CTX *ctx),
    int (**pverify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,""",
"""/**
 * @brief Retrieve the verify-recover callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method to query.
 * @param pverify_recover_init Receives the verify-recover-init callback pointer.
 * @param pverify_recover Receives the verify-recover callback pointer.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth,
    int (**pverify_recover_init)(EVP_PKEY_CTX *ctx),
    int (**pverify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig,""",
"EVP_PKEY_meth_get_verify_recover")

# ----- kdf.h -----
patch_both("kdf.h",
"int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *ctx, uint64_t n);",
"""/**
 * @brief Set the scrypt CPU/memory cost parameter N on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param n Cost parameter N (power of two).
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *ctx, uint64_t n);""",
"EVP_PKEY_CTX_set_scrypt_N")

patch_both("kdf.h",
"int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *ctx, uint64_t p);",
"""/**
 * @brief Set the scrypt parallelization parameter p on a PKEY KDF context.
 * @param ctx Context configured for the scrypt KDF.
 * @param p Parallelization parameter.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *ctx, uint64_t p);""",
"EVP_PKEY_CTX_set_scrypt_p")

patch_both("kdf.h",
"""int EVP_PKEY_CTX_set_scrypt_maxmem_bytes(EVP_PKEY_CTX *ctx,
    uint64_t maxmem_bytes);""",
"""/**
 * @brief Cap the memory scrypt may use during key derivation.
 * @param ctx Context configured for the scrypt KDF.
 * @param maxmem_bytes Maximum bytes of RAM the derivation may consume.
 * @return 1 on success, or a negative value on error.
 */
int EVP_PKEY_CTX_set_scrypt_maxmem_bytes(EVP_PKEY_CTX *ctx,
    uint64_t maxmem_bytes);""",
"EVP_PKEY_CTX_set_scrypt_maxmem_bytes")

# ----- lhash.h -----
patch_both("lhash.h",
"int OPENSSL_LH_error(OPENSSL_LHASH *lh);",
"""/**
 * @brief Return whether the last LHASH operation on @p lh failed due to memory error.
 * @param lh Hash table to query.
 * @return Non-zero if an allocation error occurred, or 0 otherwise.
 */
int OPENSSL_LH_error(OPENSSL_LHASH *lh);""",
"OPENSSL_LH_error")

patch_both("lhash.h",
"void OPENSSL_LH_free(OPENSSL_LHASH *lh);",
"""/**
 * @brief Free an LHASH table structure (does not free the caller-owned entries).
 * @param lh Hash table to free, or NULL.
 */
void OPENSSL_LH_free(OPENSSL_LHASH *lh);""",
"OPENSSL_LH_free")

patch_both("lhash.h",
"unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh);",
"""/**
 * @brief Return the number of entries stored in an LHASH table.
 * @param lh Hash table to query.
 * @return Entry count.
 */
unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh);""",
"OPENSSL_LH_num_items")

# ----- params.h -----
patch_both("params.h",
"OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf);",
"""/**
 * @brief Construct an OSSL_PARAM describing a double located at @p buf.
 * @param key Parameter name.
 * @param buf Address of the double value (read or written by the callee).
 * @return OSSL_PARAM suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf);""",
"OSSL_PARAM_construct_double")

# ----- pem.h -----
patch_both("pem.h",
"""int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
    const unsigned char *data, long len);""",
"""/**
 * @brief Write a PEM object (header, optional headers, and base64 body) to a BIO.
 * @param bp BIO that receives the PEM text.
 * @param name PEM type label such as \"CERTIFICATE\".
 * @param hdr Optional additional header lines, or NULL / empty string.
 * @param data Binary payload to base64-encode.
 * @param len Length of @p data in bytes.
 * @return 1 on success, or 0 on error.
 */
int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
    const unsigned char *data, long len);""",
"PEM_write_bio")

patch_both("pem.h",
"""int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    unsigned int *siglen, EVP_PKEY *pkey);""",
"""/**
 * @brief Finalize a PEM signing operation and write the signature.
 * @param ctx Digest context previously updated with data to sign.
 * @param sigret Buffer receiving the signature.
 * @param siglen Receives the signature length in bytes.
 * @param pkey Private key used to generate the signature.
 * @return 1 on success, or 0 on error.
 */
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
    unsigned int *siglen, EVP_PKEY *pkey);""",
"PEM_SignFinal")

# ----- pkcs7.h -----
patch_both("pkcs7.h",
"    const EVP_CIPHER *cipher;",
"""    /** Content-encryption cipher used when creating encrypted content (not serialized). */
    const EVP_CIPHER *cipher;""",
"PKCS7_ENC_CONTENT::cipher")

patch_both("pkcs7.h",
"DECLARE_ASN1_ITEM(PKCS7_ATTR_VERIFY)",
"""/**
 * @brief Return the ASN.1 item descriptor used when verifying PKCS#7 authenticated attributes.
 * @return Pointer to the static ASN1_ITEM for PKCS7_ATTR_VERIFY.
 */
const ASN1_ITEM *PKCS7_ATTR_VERIFY_it(void);""",
"PKCS7_ATTR_VERIFY_it")

patch_both("pkcs7.h",
"int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);",
"""/**
 * @brief Add a recipient info structure to a PKCS#7 enveloped-data object.
 * @param p7 PKCS#7 object of type enveloped or signed-and-enveloped data.
 * @param ri Recipient info to append; on success ownership transfers to @p p7.
 * @return 1 on success, or 0 on error.
 */
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);""",
"PKCS7_add_recipient_info")

patch_both("pkcs7.h",
"""int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int type,
    void *data);""",
"""/**
 * @brief Add an authenticated (signed) attribute to a PKCS#7 signer info.
 * @param p7si Signer info receiving the attribute.
 * @param nid Attribute type NID (for example NID_pkcs9_contentType).
 * @param type ASN.1 value type tag (V_ASN1_*) for @p data.
 * @param data Attribute value pointer interpreted according to @p type.
 * @return 1 on success, or 0 on error.
 */
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int type,
    void *data);""",
"PKCS7_add_signed_attribute")

patch_both("pkcs7.h",
"ASN1_TYPE *PKCS7_get_signed_attribute(const PKCS7_SIGNER_INFO *si, int nid);",
"""/**
 * @brief Return a signed attribute of type @p nid from a PKCS#7 signer info.
 * @param si Signer info to search.
 * @param nid Attribute type NID to look up.
 * @return Pointer to the attribute value, or NULL if not present.
 */
ASN1_TYPE *PKCS7_get_signed_attribute(const PKCS7_SIGNER_INFO *si, int nid);""",
"PKCS7_get_signed_attribute")

patch_both("pkcs7.h",
"""PKCS7 *PKCS7_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, int flags, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"""/**
 * @brief Create a PKCS#7 signed-data structure, with library context and property query.
 * @param signcert Signer certificate, or NULL when only adding certs/flags require it.
 * @param pkey Private key corresponding to @p signcert, or NULL for deferred signing.
 * @param certs Optional additional certificates to include, or NULL.
 * @param data BIO supplying the content to sign when not using detached/streaming flags.
 * @param flags PKCS7_* flags controlling detached content, streaming, and attributes.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return New PKCS7, or NULL on error; free with PKCS7_free.
 */
PKCS7 *PKCS7_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, int flags, OSSL_LIB_CTX *libctx,
    const char *propq);""",
"PKCS7_sign_ex")

# ----- rsa.h -----
patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 int RSA_bits(const RSA *rsa);",
"""/**
 * @brief Return the bit length of an RSA modulus (deprecated; use EVP_PKEY_get_bits).
 * @param rsa RSA key to query.
 * @return Number of significant bits in the modulus n.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_bits(const RSA *rsa);""",
"RSA_bits")

patch_both("rsa.h",
"OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_e(const RSA *d);",
"""/**
 * @brief Return the public exponent e of an RSA key without transferring ownership (deprecated).
 * @param d RSA key to query.
 * @return Pointer to the internal BIGNUM for e, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_e(const RSA *d);""",
"RSA_get0_e")

# ----- sha.h -----
patch_both("sha.h",
"OSSL_DEPRECATEDIN_3_0 int SHA224_Final(unsigned char *md, SHA256_CTX *c);",
"""/**
 * @brief Place the SHA-224 digest into @p md and clear @p c (deprecated).
 * @param md Buffer of at least SHA224_DIGEST_LENGTH bytes receiving the digest.
 * @param c SHA-224/256 context previously updated with SHA224_Update.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int SHA224_Final(unsigned char *md, SHA256_CTX *c);""",
"SHA224_Final")

# ----- srtp.h -----
patch_both("srtp.h",
"__owur SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);",
"""/**
 * @brief Return the SRTP protection profile negotiated on an SSL/DTLS connection.
 * @param s SSL connection that completed an SRTP negotiation (use_srtp extension).
 * @return Selected profile, or NULL if none was negotiated.
 */
__owur SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);""",
"SSL_get_selected_srtp_profile")

print(f"\nDone 7b: {len(ok)} ok, {len(missing)} missing")
for m in missing:
    print(" ", m)
