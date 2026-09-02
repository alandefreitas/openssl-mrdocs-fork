#!/usr/bin/env python3
"""Documentation repair batch 15a: async, cms, ct, dh, dsa, ec, engine, evp, pem, rand, rsa."""
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


print("=== batch 15a ===")

# ----- async.h -----
patch_both(
    "async.h",
    """void ASYNC_cleanup_thread(void);
""",
    """/**
 * @brief Release per-thread asynchronous job resources allocated by ASYNC_init_thread().
 *
 * Must be called on a thread that previously called ASYNC_init_thread() (or used
 * async jobs) after no ASYNC_JOB remains outstanding for that thread.
 */
void ASYNC_cleanup_thread(void);
""",
    "ASYNC_cleanup_thread",
)

# ----- cms.h -----
patch_both(
    "cms.h",
    """int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);
""",
    """/**
 * @brief Finalize CMS content processing after streaming through the BIO from CMS_dataInit().
 * @param cms ContentInfo whose content digests/signatures are completed.
 * @param bio BIO chain previously returned by CMS_dataInit() (or an equivalent filter chain).
 * @return 1 on success, or 0 on failure.
 */
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio);
""",
    "CMS_dataFinal",
)

patch_both(
    "cms.h",
    """int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
    const unsigned char *key, size_t keylen,
    BIO *dcont, BIO *out, unsigned int flags);
""",
    """/**
 * @brief Decrypt a CMS EncryptedData ContentInfo with a symmetric key.
 * @param cms EncryptedData ContentInfo to decrypt (AEAD ciphers are not supported).
 * @param key Symmetric decryption key bytes.
 * @param keylen Length of @p key in bytes.
 * @param dcont Detached encrypted-content BIO, or NULL when content is embedded.
 * @param out BIO that receives the decrypted plaintext.
 * @param flags Optional CMS flags (for example CMS_TEXT).
 * @return 1 on success, or 0 on failure.
 */
int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
    const unsigned char *key, size_t keylen,
    BIO *dcont, BIO *out, unsigned int flags);
""",
    "CMS_EncryptedData_decrypt",
)

patch_both(
    "cms.h",
    """CMS_ContentInfo *CMS_EncryptedData_encrypt_ex(BIO *in, const EVP_CIPHER *cipher,
    const unsigned char *key,
    size_t keylen, unsigned int flags,
    OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    """/**
 * @brief Create a CMS EncryptedData ContentInfo by encrypting data from a BIO (with libctx).
 * @param in BIO supplying the plaintext to encrypt.
 * @param cipher Symmetric cipher; must support ASN.1 encoding of its parameters (AEAD not supported).
 * @param key Encryption key bytes.
 * @param keylen Length of @p key in bytes.
 * @param flags CMS_* option flags such as CMS_DETACHED, CMS_STREAM, or CMS_PARTIAL.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for provider selection, or NULL.
 * @return New EncryptedData ContentInfo, or NULL on error.
 *
 * Unless CMS_STREAM and/or CMS_PARTIAL is set, CMS_final() is called internally.
 */
CMS_ContentInfo *CMS_EncryptedData_encrypt_ex(BIO *in, const EVP_CIPHER *cipher,
    const unsigned char *key,
    size_t keylen, unsigned int flags,
    OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    "CMS_EncryptedData_encrypt_ex",
)

patch_both(
    "cms.h",
    """STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
""",
    """/**
 * @brief Return the signer certificates collected during a successful CMS_verify().
 * @param cms SignedData ContentInfo previously verified with CMS_verify() or CMS_SignedData_verify().
 * @return Internal stack of signer certificates (do not free), or NULL on error.
 */
STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
""",
    "CMS_get0_signers",
)

patch_both(
    "cms.h",
    """EVP_PKEY_CTX *CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
""",
    """/**
 * @brief Return the EVP_PKEY_CTX used for key transport or key agreement on a recipient info.
 * @param ri Recipient info of type CMS_RECIPINFO_TRANS or CMS_RECIPINFO_AGREE.
 * @return Internal EVP_PKEY_CTX pointer (do not free), or NULL if none / wrong type.
 */
EVP_PKEY_CTX *CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
""",
    "CMS_RecipientInfo_get0_pkey_ctx",
)

patch_both(
    "cms.h",
    """STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);
""",
    """/**
 * @brief Return all CMS_SignerInfo structures from a SignedData ContentInfo.
 * @param cms ContentInfo expected to contain SignedData.
 * @return Internal stack of SignerInfos (do not free), or NULL if none / not SignedData.
 */
STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms);
""",
    "CMS_get0_SignerInfos",
)

patch_both(
    "cms.h",
    """int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain);
""",
    """/**
 * @brief Verify that the content digest matches a CMS SignerInfo (messageDigest or signature).
 * @param si SignerInfo whose content signature or signed messageDigest attribute is checked.
 * @param chain BIO chain supplying the signed content (as used during CMS verification).
 * @return 1 on success, 0 on failure, or a negative value on a more serious error.
 */
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain);
""",
    "CMS_SignerInfo_verify_content",
)

patch_both(
    "cms.h",
    """X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si, int loc);
""",
    """/**
 * @brief Return the signed attribute at index @p loc from a CMS SignerInfo.
 * @param si SignerInfo whose signedAttrs set is queried.
 * @param loc Zero-based attribute index (0 .. CMS_signed_get_attr_count() - 1).
 * @return Internal X509_ATTRIBUTE pointer (do not free), or NULL on error.
 */
X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si, int loc);
""",
    "CMS_signed_get_attr",
)

patch_both(
    "cms.h",
    """CMS_ReceiptRequest *CMS_ReceiptRequest_create0_ex(
    unsigned char *id, int idlen, int allorfirst,
    STACK_OF(GENERAL_NAMES) *receiptList,
    STACK_OF(GENERAL_NAMES) *receiptsTo,
    OSSL_LIB_CTX *libctx);
""",
    """/**
 * @brief Allocate a CMS signed-receipt request using a library context for RNG.
 * @param id Receipt content identifier bytes, or NULL to generate a random id.
 * @param idlen Length of @p id in bytes; ignored when @p id is NULL.
 * @param allorfirst Value for receiptsFrom allOrFirstTier when @p receiptList is NULL.
 * @param receiptList Stack of GeneralNames listing who should send receipts, or NULL.
 * @param receiptsTo Stack of GeneralNames listing where receipts should be sent, or NULL.
 * @param libctx Library context used to obtain the public random generator, or NULL.
 * @return New CMS_ReceiptRequest taking ownership of the stacks on success, or NULL on error.
 */
CMS_ReceiptRequest *CMS_ReceiptRequest_create0_ex(
    unsigned char *id, int idlen, int allorfirst,
    STACK_OF(GENERAL_NAMES) *receiptList,
    STACK_OF(GENERAL_NAMES) *receiptsTo,
    OSSL_LIB_CTX *libctx);
""",
    "CMS_ReceiptRequest_create0_ex",
)

patch_both(
    "cms.h",
    """void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr,
    ASN1_STRING **pcid,
    int *pallorfirst,
    STACK_OF(GENERAL_NAMES) **plist,
    STACK_OF(GENERAL_NAMES) **prto);
""",
    """/**
 * @brief Read the fields of a CMS ReceiptRequest without transferring ownership.
 * @param rr Receipt request to query.
 * @param pcid Receives the signedContentIdentifier, or NULL if not requested.
 * @param pallorfirst Receives allOrFirstTier when that receiptsFrom form is used, or NULL.
 * @param plist Receives the receiptList stack when that form is used, or NULL.
 * @param prto Receives the receiptsTo stack, or NULL if not requested.
 */
void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr,
    ASN1_STRING **pcid,
    int *pallorfirst,
    STACK_OF(GENERAL_NAMES) **plist,
    STACK_OF(GENERAL_NAMES) **prto);
""",
    "CMS_ReceiptRequest_get0_values",
)

# ----- ct.h (augment existing /* */ comments) -----
patch_both(
    "ct.h",
    """/*
 * Sets the certificate associated with the received SCTs.
 * Increments the reference count of cert.
 * Returns 1 on success, 0 otherwise.
 */
int CT_POLICY_EVAL_CTX_set1_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert);
""",
    """/*
 * Sets the certificate associated with the received SCTs.
 * Increments the reference count of cert.
 * Returns 1 on success, 0 otherwise.
 */
/**
 * @brief Set the certificate that the SCTs in a policy context were issued for.
 * @param ctx Policy evaluation context to update.
 * @param cert Certificate associated with the SCTs; a reference is taken.
 * @return 1 on success, or 0 on error.
 */
int CT_POLICY_EVAL_CTX_set1_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert);
""",
    "CT_POLICY_EVAL_CTX_set1_cert",
)

patch_both(
    "ct.h",
    """/*
 * Set *ext to point to the extension data for the SCT. ext must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext);
""",
    """/*
 * Set *ext to point to the extension data for the SCT. ext must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
/**
 * @brief Return a pointer to the extension data embedded in an SCT.
 * @param sct Signed Certificate Timestamp to query.
 * @param ext Non-NULL destination for an internal pointer to the extension bytes (do not free).
 * @return Length of the extension data in bytes.
 */
size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext);
""",
    "SCT_get0_extensions",
)

patch_both(
    "ct.h",
    """/*
 * Pretty-prints an |sct_list| to |out|.
 * It will be indented by the number of spaces specified by |indent|.
 * SCTs will be delimited by |separator|.
 * If |logs| is not NULL, it will be used to lookup the CT log that each SCT
 * came from, so that the log names can be printed.
 */
void SCT_LIST_print(const STACK_OF(SCT) *sct_list, BIO *out, int indent,
    const char *separator, const CTLOG_STORE *logs);
""",
    """/*
 * Pretty-prints an |sct_list| to |out|.
 * It will be indented by the number of spaces specified by |indent|.
 * SCTs will be delimited by |separator|.
 * If |logs| is not NULL, it will be used to lookup the CT log that each SCT
 * came from, so that the log names can be printed.
 */
/**
 * @brief Pretty-print a stack of SCTs to a BIO, optionally resolving log names.
 * @param sct_list Stack of Signed Certificate Timestamps to print.
 * @param out Destination BIO.
 * @param indent Number of leading spaces for each SCT.
 * @param separator Text inserted between consecutive SCTs.
 * @param logs Optional CT log store used to look up log names, or NULL.
 */
void SCT_LIST_print(const STACK_OF(SCT) *sct_list, BIO *out, int indent,
    const char *separator, const CTLOG_STORE *logs);
""",
    "SCT_LIST_print",
)

# ----- dh.h -----
patch_both(
    "dh.h",
    """int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid);
""",
    """/**
 * @brief Set the X9.42 KDF OID for DH key derivation, transferring ownership of @p oid.
 * @param ctx Key context configured for a DHX KDF / derive operation.
 * @param oid ASN.1 object identifying the CEK algorithm; @p ctx takes ownership.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid);
""",
    "EVP_PKEY_CTX_set0_dh_kdf_oid",
)

patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_up_ref(DH *dh);
""",
    """/**
 * @brief Increment the reference count of a DH object (deprecated).
 * @param dh Diffie-Hellman object whose reference count is increased.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_up_ref(DH *dh);
""",
    "DH_up_ref",
)

# ----- dsa.h -----
patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 DSA *DSA_new(void);
""",
    """/**
 * @brief Allocate an empty DSA object using the default method (deprecated).
 * @return New DSA, or NULL on failure; free with DSA_free().
 *
 * Prefer EVP_PKEY-based DSA APIs for new code.
 */
OSSL_DEPRECATEDIN_3_0 DSA *DSA_new(void);
""",
    "DSA_new",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
""",
    """/**
 * @brief Set the DSA domain parameters p, q, and g, transferring ownership (deprecated).
 * @param d DSA object to update.
 * @param p Prime modulus; ownership transfers to @p d.
 * @param q Subprime / order of g; ownership transfers to @p d.
 * @param g Generator; ownership transfers to @p d.
 * @return 1 on success, or 0 on failure.
 *
 * Prefer EVP_PKEY_set_bn_param() for new code. Do not free @p p, @p q, or @p g after success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
""",
    "DSA_set0_pqg",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_new(const char *name, int flags);
""",
    """/**
 * @brief Allocate a new DSA_METHOD with the given name and default flags (deprecated).
 * @param name NUL-terminated descriptive name; duplicated into the method object.
 * @param flags Flag bits copied onto DSA objects that use this method.
 * @return New DSA_METHOD, or NULL on failure; free with DSA_meth_free().
 */
OSSL_DEPRECATEDIN_3_0 DSA_METHOD *DSA_meth_new(const char *name, int flags);
""",
    "DSA_meth_new",
)

# ----- ec.h -----
patch_both(
    "ec.h",
    """typedef struct ec_group_st EC_GROUP;
""",
    """/**
 * @brief Opaque elliptic-curve parameter/group object (field, curve equation, and generator).
 */
typedef struct ec_group_st EC_GROUP;
""",
    "ec_group_st",
)

# ----- engine.h -----
patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_remove(ENGINE *e);
""",
    """/**
 * @brief Remove an ENGINE from the global ENGINE list (deprecated).
 * @param e Structural reference to the ENGINE to unregister.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_remove(ENGINE *e);
""",
    "ENGINE_remove",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_set_table_flags(unsigned int flags);
""",
    """/**
 * @brief Set the global ENGINE algorithm-table flags (deprecated).
 * @param flags Bitmask of ENGINE_TABLE_FLAG_* values (for example ENGINE_TABLE_FLAG_NOINIT).
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_set_table_flags(unsigned int flags);
""",
    "ENGINE_set_table_flags",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DH(ENGINE *e);
""",
    """/**
 * @brief Register @p e's DH method in the ENGINE DH implementation table (deprecated).
 * @param e ENGINE whose DH implementation should become available for selection.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_register_DH(ENGINE *e);
""",
    "ENGINE_register_DH",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_DH(ENGINE *e);
""",
    """/**
 * @brief Remove @p e's DH method from the ENGINE DH implementation table (deprecated).
 * @param e ENGINE previously registered for DH.
 */
OSSL_DEPRECATEDIN_3_0 void ENGINE_unregister_DH(ENGINE *e);
""",
    "ENGINE_unregister_DH",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_cmd_is_executable(ENGINE *e, int cmd);
""",
    """/**
 * @brief Test whether an ENGINE control command may be used as a config/setting command (deprecated).
 * @param e ENGINE whose command definitions are queried.
 * @param cmd Numeric command identifier from the ENGINE's cmd_defns.
 * @return 1 if @p cmd is usable via ENGINE_ctrl_cmd_string(), or 0 if it is internal-only / unavailable.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_cmd_is_executable(ENGINE *e, int cmd);
""",
    "ENGINE_cmd_is_executable",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_set_id(ENGINE *e, const char *id);
""",
    """/**
 * @brief Set the unique string identifier for an ENGINE (deprecated).
 * @param e ENGINE to update.
 * @param id NUL-terminated id; must remain valid for the life of @p e.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_id(ENGINE *e, const char *id);
""",
    "ENGINE_set_id",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_pkey_meth_engine(int nid);
""",
    """/**
 * @brief Obtain a functional reference to the default ENGINE implementing pkey method @p nid (deprecated).
 * @param nid NID of the EVP_PKEY_METHOD to look up.
 * @return Initialised ENGINE on success, or NULL if none is registered for @p nid.
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_get_pkey_meth_engine(int nid);
""",
    "ENGINE_get_pkey_meth_engine",
)

# ----- evp.h -----
patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
    const EVP_MD_CTX *from);
""",
    """/**
 * @brief Return the context-copy callback from a custom EVP_MD method (deprecated).
 * @param md Digest method to query.
 * @return Pointer to the copy callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
    const EVP_MD_CTX *from);
""",
    "EVP_MD_meth_get_copy",
)

patch_both(
    "evp.h",
    """int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
""",
    """/**
 * @brief Set algorithm parameters on a digest context via an OSSL_PARAM array.
 * @param ctx Digest context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
""",
    "EVP_MD_CTX_set_params",
)

patch_both(
    "evp.h",
    """int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
""",
    """/**
 * @brief Retrieve algorithm parameters from a RAND context into @p params.
 * @param ctx RAND context to query.
 * @param params OSSL_PARAM array describing the values to fetch (terminated by OSSL_PARAM_END).
 * @return 1 on success, or 0 on failure.
 */
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
""",
    "EVP_RAND_CTX_get_params",
)

patch_both(
    "evp.h",
    """OSSL_PROVIDER *EVP_SIGNATURE_get0_provider(const EVP_SIGNATURE *signature);
""",
    """/**
 * @brief Return the provider that implements a fetched EVP_SIGNATURE algorithm.
 * @param signature Signature algorithm object from EVP_SIGNATURE_fetch().
 * @return Borrowed OSSL_PROVIDER pointer (do not free), or NULL if unset.
 */
OSSL_PROVIDER *EVP_SIGNATURE_get0_provider(const EVP_SIGNATURE *signature);
""",
    "EVP_SIGNATURE_get0_provider",
)

patch_both(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth, int (*digest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
""",
    """/**
 * @brief Set the digest_custom callback on a custom EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param digest_custom Callback invoked by EVP_DigestSignInit()/VerifyInit() to hash algorithm-specific prefix data (for example SM2), or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth, int (*digest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));
""",
    "EVP_PKEY_meth_set_digest_custom",
)

# ----- pem.h -----
patch_both(
    "pem.h",
    """int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
""",
    """/**
 * @brief Read a named PEM object from a BIO, decrypting if needed, and return its DER bytes.
 * @param pdata Receives newly allocated DER payload (caller frees with OPENSSL_free).
 * @param plen Receives the length of *@p pdata in bytes.
 * @param pnm Optional; receives the actual PEM type name from the BEGIN line (caller frees).
 * @param name Expected PEM type label (for example "CERTIFICATE"); non-matching types are skipped.
 * @param bp BIO to read from.
 * @param cb Password callback for encrypted PEM, or NULL.
 * @param u Application data passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb,
    void *u);
""",
    "PEM_bytes_read_bio",
)

patch_both(
    "pem.h",
    """int PEM_write(FILE *fp, const char *name, const char *hdr,
    const unsigned char *data, long len);
""",
    """/**
 * @brief Write a PEM object (header, optional headers, and base64 body) to a FILE.
 * @param fp FILE that receives the PEM text.
 * @param name PEM type label such as "CERTIFICATE".
 * @param hdr Optional additional header lines, or NULL / empty string.
 * @param data Binary payload to base64-encode.
 * @param len Length of @p data in bytes.
 * @return 1 on success, or 0 on error.
 */
int PEM_write(FILE *fp, const char *name, const char *hdr,
    const unsigned char *data, long len);
""",
    "PEM_write",
)

# ----- rand.h -----
patch_both(
    "rand.h",
    """OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_engine(ENGINE *engine);
""",
    """/**
 * @brief Select an ENGINE as the source of the legacy RAND_METHOD (deprecated).
 * @param engine ENGINE providing a RAND implementation, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 *
 * Deprecated in OpenSSL 3.0; prefer EVP_RAND / provider-based DRBGs.
 */
OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_engine(ENGINE *engine);
""",
    "RAND_set_rand_engine",
)

patch_both(
    "rand.h",
    """/*
 * Equivalent of RAND_bytes() but additionally taking an OSSL_LIB_CTX and
 * a strength.
 */
int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
    unsigned int strength);
""",
    """/*
 * Equivalent of RAND_bytes() but additionally taking an OSSL_LIB_CTX and
 * a strength.
 */
/**
 * @brief Fill a buffer with public CSPRNG bytes using a library context and strength.
 * @param ctx Library context whose public DRBG is used, or NULL for the default.
 * @param buf Buffer that receives @p num random bytes.
 * @param num Number of bytes to generate.
 * @param strength Requested security strength in bits for the generated bytes.
 * @return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure.
 */
int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
    unsigned int strength);
""",
    "RAND_bytes_ex",
)

patch_both(
    "rand.h",
    """EVP_RAND_CTX *RAND_get0_private(OSSL_LIB_CTX *ctx);
""",
    """/**
 * @brief Return the thread-local private DRBG used by RAND_priv_bytes() for a library context.
 * @param ctx Library context, or NULL for the default.
 * @return Internal EVP_RAND_CTX pointer (do not free).
 */
EVP_RAND_CTX *RAND_get0_private(OSSL_LIB_CTX *ctx);
""",
    "RAND_get0_private",
)

# ----- rsa.h -----
patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmq1(const RSA *r);
""",
    """/**
 * @brief Return CRT exponent d mod (q-1) without duplicating it (deprecated).
 * @param r RSA key to query.
 * @return Internal BIGNUM pointer for dmq1, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *RSA_get0_dmq1(const RSA *r);
""",
    "RSA_get0_dmq1",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_PKCS1_OpenSSL(void);
""",
    """/**
 * @brief Return the built-in OpenSSL RSA_METHOD implementing PKCS#1 operations (deprecated).
 * @return Pointer to the default software RSA_METHOD (do not free).
 */
OSSL_DEPRECATEDIN_3_0 const RSA_METHOD *RSA_PKCS1_OpenSSL(void);
""",
    "RSA_PKCS1_OpenSSL",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
""",
    """/**
 * @brief Return the private-decrypt callback from an RSA_METHOD (deprecated).
 * @param meth Method table to query.
 * @return Pointer to the priv_dec callback used by RSA_private_decrypt(), or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0
int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))(int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa, int padding);
""",
    "RSA_meth_get_priv_dec",
)

print()
print(f"OK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
