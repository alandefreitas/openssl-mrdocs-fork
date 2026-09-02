#!/usr/bin/env python3
"""Documentation repair batch 15b: pkcs7.h remaining fields and APIs."""
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


def asn1_funcs(typename, brief):
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {typename}, or NULL on allocation failure.
 */
{typename} *{typename}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {typename}_free({typename} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {typename}, or NULL on error.
 */
{typename} *d2i_{typename}({typename} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{typename}(const {typename} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {typename}.
 * @return Pointer to the static ASN1_ITEM for {typename}.
 */
const ASN1_ITEM *{typename}_it(void);"""


print("=== batch 15b: pkcs7.h ===")

# ----- struct fields -----
patch_both(
    "pkcs7.h",
    """    /** Issuer name and serial number identifying the signing certificate. */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;
""",
    """    /** Issuer name and serial number identifying the signing certificate. */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    /** Message-digest AlgorithmIdentifier used by this signer. */
    X509_ALGOR *digest_alg;
""",
    "digest_alg",
)

patch_both(
    "pkcs7.h",
    """    ASN1_INTEGER *version; /* version 0 */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    /** Algorithm used to encrypt the content-encryption key for this recipient. */
""",
    """    ASN1_INTEGER *version; /* version 0 */
    /** Issuer name and serial number identifying the recipient certificate. */
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    /** Algorithm used to encrypt the content-encryption key for this recipient. */
""",
    "PKCS7_RECIP_INFO.issuer_and_serial",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_signed_st {
    ASN1_INTEGER *version; /* version 1 */
""",
    """typedef struct pkcs7_signed_st {
    /** PKCS#7 SignedData version (typically 1). */
    ASN1_INTEGER *version; /* version 1 */
""",
    "PKCS7_SIGNED.version",
)

patch_both(
    "pkcs7.h",
    """    /** Signer infos describing each signature over the SignedData content. */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    struct pkcs7_st *contents;
} PKCS7_SIGNED;
""",
    """    /** Signer infos describing each signature over the SignedData content. */
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    /** Encapsulated content being signed (nested PKCS#7 ContentInfo). */
    struct pkcs7_st *contents;
} PKCS7_SIGNED;
""",
    "PKCS7_SIGNED.contents",
)

patch_both(
    "pkcs7.h",
    """    /** Content-encryption cipher used when creating encrypted content (not serialized). */
    const EVP_CIPHER *cipher;
    const PKCS7_CTX *ctx;
} PKCS7_ENC_CONTENT;
""",
    """    /** Content-encryption cipher used when creating encrypted content (not serialized). */
    const EVP_CIPHER *cipher;
    /** Library/provider context associated with this encrypted content (not serialized). */
    const PKCS7_CTX *ctx;
} PKCS7_ENC_CONTENT;
""",
    "PKCS7_ENC_CONTENT.ctx",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_digest_st {
    ASN1_INTEGER *version; /* version 0 */
    /** Message-digest AlgorithmIdentifier used for DigestedData. */
    X509_ALGOR *md; /* md used */
    struct pkcs7_st *contents;
    ASN1_OCTET_STRING *digest;
} PKCS7_DIGEST;
""",
    """typedef struct pkcs7_digest_st {
    /** PKCS#7 DigestedData version (typically 0). */
    ASN1_INTEGER *version; /* version 0 */
    /** Message-digest AlgorithmIdentifier used for DigestedData. */
    X509_ALGOR *md; /* md used */
    /** Encapsulated content whose digest is stored in @c digest. */
    struct pkcs7_st *contents;
    /** Message digest octets computed over the encapsulated content. */
    ASN1_OCTET_STRING *digest;
} PKCS7_DIGEST;
""",
    "PKCS7_DIGEST.version/contents/digest",
)

patch_both(
    "pkcs7.h",
    """    /**
     * Cached DER encoding of this PKCS#7 structure when non-NULL.
     */
    unsigned char *asn1;
    long length;
""",
    """    /**
     * Cached DER encoding of this PKCS#7 structure when non-NULL.
     */
    unsigned char *asn1;
    /** Length in bytes of the cached DER encoding at @c asn1, or 0 when unused. */
    long length;
""",
    "PKCS7.length",
)

# ----- stacks (.h uses SKM; .in uses generate_stack_macros) -----
patch_one(
    "pkcs7.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(PKCS7_RECIP_INFO, PKCS7_RECIP_INFO, PKCS7_RECIP_INFO)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PKCS7_RECIP_INFO) container type.
 */
SKM_DEFINE_STACK_OF_INTERNAL(PKCS7_RECIP_INFO, PKCS7_RECIP_INFO, PKCS7_RECIP_INFO)
""",
    "stack_st_PKCS7_RECIP_INFO",
)

patch_one(
    "pkcs7.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("PKCS7_RECIP_INFO");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PKCS7_RECIP_INFO) container type.
 */
{-
    generate_stack_macros("PKCS7_RECIP_INFO");
-}
""",
    "stack_st_PKCS7_RECIP_INFO",
)

patch_one(
    "pkcs7.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(PKCS7, PKCS7, PKCS7)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PKCS7) container type.
 */
SKM_DEFINE_STACK_OF_INTERNAL(PKCS7, PKCS7, PKCS7)
""",
    "stack_st_PKCS7",
)

patch_one(
    "pkcs7.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("PKCS7");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(PKCS7) container type.
 */
{-
    generate_stack_macros("PKCS7");
-}
""",
    "stack_st_PKCS7",
)

# ----- ASN.1 helpers -----
patch_both(
    "pkcs7.h",
    """int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,
    const EVP_MD *type, unsigned char *md,
    unsigned int *len);
""",
    """/**
 * @brief Digest the DER encoding of a PKCS7_ISSUER_AND_SERIAL structure.
 * @param data Issuer-and-serial value whose ASN.1 encoding is hashed.
 * @param type Digest algorithm used to hash the DER encoding.
 * @param md Buffer that receives the digest bytes (at least EVP_MD_size(@p type)).
 * @param len Receives the digest length in bytes.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,
    const EVP_MD *type, unsigned char *md,
    unsigned int *len);
""",
    "PKCS7_ISSUER_AND_SERIAL_digest",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_FUNCTIONS(PKCS7_ENCRYPT)",
    asn1_funcs("PKCS7_ENCRYPT", "PKCS#7 EncryptedData") + "\n",
    "PKCS7_ENCRYPT ASN.1",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_ITEM(PKCS7_ATTR_SIGN)",
    """/**
 * @brief Return the ASN.1 item descriptor used when signing PKCS#7 authenticated attributes.
 * @return Pointer to the static ASN1_ITEM for PKCS7_ATTR_SIGN.
 */
const ASN1_ITEM *PKCS7_ATTR_SIGN_it(void);""",
    "PKCS7_ATTR_SIGN_it",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_PRINT_FUNCTION(PKCS7)",
    """/**
 * @brief Print a PKCS#7 structure to a BIO.
 * @param out BIO to write human-readable output to.
 * @param x PKCS#7 ContentInfo to print.
 * @param indent Indentation depth in spaces.
 * @param pctx Optional ASN.1 print context, or NULL for defaults.
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_print_ctx(BIO *out, const PKCS7 *x, int indent,
    const ASN1_PCTX *pctx);""",
    "PKCS7_print_ctx",
)

# ----- functions -----
patch_both(
    "pkcs7.h",
    """long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);
""",
    """/**
 * @brief Perform a control operation on a PKCS#7 object (for example set/get detached signature).
 * @param p7 PKCS#7 object to modify or query.
 * @param cmd Control code such as PKCS7_OP_SET_DETACHED_SIGNATURE or PKCS7_OP_GET_DETACHED_SIGNATURE.
 * @param larg Integer argument interpreted according to @p cmd (for example detached flag).
 * @param parg Optional pointer argument for @p cmd, or NULL when unused.
 * @return Command-specific long result; for set/get detached, the detached flag (non-zero when detached).
 */
long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);
""",
    "PKCS7_ctrl",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
""",
    """/**
 * @brief Compute and store the signature for a prepared PKCS#7 signer info.
 * @param si Signer info previously configured with PKCS7_SIGNER_INFO_set() (and optional attributes).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
""",
    "PKCS7_SIGNER_INFO_sign",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
    X509 *signer);
""",
    """/**
 * @brief Verify one PKCS#7 signer info's signature against content digested from @p bio.
 * @param bio BIO supplying the signed content octets (digest input).
 * @param p7 Signed PKCS#7 structure containing the signer infos / certificates.
 * @param si Signer info whose signature is verified.
 * @param signer Certificate whose public key verifies @p si (may be from @p p7).
 * @return 1 if the signature is valid, or 0 / a negative value on failure.
 */
int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
    X509 *signer);
""",
    "PKCS7_signatureVerify",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7);
""",
    """/**
 * @brief Prepare a PKCS#7 structure for streaming BER output and return content-boundary pointers.
 * @param boundary Receives a pointer into the ASN.1 encoding where streaming content is spliced.
 * @param p7 PKCS#7 object prepared with streaming flags (for example PKCS7_STREAM).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7);
""",
    "PKCS7_stream",
)

patch_both(
    "pkcs7.h",
    """PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
""",
    """/**
 * @brief Return the issuer-and-serial of signer info @p idx in a signed PKCS#7 structure.
 * @param p7 PKCS#7 SignedData or SignedAndEnvelopedData object.
 * @param idx Zero-based index into the signer-info stack.
 * @return Pointer to the internal PKCS7_ISSUER_AND_SERIAL (do not free), or NULL if out of range.
 */
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
""",
    "PKCS7_get_issuer_and_serial",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
    void *value);
""",
    """/**
 * @brief Add an unauthenticated attribute to a PKCS#7 signer info.
 * @param p7si Signer info receiving the attribute.
 * @param nid Attribute type NID (for example NID_pkcs9_unstructuredName).
 * @param atrtype ASN.1 value type tag (V_ASN1_*) for @p value.
 * @param value Attribute value pointer interpreted according to @p atrtype.
 * @return 1 on success, or 0 on error.
 */
int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
    void *value);
""",
    "PKCS7_add_attribute",
)

patch_both(
    "pkcs7.h",
    """PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, int flags);
""",
    """/**
 * @brief Create a PKCS#7 signed-data structure using the default library context.
 * @param signcert Signer certificate, or NULL when only adding certs/flags require it.
 * @param pkey Private key corresponding to @p signcert, or NULL for deferred signing.
 * @param certs Optional additional certificates to include, or NULL.
 * @param data BIO supplying the content to sign when not using detached/streaming flags.
 * @param flags PKCS7_* flags controlling detached content, streaming, and attributes.
 * @return New PKCS7, or NULL on error; free with PKCS7_free.
 */
PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
    BIO *data, int flags);
""",
    "PKCS7_sign",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data,
    int flags);
""",
    """/**
 * @brief Decrypt a PKCS#7 envelopedData (or signed-and-enveloped) structure for a recipient.
 * @param p7 Enveloped PKCS#7 object to decrypt.
 * @param pkey Recipient private key matching a RecipientInfo in @p p7.
 * @param cert Recipient certificate used to select the matching RecipientInfo, or NULL.
 * @param data BIO that receives the decrypted content.
 * @param flags PKCS7_* decryption flags (for example PKCS7_TEXT).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data,
    int flags);
""",
    "PKCS7_decrypt",
)

patch_both(
    "pkcs7.h",
    """PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
""",
    """/**
 * @brief Parse an S/MIME message into a PKCS#7 structure using the default library context.
 * @param bio BIO supplying the S/MIME message.
 * @param bcont Optional destination for a memory BIO holding cleartext signed content, or NULL.
 * @return Parsed PKCS7, or NULL on error; free with PKCS7_free.
 */
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
""",
    "SMIME_read_PKCS7",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("\n".join(missing))
    raise SystemExit(1)
