#!/usr/bin/env python3
"""Documentation repair batch 11a: cms, dh, dsa, ec, engine, pem, pkcs7, rsa, ui."""
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


# ----- cms.h -----
patch_both(
    "cms.h",
    """int CMS_decrypt_set1_key(CMS_ContentInfo *cms,
    unsigned char *key, size_t keylen,
    const unsigned char *id, size_t idlen);""",
    """/**
 * @brief Install a KEKRecipientInfo key on a CMS ContentInfo so CMS_decrypt can use it.
 * @param cms Enveloped ContentInfo that contains a KEK recipient.
 * @param key Symmetric key-encryption key octets.
 * @param keylen Length of @p key in bytes.
 * @param id Optional key identifier matching the recipient's keyEncryptionKeyIdentifier, or NULL.
 * @param idlen Length of @p id in bytes when @p id is non-NULL.
 * @return 1 on success, or 0 on failure.
 */
int CMS_decrypt_set1_key(CMS_ContentInfo *cms,
    unsigned char *key, size_t keylen,
    const unsigned char *id, size_t idlen);""",
    "CMS_decrypt_set1_key",
)

patch_both(
    "cms.h",
    """int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);""",
    """/**
 * @brief Transfer ownership of a private key into a key-transport RecipientInfo.
 * @param ri Recipient info of type CMS_RECIPINFO_TRANS.
 * @param pkey Private key that @p ri will own (or NULL to clear); previous key is freed.
 * @return 1 on success, or 0 on failure.
 */
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);""",
    "CMS_RecipientInfo_set0_pkey",
)

# ----- dh.h -----
patch_both(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_compute_key(const DH_METHOD *dhm))(unsigned char *key,
    const BIGNUM *pub_key,
    DH *dh);""",
    """/**
 * @brief Return the shared-secret compute_key callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the compute_key callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_compute_key(const DH_METHOD *dhm))(unsigned char *key,
    const BIGNUM *pub_key,
    DH *dh);""",
    "DH_meth_get_compute_key",
)

# ----- dsa.h -----
patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_verify(int type, const unsigned char *dgst,
    int dgst_len, const unsigned char *sigbuf,
    int siglen, DSA *dsa);""",
    """/**
 * @brief Verify a DSA signature over a message digest (deprecated).
 * @param type Historical digest NID; ignored by modern implementations.
 * @param dgst Digest octets that were signed.
 * @param dgst_len Length of @p dgst in bytes.
 * @param sigbuf DER-encoded DSA signature to verify.
 * @param siglen Length of @p sigbuf in bytes.
 * @param dsa DSA key containing the public key used for verification.
 * @return 1 if the signature is valid, 0 if invalid, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_verify(int type, const unsigned char *dgst,
    int dgst_len, const unsigned char *sigbuf,
    int siglen, DSA *dsa);""",
    "DSA_verify",
)

patch_both(
    "dsa.h",
    """DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(OSSL_DEPRECATEDIN_3_0,
    DSA, DSAparams)""",
    """/**
 * @brief Decode DSA domain parameters from DER (deprecated).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return DSA object holding the decoded parameters, or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0 DSA *d2i_DSAparams(DSA **a, const unsigned char **in, long len);
/**
 * @brief Encode DSA domain parameters to DER (deprecated).
 * @param a DSA object whose p, q, and g parameters are encoded.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_DSAparams(const DSA *a, unsigned char **out);""",
    "d2i_i2d_DSAparams",
)

patch_both(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_keygen(const DSA_METHOD *dsam))(DSA *);""",
    """/**
 * @brief Return the key-generation callback from a DSA_METHOD (deprecated).
 * @param dsam Method table to query.
 * @return Pointer to the keygen callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DSA_meth_get_keygen(const DSA_METHOD *dsam))(DSA *);""",
    "DSA_meth_get_keygen",
)

# ----- ec.h -----
patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 int EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
    EC_POINT *points[], BN_CTX *ctx);""",
    """/**
 * @brief Convert an array of EC_POINT objects to affine coordinates (deprecated).
 * @param group Curve that owns the points.
 * @param num Number of entries in @p points.
 * @param points Array of @p num points converted in place.
 * @param ctx BN_CTX for temporary BIGNUMs, or NULL to allocate internally.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
    EC_POINT *points[], BN_CTX *ctx);""",
    "EC_POINTs_make_affine",
)

patch_both(
    "ec.h",
    """OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_conv_form(EC_KEY *eckey,
    point_conversion_form_t cform);""",
    """/**
 * @brief Set the point-conversion form used when encoding an EC_KEY public point (deprecated).
 * @param eckey EC key whose encoding form is updated.
 * @param cform Conversion form such as POINT_CONVERSION_UNCOMPRESSED or POINT_CONVERSION_COMPRESSED.
 */
OSSL_DEPRECATEDIN_3_0 void EC_KEY_set_conv_form(EC_KEY *eckey,
    point_conversion_form_t cform);""",
    "EC_KEY_set_conv_form",
)

# ----- engine.h -----
patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f);""",
    """/**
 * @brief Install the ENGINE callback that enumerates public-key ASN.1 methods (deprecated).
 * @param e ENGINE whose pkey ASN.1 method table callback is set.
 * @param f Callback of type ENGINE_PKEY_ASN1_METHS_PTR, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f);""",
    "ENGINE_set_pkey_asn1_meths",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_get_flags(const ENGINE *e);""",
    """/**
 * @brief Return the behavioural flag mask stored on an ENGINE (deprecated).
 * @param e ENGINE to query.
 * @return Bitmask of ENGINE_FLAGS_* values currently set on @p e.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_get_flags(const ENGINE *e);""",
    "ENGINE_get_flags",
)

patch_both(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RAND(ENGINE *e);""",
    """/**
 * @brief Register @p e as the default ENGINE for RAND operations (deprecated).
 * @param e ENGINE to install as the RAND default.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int ENGINE_set_default_RAND(ENGINE *e);""",
    "ENGINE_set_default_RAND",
)

# ----- pem.h -----
patch_both(
    "pem.h",
    """int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
    pem_password_cb *callback, void *u);""",
    """/**
 * @brief Decrypt PEM payload bytes in place using cipher info and a password callback.
 * @param cipher Cipher and IV previously filled by PEM_get_EVP_CIPHER_INFO().
 * @param data Encoded payload buffer; decrypted octets overwrite the same buffer.
 * @param len On input, length of @p data; on output, length of the decrypted payload.
 * @param callback Password callback used when @p cipher indicates encryption; may be NULL.
 * @param u Application pointer forwarded to @p callback.
 * @return 1 on success, or 0 on failure.
 *
 * Deprecated: prefer PKCS#8 with PKCS#5 v2.0 PBE for new private-key storage.
 */
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
    pem_password_cb *callback, void *u);""",
    "PEM_do_header",
)

patch_both(
    "pem.h",
    """int PEM_read(FILE *fp, char **name, char **header,
    unsigned char **data, long *len);""",
    """/**
 * @brief Read one PEM object from a FILE, returning name, header, and decoded data.
 * @param fp FILE to read from.
 * @param name Receives a newly allocated PEM type name (caller frees with OPENSSL_free).
 * @param header Receives a newly allocated PEM header block, or an empty string.
 * @param data Receives newly allocated decoded payload bytes.
 * @param len Receives the length of *@p data in bytes.
 * @return 1 on success, or 0 on failure / end of input.
 */
int PEM_read(FILE *fp, char **name, char **header,
    unsigned char **data, long *len);""",
    "PEM_read",
)

# ----- pkcs7.h -----
patch_both(
    "pkcs7.h",
    """    ASN1_OCTET_STRING *enc_digest; /* confusing name, actually signature */""",
    """    /** Signature octets (historical name: enc_digest). */
    ASN1_OCTET_STRING *enc_digest; /* confusing name, actually signature */""",
    "PKCS7_SIGNER_INFO.enc_digest",
)

patch_both(
    "pkcs7.h",
    """typedef struct pkcs7_st {""",
    """/**
 * @brief PKCS#7 ContentInfo container holding typed content and related state.
 */
typedef struct pkcs7_st {""",
    "struct pkcs7_st",
)

patch_both(
    "pkcs7.h",
    "DECLARE_ASN1_FUNCTIONS(PKCS7_SIGNED)",
    asn1_funcs("PKCS7_SIGNED", "PKCS#7 SignedData") + "\n",
    "PKCS7_SIGNED_ASN1",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_content_new(PKCS7 *p7, int nid);""",
    """/**
 * @brief Allocate nested content of type @p nid and attach it to a PKCS#7 structure.
 * @param p7 PKCS#7 ContentInfo that receives the new nested content.
 * @param nid NID of the content type to create (for example NID_pkcs7_data).
 * @return 1 on success, or 0 on failure.
 */
int PKCS7_content_new(PKCS7 *p7, int nid);""",
    "PKCS7_content_new",
)

patch_both(
    "pkcs7.h",
    """int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
    BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si);""",
    """/**
 * @brief Verify a PKCS#7 signed content digest against a signer info and certificate store.
 * @param cert_store Trusted store used to locate and validate the signer certificate.
 * @param ctx Verification context reused or initialized for the signer certificate check.
 * @param bio BIO supplying the signed content octets (digest input).
 * @param p7 Signed PKCS#7 structure containing certificates and signer infos.
 * @param si Signer info whose signature and digest are verified.
 * @return 1 if verification succeeds, or 0 / a negative value on failure.
 */
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
    BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si);""",
    "PKCS7_dataVerify",
)

# ----- rsa.h -----
patch_both(
    "rsa.h",
    """int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes);""",
    """/**
 * @brief Set how many primes to use when generating a multi-prime RSA key.
 * @param ctx Keygen context for an RSA key type.
 * @param primes Number of primes (2 for classic RSA; larger for multi-prime).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes);""",
    "EVP_PKEY_CTX_set_rsa_keygen_primes",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 void RSA_set_flags(RSA *r, int flags);""",
    """/**
 * @brief Set flag bits on an RSA key object (deprecated).
 * @param r RSA key whose flags are updated.
 * @param flags Flag bits to set (OR'd into the existing mask; does not clear other bits).
 */
OSSL_DEPRECATEDIN_3_0 void RSA_set_flags(RSA *r, int flags);""",
    "RSA_set_flags",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_generate_multi_prime_key(RSA *rsa, int bits,
    int primes, BIGNUM *e,
    BN_GENCB *cb);""",
    """/**
 * @brief Generate a multi-prime RSA key pair (deprecated).
 * @param rsa Destination RSA object that receives the generated key.
 * @param bits Desired modulus size in bits.
 * @param primes Number of prime factors (2 or more).
 * @param e Public exponent to use (for example 65537).
 * @param cb Optional progress callback, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_generate_multi_prime_key(RSA *rsa, int bits,
    int primes, BIGNUM *e,
    BN_GENCB *cb);""",
    "RSA_generate_multi_prime_key",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl, int rsa_len,
    const unsigned char *p, int pl);""",
    """/**
 * @brief Verify PKCS#1 OAEP padding and recover the encoded message (deprecated).
 * @param to Destination buffer for the recovered message.
 * @param tlen Capacity of @p to in bytes.
 * @param f Encoded message after RSA public operation (typically modulus-sized).
 * @param fl Length of @p f in bytes.
 * @param rsa_len RSA modulus size in bytes (used to validate encoding length).
 * @param p Optional OAEP encoding parameter / label octets, or NULL.
 * @param pl Length of @p p in bytes.
 * @return Length of the recovered message on success, or a negative value on error.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
    const unsigned char *f, int fl, int rsa_len,
    const unsigned char *p, int pl);""",
    "RSA_padding_check_PKCS1_OAEP",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);""",
    """/**
 * @brief Apply PKCS#1 OAEP padding with explicit message and MGF1 digests (deprecated).
 * @param to Destination buffer for the encoded message (typically modulus-sized).
 * @param tlen Capacity of @p to in bytes.
 * @param from Message octets to encode.
 * @param flen Length of @p from in bytes.
 * @param param Optional OAEP encoding parameter / label octets, or NULL.
 * @param plen Length of @p param in bytes.
 * @param md Digest used for OAEP label hashing; NULL selects SHA-1.
 * @param mgf1md Digest used for MGF1; NULL selects the same digest as @p md.
 * @return 1 on success, or a non-positive value on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md);""",
    "RSA_padding_add_PKCS1_OAEP_mgf1",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0 int RSA_meth_set1_name(RSA_METHOD *meth,
    const char *name);""",
    """/**
 * @brief Set the descriptive name stored on an RSA_METHOD (deprecated).
 * @param meth Method table whose name is replaced.
 * @param name NUL-terminated name to copy into @p meth.
 * @return 1 on success, or 0 on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 int RSA_meth_set1_name(RSA_METHOD *meth,
    const char *name);""",
    "RSA_meth_set1_name",
)

patch_both(
    "rsa.h",
    """OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_init(RSA_METHOD *rsa, int (*init)(RSA *rsa));""",
    """/**
 * @brief Install the init callback on an RSA_METHOD (deprecated).
 * @param rsa Method table to update.
 * @param init Callback invoked when an RSA key using this method is initialized, or NULL.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int RSA_meth_set_init(RSA_METHOD *rsa, int (*init)(RSA *rsa));""",
    "RSA_meth_set_init",
)

# ----- ui.h -----
patch_both(
    "ui.h",
    """int UI_add_error_string(UI *ui, const char *text);""",
    """/**
 * @brief Add an error message string to a UI for display (pointer stored, not copied).
 * @param ui UI that will show the error text.
 * @param text Error text that must remain valid for the lifetime of @p ui.
 * @return Positive index on success, or a value <= 0 on failure.
 */
int UI_add_error_string(UI *ui, const char *text);""",
    "UI_add_error_string",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    print("\n".join(missing))
    raise SystemExit(1)
