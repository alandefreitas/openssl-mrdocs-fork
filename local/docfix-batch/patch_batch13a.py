#!/usr/bin/env python3
"""Documentation repair batch 13a: asn1..dh (+ conf/crypto/comp/cms)."""
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


print("=== batch 13a ===")

# ----- asn1.h -----
patch_both(
    "asn1.h",
    """ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, const unsigned char **pp,
    long length);
""",
    """/**
 * @brief Decode an ASN.1 INTEGER that must be treated as unsigned (no leading 0x00 ignored).
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param pp Address of a pointer to the DER input; advanced past the decoded value.
 * @param length Number of bytes available at *@p pp.
 * @return Decoded ASN1_INTEGER, or NULL on error.
 */
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, const unsigned char **pp,
    long length);
""",
    "d2i_ASN1_UINTEGER",
)

patch_both(
    "asn1.h",
    """int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
""",
    """/**
 * @brief Compare an ASN.1 UTCTime value with a calendar time_t.
 * @param s UTCTime value to compare (must be a valid ASN1_UTCTIME).
 * @param t POSIX time to compare against.
 * @return -1 if @p s is before @p t, 0 if equal, 1 if after, or 0 on parse error (check ERR).
 */
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
""",
    "ASN1_UTCTIME_cmp_time_t",
)

patch_both(
    "asn1.h",
    """int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
    int *pclass, long omax);
""",
    """/**
 * @brief Parse the ASN.1 identifier and length octets at *@p pp.
 * @param pp Address of the input cursor; advanced past the header on success.
 * @param plength Receives the content length in bytes (or -1 for indefinite length).
 * @param ptag Receives the tag number.
 * @param pclass Receives the class (V_ASN1_UNIVERSAL, CONTEXT_SPECIFIC, …).
 * @param omax Maximum number of bytes available from *@p pp.
 * @return Bitmask including 0x80 on error, 0x01 if constructed, 0x20 if indefinite length.
 */
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
    int *pclass, long omax);
""",
    "ASN1_get_object",
)

patch_both(
    "asn1.h",
    """void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);
""",
    """/**
 * @brief Decode an ASN.1 value from a FILE using allocator and d2i callbacks.
 * @param xnew Allocator returning a new empty object (for example TYPE_new).
 * @param d2i Decoder of type d2i_of_void that parses DER into the object.
 * @param in Input FILE positioned at DER (or BER) encoding.
 * @param x Optional destination pointer updated to the decoded object, or NULL.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);
""",
    "ASN1_d2i_fp",
)

patch_both(
    "asn1.h",
    """BIO *ASN1_item_i2d_mem_bio(const ASN1_ITEM *it, const ASN1_VALUE *val);
""",
    """/**
 * @brief Encode an ASN.1 value described by @p it into a newly allocated memory BIO.
 * @param it ASN.1 item descriptor for the type of @p val.
 * @param val Value to encode (may be NULL for some optional types).
 * @return Memory BIO holding the DER encoding, or NULL on error; free with BIO_free().
 */
BIO *ASN1_item_i2d_mem_bio(const ASN1_ITEM *it, const ASN1_VALUE *val);
""",
    "ASN1_item_i2d_mem_bio",
)

patch_both(
    "asn1.h",
    """unsigned long ASN1_STRING_get_default_mask(void);
""",
    """/**
 * @brief Return the process-wide default ASN.1 string type mask.
 * @return Mask of B_ASN1_* bits previously set with ASN1_STRING_set_default_mask().
 */
unsigned long ASN1_STRING_get_default_mask(void);
""",
    "ASN1_STRING_get_default_mask",
)

patch_both(
    "asn1.h",
    """ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
""",
    """/**
 * @brief Look up the ASN1_STRING_TABLE entry for a string-valued NID.
 * @param nid Object identifier NID whose string encoding policy is requested.
 * @return Pointer to the table entry (do not free), or NULL if none is registered.
 */
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
""",
    "ASN1_STRING_TABLE_get",
)

# ----- async.h -----
patch_one(
    "async.h",
    """int ASYNC_init_thread(size_t max_size, size_t init_size);
""",
    """/**
 * @brief Initialise per-thread asynchronous job support for the current thread.
 * @param max_size Maximum stack pool size in bytes for ASYNC jobs (0 for the default).
 * @param init_size Initial stack pool size in bytes (0 for the default); must be <= @p max_size.
 * @return 1 on success, or 0 on failure.
 */
int ASYNC_init_thread(size_t max_size, size_t init_size);
""",
    "ASYNC_init_thread",
)

# ----- bio.h -----
patch_both(
    "bio.h",
    """void BIO_set_flags(BIO *b, int flags);
""",
    """/**
 * @brief Set the given flag bits on a BIO (bitwise OR into the BIO's flags).
 * @param b BIO whose flags are updated.
 * @param flags Bitmask of BIO_FLAGS_* values to set.
 */
void BIO_set_flags(BIO *b, int flags);
""",
    "BIO_set_flags",
)

patch_both(
    "bio.h",
    """SKM_DEFINE_STACK_OF_INTERNAL(BIO, BIO, BIO)
""",
    """/**
 * @brief Opaque STACK_OF(BIO) container type.
 */
SKM_DEFINE_STACK_OF_INTERNAL(BIO, BIO, BIO)
""",
    "stack_st_BIO",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_connect(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a TCP connect (client) socket BIO.
 * @return Pointer to the static connect BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_connect(void);
""",
    "BIO_s_connect",
)

patch_both(
    "bio.h",
    """void BIO_ADDR_free(BIO_ADDR *);
""",
    """/**
 * @brief Free a BIO_ADDR allocated with BIO_ADDR_new() or BIO_ADDR_dup().
 * @param ap Address object to free, or NULL (no-op).
 */
void BIO_ADDR_free(BIO_ADDR *ap);
""",
    "BIO_ADDR_free",
)

patch_both(
    "bio.h",
    """int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai);
""",
    """/**
 * @brief Return the address family of a BIO_ADDRINFO node (for example AF_INET).
 * @param bai Address-info node to query.
 * @return Address family constant suitable for socket().
 */
int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai);
""",
    "BIO_ADDRINFO_family",
)

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_1_1_0 int BIO_get_accept_socket(char *host_port, int mode);
""",
    """/**
 * @brief Create a listening TCP socket for @p host_port (deprecated; prefer BIO_new_accept).
 * @param host_port Host:port string (or ":port" / "port") describing the bind address.
 * @param mode BIO_BIND_* behaviour (for example BIO_BIND_REUSEADDR).
 * @return Accepted listening socket fd on success, or INVALID_SOCKET / -1 on error.
 */
OSSL_DEPRECATEDIN_1_1_0 int BIO_get_accept_socket(char *host_port, int mode);
""",
    "BIO_get_accept_socket",
)

# ----- blowfish.h -----
patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 void BF_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    const BF_KEY *schedule,
    unsigned char *ivec, int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with Blowfish in CBC mode (deprecated).
 * @param in Input bytes of length @p length (need not be block-aligned; CFB-style trailing handled).
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param schedule Expanded Blowfish key from BF_set_key().
 * @param ivec 8-byte IV; updated to the last ciphertext block on return.
 * @param enc BF_ENCRYPT to encrypt, or BF_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void BF_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    const BF_KEY *schedule,
    unsigned char *ivec, int enc);
""",
    "BF_cbc_encrypt",
)

# ----- bn.h -----
patch_one(
    "bn.h",
    """void BN_CTX_free(BN_CTX *c);
""",
    """/**
 * @brief Free a BN_CTX and any BIGNUMs still owned by its stack frames.
 * @param c Context to free, or NULL (no-op).
 */
void BN_CTX_free(BN_CTX *c);
""",
    "BN_CTX_free",
)

patch_one(
    "bn.h",
    """void BN_free(BIGNUM *a);
""",
    """/**
 * @brief Free a BIGNUM and its limbs (no-op for static BIGNUMs flagged BN_FLG_STATIC_DATA).
 * @param a BIGNUM to free, or NULL (no-op).
 */
void BN_free(BIGNUM *a);
""",
    "BN_free",
)

patch_one(
    "bn.h",
    """int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
""",
    """/**
 * @brief Compute r = (a / b) mod p for binary polynomial-field (GF(2^m)) values.
 * @param r Result BIGNUM.
 * @param a Dividend.
 * @param b Divisor (must be invertible modulo @p p).
 * @param p Irreducible reduction polynomial.
 * @param ctx BN_CTX for temporaries.
 * @return 1 on success, or 0 on failure.
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
""",
    "BN_GF2m_mod_div",
)

# ----- cms.h -----
patch_both(
    "cms.h",
    """int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);
""",
    """/**
 * @brief Write a CMS_ContentInfo as an S/MIME (MIME) message to @p bio.
 * @param bio Output BIO receiving the MIME-formatted CMS.
 * @param cms CMS object to serialise (typically signed or enveloped data).
 * @param data Optional content BIO for detached/streaming content, or NULL.
 * @param flags CMS_* / SMIME_* flags controlling MIME headers and streaming.
 * @return 1 on success, or 0 on failure.
 */
int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags);
""",
    "SMIME_write_CMS",
)

patch_both(
    "cms.h",
    """int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri,
    X509_ALGOR **palg,
    ASN1_OCTET_STRING **pid,
    ASN1_GENERALIZEDTIME **pdate,
    ASN1_OBJECT **potherid,
    ASN1_TYPE **pothertype);
""",
    """/**
 * @brief Return non-owning pointers to the key-encryption key identifier fields of a KEKRI.
 * @param ri Recipient info of type CMS_RECIPINFO_KEK.
 * @param palg Optional out-parameter for the keyEncryptionAlgorithm, or NULL.
 * @param pid Optional out-parameter for the keyIdentifier OCTET STRING, or NULL.
 * @param pdate Optional out-parameter for the optional date, or NULL.
 * @param potherid Optional out-parameter for otherKeyAttribute OID, or NULL.
 * @param pothertype Optional out-parameter for otherKeyAttribute value, or NULL.
 * @return 1 on success, or 0 if @p ri is not a KEK recipient info.
 */
int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri,
    X509_ALGOR **palg,
    ASN1_OCTET_STRING **pid,
    ASN1_GENERALIZEDTIME **pdate,
    ASN1_OBJECT **potherid,
    ASN1_TYPE **pothertype);
""",
    "CMS_RecipientInfo_kekri_get0_id",
)

patch_both(
    "cms.h",
    """int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
    unsigned char *key, size_t keylen);
""",
    """/**
 * @brief Attach a symmetric key-encryption key to a KEK RecipientInfo (transfers ownership of @p key).
 * @param ri Recipient info of type CMS_RECIPINFO_KEK.
 * @param key Key bytes allocated with OPENSSL_malloc(); ownership transferred to @p ri (may be NULL to clear).
 * @param keylen Length of @p key in bytes.
 * @return 1 on success, or 0 on failure.
 */
int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
    unsigned char *key, size_t keylen);
""",
    "CMS_RecipientInfo_set0_key",
)

patch_both(
    "cms.h",
    """int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
""",
    """/**
 * @brief Return the number of signed attributes on a CMS SignerInfo.
 * @param si SignerInfo whose signedAttrs set is queried.
 * @return Attribute count, or -1 if signedAttrs is absent.
 */
int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
""",
    "CMS_signed_get_attr_count",
)

patch_both(
    "cms.h",
    """int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si,
    int nid, int type,
    const void *bytes, int len);
""",
    """/**
 * @brief Append a signed attribute identified by NID to a CMS SignerInfo.
 * @param si SignerInfo whose signedAttrs set is extended.
 * @param nid Attribute type NID (for example NID_pkcs9_signingTime).
 * @param type ASN.1 string/type code for @p bytes (for example V_ASN1_OCTET_STRING).
 * @param bytes Attribute value bytes interpreted according to @p type.
 * @param len Length of @p bytes in bytes.
 * @return 1 on success, or 0 on failure.
 */
int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si,
    int nid, int type,
    const void *bytes, int len);
""",
    "CMS_signed_add1_attr_by_NID",
)

# ----- comp.h -----
patch_one(
    "comp.h",
    """COMP_METHOD *COMP_zstd_oneshot(void);
""",
    """/**
 * @brief Return the one-shot Zstandard COMP_METHOD (compresses each BIO_write as a complete frame).
 * @return Pointer to the static oneshot ZSTD method, or NULL if ZSTD support is unavailable.
 */
COMP_METHOD *COMP_zstd_oneshot(void);
""",
    "COMP_zstd_oneshot",
)

# ----- conf.h -----
patch_both(
    "conf.h",
    """STACK_OF(CONF_MODULE);
""",
    """/**
 * @brief Opaque STACK_OF(CONF_MODULE) container type for loaded DSO configuration modules.
 */
STACK_OF(CONF_MODULE);
""",
    "stack_st_CONF_MODULE",
)

patch_both(
    "conf.h",
    """CONF *NCONF_new_ex(OSSL_LIB_CTX *libctx, CONF_METHOD *meth);
""",
    """/**
 * @brief Allocate a CONF object associated with a library context.
 * @param libctx Library context used for subsequent CONF/module operations, or NULL for the default.
 * @param meth Configuration method (typically NCONF_default()), or NULL for the default method.
 * @return New CONF, or NULL on allocation failure; free with NCONF_free().
 */
CONF *NCONF_new_ex(OSSL_LIB_CTX *libctx, CONF_METHOD *meth);
""",
    "NCONF_new_ex",
)

patch_both(
    "conf.h",
    """void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data);
""",
    """/**
 * @brief Store an opaque application pointer on a loaded configuration module instance.
 * @param md Module instance to update.
 * @param usr_data Caller-owned pointer retrieved later with CONF_imodule_get_usr_data().
 */
void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data);
""",
    "CONF_imodule_set_usr_data",
)

# ----- conftypes.h -----
patch_one(
    "conftypes.h",
    """    CONF *(*create)(CONF_METHOD *meth);
""",
    """    /** Allocate a new CONF object for this method (may be NULL). */
    CONF *(*create)(CONF_METHOD *meth);
""",
    "conf_method_st.create",
)

# ----- crypto.h -----
patch_both(
    "crypto.h",
    """int CRYPTO_secure_malloc_initialized(void);
""",
    """/**
 * @brief Report whether the secure heap has been successfully initialised.
 * @return 1 if CRYPTO_secure_malloc_init() succeeded, or 0 otherwise.
 */
int CRYPTO_secure_malloc_initialized(void);
""",
    "CRYPTO_secure_malloc_initialized",
)

patch_both(
    "crypto.h",
    """void OPENSSL_cleanse(void *ptr, size_t len);
""",
    """/**
 * @brief Overwrite @p len bytes at @p ptr with zeros in a way that resists compiler elision.
 * @param ptr Buffer to scrub (may be NULL when @p len is 0).
 * @param len Number of bytes to clear.
 */
void OPENSSL_cleanse(void *ptr, size_t len);
""",
    "OPENSSL_cleanse",
)

# ----- dh.h -----
patch_one(
    "dh.h",
    """int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad);
""",
    """/**
 * @brief Enable or disable leading-zero padding of the DH shared secret to the prime length.
 * @param ctx Key-derivation / derive context for a DH key.
 * @param pad Non-zero to pad the secret to BN_num_bytes(p); 0 to return the minimal big-endian form.
 * @return 1 on success, or a negative value for unsupported / failure.
 */
int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad);
""",
    "EVP_PKEY_CTX_set_dh_pad",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_check_params_ex(const DH *dh);
""",
    """/**
 * @brief Validate Diffie-Hellman p/g (and q if present) and report problems via the error queue (deprecated).
 * @param dh DH object whose domain parameters are checked.
 * @return 1 if the parameters look suitable, or 0 if checks fail (reasons are pushed to the error stack).
 */
OSSL_DEPRECATEDIN_3_0 int DH_check_params_ex(const DH *dh);
""",
    "DH_check_params_ex",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_pub_key(const DH *dh);
""",
    """/**
 * @brief Return the public key component of a DH object without duplicating it (deprecated).
 * @param dh DH key to query.
 * @return Internal BIGNUM pointer for the public key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DH_get0_pub_key(const DH *dh);
""",
    "DH_get0_pub_key",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_key(const DH_METHOD *dhm))(DH *);
""",
    """/**
 * @brief Return the key-generation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the generate_key callback, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_generate_key(const DH_METHOD *dhm))(DH *);
""",
    "DH_meth_get_generate_key",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_bn_mod_exp(const DH_METHOD *dhm))(const DH *, BIGNUM *,
    const BIGNUM *,
    const BIGNUM *,
    const BIGNUM *, BN_CTX *,
    BN_MONT_CTX *);
""",
    """/**
 * @brief Return the modular-exponentiation callback from a DH_METHOD (deprecated).
 * @param dhm Method table to query.
 * @return Pointer to the bn_mod_exp callback used during DH operations, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 int (*DH_meth_get_bn_mod_exp(const DH_METHOD *dhm))(const DH *, BIGNUM *,
    const BIGNUM *,
    const BIGNUM *,
    const BIGNUM *, BN_CTX *,
    BN_MONT_CTX *);
""",
    "DH_meth_get_bn_mod_exp",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_params(DH_METHOD *dhm,
    int (*generate_params)(DH *, int, int,
        BN_GENCB *));
""",
    """/**
 * @brief Set the parameter-generation callback on a DH_METHOD (deprecated).
 * @param dhm Method table to update.
 * @param generate_params Callback that fills domain parameters for a DH object, or NULL to clear.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_set_generate_params(DH_METHOD *dhm,
    int (*generate_params)(DH *, int, int,
        BN_GENCB *));
""",
    "DH_meth_set_generate_params",
)

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_0_9_8 DH *DH_generate_parameters(int prime_len, int generator,
    void (*callback)(int, int,
        void *),
    void *cb_arg);
""",
    """/**
 * @brief Generate Diffie-Hellman parameters with a legacy progress callback (deprecated).
 * @param prime_len Desired length of the prime p in bits.
 * @param generator DH generator g (commonly 2 or 5).
 * @param callback Optional progress callback (int, int, void *), or NULL.
 * @param cb_arg Opaque pointer passed to @p callback.
 * @return Newly allocated DH with generated parameters, or NULL on failure.
 */
OSSL_DEPRECATEDIN_0_9_8 DH *DH_generate_parameters(int prime_len, int generator,
    void (*callback)(int, int,
        void *),
    void *cb_arg);
""",
    "DH_generate_parameters",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    for m in missing:
        print(" ", m)
