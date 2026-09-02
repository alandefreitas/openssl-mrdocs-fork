#!/usr/bin/env python3
"""Documentation repair batch 22d: pkcs12.h undocumented symbols."""
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


print("=== batch 22d (pkcs12.h) ===")

patch_both(
    "pkcs12.h",
    """ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid);
int PKCS12_mac_present(const PKCS12 *p12);
void PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac,
    const X509_ALGOR **pmacalg,
    const ASN1_OCTET_STRING **psalt,
    const ASN1_INTEGER **piter,
    const PKCS12 *p12);
""",
    """ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid);
/**
 * @brief Test whether a PKCS#12 PFX carries an integrity MAC.
 * @param p12 PKCS#12 structure to query.
 * @return 1 if a MAC is present, or 0 if absent or @p p12 is NULL.
 */
int PKCS12_mac_present(const PKCS12 *p12);
/**
 * @brief Retrieve MAC value and MAC-parameter fields from a PKCS#12 PFX.
 * @param pmac Receives the MAC octet string, or NULL to skip.
 * @param pmacalg Receives the MAC algorithm identifier, or NULL to skip.
 * @param psalt Receives the MAC salt, or NULL to skip.
 * @param piter Receives the MAC iteration count, or NULL to skip.
 * @param p12 PKCS#12 structure to query.
 */
void PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac,
    const X509_ALGOR **pmacalg,
    const ASN1_OCTET_STRING **psalt,
    const ASN1_INTEGER **piter,
    const PKCS12 *p12);
""",
    "PKCS12_mac_present/get0_mac",
)

patch_both(
    "pkcs12.h",
    """const ASN1_TYPE *PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag,
    int attr_nid);
const ASN1_OBJECT *PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag);
""",
    """const ASN1_TYPE *PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag,
    int attr_nid);
/**
 * @brief Return the safeBag type OID without copying it.
 * @param bag SafeBag to query.
 * @return Internal safeBag type OID, or NULL if @p bag is NULL; do not free.
 */
const ASN1_OBJECT *PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag);
""",
    "PKCS12_SAFEBAG_get0_type",
)

patch_both(
    "pkcs12.h",
    """const ASN1_OBJECT *PKCS12_SAFEBAG_get0_bag_type(const PKCS12_SAFEBAG *bag);

X509 *PKCS12_SAFEBAG_get1_cert_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx, const char *propq);
""",
    """const ASN1_OBJECT *PKCS12_SAFEBAG_get0_bag_type(const PKCS12_SAFEBAG *bag);

/**
 * @brief Extract an X.509 certificate from a certBag safeBag with a library context.
 * @param bag SafeBag containing a certificate.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return New X509 certificate, or NULL on error. Caller must free.
 */
X509 *PKCS12_SAFEBAG_get1_cert_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx, const char *propq);
""",
    "PKCS12_SAFEBAG_get1_cert_ex",
)

patch_both(
    "pkcs12.h",
    """X509 *PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag);
X509_CRL *PKCS12_SAFEBAG_get1_crl_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx, const char *propq);
""",
    """X509 *PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag);
/**
 * @brief Extract an X.509 CRL from a crlBag safeBag with a library context.
 * @param bag SafeBag containing a CRL.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return New X509_CRL, or NULL on error. Caller must free.
 */
X509_CRL *PKCS12_SAFEBAG_get1_crl_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx, const char *propq);
""",
    "PKCS12_SAFEBAG_get1_crl_ex",
)

patch_both(
    "pkcs12.h",
    """const PKCS8_PRIV_KEY_INFO *PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag);
const X509_SIG *PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag);

PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_cert(X509 *x509);
""",
    """const PKCS8_PRIV_KEY_INFO *PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag);
/**
 * @brief Return the encrypted PKCS#8 structure from a pkcs8ShroudedKeyBag safeBag.
 * @param bag SafeBag to query.
 * @return Internal X509_SIG pointer for the shrouded key, or NULL if @p bag is not pkcs8ShroudedKeyBag; do not free.
 */
const X509_SIG *PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag);

/**
 * @brief Create a certBag safeBag containing the supplied certificate.
 * @param x509 Certificate to embed.
 * @return New safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_cert(X509 *x509);
""",
    "PKCS12_SAFEBAG_get0_pkcs8/create_cert",
)

patch_both(
    "pkcs12.h",
    """PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_secret(int type, int vtype, const unsigned char *value, int len);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8);
""",
    """PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_secret(int type, int vtype, const unsigned char *value, int len);
/**
 * @brief Create an unencrypted keyBag safeBag from PKCS#8 private key info.
 * @param p8 Private key info to embed (ownership transfers to the safeBag on success).
 * @return New safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8);
""",
    "PKCS12_SAFEBAG_create0_p8inf",
)

patch_both(
    "pkcs12.h",
    """PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
    const char *pass,
    int passlen,
    unsigned char *salt,
    int saltlen, int iter,
    PKCS8_PRIV_KEY_INFO *p8inf);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid,
    const char *pass,
    int passlen,
    unsigned char *salt,
    int saltlen, int iter,
    PKCS8_PRIV_KEY_INFO *p8inf,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    """PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
    const char *pass,
    int passlen,
    unsigned char *salt,
    int saltlen, int iter,
    PKCS8_PRIV_KEY_INFO *p8inf);
/**
 * @brief Create an encrypted pkcs8ShroudedKeyBag safeBag from PKCS#8 private key info.
 * @param pbe_nid PBE algorithm NID, or 0 for a default.
 * @param pass Passphrase for encryption.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param salt Salt for key derivation, or NULL to generate one.
 * @param saltlen Length of @p salt in bytes.
 * @param iter Iteration count, or 0 for the default (2048).
 * @param p8inf Private key info to encrypt.
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return New safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid,
    const char *pass,
    int passlen,
    unsigned char *salt,
    int saltlen, int iter,
    PKCS8_PRIV_KEY_INFO *p8inf,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    "PKCS12_SAFEBAG_create_pkcs8_encrypt_ex",
)

patch_both(
    "pkcs12.h",
    """PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(const X509_SIG *p8, const char *pass,
    int passlen);
PKCS8_PRIV_KEY_INFO *PKCS8_decrypt_ex(const X509_SIG *p8, const char *pass,
    int passlen, OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    """PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(const X509_SIG *p8, const char *pass,
    int passlen);
/**
 * @brief Decrypt a PKCS#8 encrypted private key using a library context.
 * @param p8 Encrypted PKCS#8 structure (X509_SIG).
 * @param pass Passphrase for decryption.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Decrypted PKCS#8 private key info, or NULL on error.
 */
PKCS8_PRIV_KEY_INFO *PKCS8_decrypt_ex(const X509_SIG *p8, const char *pass,
    int passlen, OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    "PKCS8_decrypt_ex",
)

patch_both(
    "pkcs12.h",
    """PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(const PKCS12_SAFEBAG *bag,
    const char *pass, int passlen);
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey_ex(const PKCS12_SAFEBAG *bag,
    const char *pass, int passlen,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    """PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(const PKCS12_SAFEBAG *bag,
    const char *pass, int passlen);
/**
 * @brief Decrypt the PKCS#8 shrouded key in a pkcs8ShroudedKeyBag safeBag.
 * @param bag SafeBag containing an encrypted private key.
 * @param pass Passphrase for decryption.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Decrypted PKCS#8 private key info, or NULL on error.
 */
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey_ex(const PKCS12_SAFEBAG *bag,
    const char *pass, int passlen,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    "PKCS12_decrypt_skey_ex",
)

patch_both(
    "pkcs12.h",
    """X509_SIG *PKCS8_set0_pbe_ex(const char *pass, int passlen,
    PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe,
    OSSL_LIB_CTX *ctx, const char *propq);
PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
""",
    """X509_SIG *PKCS8_set0_pbe_ex(const char *pass, int passlen,
    PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe,
    OSSL_LIB_CTX *ctx, const char *propq);
/**
 * @brief Pack a stack of safeBags into a PKCS#7 data ContentInfo.
 * @param sk Stack of safeBags to encode.
 * @return PKCS#7 data object, or NULL on error.
 */
PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
""",
    "PKCS12_pack_p7data",
)

patch_both(
    "pkcs12.h",
    """PKCS7 *PKCS12_pack_p7encdata_ex(int pbe_nid, const char *pass, int passlen,
    unsigned char *salt, int saltlen, int iter,
    STACK_OF(PKCS12_SAFEBAG) *bags,
    OSSL_LIB_CTX *ctx, const char *propq);

STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass,
    int passlen);

int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
""",
    """PKCS7 *PKCS12_pack_p7encdata_ex(int pbe_nid, const char *pass, int passlen,
    unsigned char *salt, int saltlen, int iter,
    STACK_OF(PKCS12_SAFEBAG) *bags,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Unpack safeBags from a PKCS#7 encrypted-data ContentInfo.
 * @param p7 PKCS#7 encrypted-data content info wrapping a PKCS12_SAFEBAGS sequence.
 * @param pass Passphrase for decryption.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @return Stack of safeBags, or NULL if @p p7 is not encrypted-data or on decode error.
 */
STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass,
    int passlen);

/**
 * @brief Encode a stack of PKCS#7 authSafes contentInfos into a PKCS#12 structure.
 * @param p12 PKCS#12 structure whose authSafes field is updated.
 * @param safes Stack of PKCS#7 content infos to embed.
 * @return 1 on success, 0 on failure.
 */
int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
""",
    "PKCS12_unpack_p7encdata/pack_authsafes",
)

patch_both(
    "pkcs12.h",
    """int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name,
    int namelen);
int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,
    int namelen);
""",
    """int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name,
    int namelen);
/**
 * @brief Add a PKCS#9 friendlyName attribute (ASCII) to a safeBag.
 * @param bag SafeBag to modify.
 * @param name ASCII friendly name.
 * @param namelen Length of @p name in bytes, or -1 for strlen().
 * @return 1 on success, 0 on failure.
 */
int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,
    int namelen);
""",
    "PKCS12_add_friendlyname_asc",
)

patch_both(
    "pkcs12.h",
    """int PKCS12_add1_attr_by_txt(PKCS12_SAFEBAG *bag, const char *attrname, int type,
    const unsigned char *bytes, int len);
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
""",
    """int PKCS12_add1_attr_by_txt(PKCS12_SAFEBAG *bag, const char *attrname, int type,
    const unsigned char *bytes, int len);
/**
 * @brief Add a Microsoft key-usage attribute to PKCS#8 private key info.
 * @param p8 PKCS#8 private key info to modify.
 * @param usage Key-usage flag (KEY_SIG or KEY_EX).
 * @return 1 on success, 0 on failure.
 */
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
""",
    "PKCS8_add_keyusage",
)

patch_both(
    "pkcs12.h",
    """char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
const STACK_OF(X509_ATTRIBUTE) *
PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
""",
    """char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
/**
 * @brief Return the attribute stack attached to a safeBag without copying it.
 * @param bag SafeBag to query.
 * @return Internal stack of X509_ATTRIBUTE, or NULL if @p bag is NULL; do not free.
 */
const STACK_OF(X509_ATTRIBUTE) *
PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
""",
    "PKCS12_SAFEBAG_get0_attrs",
)

patch_both(
    "pkcs12.h",
    """ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor,
    const ASN1_ITEM *it,
    const char *pass, int passlen,
    void *obj, int zbuf);
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt_ex(X509_ALGOR *algor,
    const ASN1_ITEM *it,
    const char *pass, int passlen,
    void *obj, int zbuf,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    """ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor,
    const ASN1_ITEM *it,
    const char *pass, int passlen,
    void *obj, int zbuf);
/**
 * @brief Encode an ASN.1 object and encrypt the result using a library context.
 * @param algor PBE algorithm identifier.
 * @param it ASN.1 item descriptor for @p obj.
 * @param pass Passphrase for encryption.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param obj Object to encode and encrypt.
 * @param zbuf If nonzero, zero the plaintext encoding buffer after encryption.
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Encrypted data as an ASN.1 octet string, or NULL on error.
 */
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt_ex(X509_ALGOR *algor,
    const ASN1_ITEM *it,
    const char *pass, int passlen,
    void *obj, int zbuf,
    OSSL_LIB_CTX *ctx,
    const char *propq);
""",
    "PKCS12_item_i2d_encrypt_ex",
)

patch_both(
    "pkcs12.h",
    """int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
    int saltlen, int id, int iter, int n,
    unsigned char *out, const EVP_MD *md_type);
int PKCS12_key_gen_asc_ex(const char *pass, int passlen, unsigned char *salt,
    int saltlen, int id, int iter, int n,
    unsigned char *out, const EVP_MD *md_type,
    OSSL_LIB_CTX *ctx, const char *propq);
""",
    """int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
    int saltlen, int id, int iter, int n,
    unsigned char *out, const EVP_MD *md_type);
/**
 * @brief Derive key material using the PKCS#12 key-generation function (ASCII passphrase).
 * @param pass ASCII passphrase.
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param salt Salt for derivation.
 * @param saltlen Length of @p salt in bytes.
 * @param id Purpose byte (PKCS12_KEY_ID, PKCS12_IV_ID, or PKCS12_MAC_ID).
 * @param iter Iteration count (values less than 1 are treated as 1).
 * @param n Number of bytes to derive.
 * @param out Buffer to receive derived key material.
 * @param md_type Message digest for the derivation.
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return 1 on success, 0 on error.
 */
int PKCS12_key_gen_asc_ex(const char *pass, int passlen, unsigned char *salt,
    int saltlen, int id, int iter, int n,
    unsigned char *out, const EVP_MD *md_type,
    OSSL_LIB_CTX *ctx, const char *propq);
""",
    "PKCS12_key_gen_asc_ex",
)

patch_both(
    "pkcs12.h",
    """int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md_type, int en_de);
int PKCS12_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md_type, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md_type, int en_de);
/**
 * @brief Initialise a cipher context for PKCS#12 PBE encryption or decryption.
 * @param ctx Cipher context to initialise.
 * @param pass Passphrase (treated as a byte sequence).
 * @param passlen Length of @p pass, or -1 to use strlen().
 * @param param PBE algorithm parameters.
 * @param cipher Cipher for the operation.
 * @param md_type Message digest for key derivation.
 * @param en_de 1 to encrypt, 0 to decrypt.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return 1 on success, 0 on error.
 */
int PKCS12_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md_type, int en_de,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "PKCS12_PBE_keyivgen_ex",
)

patch_both(
    "pkcs12.h",
    """const ASN1_ITEM *PKCS12_AUTHSAFES_it(void);

void PKCS12_PBE_add(void);
""",
    """const ASN1_ITEM *PKCS12_AUTHSAFES_it(void);

/**
 * @brief Register PKCS#12 PBE algorithms (historical no-op; algorithms are built in).
 */
void PKCS12_PBE_add(void);
""",
    "PKCS12_PBE_add",
)

patch_both(
    "pkcs12.h",
    """int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
    STACK_OF(X509) **ca);
typedef int PKCS12_create_cb(PKCS12_SAFEBAG *bag, void *cbarg);
PKCS12 *PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey,
""",
    """int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
    STACK_OF(X509) **ca);
/**
 * @brief Callback invoked for each safeBag while building a PKCS#12 structure.
 * @param bag SafeBag just added by PKCS12_create_ex2().
 * @param cbarg Opaque argument supplied to PKCS12_create_ex2().
 * @return 1 to keep @p bag, 0 to remove it, or -1 for a fatal error.
 */
typedef int PKCS12_create_cb(PKCS12_SAFEBAG *bag, void *cbarg);
PKCS12 *PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey,
""",
    "PKCS12_create_cb",
)

patch_both(
    "pkcs12.h",
    """PKCS12_SAFEBAG *PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags,
    EVP_PKEY *key, int key_usage, int iter,
    int key_nid, const char *pass);
PKCS12_SAFEBAG *PKCS12_add_key_ex(STACK_OF(PKCS12_SAFEBAG) **pbags,
    EVP_PKEY *key, int key_usage, int iter,
    int key_nid, const char *pass,
    OSSL_LIB_CTX *ctx, const char *propq);

PKCS12_SAFEBAG *PKCS12_add_secret(STACK_OF(PKCS12_SAFEBAG) **pbags,
    int nid_type, const unsigned char *value, int len);
""",
    """PKCS12_SAFEBAG *PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
/**
 * @brief Create a key safeBag and append it to a stack of safeBags.
 * @param pbags Address of safeBag stack pointer (created if *@p pbags is NULL).
 * @param key Private key to add.
 * @param key_usage MS key-usage flag (KEY_SIG or KEY_EX), or 0 to omit.
 * @param iter Iteration count for key encryption, or 0 for default.
 * @param key_nid PBE NID for key encryption, or -1 for an unencrypted keyBag.
 * @param pass Passphrase when @p key_nid selects encryption, or NULL otherwise.
 * @return The new safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags,
    EVP_PKEY *key, int key_usage, int iter,
    int key_nid, const char *pass);
/**
 * @brief Create a key safeBag and append it to a stack of safeBags.
 * @param pbags Address of safeBag stack pointer (created if *@p pbags is NULL).
 * @param key Private key to add.
 * @param key_usage MS key-usage flag (KEY_SIG or KEY_EX), or 0 to omit.
 * @param iter Iteration count for key encryption, or 0 for default.
 * @param key_nid PBE NID for key encryption, or -1 for an unencrypted keyBag.
 * @param pass Passphrase when @p key_nid selects encryption, or NULL otherwise.
 * @param ctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return The new safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_add_key_ex(STACK_OF(PKCS12_SAFEBAG) **pbags,
    EVP_PKEY *key, int key_usage, int iter,
    int key_nid, const char *pass,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Create a secretBag safeBag and append it to a stack of safeBags.
 * @param pbags Address of safeBag stack pointer (created if *@p pbags is NULL).
 * @param nid_type NID tagging the secret contents.
 * @param value Octets of the secret value.
 * @param len Length of @p value in bytes.
 * @return The new safeBag, or NULL on error.
 */
PKCS12_SAFEBAG *PKCS12_add_secret(STACK_OF(PKCS12_SAFEBAG) **pbags,
    int nid_type, const unsigned char *value, int len);
""",
    "PKCS12_add_key/add_key_ex/add_secret",
)

patch_both(
    "pkcs12.h",
    """PKCS12 *PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int p7_nid,
    OSSL_LIB_CTX *ctx, const char *propq);

int i2d_PKCS12_bio(BIO *bp, const PKCS12 *p12);
""",
    """PKCS12 *PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int p7_nid,
    OSSL_LIB_CTX *ctx, const char *propq);

/**
 * @brief Encode a PKCS12 structure to DER and write it to a BIO.
 * @param bp Destination BIO.
 * @param p12 PKCS#12 structure to encode.
 * @return Number of bytes written, or a negative value on error.
 */
int i2d_PKCS12_bio(BIO *bp, const PKCS12 *p12);
""",
    "i2d_PKCS12_bio",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
