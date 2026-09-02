#!/usr/bin/env python3
"""Documentation repair batch 11c: evp.h part 2."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


def patch(rel, old, new, label):
    path = INC / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(label)
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {label}")
    ok.append(label)


print("=== batch 11c: evp.h (part 2) ===")

patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
/**
 * @brief Register an application-defined EVP_PKEY_METHOD (deprecated).
""",
    """/**
 * @brief Free an application-defined EVP_PKEY_METHOD allocated with EVP_PKEY_meth_new (deprecated).
 * @param pmeth Method table to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
/**
 * @brief Register an application-defined EVP_PKEY_METHOD (deprecated).
""",
    "EVP_PKEY_meth_free",
)

patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth);
OSSL_DEPRECATEDIN_3_0 size_t EVP_PKEY_meth_get_count(void);
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx);
#endif

EVP_KEYMGMT *EVP_KEYMGMT_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
""",
    """/**
 * @brief Unregister a previously added EVP_PKEY_METHOD from the global list (deprecated).
 * @param pmeth Method table previously passed to EVP_PKEY_meth_add0().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth);
/**
 * @brief Return the number of registered EVP_PKEY_METHOD implementations (deprecated).
 * @return Count of methods available via EVP_PKEY_meth_get0().
 */
OSSL_DEPRECATEDIN_3_0 size_t EVP_PKEY_meth_get_count(void);
/**
 * @brief Return the registered EVP_PKEY_METHOD at index @p idx (deprecated).
 * @param idx Zero-based index in the range [0, EVP_PKEY_meth_get_count()).
 * @return Internal method pointer, or NULL if @p idx is out of range.
 */
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx);
#endif

/**
 * @brief Fetch a key-management implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "RSA" or "EC".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEYMGMT, or NULL on error; free with EVP_KEYMGMT_free.
 */
EVP_KEYMGMT *EVP_KEYMGMT_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
""",
    "EVP_PKEY_meth_remove/count/get0+KEYMGMT_fetch",
)

patch(
    "evp.h",
    """int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name);
/**
 * @brief Invoke @p fn for every KEYMGMT implementation available in @p libctx.
""",
    """/**
 * @brief Test whether a key-management implementation is known under the given name.
 * @param keymgmt Keymgmt method to query.
 * @param name Algorithm name to match (for example "RSA").
 * @return 1 if @p name is an alias for @p keymgmt, or 0 otherwise.
 */
int EVP_KEYMGMT_is_a(const EVP_KEYMGMT *keymgmt, const char *name);
/**
 * @brief Invoke @p fn for every KEYMGMT implementation available in @p libctx.
""",
    "EVP_KEYMGMT_is_a",
)

patch(
    "evp.h",
    """int EVP_KEYMGMT_names_do_all(const EVP_KEYMGMT *keymgmt,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Describe parameters that can be read from keys managed by a keymgmt.
""",
    """/**
 * @brief Invoke a callback for every name (including aliases) associated with a keymgmt.
 * @param keymgmt Key management implementation whose names are enumerated.
 * @param fn Callback receiving each name and @p data.
 * @param data Opaque pointer forwarded to @p fn.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEYMGMT_names_do_all(const EVP_KEYMGMT *keymgmt,
    void (*fn)(const char *name, void *data),
    void *data);
/**
 * @brief Describe parameters that can be read from keys managed by a keymgmt.
""",
    "EVP_KEYMGMT_names_do_all",
)

patch(
    "evp.h",
    """void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);

int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params);
const OSSL_PARAM *EVP_PKEY_CTX_gettable_params(const EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params);
const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
    const char *value);
/**
 * @brief Send a control command with a uint64_t argument to a key context.
""",
    """/**
 * @brief Free an EVP_PKEY_CTX and release associated resources.
 * @param ctx Key context to free, or NULL.
 */
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype);

/**
 * @brief Retrieve parameters from a key context into an OSSL_PARAM array.
 * @param ctx Key context to query.
 * @param params Array of OSSL_PARAM request/response descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params);
/**
 * @brief Return the OSSL_PARAM descriptors gettable from a key context.
 * @param ctx Key context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_PKEY_CTX_gettable_params(const EVP_PKEY_CTX *ctx);
/**
 * @brief Set parameters on a key context via an OSSL_PARAM array.
 * @param ctx Key context to configure.
 * @param params Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params);
const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx);
/**
 * @brief Send an algorithm-specific control command to a key context.
 * @param ctx Key context receiving the command.
 * @param keytype Expected key type, or -1 to skip the type check.
 * @param optype Expected operation type, or -1 to skip the operation check.
 * @param cmd Algorithm-specific control command.
 * @param p1 Integer argument for @p cmd.
 * @param p2 Pointer argument for @p cmd, or NULL.
 * @return Positive on success, 0 or negative on failure.
 */
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
/**
 * @brief Send a named string control to a key context (for example "rsa_padding").
 * @param ctx Key context receiving the control.
 * @param type Control name understood by the algorithm.
 * @param value Control value as a NUL-terminated string, or NULL when unused.
 * @return Positive on success, 0 or negative on failure.
 */
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
    const char *value);
/**
 * @brief Send a control command with a uint64_t argument to a key context.
""",
    "EVP_PKEY_CTX_free/get/set/ctrl/ctrl_str",
)

patch(
    "evp.h",
    """int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str);
/**
 * @brief Decode a hex string to bytes and pass them to EVP_PKEY_CTX_ctrl as the p2 buffer.
""",
    """/**
 * @brief Pass a NUL-terminated string to EVP_PKEY_CTX_ctrl as the p2 argument.
 * @param ctx Key context that receives the control.
 * @param cmd Control command number understood by the key method.
 * @param str NUL-terminated string passed as @c p2 (length is strlen(@p str)).
 * @return Positive on success, 0 or negative on failure (same convention as EVP_PKEY_CTX_ctrl).
 */
int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str);
/**
 * @brief Decode a hex string to bytes and pass them to EVP_PKEY_CTX_ctrl as the p2 buffer.
""",
    "EVP_PKEY_CTX_str2ctrl",
)

patch(
    "evp.h",
    """EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype, const char *propq,
    const unsigned char *pub, size_t len);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub,
    size_t len);
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
    size_t *len);
/**
 * @brief Export the raw public key bytes of @p pkey into @p pub.
""",
    """/**
 * @brief Create an EVP_PKEY from raw public-key octets using a named algorithm and library context.
 * @param libctx Library context used to fetch the key type, or NULL for the default.
 * @param keytype Algorithm name such as "ED25519" or "X25519".
 * @param propq Property query string, or NULL.
 * @param pub Raw public-key bytes in the algorithm-native format.
 * @param len Length of @p pub in bytes.
 * @return New EVP_PKEY, or NULL on failure; free with EVP_PKEY_free.
 */
EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx,
    const char *keytype, const char *propq,
    const unsigned char *pub, size_t len);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub,
    size_t len);
/**
 * @brief Export the raw private key bytes of @p pkey into @p priv.
 * @param pkey Key whose private material is exported (algorithm-dependent format).
 * @param priv Output buffer, or NULL to only query the required length via @p len.
 * @param len On entry, capacity of @p priv when non-NULL; on return, number of bytes written or required.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
    size_t *len);
/**
 * @brief Export the raw public key bytes of @p pkey into @p pub.
""",
    "EVP_PKEY_new_raw_public_key_ex+get_raw_private_key",
)

patch(
    "evp.h",
    """void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx);
/**
 * @brief Return the primary EVP_PKEY associated with a key context.
""",
    """/**
 * @brief Return the application-private data pointer previously set on a key context.
 * @param ctx Key context to query.
 * @return Opaque pointer from EVP_PKEY_CTX_set_data(), or NULL if unset.
 */
void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx);
/**
 * @brief Return the primary EVP_PKEY associated with a key context.
""",
    "EVP_PKEY_CTX_get_data",
)

patch(
    "evp.h",
    """const char *EVP_SIGNATURE_get0_name(const EVP_SIGNATURE *signature);
/**
 * @brief Return a human-readable description of a signature algorithm implementation.
""",
    """/**
 * @brief Return the primary algorithm name of a signature implementation.
 * @param signature Signature algorithm object from EVP_SIGNATURE_fetch().
 * @return NUL-terminated name string owned by @p signature, or NULL if unavailable.
 */
const char *EVP_SIGNATURE_get0_name(const EVP_SIGNATURE *signature);
/**
 * @brief Return a human-readable description of a signature algorithm implementation.
""",
    "EVP_SIGNATURE_get0_name",
)

patch(
    "evp.h",
    """const OSSL_PARAM *EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig);
const OSSL_PARAM *EVP_SIGNATURE_settable_ctx_params(const EVP_SIGNATURE *sig);

/**
 * @brief Release a reference to a fetched asymmetric cipher algorithm.
""",
    """/**
 * @brief Return the OSSL_PARAM descriptors gettable on a signature context for @p sig.
 * @param sig Signature algorithm whose gettable context parameters are listed.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig);
/**
 * @brief Return the OSSL_PARAM descriptors settable on a signature context for @p sig.
 * @param sig Signature algorithm whose settable context parameters are listed.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_END, or NULL.
 */
const OSSL_PARAM *EVP_SIGNATURE_settable_ctx_params(const EVP_SIGNATURE *sig);

/**
 * @brief Release a reference to a fetched asymmetric cipher algorithm.
""",
    "EVP_SIGNATURE_gettable/settable_ctx_params",
)

patch(
    "evp.h",
    """int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER *cipher);
OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher);
""",
    """/**
 * @brief Increment the reference count on a fetched asymmetric cipher algorithm.
 * @param cipher Algorithm object whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER *cipher);
OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher);
""",
    "EVP_ASYM_CIPHER_up_ref",
)

patch(
    "evp.h",
    """int EVP_KEM_up_ref(EVP_KEM *wrap);
OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *wrap);
EVP_KEM *EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Test whether a KEM implementation is known by a given name.
""",
    """/**
 * @brief Increment the reference count on a fetched KEM algorithm.
 * @param wrap KEM object whose reference count is increased.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KEM_up_ref(EVP_KEM *wrap);
OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *wrap);
/**
 * @brief Fetch a key-encapsulation mechanism implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "RSA" or a provider KEM name.
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEM, or NULL on error; free with EVP_KEM_free.
 */
EVP_KEM *EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Test whether a KEM implementation is known by a given name.
""",
    "EVP_KEM_up_ref+fetch",
)

patch(
    "evp.h",
    """int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for signing and apply optional algorithm parameters.
""",
    """/**
 * @brief Initialize a key context for signing with the key bound to @p ctx.
 * @param ctx Key context created for a signing-capable algorithm.
 * @return 1 on success, or 0 / a negative value on failure.
 */
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialize @p ctx for signing and apply optional algorithm parameters.
""",
    "EVP_PKEY_sign_init",
)

patch(
    "evp.h",
    """int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialise @p ctx for signature verification with optional parameters.
""",
    """/**
 * @brief Initialise a key context for signature verification with the key bound to @p ctx.
 * @param ctx Key context holding the public key (or key pair) used to verify.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Initialise @p ctx for signature verification with optional parameters.
""",
    "EVP_PKEY_verify_init",
)

patch(
    "evp.h",
    """int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
/**
 * @brief Initialise @p ctx for private-key decryption.
""",
    """/**
 * @brief Encrypt data with a public key using a context from EVP_PKEY_encrypt_init().
 * @param ctx Encryption context holding the public key.
 * @param out Output buffer for ciphertext, or NULL to query the required size via @p outlen.
 * @param outlen On entry, capacity of @p out when non-NULL; on return, bytes written or required.
 * @param in Plaintext bytes to encrypt.
 * @param inlen Length of @p in in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
/**
 * @brief Initialise @p ctx for private-key decryption.
""",
    "EVP_PKEY_encrypt",
)

patch(
    "evp.h",
    """int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *ctx, EVP_PKEY *peer,
    int validate_peer);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
""",
    """/**
 * @brief Initialize @p ctx for key derivation and apply optional algorithm parameters.
 * @param ctx Key context created for a derivation-capable algorithm.
 * @param params Optional OSSL_PARAM array set on the context before return, or NULL.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
/**
 * @brief Set the peer public key for derivation, optionally validating it first.
 * @param ctx Derivation context previously initialized with EVP_PKEY_derive_init() or _ex().
 * @param peer Peer's public key used to compute the shared secret.
 * @param validate_peer Non-zero to run a public-key check on @p peer before use, or 0 to skip.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *ctx, EVP_PKEY *peer,
    int validate_peer);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
""",
    "EVP_PKEY_derive_init_ex+set_peer_ex",
)

patch(
    "evp.h",
    """int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *unwrapped, size_t *unwrappedlen,
    const unsigned char *wrapped, size_t wrappedlen);
/**
 * @brief Callback type invoked during key or parameter generation to report progress or cancel.
""",
    """/**
 * @brief Decapsulate a shared secret from a KEM ciphertext using a context from EVP_PKEY_decapsulate_init().
 * @param ctx Decapsulation context holding the private key.
 * @param unwrapped Buffer for the recovered shared secret, or NULL to query size via @p unwrappedlen.
 * @param unwrappedlen On entry, capacity of @p unwrapped when non-NULL; on return, bytes written or required.
 * @param wrapped Encapsulation ciphertext bytes.
 * @param wrappedlen Length of @p wrapped in bytes.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
    unsigned char *unwrapped, size_t *unwrappedlen,
    const unsigned char *wrapped, size_t wrappedlen);
/**
 * @brief Callback type invoked during key or parameter generation to report progress or cancel.
""",
    "EVP_PKEY_decapsulate",
)

patch(
    "evp.h",
    """int EVP_PKEY_get_size_t_param(const EVP_PKEY *pkey, const char *key_name,
    size_t *out);
/**
 * @brief Fetch a named BIGNUM parameter from an EVP_PKEY.
""",
    """/**
 * @brief Fetch a named size_t parameter from an EVP_PKEY.
 * @param pkey Key to query.
 * @param key_name Parameter name (OSSL_PKEY_PARAM_*).
 * @param out On success, receives the parameter value.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_get_size_t_param(const EVP_PKEY *pkey, const char *key_name,
    size_t *out);
/**
 * @brief Fetch a named BIGNUM parameter from an EVP_PKEY.
""",
    "EVP_PKEY_get_size_t_param",
)

patch(
    "evp.h",
    """int EVP_PKEY_set_int_param(EVP_PKEY *pkey, const char *key_name, int in);
int EVP_PKEY_set_size_t_param(EVP_PKEY *pkey, const char *key_name, size_t in);
/**
 * @brief Set a named BIGNUM parameter on an EVP_PKEY.
""",
    """/**
 * @brief Set a named integer parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param in Integer value to assign.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_int_param(EVP_PKEY *pkey, const char *key_name, int in);
/**
 * @brief Set a named size_t parameter on an EVP_PKEY.
 * @param pkey Key to update.
 * @param key_name Parameter name understood by the key type (OSSL_PKEY_PARAM_*).
 * @param in Size value to assign.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_set_size_t_param(EVP_PKEY *pkey, const char *key_name, size_t in);
/**
 * @brief Set a named BIGNUM parameter on an EVP_PKEY.
""",
    "EVP_PKEY_set_int_param+set_size_t_param",
)

patch(
    "evp.h",
    """int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Initialise a key context for algorithm parameter generation.
 * @param ctx Context prepared for a parameter-generation-capable algorithm.
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
/**
 * @brief Generate algorithm parameters into *@p ppkey using an initialised paramgen context.
 * @param ctx Context prepared with EVP_PKEY_paramgen_init() (and any controls).
 * @param ppkey Address of an EVP_PKEY pointer that receives the parameters (allocated if NULL).
 * @return 1 on success, or a non-positive value on failure.
 */
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_paramgen_init+paramgen",
)

patch(
    "evp.h",
    """int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);
""",
    """/**
 * @brief Validate the private key associated with a key context.
 * @param ctx Context holding the key to check (typically created with EVP_PKEY_CTX_new).
 * @return 1 if the private key is valid, or a non-positive value on failure.
 */
int EVP_PKEY_private_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx);
""",
    "EVP_PKEY_private_check",
)

patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth, int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
        EVP_MD_CTX *mctx));
/**
 * @brief Set public-key encryption callbacks on an EVP_PKEY_METHOD (deprecated).
""",
    """/**
 * @brief Set digest-context verification callbacks on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to update.
 * @param verifyctx_init Optional initialiser called before streaming verify, or NULL.
 * @param verifyctx Callback that verifies @p sig against digest state in @p mctx, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth, int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
    int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
        EVP_MD_CTX *mctx));
/**
 * @brief Set public-key encryption callbacks on an EVP_PKEY_METHOD (deprecated).
""",
    "EVP_PKEY_meth_set_verifyctx",
)

patch(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth, int (**pdecrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pdecrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, int (**pderive_init)(EVP_PKEY_CTX *ctx),
""",
    """/**
 * @brief Return the decrypt_init and decrypt callbacks from an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method table to query.
 * @param pdecrypt_init Optional destination for the decrypt_init function pointer, or NULL.
 * @param pdecrypt Optional destination for the decrypt function pointer, or NULL.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth, int (**pdecrypt_init)(EVP_PKEY_CTX *ctx),
    int (**pdecrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, int (**pderive_init)(EVP_PKEY_CTX *ctx),
""",
    "EVP_PKEY_meth_get_decrypt",
)

patch(
    "evp.h",
    """EVP_KEYEXCH *EVP_KEYEXCH_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Return the provider that implements a key-exchange algorithm.
""",
    """/**
 * @brief Fetch a key-exchange algorithm implementation from providers.
 * @param ctx Library context to search, or NULL for the default.
 * @param algorithm Algorithm name such as "DH" or "X25519".
 * @param properties Property query string, or NULL.
 * @return Fetched EVP_KEYEXCH, or NULL on error; free with EVP_KEYEXCH_free.
 */
EVP_KEYEXCH *EVP_KEYEXCH_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
/**
 * @brief Return the provider that implements a key-exchange algorithm.
""",
    "EVP_KEYEXCH_fetch",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
if missing:
    raise SystemExit(1)
