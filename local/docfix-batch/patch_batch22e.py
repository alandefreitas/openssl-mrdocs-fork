#!/usr/bin/env python3
"""Documentation repair batch 22e: srp.h undocumented symbols."""
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


print("=== batch 22e (srp.h) ===")

patch_both(
    "srp.h",
    """typedef struct SRP_gN_cache_st {
    char *b64_bn;
    BIGNUM *bn;
} SRP_gN_cache;
""",
    """/**
 * @brief Cache entry mapping a base64-encoded SRP group parameter to a BIGNUM.
 */
typedef struct SRP_gN_cache_st {
    /** Base64 text of the cached parameter (used as the lookup key). */
    char *b64_bn;
    /** Parsed big-number value for @c b64_bn. */
    BIGNUM *bn;
} SRP_gN_cache;
""",
    "SRP_gN_cache_st",
)

patch_both(
    "srp.h",
    """typedef struct SRP_user_pwd_st {
    /* Owned by us. */
    char *id;
    BIGNUM *s;
    BIGNUM *v;
    /* Not owned by us. */
    const BIGNUM *g;
    const BIGNUM *N;
    /* Owned by us. */
    char *info;
} SRP_user_pwd;
""",
    """/**
 * @brief SRP verifier database entry for one user (salt, verifier, and group parameters).
 */
typedef struct SRP_user_pwd_st {
    /** User identifier string (owned by this structure). */
    char *id;
    /** Salt value @c s used when computing the verifier (owned by this structure). */
    BIGNUM *s;
    /** Password verifier @c v = g^x mod N (owned by this structure). */
    BIGNUM *v;
    /** Generator @c g for the SRP group (not owned; typically points at shared constants). */
    const BIGNUM *g;
    /** Safe prime modulus @c N for the SRP group (not owned; typically points at shared constants). */
    const BIGNUM *N;
    /** Optional informational string stored with the user entry (owned by this structure). */
    char *info;
} SRP_user_pwd;
""",
    "SRP_user_pwd_st",
)

patch_both(
    "srp.h",
    """OSSL_DEPRECATEDIN_3_0
SRP_user_pwd *SRP_user_pwd_new(void);
OSSL_DEPRECATEDIN_3_0
void SRP_user_pwd_free(SRP_user_pwd *user_pwd);

OSSL_DEPRECATEDIN_3_0
void SRP_user_pwd_set_gN(SRP_user_pwd *user_pwd, const BIGNUM *g,
    const BIGNUM *N);
OSSL_DEPRECATEDIN_3_0
int SRP_user_pwd_set1_ids(SRP_user_pwd *user_pwd, const char *id,
    const char *info);
OSSL_DEPRECATEDIN_3_0
int SRP_user_pwd_set0_sv(SRP_user_pwd *user_pwd, BIGNUM *s, BIGNUM *v);
""",
    """/**
 * @brief Allocate an empty SRP_user_pwd structure.
 * @return New user entry, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0
SRP_user_pwd *SRP_user_pwd_new(void);
/**
 * @brief Free an SRP_user_pwd structure and owned fields.
 * @param user_pwd Entry to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0
void SRP_user_pwd_free(SRP_user_pwd *user_pwd);

OSSL_DEPRECATEDIN_3_0
void SRP_user_pwd_set_gN(SRP_user_pwd *user_pwd, const BIGNUM *g,
    const BIGNUM *N);
/**
 * @brief Set the user identifier and optional info string on an SRP_user_pwd.
 * @param user_pwd Entry to update.
 * @param id User name to copy, or NULL to clear.
 * @param info Optional info string to copy, or NULL to clear.
 * @return 1 on success, 0 on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_user_pwd_set1_ids(SRP_user_pwd *user_pwd, const char *id,
    const char *info);
/**
 * @brief Assign salt and verifier BIGNUMs to an SRP_user_pwd (ownership transfers on success).
 * @param user_pwd Entry to update.
 * @param s Salt value, or NULL to clear.
 * @param v Verifier value, or NULL to clear.
 * @return 1 on success, 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_user_pwd_set0_sv(SRP_user_pwd *user_pwd, BIGNUM *s, BIGNUM *v);
""",
    "SRP_user_pwd_new/free/set1_ids/set0_sv",
)

patch_both(
    "srp.h",
    """typedef struct SRP_VBASE_st {
    STACK_OF(SRP_user_pwd) *users_pwd;
    STACK_OF(SRP_gN_cache) *gN_cache;
    /* to simulate a user */
    char *seed_key;
    const BIGNUM *default_g;
    const BIGNUM *default_N;
} SRP_VBASE;
""",
    """/**
 * @brief In-memory SRP verifier database loaded from a verifier file.
 */
typedef struct SRP_VBASE_st {
    /** Stack of registered user verifier entries. */
    STACK_OF(SRP_user_pwd) *users_pwd;
    /** Cache of parsed SRP group parameters keyed by base64 text. */
    STACK_OF(SRP_gN_cache) *gN_cache;
    /* to simulate a user */
    char *seed_key;
    const BIGNUM *default_g;
    const BIGNUM *default_N;
} SRP_VBASE;
""",
    "SRP_VBASE",
)

patch_both(
    "srp.h",
    """typedef struct SRP_gN_st {
    char *id;
    const BIGNUM *g;
    const BIGNUM *N;
} SRP_gN;
""",
    """/**
 * @brief Named SRP group parameters (generator @c g and safe prime @c N).
 */
typedef struct SRP_gN_st {
    /** Text identifier for the group (for example "2048" or "8192"). */
    char *id;
    const BIGNUM *g;
    /** Safe prime modulus @c N for the group. */
    const BIGNUM *N;
} SRP_gN;
""",
    "SRP_gN",
)

patch_both(
    "srp.h",
    """OSSL_DEPRECATEDIN_3_0
SRP_VBASE *SRP_VBASE_new(char *seed_key);
OSSL_DEPRECATEDIN_3_0
void SRP_VBASE_free(SRP_VBASE *vb);
OSSL_DEPRECATEDIN_3_0
int SRP_VBASE_init(SRP_VBASE *vb, char *verifier_file);

OSSL_DEPRECATEDIN_3_0
int SRP_VBASE_add0_user(SRP_VBASE *vb, SRP_user_pwd *user_pwd);

/* NOTE: unlike in SRP_VBASE_get_by_user, caller owns the returned pointer.*/
OSSL_DEPRECATEDIN_3_0
SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username);
""",
    """OSSL_DEPRECATEDIN_3_0
SRP_VBASE *SRP_VBASE_new(char *seed_key);
/**
 * @brief Free an SRP verifier database and its contents.
 * @param vb Database to free, or NULL.
 */
OSSL_DEPRECATEDIN_3_0
void SRP_VBASE_free(SRP_VBASE *vb);
/**
 * @brief Load SRP verifier entries from a text verifier file into a database.
 * @param vb Database to populate.
 * @param verifier_file Path to the verifier file (see SRP_VBASE format in srp.c).
 * @return SRP_NO_ERROR on success, or an SRP_ERR_* code on failure.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_VBASE_init(SRP_VBASE *vb, char *verifier_file);

/**
 * @brief Append a user entry to an SRP verifier database (ownership transfers on success).
 * @param vb Database to update.
 * @param user_pwd User entry to store.
 * @return 1 on success, 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_VBASE_add0_user(SRP_VBASE *vb, SRP_user_pwd *user_pwd);

/* NOTE: unlike in SRP_VBASE_get_by_user, caller owns the returned pointer.*/
/**
 * @brief Look up an SRP user entry, synthesizing one from @c seed_key when absent.
 * @param vb Verifier database to search.
 * @param username User name to look up.
 * @return Newly allocated SRP_user_pwd on success (caller must free), or NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username);
""",
    "SRP_VBASE_free/init/add0_user/get1_by_user",
)

patch_both(
    "srp.h",
    """OSSL_DEPRECATEDIN_3_0
char *SRP_create_verifier_ex(const char *user, const char *pass, char **salt,
    char **verifier, const char *N, const char *g,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
char *SRP_create_verifier(const char *user, const char *pass, char **salt,
    char **verifier, const char *N, const char *g);
OSSL_DEPRECATEDIN_3_0
int SRP_create_verifier_BN_ex(const char *user, const char *pass, BIGNUM **salt,
    BIGNUM **verifier, const BIGNUM *N,
    const BIGNUM *g, OSSL_LIB_CTX *libctx,
    const char *propq);
OSSL_DEPRECATEDIN_3_0
int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUM **salt,
    BIGNUM **verifier, const BIGNUM *N,
    const BIGNUM *g);
""",
    """/**
 * @brief Create base64-encoded SRP salt and verifier strings for a user/password.
 * @param user User name.
 * @param pass Password.
 * @param salt Address of salt pointer: receives a newly allocated base64 salt when *@p salt is NULL, or uses the supplied value.
 * @param verifier Receives a newly allocated base64 verifier string.
 * @param N Base64-encoded safe prime, or NULL to select a default group via @p g.
 * @param g Base64-encoded generator when @p N is set, or a default group id such as "2048" when @p N is NULL.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return "*" if @p N was supplied, the selected group id otherwise; do not free. NULL on error.
 */
OSSL_DEPRECATEDIN_3_0
char *SRP_create_verifier_ex(const char *user, const char *pass, char **salt,
    char **verifier, const char *N, const char *g,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
char *SRP_create_verifier(const char *user, const char *pass, char **salt,
    char **verifier, const char *N, const char *g);
/**
 * @brief Create SRP salt and verifier BIGNUMs for a user/password.
 * @param user User name.
 * @param pass Password.
 * @param salt Address of salt pointer: receives a newly allocated salt when *@p salt is NULL, or uses the supplied value.
 * @param verifier Receives a newly allocated verifier BIGNUM.
 * @param N Safe prime modulus for the SRP group.
 * @param g Generator for the SRP group.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return 1 on success, 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_create_verifier_BN_ex(const char *user, const char *pass, BIGNUM **salt,
    BIGNUM **verifier, const BIGNUM *N,
    const BIGNUM *g, OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Create SRP salt and verifier BIGNUMs for a user/password.
 * @param user User name.
 * @param pass Password.
 * @param salt Address of salt pointer: receives a newly allocated salt when *@p salt is NULL, or uses the supplied value.
 * @param verifier Receives a newly allocated verifier BIGNUM.
 * @param N Safe prime modulus for the SRP group.
 * @param g Generator for the SRP group.
 * @return 1 on success, 0 on error.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUM **salt,
    BIGNUM **verifier, const BIGNUM *N,
    const BIGNUM *g);
""",
    "SRP_create_verifier*",
)

patch_both(
    "srp.h",
    """/* see srp.c */
OSSL_DEPRECATEDIN_3_0
char *SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N);
""",
    """/* see srp.c */
/**
 * @brief Test whether @p g and @p N match a built-in RFC 5054 SRP group.
 * @param g Generator to test.
 * @param N Safe prime modulus to test.
 * @return Text group id (for example "2048") when recognized; do not free. NULL if unknown or on error.
 */
OSSL_DEPRECATEDIN_3_0
char *SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N);
""",
    "SRP_check_known_gN_param",
)

patch_both(
    "srp.h",
    """OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_B_ex(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g,
    const BIGNUM *v, OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_B(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g,
    const BIGNUM *v);

OSSL_DEPRECATEDIN_3_0
int SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_u_ex(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_u(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N);
""",
    """/**
 * @brief Compute the server public value B = g^b + k*v (mod N) for TLS-SRP.
 * @param b Server secret exponent.
 * @param N Safe prime modulus.
 * @param g Generator.
 * @param v User password verifier.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Newly allocated B value, or NULL on error. Caller must free.
 */
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_B_ex(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g,
    const BIGNUM *v, OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_B(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g,
    const BIGNUM *v);

/**
 * @brief Verify that the client public value A is non-zero modulo N.
 * @param A Client public value.
 * @param N Safe prime modulus.
 * @return 1 if A mod N is non-zero, 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N);
/**
 * @brief Compute the SRP scrambling parameter u = H(PAD(A) || PAD(B)).
 * @param A Client public value.
 * @param B Server public value.
 * @param N Safe prime modulus used for padding width.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Newly allocated u value, or NULL on error. Caller must free.
 */
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_u_ex(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_u(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N);
""",
    "SRP_Calc_B_ex/Verify_A_mod_N/Calc_u*",
)

patch_both(
    "srp.h",
    """OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_x_ex(const BIGNUM *s, const char *user, const char *pass,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_x(const BIGNUM *s, const char *user, const char *pass);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_A(const BIGNUM *a, const BIGNUM *N, const BIGNUM *g);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_client_key_ex(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g,
    const BIGNUM *x, const BIGNUM *a, const BIGNUM *u,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_client_key(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g,
    const BIGNUM *x, const BIGNUM *a, const BIGNUM *u);
OSSL_DEPRECATEDIN_3_0
int SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N);
""",
    """/**
 * @brief Compute the private exponent x = H(s, H(user:pass)) for TLS-SRP.
 * @param s Salt value.
 * @param user User name.
 * @param pass Password.
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Newly allocated x value, or NULL on error. Caller must free.
 */
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_x_ex(const BIGNUM *s, const char *user, const char *pass,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_x(const BIGNUM *s, const char *user, const char *pass);
/**
 * @brief Compute the client public value A = g^a mod N.
 * @param a Client secret exponent.
 * @param N Safe prime modulus.
 * @param g Generator.
 * @return Newly allocated A value, or NULL on error. Caller must free.
 */
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_A(const BIGNUM *a, const BIGNUM *N, const BIGNUM *g);
/**
 * @brief Compute the client session key K for TLS-SRP.
 * @param N Safe prime modulus.
 * @param B Server public value.
 * @param g Generator.
 * @param x Private exponent from SRP_Calc_x().
 * @param a Client secret exponent.
 * @param u Scrambling parameter from SRP_Calc_u().
 * @param libctx Library context for algorithm fetching, or NULL for default.
 * @param propq Property query for algorithm fetching, or NULL.
 * @return Newly allocated session key, or NULL on error. Caller must free.
 */
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_client_key_ex(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g,
    const BIGNUM *x, const BIGNUM *a, const BIGNUM *u,
    OSSL_LIB_CTX *libctx, const char *propq);
OSSL_DEPRECATEDIN_3_0
BIGNUM *SRP_Calc_client_key(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g,
    const BIGNUM *x, const BIGNUM *a, const BIGNUM *u);
/**
 * @brief Verify that the server public value B is non-zero modulo N.
 * @param B Server public value.
 * @param N Safe prime modulus.
 * @return 1 if B mod N is non-zero, 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0
int SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N);
""",
    "SRP_Calc_x*/Calc_A/client_key*/Verify_B_mod_N",
)

patch_both(
    "srp.h",
    """#ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0
SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username);
#endif
""",
    """#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/**
 * @brief Look up an SRP user entry without transferring ownership (deprecated).
 * @param vb Verifier database to search.
 * @param username User name to look up.
 * @return Internal SRP_user_pwd pointer, or NULL if not found; do not free.
 */
OSSL_DEPRECATEDIN_1_1_0
SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username);
#endif
""",
    "SRP_VBASE_get_by_user",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
