#include "xwing/xwing.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <string.h>

static const uint8_t label[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

static int shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx != NULL && EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, in, in_len) == 1 && EVP_DigestFinalXOF(ctx, out, out_len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int hash256(const uint8_t *in, size_t len, uint8_t out[32])
{
    unsigned int out_len = 0;
    return EVP_Digest(in, len, out, &out_len, EVP_sha3_256(), NULL) == 1 && out_len == 32;
}

static EVP_PKEY *mlkem_from_seed(const uint8_t seed[64])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                                   (void *)seed, 64);
    params[1] = OSSL_PARAM_construct_end();
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_generate(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int x25519_public(const uint8_t sk[32], uint8_t pk[32])
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, sk, 32);
    size_t len = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key, pk, &len) == 1 && len == 32;
    EVP_PKEY_free(key);
    return ok;
}

static int x25519_dh(const uint8_t sk[32], const uint8_t peer_pk[32], uint8_t ss[32])
{
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, sk, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, peer_pk, 32);
    EVP_PKEY_CTX *ctx = local ? EVP_PKEY_CTX_new_from_pkey(NULL, local, NULL) : NULL;
    size_t len = 32;
    int ok = ctx && peer && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, peer) == 1 && EVP_PKEY_derive(ctx, ss, &len) == 1 && len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    return ok;
}

static int expand(const uint8_t sk[32], EVP_PKEY **mlkem,
                  uint8_t x_sk[32], uint8_t ml_pk[1184], uint8_t x_pk[32])
{
    uint8_t expanded[96], ml_seed[64];
    size_t pk_len = 1184;
    int ok = 0;
    *mlkem = NULL;
    if (!shake256(sk, 32, expanded, sizeof(expanded))) goto done;
    memcpy(ml_seed, expanded, 64);
    memcpy(x_sk, expanded + 64, 32);
    *mlkem = mlkem_from_seed(ml_seed);
    if (!*mlkem || EVP_PKEY_get_octet_string_param(*mlkem, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            ml_pk, 1184, &pk_len) != 1 || pk_len != 1184 || !x25519_public(x_sk, x_pk)) goto done;
    ok = 1;
done:
    OPENSSL_cleanse(expanded, sizeof(expanded));
    OPENSSL_cleanse(ml_seed, sizeof(ml_seed));
    if (!ok) { EVP_PKEY_free(*mlkem); *mlkem = NULL; }
    return ok;
}

static int combine(const uint8_t ml_ss[32], const uint8_t x_ss[32],
                   const uint8_t ml_ct[1088], const uint8_t x_ct[32],
                   const uint8_t x_pk[32], xwing_mode mode, uint8_t out[32])
{
    uint8_t input[1222];
    size_t n = 0;
    if (mode == XWING_DRAFT11) {
        memcpy(input + n, ml_ss, 32); n += 32;
        memcpy(input + n, x_ss, 32); n += 32;
        memcpy(input + n, x_ct, 32); n += 32;
        memcpy(input + n, x_pk, 32); n += 32;
        memcpy(input + n, label, 6); n += 6;
    } else if (mode == XWING_RESEARCH_HASH_CT) {
        memcpy(input + n, label, 6); n += 6;
        memcpy(input + n, ml_ss, 32); n += 32;
        memcpy(input + n, x_ss, 32); n += 32;
        memcpy(input + n, x_ct, 32); n += 32;
        memcpy(input + n, x_pk, 32); n += 32;
        memcpy(input + n, ml_ct, 1088); n += 1088;
    } else return 0;
    int ok = hash256(input, n, out);
    OPENSSL_cleanse(input, sizeof(input));
    return ok;
}

int xwing_keygen(uint8_t sk[32], uint8_t pk[1216])
{
    EVP_PKEY *mlkem = NULL;
    uint8_t x_sk[32], ml_pk[1184], x_pk[32];
    int ok = 0;
    if (!sk || !pk || RAND_bytes(sk, 32) != 1) return 0;
    if (!expand(sk, &mlkem, x_sk, ml_pk, x_pk)) goto done;
    memcpy(pk, ml_pk, 1184); memcpy(pk + 1184, x_pk, 32);
    ok = 1;
done:
    EVP_PKEY_free(mlkem);
    OPENSSL_cleanse(x_sk, sizeof(x_sk)); OPENSSL_cleanse(ml_pk, sizeof(ml_pk));
    OPENSSL_cleanse(x_pk, sizeof(x_pk));
    if (!ok) { OPENSSL_cleanse(sk, 32); OPENSSL_cleanse(pk, 1216); }
    return ok;
}

int xwing_encapsulate(const uint8_t pk[1216], uint8_t ct[1120], uint8_t ss[32], xwing_mode mode)
{
    EVP_PKEY_CTX *import_ctx = NULL, *kem_ctx = NULL;
    EVP_PKEY *ml_pk = NULL;
    OSSL_PARAM params[2];
    uint8_t eph_sk[32], ml_ss[32], x_ss[32], x_ct[32];
    size_t ct_len = 1088, ss_len = 32;
    int ok = 0;
    if (ct) OPENSSL_cleanse(ct, 1120);
    if (ss) OPENSSL_cleanse(ss, 32);
    if (!pk || !ct || !ss || (mode != XWING_DRAFT11 && mode != XWING_RESEARCH_HASH_CT)) return 0;
    import_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pk, 1184);
    params[1] = OSSL_PARAM_construct_end();
    if (!import_ctx || EVP_PKEY_fromdata_init(import_ctx) <= 0 ||
        EVP_PKEY_fromdata(import_ctx, &ml_pk, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
        RAND_bytes(eph_sk, 32) != 1 || !x25519_public(eph_sk, x_ct) ||
        !x25519_dh(eph_sk, pk + 1184, x_ss)) goto done;
    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_pk, NULL);
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(kem_ctx, ct, &ct_len, ml_ss, &ss_len) <= 0 || ct_len != 1088 || ss_len != 32)
        goto done;
    memcpy(ct + 1088, x_ct, 32);
    if (!combine(ml_ss, x_ss, ct, x_ct, pk + 1184, mode, ss)) goto done;
    ok = 1;
done:
    if (!ok) { OPENSSL_cleanse(ct, 1120); OPENSSL_cleanse(ss, 32); }
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk)); OPENSSL_cleanse(ml_ss, sizeof(ml_ss));
    OPENSSL_cleanse(x_ss, sizeof(x_ss)); OPENSSL_cleanse(x_ct, sizeof(x_ct));
    EVP_PKEY_CTX_free(kem_ctx); EVP_PKEY_CTX_free(import_ctx); EVP_PKEY_free(ml_pk);
    return ok;
}

int xwing_decapsulate(const uint8_t sk[32], const uint8_t ct[1120], uint8_t ss[32], xwing_mode mode)
{
    EVP_PKEY *ml_sk = NULL;
    EVP_PKEY_CTX *kem_ctx = NULL;
    uint8_t x_sk[32], ml_pk[1184], x_pk[32], ml_ss[32], x_ss[32];
    size_t ss_len = 32;
    int ok = 0;
    if (ss) OPENSSL_cleanse(ss, 32);
    if (!sk || !ct || !ss || (mode != XWING_DRAFT11 && mode != XWING_RESEARCH_HASH_CT)) return 0;
    if (!expand(sk, &ml_sk, x_sk, ml_pk, x_pk)) goto done;
    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_sk, NULL);
    if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(kem_ctx, ml_ss, &ss_len, ct, 1088) <= 0 || ss_len != 32 ||
        !x25519_dh(x_sk, ct + 1088, x_ss) || !combine(ml_ss, x_ss, ct, ct + 1088, x_pk, mode, ss))
        goto done;
    ok = 1;
done:
    if (!ok) OPENSSL_cleanse(ss, 32);
    OPENSSL_cleanse(x_sk, sizeof(x_sk)); OPENSSL_cleanse(ml_pk, sizeof(ml_pk));
    OPENSSL_cleanse(x_pk, sizeof(x_pk)); OPENSSL_cleanse(ml_ss, sizeof(ml_ss)); OPENSSL_cleanse(x_ss, sizeof(x_ss));
    EVP_PKEY_CTX_free(kem_ctx); EVP_PKEY_free(ml_sk);
    return ok;
}

struct xwing_encap_context {
    EVP_PKEY *ml_pk;
    EVP_PKEY *x_pk;
    uint8_t x_pk_raw[32];
};

struct xwing_decap_context {
    EVP_PKEY *ml_sk;
    EVP_PKEY *x_sk;
    uint8_t x_sk_raw[32];
    uint8_t ml_pk_raw[1184];
    uint8_t x_pk_raw[32];
};

xwing_encap_context *xwing_encap_context_new(const uint8_t pk[1216])
{
    xwing_encap_context *ctx = NULL;
    EVP_PKEY_CTX *import_ctx = NULL;
    OSSL_PARAM params[2];
    if (!pk) return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    import_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pk, 1184);
    params[1] = OSSL_PARAM_construct_end();
    if (!import_ctx || EVP_PKEY_fromdata_init(import_ctx) <= 0 ||
        EVP_PKEY_fromdata(import_ctx, &ctx->ml_pk, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
        !(ctx->x_pk = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, pk + 1184, 32))) {
        EVP_PKEY_CTX_free(import_ctx);
        xwing_encap_context_free(ctx);
        return NULL;
    }
    memcpy(ctx->x_pk_raw, pk + 1184, 32);
    EVP_PKEY_CTX_free(import_ctx);
    return ctx;
}

void xwing_encap_context_free(xwing_encap_context *ctx)
{
    if (!ctx) return;
    EVP_PKEY_free(ctx->ml_pk);
    EVP_PKEY_free(ctx->x_pk);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    OPENSSL_free(ctx);
}

int xwing_encapsulate_prepared(xwing_encap_context *ctx, uint8_t ct[1120], uint8_t ss[32], xwing_mode mode)
{
    EVP_PKEY_CTX *kem_ctx = NULL, *dh_ctx = NULL;
    EVP_PKEY *eph = NULL;
    uint8_t eph_sk[32], ml_ss[32], x_ss[32], x_ct[32];
    size_t ct_len = 1088, ss_len = 32, x_len = 32;
    int ok = 0;
    if (ct) OPENSSL_cleanse(ct, 1120);
    if (ss) OPENSSL_cleanse(ss, 32);
    if (!ctx || !ct || !ss || (mode != XWING_DRAFT11 && mode != XWING_RESEARCH_HASH_CT)) return 0;
    if (RAND_bytes(eph_sk, 32) != 1 ||
        !(eph = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, eph_sk, 32)) ||
        EVP_PKEY_get_raw_public_key(eph, x_ct, &x_len) != 1 || x_len != 32) goto done;
    dh_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, eph, NULL);
    if (!dh_ctx || EVP_PKEY_derive_init(dh_ctx) != 1 ||
        EVP_PKEY_derive_set_peer(dh_ctx, ctx->x_pk) != 1 ||
        EVP_PKEY_derive(dh_ctx, x_ss, &x_len) != 1 || x_len != 32) goto done;
    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->ml_pk, NULL);
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(kem_ctx, ct, &ct_len, ml_ss, &ss_len) <= 0 || ct_len != 1088 || ss_len != 32)
        goto done;
    memcpy(ct + 1088, x_ct, 32);
    if (!combine(ml_ss, x_ss, ct, x_ct, ctx->x_pk_raw, mode, ss)) goto done;
    ok = 1;
done:
    if (!ok && ct) OPENSSL_cleanse(ct, 1120);
    if (!ok && ss) OPENSSL_cleanse(ss, 32);
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk)); OPENSSL_cleanse(ml_ss, sizeof(ml_ss));
    OPENSSL_cleanse(x_ss, sizeof(x_ss)); OPENSSL_cleanse(x_ct, sizeof(x_ct));
    EVP_PKEY_CTX_free(kem_ctx); EVP_PKEY_CTX_free(dh_ctx); EVP_PKEY_free(eph);
    return ok;
}

xwing_decap_context *xwing_decap_context_new(const uint8_t sk[32])
{
    xwing_decap_context *ctx = NULL;
    if (!sk) return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    if (!expand(sk, &ctx->ml_sk, ctx->x_sk_raw, ctx->ml_pk_raw, ctx->x_pk_raw) ||
        !(ctx->x_sk = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, ctx->x_sk_raw, 32))) {
        xwing_decap_context_free(ctx);
        return NULL;
    }
    return ctx;
}

void xwing_decap_context_free(xwing_decap_context *ctx)
{
    if (!ctx) return;
    EVP_PKEY_free(ctx->ml_sk);
    EVP_PKEY_free(ctx->x_sk);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    OPENSSL_free(ctx);
}

int xwing_decapsulate_prepared(xwing_decap_context *ctx, const uint8_t ct[1120], uint8_t ss[32], xwing_mode mode)
{
    EVP_PKEY_CTX *kem_ctx = NULL, *dh_ctx = NULL;
    EVP_PKEY *peer = NULL;
    uint8_t ml_ss[32], x_ss[32];
    size_t ss_len = 32, x_len = 32;
    int ok = 0;
    if (ss) OPENSSL_cleanse(ss, 32);
    if (!ctx || !ct || !ss || (mode != XWING_DRAFT11 && mode != XWING_RESEARCH_HASH_CT)) return 0;
    kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->ml_sk, NULL);
    if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(kem_ctx, ml_ss, &ss_len, ct, 1088) <= 0 || ss_len != 32 ||
        !(peer = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, ct + 1088, 32))) goto done;
    dh_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->x_sk, NULL);
    if (!dh_ctx || EVP_PKEY_derive_init(dh_ctx) != 1 || EVP_PKEY_derive_set_peer(dh_ctx, peer) != 1 ||
        EVP_PKEY_derive(dh_ctx, x_ss, &x_len) != 1 || x_len != 32 ||
        !combine(ml_ss, x_ss, ct, ct + 1088, ctx->x_pk_raw, mode, ss)) goto done;
    ok = 1;
done:
    if (!ok) OPENSSL_cleanse(ss, 32);
    OPENSSL_cleanse(ml_ss, sizeof(ml_ss)); OPENSSL_cleanse(x_ss, sizeof(x_ss));
    EVP_PKEY_CTX_free(kem_ctx); EVP_PKEY_CTX_free(dh_ctx); EVP_PKEY_free(peer);
    return ok;
}
