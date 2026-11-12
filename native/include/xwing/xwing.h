#ifndef XWING_NATIVE_H
#define XWING_NATIVE_H

#include <stdint.h>
#include <stddef.h>

#define XWING_SK_BYTES 32u
#define XWING_PK_BYTES 1216u
#define XWING_CT_BYTES 1120u
#define XWING_SS_BYTES 32u
#define XWING_MLKEM_PK_BYTES 1184u
#define XWING_MLKEM_CT_BYTES 1088u

/* Prepared contexts cache public/private key objects for repeated operations.
   Keep one context per worker thread; contexts are not shared concurrently. */
typedef struct xwing_encap_context xwing_encap_context;
typedef struct xwing_decap_context xwing_decap_context;

typedef enum {
    XWING_DRAFT11 = 0,
    /* Research comparator. It includes ML-KEM ct in the combiner and is not
       wire-compatible with draft 11 or the original paper implementation. */
    XWING_RESEARCH_HASH_CT = 1
} xwing_mode;

int xwing_keygen(uint8_t sk[XWING_SK_BYTES], uint8_t pk[XWING_PK_BYTES]);
int xwing_encapsulate(const uint8_t pk[XWING_PK_BYTES],
                      uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                      xwing_mode mode);
int xwing_decapsulate(const uint8_t sk[XWING_SK_BYTES],
                      const uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                      xwing_mode mode);

xwing_encap_context *xwing_encap_context_new(const uint8_t pk[XWING_PK_BYTES]);
void xwing_encap_context_free(xwing_encap_context *ctx);
int xwing_encapsulate_prepared(xwing_encap_context *ctx,
                               uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                               xwing_mode mode);
xwing_decap_context *xwing_decap_context_new(const uint8_t sk[XWING_SK_BYTES]);
void xwing_decap_context_free(xwing_decap_context *ctx);
int xwing_decapsulate_prepared(xwing_decap_context *ctx,
                               const uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                               xwing_mode mode);

#endif
