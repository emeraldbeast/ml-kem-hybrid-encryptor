#include "xwing/xwing.h"
#include <openssl/crypto.h>
#include <stdio.h>

int main(void)
{
    uint8_t sk[32], pk[1216], ct[1120], sender[32], receiver[32];
    const xwing_mode modes[] = {XWING_DRAFT11, XWING_RESEARCH_HASH_CT};
    const char *names[] = {"Draft-11 X-Wing", "research hash-CT comparator"};
    if (!xwing_keygen(sk, pk)) { fputs("X-Wing key generation failed.\n", stderr); return 1; }
    for (size_t i = 0; i < 2; ++i) {
        if (!xwing_encapsulate(pk, ct, sender, modes[i]) ||
            !xwing_decapsulate(sk, ct, receiver, modes[i]) || CRYPTO_memcmp(sender, receiver, 32) != 0) {
            fprintf(stderr, "%s round trip failed.\n", names[i]);
            OPENSSL_cleanse(sk, sizeof(sk)); return 1;
        }
        printf("%s round trip: matching 32-byte secrets (not displayed).\n", names[i]);
    }
    puts("The hash-CT comparator is research-only and does not interoperate with draft 11.");
    OPENSSL_cleanse(sk, sizeof(sk)); OPENSSL_cleanse(sender, sizeof(sender));
    OPENSSL_cleanse(receiver, sizeof(receiver));
    return 0;
}
