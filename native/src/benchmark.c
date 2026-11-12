#include "xwing/xwing.h"
#include <omp.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>

static int read_count(const char *s, int *value)
{
    char *end = NULL; long n = strtol(s, &end, 10);
    if (!s[0] || !end || *end || n < 1 || n > 10000000) return 0;
    *value = (int)n; return 1;
}

int main(int argc, char **argv)
{
    int count = 1000;
    uint8_t sk[32], pk[1216];
    if (argc > 2 || (argc == 2 && !read_count(argv[1], &count))) {
        fprintf(stderr, "Usage: %s [encapsulations-per-mode-and-thread-count]\n", argv[0]); return 2;
    }
    if (!xwing_keygen(sk, pk)) { fputs("X-Wing key generation failed.\n", stderr); return 1; }
    fprintf(stderr, "compiler=%s; openssl=%s; omp_processors=%d\n",
#ifdef __VERSION__
            __VERSION__,
#else
            "unknown",
#endif
            OpenSSL_version(OPENSSL_VERSION), omp_get_num_procs());
    puts("mode,threads,operations,seconds,operations_per_second,speedup,efficiency");
    for (int mode_id = 0; mode_id < 2; ++mode_id) {
        double serial_seconds = 0.0;
        for (int threads = 1; threads <= omp_get_num_procs(); threads *= 2) {
            xwing_mode mode = mode_id == 0 ? XWING_DRAFT11 : XWING_RESEARCH_HASH_CT;
            int failed = 0;
            omp_set_num_threads(threads);
            double start = omp_get_wtime();
            #pragma omp parallel for schedule(static) reduction(|:failed)
            for (int i = 0; i < count; ++i) {
                uint8_t ct[1120], ss[32];
                if (!xwing_encapsulate(pk, ct, ss, mode)) failed = 1;
                OPENSSL_cleanse(ss, sizeof(ss));
            }
            double elapsed = omp_get_wtime() - start;
            if (failed) { fputs("An encapsulation failed.\n", stderr); return 1; }
            if (threads == 1) serial_seconds = elapsed;
            double speedup = serial_seconds / elapsed;
            printf("%s,%d,%d,%.6f,%.2f,%.4f,%.4f\n",
                   mode_id == 0 ? "draft11" : "paper_hash_ct", threads, count, elapsed,
                   count / elapsed, speedup, speedup / threads);
            if (threads > omp_get_num_procs() / 2) break;
        }
    }
    OPENSSL_cleanse(sk, sizeof(sk));
    return 0;
}
