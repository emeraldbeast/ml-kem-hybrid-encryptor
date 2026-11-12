#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Teaching workload: cyclic convolution modulo q in F_q[X]/(X^256-1).
   q=12289 admits a radix-2 length-256 transform. This is not ML-KEM's
   negacyclic ring Z_3329[X]/(X^256+1), and is never linked into X-Wing. */
#define N 256
#define Q 12289u
#define ROOT 11u
#define BARRETT_MU 349496u
#define STAGES 8

typedef struct {
    uint16_t forward[STAGES][N / 2];
    uint16_t inverse[STAGES][N / 2];
    uint16_t inv_n;
} ntt_plan;

static uint16_t reduce32(uint32_t x)
{
    uint32_t quotient = (uint32_t)(((uint64_t)x * BARRETT_MU) >> 32);
    uint32_t r = x - quotient * Q;
    if (r >= Q) r -= Q;
    if (r >= Q) r -= Q;
    return (uint16_t)r;
}

static uint16_t addq(uint16_t a, uint16_t b)
{
    uint32_t r = (uint32_t)a + b;
    if (r >= Q) r -= Q;
    return (uint16_t)r;
}

static uint16_t subq(uint16_t a, uint16_t b)
{
    uint32_t result = a >= b ? (uint32_t)a - (uint32_t)b : (uint32_t)a + Q - (uint32_t)b;
    return (uint16_t)result;
}

static uint16_t mulq(uint16_t a, uint16_t b)
{
    return reduce32((uint32_t)a * b);
}

static uint16_t powq(uint16_t a, uint32_t exponent)
{
    uint16_t result = 1;
    while (exponent) {
        if (exponent & 1u) result = mulq(result, a);
        a = mulq(a, a);
        exponent >>= 1;
    }
    return result;
}

static void plan_init(ntt_plan *plan)
{
    uint16_t root = powq(ROOT, (Q - 1u) / N);
    uint16_t inv_root = powq(root, Q - 2u);
    unsigned stage = 0;
    for (unsigned len = 2; len <= N; len <<= 1, ++stage) {
        uint16_t w = 1;
        uint16_t wlen = powq(root, N / len);
        uint16_t inv_wlen = powq(inv_root, N / len);
        for (unsigned j = 0; j < len / 2; ++j) {
            plan->forward[stage][j] = w;
            plan->inverse[stage][j] = 1;
            w = mulq(w, wlen);
        }
        w = 1;
        for (unsigned j = 0; j < len / 2; ++j) {
            plan->inverse[stage][j] = w;
            w = mulq(w, inv_wlen);
        }
    }
    plan->inv_n = powq(N, Q - 2u);
}

static void bit_reverse(uint16_t a[N])
{
    unsigned j = 0;
    for (unsigned i = 1; i < N; ++i) {
        unsigned bit = N >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j ^= bit;
        if (i < j) { uint16_t t = a[i]; a[i] = a[j]; a[j] = t; }
    }
}

static void transform(uint16_t a[N], const ntt_plan *plan, int inverse, int parallel_stages)
{
    bit_reverse(a);
    unsigned stage = 0;
    for (unsigned len = 2; len <= N; len <<= 1, ++stage) {
        const uint16_t *twiddle = inverse ? plan->inverse[stage] : plan->forward[stage];
        #pragma omp parallel for if(parallel_stages) schedule(static)
        for (int block = 0; block < N; block += (int)len) {
            for (unsigned j = 0; j < len / 2; ++j) {
                uint16_t u = a[block + (int)j];
                uint16_t v = mulq(a[block + (int)j + (int)(len / 2)], twiddle[j]);
                a[block + (int)j] = addq(u, v);
                a[block + (int)j + (int)(len / 2)] = subq(u, v);
            }
        }
    }
    if (inverse) {
        #pragma omp parallel for if(parallel_stages) schedule(static)
        for (int i = 0; i < N; ++i) a[i] = mulq(a[i], plan->inv_n);
    }
}

static void multiply_naive(const uint16_t a[N], const uint16_t b[N], uint16_t out[N])
{
    memset(out, 0, sizeof(uint16_t) * N);
    for (unsigned i = 0; i < N; ++i) {
        for (unsigned j = 0; j < N; ++j) {
            unsigned k = (i + j) & (N - 1u);
            out[k] = addq(out[k], mulq(a[i], b[j]));
        }
    }
}

static void multiply_ntt(const uint16_t a[N], const uint16_t b[N], uint16_t out[N],
                         const ntt_plan *plan, int parallel_stages)
{
    uint16_t fa[N], fb[N];
    memcpy(fa, a, sizeof(fa)); memcpy(fb, b, sizeof(fb));
    transform(fa, plan, 0, parallel_stages);
    transform(fb, plan, 0, parallel_stages);
    #pragma omp parallel for if(parallel_stages) schedule(static)
    for (int i = 0; i < N; ++i) fa[i] = mulq(fa[i], fb[i]);
    transform(fa, plan, 1, parallel_stages);
    memcpy(out, fa, sizeof(fa));
}

static int parse_count(const char *s, int *count)
{
    char *end = NULL; long n = strtol(s, &end, 10);
    if (!s[0] || !end || *end || n < 1 || n > 10000000) return 0;
    *count = (int)n;
    return 1;
}

static void fill_poly(uint16_t a[N], uint32_t seed)
{
    for (uint32_t i = 0; i < N; ++i) a[i] = (uint16_t)((seed + i * 97u + i * i * 13u) % Q);
}

int main(int argc, char **argv)
{
    int count = 100;
    uint16_t a[N], b[N], ref[N], got[N];
    uint64_t checksum = 0;
    ntt_plan plan;
    if (argc > 2 || (argc == 2 && !parse_count(argv[1], &count))) {
        fprintf(stderr, "Usage: %s [multiplications-per-configuration]\n", argv[0]); return 2;
    }
    plan_init(&plan);
    for (uint32_t sample = 0; sample < 16; ++sample) {
        fill_poly(a, sample * 7919u + 7u); fill_poly(b, sample * 3571u + 19u);
        multiply_naive(a, b, ref); multiply_ntt(a, b, got, &plan, 0);
        if (memcmp(ref, got, sizeof(ref)) != 0) {
            fputs("NTT consistency check failed; stopping before timing.\n", stderr); return 1;
        }
    }
    fprintf(stderr, "compiler=%s; omp_processors=%d\n",
#ifdef __VERSION__
            __VERSION__,
#else
            "unknown",
#endif
            omp_get_num_procs());
    puts("algorithm,threads,n,operations,seconds,operations_per_second,speedup,efficiency");
    double serial = 0.0;
    double start = omp_get_wtime();
    for (int i = 0; i < count; ++i) {
        fill_poly(a, (uint32_t)i + 7u); fill_poly(b, (uint32_t)i + 19u);
        multiply_naive(a, b, got); checksum += got[i & (N - 1)];
    }
    serial = omp_get_wtime() - start;
    printf("naive,1,%d,%d,%.6f,%.2f,1.0000,1.0000\n", N, count, serial, count / serial);

    start = omp_get_wtime();
    for (int i = 0; i < count; ++i) {
        fill_poly(a, (uint32_t)i + 7u); fill_poly(b, (uint32_t)i + 19u);
        multiply_ntt(a, b, got, &plan, 0); checksum += got[i & (N - 1)];
    }
    double ntt_seconds = omp_get_wtime() - start;
    printf("ntt_precomputed_twiddles,1,%d,%d,%.6f,%.2f,%.4f,%.4f\n",
           N, count, ntt_seconds, count / ntt_seconds, serial / ntt_seconds, serial / ntt_seconds);

    for (int threads = 1; threads <= omp_get_num_procs(); threads *= 2) {
        omp_set_num_threads(threads);
        start = omp_get_wtime();
        #pragma omp parallel for schedule(static) reduction(+:checksum)
        for (int i = 0; i < count; ++i) {
            uint16_t local_a[N], local_b[N], local_out[N];
            fill_poly(local_a, (uint32_t)i + 7u); fill_poly(local_b, (uint32_t)i + 19u);
            multiply_ntt(local_a, local_b, local_out, &plan, 0);
            checksum += local_out[i & (N - 1)];
        }
        double elapsed = omp_get_wtime() - start;
        double speedup = ntt_seconds / elapsed;
        printf("ntt_openmp_batch,%d,%d,%d,%.6f,%.2f,%.4f,%.4f\n",
               threads, N, count, elapsed, count / elapsed, speedup, speedup / threads);
        if (threads > omp_get_num_procs() / 2) break;
    }

    for (int threads = 2; threads <= omp_get_num_procs(); threads *= 2) {
        omp_set_num_threads(threads);
        start = omp_get_wtime();
        for (int i = 0; i < count; ++i) {
            fill_poly(a, (uint32_t)i + 7u); fill_poly(b, (uint32_t)i + 19u);
            multiply_ntt(a, b, got, &plan, 1); checksum += got[i & (N - 1)];
        }
        double elapsed = omp_get_wtime() - start;
        double speedup = ntt_seconds / elapsed;
        printf("ntt_stage_parallel,%d,%d,%d,%.6f,%.2f,%.4f,%.4f\n",
               threads, N, count, elapsed, count / elapsed, speedup, speedup / threads);
        if (threads > omp_get_num_procs() / 2) break;
    }
    fprintf(stderr, "checksum=%llu\n", (unsigned long long)checksum);
    return 0;
}
