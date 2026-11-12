#include "xwing/xwing.h"
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int count_arg(const char *s, int *v) { char *e=NULL; long n=strtol(s,&e,10); if(!s[0]||!e||*e||n<10||n>1000000)return 0;*v=(int)n;return 1; }
#define NS_PER_SEC 1e9
int main(int argc, char **argv)
{
    int n=500, ok=1; uint8_t sk[32],pk[1216],kgsk[32],kgpk[1216],ct[1120],a[32],b[32];
    if(argc>2||(argc==2&&!count_arg(argv[1],&n))){fprintf(stderr,"Usage: %s [iterations>=10]\n",argv[0]);return 2;}
    if(!xwing_keygen(sk,pk))return 1;
    xwing_encap_context *ec=xwing_encap_context_new(pk); xwing_decap_context *dc=xwing_decap_context_new(sk);
    if(!ec||!dc||!xwing_encapsulate(pk,ct,a,XWING_DRAFT11)||!xwing_decapsulate_prepared(dc,ct,b,XWING_DRAFT11)||CRYPTO_memcmp(a,b,32))return 1;
    if(!xwing_encapsulate_prepared(ec,ct,a,XWING_DRAFT11)||!xwing_decapsulate(sk,ct,b,XWING_DRAFT11)||CRYPTO_memcmp(a,b,32))return 1;
    fprintf(stderr,"compiler=%s; openssl=%s; iterations=%d; prepared_setup=excluded_from_repeated_op_latency\n",
#ifdef __VERSION__
      __VERSION__,
#else
      "unknown",
#endif
      OpenSSL_version(OPENSSL_VERSION),n);
    puts("operation,implementation,iterations,total_ns,ns_per_op,ops_per_second,correctness");
    double start=omp_get_wtime();
    for(int i=0;i<n;i++)if(!xwing_keygen(kgsk,kgpk)){ok=0;break;}
    double keygen=(omp_get_wtime()-start)*NS_PER_SEC;
    printf("keygen,baseline,%d,%.0f,%.2f,%.2f,%s\n",n,keygen,keygen/n,n/(keygen/NS_PER_SEC),ok?"PASS":"FAIL");
    for(int prep=0;prep<2;prep++){
        if(!ok)break;
        start=omp_get_wtime();
        for(int i=0;i<n;i++)if(!(prep?xwing_encapsulate_prepared(ec,ct,a,XWING_DRAFT11):xwing_encapsulate(pk,ct,a,XWING_DRAFT11))){ok=0;break;}
        double enc=(omp_get_wtime()-start)*NS_PER_SEC;
        printf("encaps,%s,%d,%.0f,%.2f,%.2f,%s\n",prep?"prepared":"baseline",n,enc,enc/n,n/(enc/NS_PER_SEC),ok?"PASS":"FAIL");
        start=omp_get_wtime();
        for(int i=0;i<n;i++)if(!(prep?xwing_decapsulate_prepared(dc,ct,b,XWING_DRAFT11):xwing_decapsulate(sk,ct,b,XWING_DRAFT11))||CRYPTO_memcmp(a,b,32)){ok=0;break;}
        double dec=(omp_get_wtime()-start)*NS_PER_SEC;
        printf("decaps,%s,%d,%.0f,%.2f,%.2f,%s\n",prep?"prepared":"baseline",n,dec,dec/n,n/(dec/NS_PER_SEC),ok?"PASS":"FAIL");
        start=omp_get_wtime();
        for(int i=0;i<n;i++){
            if(!(prep?xwing_encapsulate_prepared(ec,ct,a,XWING_DRAFT11):xwing_encapsulate(pk,ct,a,XWING_DRAFT11))||
               !(prep?xwing_decapsulate_prepared(dc,ct,b,XWING_DRAFT11):xwing_decapsulate(sk,ct,b,XWING_DRAFT11))||CRYPTO_memcmp(a,b,32)){ok=0;break;}
        }
        double hs=(omp_get_wtime()-start)*NS_PER_SEC;
        printf("repeated_exchange,%s,%d,%.0f,%.2f,%.2f,%s\n",prep?"prepared":"baseline",n,hs,hs/n,n/(hs/NS_PER_SEC),ok?"PASS":"FAIL");
        if(!ok)break;
    }
    for(int prep=0;prep<2&&ok;prep++){
        double start=omp_get_wtime();
        for(int i=0;i<n;i++){
            xwing_encap_context *per_ec=NULL; xwing_decap_context *per_dc=NULL;
            if(!xwing_keygen(kgsk,kgpk)){ok=0;break;}
            if(prep){per_ec=xwing_encap_context_new(kgpk);per_dc=xwing_decap_context_new(kgsk);if(!per_ec||!per_dc)ok=0;}
            if(ok&&(prep?!xwing_encapsulate_prepared(per_ec,ct,a,XWING_DRAFT11):!xwing_encapsulate(kgpk,ct,a,XWING_DRAFT11)))ok=0;
            if(ok&&!(prep?xwing_decapsulate_prepared(per_dc,ct,b,XWING_DRAFT11):xwing_decapsulate(kgsk,ct,b,XWING_DRAFT11)))ok=0;
            if(ok&&CRYPTO_memcmp(a,b,32))ok=0;
            xwing_encap_context_free(per_ec);xwing_decap_context_free(per_dc);
            if(!ok)break;
        }
        double complete=(omp_get_wtime()-start)*NS_PER_SEC;
        printf("complete_handshake,%s,%d,%.0f,%.2f,%.2f,%s\n",prep?"per_key_context":"baseline",n,complete,complete/n,n/(complete/NS_PER_SEC),ok?"PASS":"FAIL");
    }
    xwing_encap_context_free(ec);xwing_decap_context_free(dc);OPENSSL_cleanse(sk,sizeof(sk));OPENSSL_cleanse(pk,sizeof(pk));OPENSSL_cleanse(kgsk,sizeof(kgsk));OPENSSL_cleanse(kgpk,sizeof(kgpk));OPENSSL_cleanse(ct,sizeof(ct));OPENSSL_cleanse(a,sizeof(a));OPENSSL_cleanse(b,sizeof(b));
    return ok?0:1;
}
