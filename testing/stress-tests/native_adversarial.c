#include "xwing/xwing.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <omp.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hkdf(const uint8_t ss[32], uint8_t key[32]) {
    static const uint8_t info[]="X-Wing adversarial test AES-256-GCM key";
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL); size_t n=32;
    int ok=c&&EVP_PKEY_derive_init(c)>0&&EVP_PKEY_CTX_set_hkdf_md(c,EVP_sha256())>0&&EVP_PKEY_CTX_set1_hkdf_key(c,ss,32)>0&&EVP_PKEY_CTX_add1_hkdf_info(c,info,sizeof(info)-1)>0&&EVP_PKEY_derive(c,key,&n)>0&&n==32;
    EVP_PKEY_CTX_free(c);return ok;
}
static int gcm_enc(const uint8_t key[32],const uint8_t *p,int n,uint8_t nonce[12],uint8_t *c,uint8_t tag[16]) {
    EVP_CIPHER_CTX *x=EVP_CIPHER_CTX_new();int z=0,t=0;
    int ok=x&&RAND_bytes(nonce,12)==1&&EVP_EncryptInit_ex(x,EVP_aes_256_gcm(),NULL,NULL,NULL)==1&&EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1&&EVP_EncryptInit_ex(x,NULL,NULL,key,nonce)==1&&EVP_EncryptUpdate(x,c,&z,p,n)==1;
    if(ok){t=z;ok=EVP_EncryptFinal_ex(x,c+t,&z)==1;t+=z;} if(ok)ok=EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_GCM_GET_TAG,16,tag)==1&&t==n;EVP_CIPHER_CTX_free(x);return ok;
}
/* OpenSSL writes provisional plaintext in Update; clear it unless Final authenticates. */
static int gcm_dec(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *c,int n,const uint8_t tag[16],uint8_t *p) {
    EVP_CIPHER_CTX *x=EVP_CIPHER_CTX_new();int z=0,t=0;
    int ok=x&&EVP_DecryptInit_ex(x,EVP_aes_256_gcm(),NULL,NULL,NULL)==1&&EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1&&EVP_DecryptInit_ex(x,NULL,NULL,key,nonce)==1&&EVP_DecryptUpdate(x,p,&z,c,n)==1;
    if(ok){t=z;ok=EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_GCM_SET_TAG,16,(void*)tag)==1;}
    if(ok){ok=EVP_DecryptFinal_ex(x,p+t,&z)==1;t+=z;}
    EVP_CIPHER_CTX_free(x); if(!ok||t!=n){OPENSSL_cleanse(p,(size_t)n);return 0;}return 1;
}
static int allzero(const uint8_t *p,size_t n){uint8_t v=0;for(size_t i=0;i<n;i++)v|=p[i];return v==0;}
static int run_case(const char *name,const uint8_t sk[32],const uint8_t *ct,const uint8_t original[32],const uint8_t nonce[12],const uint8_t *cipher,int mlen,const uint8_t tag[16],int expected_reject) {
    uint8_t ss[32],key[32],plain[128]; memset(plain,0xa5,sizeof(plain));
    int dec=xwing_decapsulate(sk,ct,ss,XWING_DRAFT11),eq=dec&&CRYPTO_memcmp(ss,original,32)==0;
    int aead=0,cleared=0;if(dec&&hkdf(ss,key))aead=gcm_dec(key,nonce,cipher,mlen,tag,plain);
    if(!aead)cleared=dec?allzero(plain,(size_t)mlen):allzero(ss,32);
    int pass=expected_reject?(dec&&!eq&&!aead&&cleared):(!dec&&cleared);
    printf("adversarial,%s,%s,%d,%d,%d,%s\n",name,dec?"DECAPPED":"REJECTED",eq,aead,cleared,pass?"PASS":"FAIL");
    OPENSSL_cleanse(ss,sizeof(ss));OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(plain,sizeof(plain));return pass;
}
typedef struct {uint64_t n;double mean,m2;} stats;
static void add(stats *s,double x){s->n++;double d=x-s->mean;s->mean+=d/(double)s->n;s->m2+=d*(x-s->mean);}
static int cmp_double(const void *a,const void *b){double x=*(const double*)a,y=*(const double*)b;return (x>y)-(x<y);}
static int timing(int rounds,const uint8_t sk[32],const uint8_t *valid,FILE *raw) {
    uint8_t cases[3][1120];memcpy(cases[0],valid,1120);memcpy(cases[1],valid,1120);memcpy(cases[2],valid,1120);
    cases[1][17]^=1;cases[2][1088+7]^=1; stats s[3]={{0}};double *samples[3];int order[3]={0,1,2};
    for(int i=0;i<3;i++)if(!(samples[i]=malloc((size_t)rounds*sizeof(double)))){for(int j=0;j<i;j++)free(samples[j]);return 0;}
    fprintf(raw,"sample,class,elapsed_ns,api_success\n");
    for(int i=0;i<rounds;i++){
        uint32_t rnd=0;if(RAND_bytes((uint8_t*)&rnd,sizeof(rnd))!=1)return 0;
        for(int j=2;j>0;j--){int k=(int)(rnd%(uint32_t)(j+1));int q=order[j];order[j]=order[k];order[k]=q;rnd=rnd*1664525u+1013904223u;}
        for(int j=0;j<3;j++){int c=order[j];uint8_t ss[32];double t=omp_get_wtime();int ok=xwing_decapsulate(sk,cases[c],ss,XWING_DRAFT11);double ns=(omp_get_wtime()-t)*1e9;add(&s[c],ns);samples[c][i]=ns;fprintf(raw,"%d,%s,%.0f,%d\n",i,c==0?"valid":c==1?"mlkem_bitflip":"x25519_bitflip",ns,ok);OPENSSL_cleanse(ss,sizeof(ss));}
    }
    fprintf(stderr,"class,n,mean_ns,median_ns,variance_ns2,sd_ns\n");const char *names[]={"valid","mlkem_bitflip","x25519_bitflip"};
    for(int i=0;i<3;i++){qsort(samples[i],(size_t)rounds,sizeof(double),cmp_double);double med=rounds%2?samples[i][rounds/2]:(samples[i][rounds/2-1]+samples[i][rounds/2])/2.0;fprintf(stderr,"%s,%llu,%.2f,%.2f,%.2f,%.2f\n",names[i],(unsigned long long)s[i].n,s[i].mean,med,s[i].m2/(s[i].n-1),sqrt(s[i].m2/(s[i].n-1)));}
    for(int i=1;i<3;i++){double v0=s[0].m2/(s[0].n-1),vi=s[i].m2/(s[i].n-1);double se=sqrt(v0/s[0].n+vi/s[i].n);fprintf(stderr,"welch_t_valid_vs_%s,%.4f\n",names[i],se?(s[0].mean-s[i].mean)/se:0.0);}
    for(int i=0;i<3;i++) free(samples[i]);
    return 1;
}
int main(int argc,char **argv){
    int rounds=2000;if(argc>3){fprintf(stderr,"Usage: %s [timing-rounds>=100] [timing.csv]\n",argv[0]);return 2;}if(argc>=2){char *end=NULL;long n=strtol(argv[1],&end,10);if(!argv[1][0]||!end||*end||n<100||n>1000000){fprintf(stderr,"Usage: %s [timing-rounds=100..1000000] [timing.csv]\n",argv[0]);return 2;}rounds=(int)n;}
    FILE *raw=argc==3?fopen(argv[2],"w"):stdout;if(!raw){perror("timing CSV");return 1;}
    static const uint8_t message[]="Authenticated application data must never be accepted after KEM tampering.";
    uint8_t sk[32],wrong_sk[32],pk[1216],wrong_pk[1216],ct[1120],bad[1120],ss[32],ss2[32],key[32],nonce[12],cipher[sizeof(message)],tag[16],out[sizeof(message)];int pass=1;
    if(!xwing_keygen(sk,pk)||!xwing_keygen(wrong_sk,wrong_pk)||!xwing_encapsulate(pk,ct,ss,XWING_DRAFT11)||!hkdf(ss,key)||!gcm_enc(key,message,sizeof(message)-1,nonce,cipher,tag))return 1;
    puts("kind,test,decapsulation,shared_secret_match,aes_gcm_accepted,output_cleared,result");
    int kem_ok=xwing_decapsulate(sk,ct,ss2,XWING_DRAFT11);int kem_match=kem_ok&&CRYPTO_memcmp(ss,ss2,32)==0;
    int valid_aead=kem_match&&hkdf(ss2,key)&&gcm_dec(key,nonce,cipher,sizeof(message)-1,tag,out);
    int valid_pass=valid_aead&&memcmp(out,message,sizeof(message)-1)==0;
    printf("adversarial,valid_ciphertext,%s,%d,%d,NA,%s\n",kem_ok?"DECAPPED":"REJECTED",kem_match,valid_aead,valid_pass?"PASS":"FAIL");pass&=valid_pass;
    memset(out,0xa5,sizeof(out));int correct=gcm_dec(key,nonce,cipher,sizeof(message)-1,tag,out);
    int correct_ok=correct&&memcmp(out,message,sizeof(message)-1)==0;printf("aead,correct_ciphertext_and_tag,NA,NA,%d,NA,%s\n",correct,correct_ok?"PASS":"FAIL");pass&=correct_ok;
    memcpy(bad,ct,1120);bad[0]^=1;pass&=run_case("mlkem_single_bit",sk,bad,ss,nonce,cipher,sizeof(message)-1,tag,1);
    memcpy(bad,ct,1120);bad[0]^=0x81;bad[611]^=0x20;bad[1087]^=0x04;pass&=run_case("mlkem_multiple_bits",sk,bad,ss,nonce,cipher,sizeof(message)-1,tag,1);
    memcpy(bad,ct,1120);bad[1095]^=1;pass&=run_case("x25519_public_bitflip",sk,bad,ss,nonce,cipher,sizeof(message)-1,tag,1);
    memcpy(bad,ct,1120);pass&=run_case("wrong_recipient_private_key",wrong_sk,bad,ss,nonce,cipher,sizeof(message)-1,tag,1);
    memcpy(bad,ct,1120);memset(bad+1088,0,32);pass&=run_case("low_order_x25519_value",sk,bad,ss,nonce,cipher,sizeof(message)-1,tag,0);
    printf("adversarial,truncated_ciphertext,NOT_TESTABLE_FIXED_SIZE_API,0,0,0,REQUIRES_CALLER_LENGTH_CHECK\n");
    bad[0]=cipher[0]^1;
    memset(out,0xa5,sizeof(out));int c1=gcm_dec(key,nonce,bad,sizeof(message)-1,tag,out);printf("aead,ciphertext_bitflip,NA,NA,%d,%d,%s\n",c1,allzero(out,sizeof(message)-1),(!c1&&allzero(out,sizeof(message)-1))?"PASS":"FAIL");pass&=!c1&&allzero(out,sizeof(message)-1);
    uint8_t btag[16];memcpy(btag,tag,16);btag[3]^=1;memset(out,0xa5,sizeof(out));int c2=gcm_dec(key,nonce,cipher,sizeof(message)-1,btag,out);printf("aead,tag_bitflip,NA,NA,%d,%d,%s\n",c2,allzero(out,sizeof(message)-1),(!c2&&allzero(out,sizeof(message)-1))?"PASS":"FAIL");pass&=!c2&&allzero(out,sizeof(message)-1);
    uint8_t wrong_aes[32];memcpy(wrong_aes,key,32);wrong_aes[0]^=1;memset(out,0xa5,sizeof(out));int c3=gcm_dec(wrong_aes,nonce,cipher,sizeof(message)-1,tag,out);printf("aead,wrong_aes_key,NA,NA,%d,%d,%s\n",c3,allzero(out,sizeof(message)-1),(!c3&&allzero(out,sizeof(message)-1))?"PASS":"FAIL");pass&=!c3&&allzero(out,sizeof(message)-1);
    if(!timing(rounds,sk,ct,raw))pass=0;
    if(raw!=stdout)fclose(raw);
    OPENSSL_cleanse(sk,32);OPENSSL_cleanse(wrong_sk,32);OPENSSL_cleanse(ss,32);OPENSSL_cleanse(ss2,32);OPENSSL_cleanse(key,32);OPENSSL_cleanse(wrong_aes,32);
    return pass?0:1;
}
