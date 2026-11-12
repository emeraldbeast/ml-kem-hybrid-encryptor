#include "xwing/xwing.h"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
int main(void){
 uint8_t sk[32],pk[1216],ct[1120],ss[32];
 for(int i=0;i<5000;i++){
   if(RAND_bytes(sk,32)!=1||RAND_bytes(ct,1120)!=1) return 2;
   (void)xwing_decapsulate(sk,ct,ss,(i&1)?XWING_DRAFT11:XWING_RESEARCH_HASH_CT);
   if(RAND_bytes(pk,1216)!=1) return 2;
   (void)xwing_encapsulate(pk,ct,ss,(i&1)?XWING_DRAFT11:XWING_RESEARCH_HASH_CT);
 }
 puts("PASS: 5,000 random malformed ciphertext/private-key decapsulation attempts and 5,000 random public-key encapsulation attempts completed without crash");
 return 0;
}
