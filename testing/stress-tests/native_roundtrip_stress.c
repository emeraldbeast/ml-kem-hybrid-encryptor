#include "xwing/xwing.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x,msg) do { if (!(x)) { fprintf(stderr,"FAIL: %s at %d\n",msg,__LINE__); return 1; } } while(0)
int main(void) {
  unsigned long rounds=0;
  for (int k=0;k<30;k++) {
    uint8_t sk[32],pk[1216];
    CHECK(xwing_keygen(sk,pk),"keygen");
    for (int mode=0;mode<2;mode++) for(int i=0;i<40;i++) {
      uint8_t ct[1120], a[32],b[32];
      CHECK(xwing_encapsulate(pk,ct,a,(xwing_mode)mode),"encapsulate");
      CHECK(xwing_decapsulate(sk,ct,b,(xwing_mode)mode),"decapsulate");
      CHECK(CRYPTO_memcmp(a,b,32)==0,"roundtrip equality");
      rounds++;
    }
    OPENSSL_cleanse(sk,sizeof sk);
  }
  /* API argument and invalid-mode failure paths. */
  uint8_t sk[32],pk[1216],ct[1120],ss[32];
  CHECK(xwing_keygen(sk,pk),"edge keygen");
  memset(ct,0xA5,sizeof ct); memset(ss,0xA5,sizeof ss);
  CHECK(!xwing_encapsulate(pk,ct,ss,(xwing_mode)99),"invalid encaps mode rejected");
  for(size_t i=0;i<sizeof ct;i++) CHECK(ct[i]==0,"invalid encaps clears ciphertext");
  for(size_t i=0;i<sizeof ss;i++) CHECK(ss[i]==0,"invalid encaps clears secret");
  memset(ct,0xA5,sizeof ct); memset(ss,0xA5,sizeof ss);
  CHECK(!xwing_decapsulate(sk,ct,ss,(xwing_mode)99),"invalid decaps mode rejected");
  for(size_t i=0;i<sizeof ss;i++) CHECK(ss[i]==0,"invalid decaps clears secret");
  CHECK(!xwing_keygen(NULL,pk),"null keygen input rejected");
  CHECK(!xwing_encapsulate(NULL,ct,ss,XWING_DRAFT11),"null pk rejected");
  CHECK(!xwing_decapsulate(sk,NULL,ss,XWING_DRAFT11),"null ct rejected");
  /* A malformed X25519 low-order point must fail closed and clear output. */
  CHECK(xwing_encapsulate(pk,ct,ss,XWING_DRAFT11),"tamper seed encaps");
  memset(ct+1088,0,32); memset(ss,0xA5,32);
  CHECK(!xwing_decapsulate(sk,ct,ss,XWING_DRAFT11),"all-zero X25519 point rejected");
  for(int i=0;i<32;i++) CHECK(ss[i]==0,"decaps failure clears secret");
  /* Mutating ML-KEM ciphertext should be handled by ML-KEM implicit rejection,
     i.e. decapsulation returns a pseudorandom/different secret, not an error. */
  CHECK(xwing_encapsulate(pk,ct,ss,XWING_DRAFT11),"tamper MLKEM seed encaps");
  ct[17]^=0x80;
  uint8_t tampered_ss[32];
  CHECK(xwing_decapsulate(sk,ct,tampered_ss,XWING_DRAFT11),"ML-KEM implicit rejection path");
  CHECK(CRYPTO_memcmp(ss,tampered_ss,32)!=0,"tampered ML-KEM ct changes hybrid secret");
  printf("PASS: %lu valid round trips (30 keypairs x 40 per mode); null/invalid-mode, zeroization, low-order X25519, ML-KEM implicit-rejection checks.\n",rounds);
  return 0;
}
