#include "xwing/xwing.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static int derive_aes_key(const uint8_t shared_secret[32], uint8_t key[32])
{
    static const uint8_t info[] = "X-Wing local demo AES-256-GCM key";
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t out_len = 32;
    int ok = ctx && EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, 32) > 0 &&
             EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1) > 0 &&
             EVP_PKEY_derive(ctx, key, &out_len) > 0 && out_len == 32;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int encrypt_gcm(const uint8_t key[32], const uint8_t *plain, int plain_len,
                       uint8_t nonce[12], uint8_t *cipher, uint8_t tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    int ok = ctx && RAND_bytes(nonce, 12) == 1 &&
             EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) == 1;
    if (ok) { total = len; ok = EVP_EncryptFinal_ex(ctx, cipher + total, &len) == 1; total += len; }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1 && total == plain_len;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int decrypt_gcm(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *cipher, int cipher_len, const uint8_t tag[16],
                       uint8_t *plain)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    int ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len) == 1;
    if (ok) { total = len; ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1; }
    if (ok) { ok = EVP_DecryptFinal_ex(ctx, plain + total, &len) == 1; total += len; }
    EVP_CIPHER_CTX_free(ctx);
    ok = ok && total == cipher_len;
    if (!ok) OPENSSL_cleanse(plain, (size_t)cipher_len);
    return ok;
}

static int buffer_is_zero(const uint8_t *buf, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= buf[i];
    return acc == 0;
}

int main(void)
{
    static const uint8_t message[] = "X-Wing established key material for an AES-256-GCM demo.";
    uint8_t sk[32], pk[1216], kem_ct[1120], sender_ss[32], receiver_ss[32];
    uint8_t sender_key[32], receiver_key[32], nonce[12], tag[16];
    uint8_t cipher[sizeof(message)], recovered[sizeof(message)];
    uint8_t tampered_cipher[sizeof(message)], tampered_tag[16], wrong_key[32], scratch[sizeof(message)];
    int ok = xwing_keygen(sk, pk) &&
             xwing_encapsulate(pk, kem_ct, sender_ss, XWING_DRAFT11) &&
             xwing_decapsulate(sk, kem_ct, receiver_ss, XWING_DRAFT11) &&
             CRYPTO_memcmp(sender_ss, receiver_ss, 32) == 0 &&
             derive_aes_key(sender_ss, sender_key) && derive_aes_key(receiver_ss, receiver_key) &&
             encrypt_gcm(sender_key, message, (int)(sizeof(message) - 1), nonce, cipher, tag) &&
             decrypt_gcm(receiver_key, nonce, cipher, (int)(sizeof(message) - 1), tag, recovered) &&
             memcmp(message, recovered, sizeof(message) - 1) == 0;
    if (!ok) { fputs("KEM + AEAD demonstration failed.\n", stderr); return 1; }
    puts("Draft-11 KEM -> HKDF-SHA256 -> AES-256-GCM: message authenticated and recovered.");
    memcpy(tampered_cipher, cipher, sizeof(message) - 1); tampered_cipher[0] ^= 1;
    memcpy(tampered_tag, tag, sizeof(tag)); tampered_tag[0] ^= 1;
    memcpy(wrong_key, receiver_key, sizeof(wrong_key)); wrong_key[0] ^= 1;
    memset(scratch, 0xa5, sizeof(scratch));
    int cipher_rejected = !decrypt_gcm(receiver_key, nonce, tampered_cipher,
                                        (int)(sizeof(message) - 1), tag, scratch) &&
                          buffer_is_zero(scratch, sizeof(message) - 1);
    memset(scratch, 0xa5, sizeof(scratch));
    int tag_rejected = !decrypt_gcm(receiver_key, nonce, cipher,
                                     (int)(sizeof(message) - 1), tampered_tag, scratch) &&
                       buffer_is_zero(scratch, sizeof(message) - 1);
    memset(scratch, 0xa5, sizeof(scratch));
    int key_rejected = !decrypt_gcm(wrong_key, nonce, cipher,
                                     (int)(sizeof(message) - 1), tag, scratch) &&
                       buffer_is_zero(scratch, sizeof(message) - 1);
    printf("AES-GCM tamper checks: ciphertext=%s, tag=%s, wrong_key=%s; failed output cleared=%s.\n",
           cipher_rejected ? "rejected" : "FAILED", tag_rejected ? "rejected" : "FAILED",
           key_rejected ? "rejected" : "FAILED",
           cipher_rejected && tag_rejected && key_rejected ? "yes" : "FAILED");
    ok = cipher_rejected && tag_rejected && key_rejected;
    puts("This local demonstration does not authenticate the recipient public key or peer identity.");
    OPENSSL_cleanse(sk, sizeof(sk)); OPENSSL_cleanse(sender_ss, sizeof(sender_ss));
    OPENSSL_cleanse(receiver_ss, sizeof(receiver_ss)); OPENSSL_cleanse(sender_key, sizeof(sender_key));
    OPENSSL_cleanse(receiver_key, sizeof(receiver_key)); OPENSSL_cleanse(recovered, sizeof(recovered));
    OPENSSL_cleanse(wrong_key, sizeof(wrong_key)); OPENSSL_cleanse(scratch, sizeof(scratch));
    OPENSSL_cleanse(tampered_cipher, sizeof(tampered_cipher)); OPENSSL_cleanse(tampered_tag, sizeof(tampered_tag));
    return ok ? 0 : 1;
}
