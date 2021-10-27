#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "crypto_utils/dgst.h"
#include "crypto_utils/ecc_sign.h"
#include "crypto_utils/cipher_aes.h"
#include <openssl/obj_mac.h>

#define NB_ALGO_DGST 5
#define NB_ALGO_ECC 5
static char *algos_str[NB_ALGO_DGST] = {
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sm3",
};

static uint16_t dgst_size[NB_ALGO_DGST] = {
    28,
    32,
    48,
    64,
    32,
};

static int curves_openssl[NB_ALGO_ECC] = {
    //NID_sm2,
    NID_X9_62_prime256v1,
    NID_secp384r1,
    NID_secp521r1,
    NID_brainpoolP256r1,
    NID_brainpoolP384r1,
};

static char *algos_dgst_ecc[NB_ALGO_ECC] = {
    //"sm3",
    "sha256",
    "sha384",
    "sha512",
    "sha256",
    "sha384",
};

static uint16_t size_pub_key[NB_ALGO_ECC] = {
    //0x40,
    0x40,
    0x60,
    0x84,
    0x40,
    0x60,
};

int digest_openssl_sanity(void) {

    uint8_t dgst_in_buff[300];
    uint8_t dgst_expected[256];
    uint32_t size_input = 300;
    uint32_t i;
    ITEST_LOG("Digest sanity test... ");
    for(i = 0; i < NB_ALGO_DGST; i++) {
        // INPUT BUFF AS RANDOM
        ASSERT_EQUAL(randomize(dgst_in_buff, size_input), size_input);
        // GEN EXPECTED DIGEST (OPENSSL)
        ASSERT_EQUAL(icrypto_hash_one_go((unsigned char *)dgst_in_buff, (unsigned char *) dgst_expected, algos_str[i], size_input), dgst_size[i]);
    }
    ITEST_LOG("PASS\n");
    return TRUE_TEST;
}

int aes_ccm_sanity(void) {
    uint8_t msg[300];
    uint8_t enc_msg[300];
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];
    uint8_t iv[16];

    ITEST_LOG("AES CCM sanity test... ");
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));
    ASSERT_EQUAL(randomize(iv, 12), 12);
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_CCM, aes_128_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_192_CCM, aes_192_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_256_CCM, aes_256_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ITEST_LOG("PASS\n");
    return TRUE_TEST;
}

int aes_cbc_sanity(void) {
    uint8_t msg[300];
    uint8_t enc_msg[300];
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];
    uint8_t iv[16];

    ITEST_LOG("AES CBC sanity test... ");
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));
    ASSERT_EQUAL(randomize(iv, 16), 16);
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_CBC, aes_128_key_data, iv, 16, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_192_CBC, aes_192_key_data, iv, 16, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_256_CBC, aes_256_key_data, iv, 16, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ITEST_LOG("PASS\n");
    return TRUE_TEST;
}

int aes_ecb_sanity(void) {
    uint8_t msg[300];
    uint8_t enc_msg[300];
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];

    ITEST_LOG("AES ECB sanity test... ");
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_ECB, aes_128_key_data, NULL, 0, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_192_ECB, aes_192_key_data, NULL, 0, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_256_ECB, aes_256_key_data, NULL, 0, NULL, 0, 0/*tag size*/), (int)(16 + 16));
    ITEST_LOG("PASS\n");
    return TRUE_TEST;
}

int aes_gcm_sanity(void) {
    uint8_t msg[300];
    uint8_t enc_msg[300];
    uint8_t aes_128_key_data[16];
    uint8_t aes_192_key_data[24];
    uint8_t aes_256_key_data[32];
    uint8_t iv[16];

    ITEST_LOG("AES GCM sanity test... ");
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(aes_192_key_data, sizeof(aes_192_key_data)), sizeof(aes_192_key_data));
    ASSERT_EQUAL(randomize(aes_256_key_data, sizeof(aes_256_key_data)), sizeof(aes_256_key_data));
    ASSERT_EQUAL(randomize(iv, 12), 12);
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_GCM, aes_128_key_data, iv, 12, NULL, 0, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_GCM, aes_128_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_192_GCM, aes_192_key_data, iv, 12, NULL, 0, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_192_GCM, aes_192_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_256_GCM, aes_256_key_data, iv, 12, NULL, 0, 16/*tag size*/), (int)(16 + 16));
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_256_GCM, aes_256_key_data, iv, 12, iv/*aad*/, 16, 16/*tag size*/), (int)(16 + 16));
    ITEST_LOG("PASS\n");
    return TRUE_TEST;
}

int generate_key_sign_gen_verif_openssl_sanity(void) {
    uint8_t privk[1024];
    int size_privk;
    uint8_t pubk[1024];
    int size_pubk;
    uint8_t msg[] = "hello it's me...";
    uint8_t sign_out[512];
    int sign_size;
    int i;

    for ( i = 0; i < NB_ALGO_ECC; i++ ) {

        ASSERT_EQUAL(icrypto_generate_key_pair(curves_openssl[i], (unsigned char *) pubk, &size_pubk, (unsigned char *)privk, &size_privk), 1);
        ITEST_LOG("privk size = %d --- pubk size = %d\n", size_privk, size_pubk);
        ASSERT_EQUAL(size_pubk, size_pub_key[i]);
        ASSERT_EQUAL(size_privk, (int)(size_pub_key[i] / 2));

        ASSERT_EQUAL(icrypto_generate_signature(curves_openssl[i], (unsigned char *)privk, size_privk, (unsigned char *) msg,\
                                                        sizeof(msg), algos_dgst_ecc[i], (unsigned char *) sign_out, &sign_size), 1);
        ITEST_LOG("sign size = %d\n", sign_size);

        ASSERT_EQUAL(icrypto_verify_signature(curves_openssl[i], (unsigned char *) pubk, size_pubk, (unsigned char *)privk,\
                                                        size_privk, (unsigned char *) msg, sizeof(msg), algos_dgst_ecc[i], (unsigned char *) sign_out, sign_size), 1);
        msg[0] += 1;
        ASSERT_EQUAL(icrypto_verify_signature(curves_openssl[i], (unsigned char *) pubk, size_pubk, (unsigned char *)privk,\
                                                        size_privk, (unsigned char *) msg, sizeof(msg), algos_dgst_ecc[i], (unsigned char *) sign_out, sign_size), 0);
        ITEST_LOG("ecc key gen, sign, verify sanity test... PASS\n");
    }
    return TRUE_TEST;
}

int openssl_sanity(void){
    generate_key_sign_gen_verif_openssl_sanity();
    aes_ecb_sanity();
    aes_cbc_sanity();
    aes_gcm_sanity();
    aes_ccm_sanity();
    digest_openssl_sanity();
    return TRUE_TEST;
}