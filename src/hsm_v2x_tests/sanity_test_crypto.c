#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "crypto_utils/dgst.h"
#include "crypto_utils/ecc_sign.h"
#include "crypto_utils/cipher_aes.h"
#include <openssl/obj_mac.h>

#define NB_ALGO 5

static char *algos_str[NB_ALGO] = {
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sm3",
};

static uint16_t dgst_size[NB_ALGO] = {
    28,
    32,
    48,
    64,
    32,
};

int digest_openssl_sanity(void) {

    uint8_t dgst_in_buff[300];
    uint8_t dgst_expected[256];
    uint32_t size_input = 300;
    uint32_t i;
    ITEST_LOG("Digest sanity test... ");
    for(i = 0; i < NB_ALGO; i++) {
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
    uint8_t iv[16];

    ITEST_LOG("AES CCM sanity test... ");
    ASSERT_EQUAL(randomize(aes_128_key_data, sizeof(aes_128_key_data)), sizeof(aes_128_key_data));
    ASSERT_EQUAL(randomize(iv, 12), 12);
    ASSERT_EQUAL(icrypto_cipher_one_go(msg, enc_msg, 16, ICRYPTO_AES_128_CCM, aes_128_key_data, iv, iv, 16), (int)(16 + 16));
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

    ASSERT_EQUAL(icrypto_generate_key_pair(NID_X9_62_prime256v1, (unsigned char *) pubk, &size_pubk, (unsigned char *)privk, &size_privk), 1);
    ITEST_LOG("privk size = %d --- pubk size = %d\n", size_privk, size_pubk);

    ASSERT_EQUAL(icrypto_generate_signature(NID_X9_62_prime256v1, (unsigned char *)privk, size_privk, (unsigned char *) msg,\
                                                     sizeof(msg), "sha256", (unsigned char *) sign_out, &sign_size), 1);
    ITEST_LOG("sign size = %d\n", sign_size);

    ASSERT_EQUAL(icrypto_verify_signature(NID_X9_62_prime256v1, (unsigned char *) pubk, size_pubk, (unsigned char *)privk,\
                                                    size_privk, (unsigned char *) msg, sizeof(msg), "sha256", (unsigned char *) sign_out, sign_size), 1);
    msg[0] = 'A';
    ASSERT_EQUAL(icrypto_verify_signature(NID_X9_62_prime256v1, (unsigned char *) pubk, size_pubk, (unsigned char *)privk,\
                                                    size_privk, (unsigned char *) msg, sizeof(msg), "sha256", (unsigned char *) sign_out, sign_size), 0);
    ITEST_LOG("ecc key gen, sign, verify sanity test... PASS\n");
    return TRUE_TEST;
}

int openssl_sanity(void){
    aes_ccm_sanity();
    digest_openssl_sanity();
    generate_key_sign_gen_verif_openssl_sanity();
    return TRUE_TEST;
}