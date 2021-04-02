#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "crypto_utils/dgst.h"

// requirement: hash tests all algos from 1 byte to 300 bytes

// HSM_HASH_ALGO_SHA_224
// HSM_HASH_ALGO_SHA_256
// HSM_HASH_ALGO_SHA_384
// HSM_HASH_ALGO_SHA_512
// HSM_HASH_ALGO_SM3_256

#define NB_ALGO 5

static hsm_hash_algo_t algos[NB_ALGO] = {
    HSM_HASH_ALGO_SHA_224,
    HSM_HASH_ALGO_SHA_256,
    HSM_HASH_ALGO_SHA_384,
    HSM_HASH_ALGO_SHA_512,
    HSM_HASH_ALGO_SM3_256,
};

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

int v2x_hash_one_go_all_001(void){

    open_session_args_t args;
    open_svc_hash_args_t hash_srv_args;
    op_hash_one_go_args_t hash_args;

    hsm_hdl_t sv0_sess;
    hsm_hdl_t sv1_sess;
    hsm_hdl_t sv0_hash_serv, sv1_hash_serv;
    uint8_t dgst_in_buff[300];
    uint8_t dgst_out_buff[256];
    uint8_t dgst_expected[256];
    uint32_t size_input;
    uint32_t size_input_max = 300;
    uint32_t i;

    // SV0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    // SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv1_sess), HSM_NO_ERROR);

    // OPEN HASH SERV
    hash_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_hash_service(sv0_sess, &hash_srv_args, &sv0_hash_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_hash_service(sv1_sess, &hash_srv_args, &sv1_hash_serv), HSM_NO_ERROR);

    for(i = 0; i < NB_ALGO; i++) {

        for(size_input = 1; size_input <= size_input_max; size_input++) {

            // GEN HASH Mu SV0
            hash_args.input = dgst_in_buff;
            hash_args.output = dgst_out_buff;
            hash_args.input_size = size_input;
            hash_args.output_size = dgst_size[i];
            hash_args.algo = algos[i];
            hash_args.flags = 0;
            // INPUT BUFF AS RANDOM
            ASSERT_EQUAL(randomize(dgst_in_buff, size_input), size_input);
            ASSERT_EQUAL(hsm_hash_one_go(sv0_hash_serv, &hash_args), HSM_NO_ERROR);
            // GEN EXPECTED DIGEST (OPENSSL)
            ASSERT_EQUAL(hash_one_go((unsigned char *)dgst_in_buff, (unsigned char *) dgst_expected, algos_str[i], size_input), dgst_size[i]);
            // CHECK HASH OUTPUT
            ASSERT_EQUAL(memcmp(dgst_out_buff, dgst_expected, dgst_size[i]), 0);

            // GEN HASH Mu SV1
            // INPUT BUFF AS RANDOM
            ASSERT_EQUAL(randomize(dgst_in_buff, size_input), size_input);
            ASSERT_EQUAL(hsm_hash_one_go(sv1_hash_serv, &hash_args), HSM_NO_ERROR);
            // GEN EXPECTED DIGEST (OPENSSL)
            ASSERT_EQUAL(hash_one_go((unsigned char *)dgst_in_buff, (unsigned char *) dgst_expected, algos_str[i], size_input), dgst_size[i]);
            // CHECK HASH OUTPUT
            ASSERT_EQUAL(memcmp(dgst_out_buff, dgst_expected, dgst_size[i]), 0);
        }
    }

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_hash_service(sv0_hash_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_hash_service(sv1_hash_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv1_sess), HSM_NO_ERROR);

    return TRUE_TEST;
}
