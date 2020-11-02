#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

// perf test of various algo

int v2x_cipher_ccm_perf(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_generate_key_args_t gen_key_args;
    op_cipher_one_go_args_t cipher_args;
    
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id_aes_128 = 0;
    uint32_t key_id_aes_192 = 0;
    uint32_t key_id_aes_256 = 0;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    uint8_t msg[1024];
    uint8_t iv[16];
    
    uint32_t msg_size = 384;
    uint32_t iter = 6000;
    uint32_t i;
    timer_perf_t t_perf;

    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 300), 300);
    ASSERT_EQUAL(randomize(iv, 16), 16);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);
    
    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id_aes_128;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;

    // GEN KEY AES_128
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    
    // GEN KEY AES_192
    gen_key_args.key_identifier = &key_id_aes_192;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_192;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    // GEN KEY AES_256
    gen_key_args.key_identifier = &key_id_aes_256;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_256;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    printf("aes ccm key_aes_128 encrypt\n");
    // CIPHER ONE GO AES_128 CCM -> ENCRYPT
    cipher_args.key_identifier = key_id_aes_128;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = msg;
    cipher_args.output = buff_encr;
    cipher_args.input_size = msg_size;
    cipher_args.output_size = msg_size + 16;

    init_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);

    printf("aes ccm key_aes_128 decrypt\n");
    // CIPHER ONE GO AES_128 CCM -> DECRYPT
    cipher_args.key_identifier = key_id_aes_128;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.input = buff_encr;
    cipher_args.output = buff_decr;
    cipher_args.input_size = msg_size + 16;
    cipher_args.output_size = msg_size;

    init_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    printf("aes ccm key_aes_192 encrypt\n");
    // CIPHER ONE GO AES_192 CCM -> ENCRYPT
    cipher_args.key_identifier = key_id_aes_192;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = msg;
    cipher_args.output = buff_encr;
    cipher_args.input_size = msg_size;
    cipher_args.output_size = msg_size + 16;

    start_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);

    printf("aes ccm key_aes_192 decrypt\n");
    // CIPHER ONE GO AES_192 CCM -> DECRYPT
    cipher_args.key_identifier = key_id_aes_192;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.input = buff_encr;
    cipher_args.output = buff_decr;
    cipher_args.input_size = msg_size + 16;
    cipher_args.output_size = msg_size;

    init_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    printf("aes ccm key_aes_256 encrypt\n");
    // CIPHER ONE GO AES_256 CCM -> ENCRYPT
    cipher_args.key_identifier = key_id_aes_256;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = msg;
    cipher_args.output = buff_encr;
    cipher_args.input_size = msg_size;
    cipher_args.output_size = msg_size + 16;

    init_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);

    printf("aes ccm key_aes_256 decrypt\n");
    // CIPHER ONE GO AES_256 CCM -> DECRYPT
    cipher_args.key_identifier = key_id_aes_256;
    cipher_args.iv = iv;
    cipher_args.iv_size = 12;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.input = buff_encr;
    cipher_args.output = buff_decr;
    cipher_args.input_size = msg_size + 16;
    cipher_args.output_size = msg_size;

    init_timer(&t_perf);
    for (i = 0; i <= iter; i++) {
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        stop_timer(&t_perf);
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    print_perf(&t_perf);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);
    
    ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}

#define NB_ALGO 7
static hsm_key_type_t algos[NB_ALGO] = {
    HSM_KEY_TYPE_DSA_SM2_FP_256,
    HSM_KEY_TYPE_ECDSA_NIST_P256,
    HSM_KEY_TYPE_ECDSA_NIST_P384,
    //HSM_KEY_TYPE_ECDSA_NIST_P521,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384,
};

static hsm_key_type_t algos_sign[NB_ALGO] = {
    HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384,
    //HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256,
    HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384,
};

static char *algos_str[NB_ALGO] = {
    "HSM_KEY_TYPE_DSA_SM2_FP_256",
    "HSM_KEY_TYPE_ECDSA_NIST_P256",
    "HSM_KEY_TYPE_ECDSA_NIST_P384",
    //"HSM_KEY_TYPE_ECDSA_NIST_P521",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384",
};

static uint16_t size_pub_key[NB_ALGO] = {
    0x40,
    0x40,
    0x60,
    //0x90,
    0x40,
    0x60,
    0x40,
    0x60
};

int v2x_sign_gen_verify_perf(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    
    op_generate_key_args_t gen_key_args;
    op_generate_sign_args_t sig_gen_args;
    op_verify_sign_args_t sig_ver_args;    
    hsm_hdl_t sg0_sess, sg0_sig_gen_serv;
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id = 0;
    hsm_verification_status_t status;
    uint8_t pub_key[1024];
    uint8_t msg[300];
    uint8_t sign_out[1281024];
    uint32_t iter = 300;
    uint32_t i, j;
    timer_perf_t t_perf;

    // REMOVE NVM
    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 300), 300);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);
    
    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // SV0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // SIGN GEN OPEN SRV
    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);

    // SIGN VER OPEN SRV
    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess, &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);

    for(i = 0; i < NB_ALGO; i++){
        printf("\n======algo: %s=====\n", algos_str[i]);
        // PARAM KEY_GEN strict_update
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = pub_key;

        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

        init_timer(&t_perf);
        for (j = 0; j < iter; j++) {
            sig_gen_args.key_identifier = key_id;
            sig_gen_args.message = msg;
            sig_gen_args.signature = sign_out;
            sig_gen_args.message_size = 300;
            sig_gen_args.signature_size = size_pub_key[i]+1;
            sig_gen_args.scheme_id = algos_sign[i];
            sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);
            stop_timer(&t_perf);
        }
        printf("sign gen input msg\n");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        print_perf(&t_perf);
        
        init_timer(&t_perf);
        for (j = 0; j < iter; j++) {

            sig_ver_args.key = pub_key;
            sig_ver_args.message = msg;
            sig_ver_args.signature = sign_out;
            sig_ver_args.key_size = size_pub_key[i];
            sig_ver_args.signature_size = size_pub_key[i]+1;
            sig_ver_args.message_size = 300;
            sig_ver_args.scheme_id = algos_sign[i];
            sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
            stop_timer(&t_perf);
            ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        }
        printf("sign verify input msg\n");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        print_perf(&t_perf);

        init_timer(&t_perf);
        for (j = 0; j < iter; j++) {
            sig_gen_args.key_identifier = key_id;
            sig_gen_args.message = msg;
            sig_gen_args.signature = sign_out;
            sig_gen_args.message_size = size_pub_key[i]/2;
            sig_gen_args.signature_size = size_pub_key[i]+1;
            sig_gen_args.scheme_id = algos_sign[i];
            sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);
            stop_timer(&t_perf);
        }
        printf("sign gen input dgst\n");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        print_perf(&t_perf);

        init_timer(&t_perf);
        for (j = 0; j < iter; j++) {

            sig_ver_args.key = pub_key;
            sig_ver_args.message = msg;
            sig_ver_args.signature = sign_out;
            sig_ver_args.key_size = size_pub_key[i];
            sig_ver_args.signature_size = size_pub_key[i]+1;
            sig_ver_args.message_size = size_pub_key[i]/2;
            sig_ver_args.scheme_id = algos_sign[i];
            sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_DIGEST;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
            stop_timer(&t_perf);
            ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        }
        printf("sign verify input dgst\n");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        print_perf(&t_perf);
    }
    
    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}
