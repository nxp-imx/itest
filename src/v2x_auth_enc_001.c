#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"

// perf test of various algo

int v2x_auth_enc_test(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_generate_key_args_t gen_key_args;
    op_auth_enc_args_t auth_enc_args;
    
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
    
    uint32_t msg_size = 378;
    uint8_t aad[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    clear_v2x_nvm();
    
    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 300), 300);
    ASSERT_EQUAL(randomize(iv, 16), 16);

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

    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // AUTH ENC KEY AES128 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_128;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

    // AUTH ENC KEY AES192 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // AUTH ENC KEY AES192 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_192;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);


    // AUTH ENC KEY AES256 -> ENCRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
    auth_enc_args.input = msg;
    auth_enc_args.output = buff_encr;
    auth_enc_args.input_size = msg_size;
    auth_enc_args.output_size = msg_size + 16U;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);

    // AUTH ENC KEY AES256 -> DECRYPT
    auth_enc_args.key_identifier = key_id_aes_256;
    auth_enc_args.iv = iv;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = aad;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = buff_encr;
    auth_enc_args.output = buff_decr;
    auth_enc_args.input_size = msg_size + 16U;
    auth_enc_args.output_size = msg_size;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);
    
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);

    return TRUE;
}
