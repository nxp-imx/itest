#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement: enc/decr with all aes algos

int v2x_cipher_aes_ecb_cbc_001(void){

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
    uint32_t msg_size;

    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 128), 128);
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

    for (msg_size = 16; msg_size <= 128; msg_size+= 16) {
        // CIPHER ONE GO AES_128 ECB -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_128 ECB -> DECRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        // CIPHER ONE GO AES_128 CBC -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_128 CBC -> DECRYPT
        cipher_args.key_identifier = key_id_aes_128;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        /*========================================================*/
        // CIPHER ONE GO AES_192 ECB -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_192 ECB -> DECRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        // CIPHER ONE GO AES_192 CBC -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_192 CBC -> DECRYPT
        cipher_args.key_identifier = key_id_aes_192;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        /*========================================================*/
        // CIPHER ONE GO AES_256 ECB -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_256 ECB -> DECRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 0;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

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
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);

        // CIPHER ONE GO AES_256 CBC -> ENCRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = msg;
        cipher_args.output = buff_encr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

        // CIPHER ONE GO AES_256 CBC -> DECRYPT
        cipher_args.key_identifier = key_id_aes_256;
        cipher_args.iv = iv;
        cipher_args.iv_size = 16;
        cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = buff_encr;
        cipher_args.output = buff_decr;
        cipher_args.input_size = msg_size;
        cipher_args.output_size = msg_size;
        ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // CHECK DECRYPTED OUTPUT
        ASSERT_EQUAL(memcmp(msg, buff_decr, msg_size), 0);
    }

    ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE;
}
