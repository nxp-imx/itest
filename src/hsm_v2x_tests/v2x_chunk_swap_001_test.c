#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: one key group should be able to store 100 key

static uint8_t SM2_IDENTIFIER[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

int v2x_chunk_swap_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    
    op_generate_key_args_t gen_key_args;
    op_cipher_one_go_args_t cipher_args;
    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id[3] = {0, 0, 0}, i, key_id_cur = 0U;
    uint8_t cipher_buff[3][512];
    uint8_t clear_buff[512];
    uint8_t decrypt_buff[512];
    uint16_t cipher_len = 512;

    clear_v2x_nvm();

    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);
    ASSERT_EQUAL(randomize(clear_buff, cipher_len), cipher_len);
    
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

    // PARAM SM4 KEY_GEN strict_update
    gen_key_args.key_identifier = &key_id_cur;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // GEN 100 KEY IN KEY GROUP 1
    for (i = 0; i < 100; i++){
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
        if (i == 0)
            key_id[0] = key_id_cur;
        else if (i == 49)
            key_id[1] = key_id_cur;
        else if (i == 99)
            key_id[2] = key_id_cur;
            
    }

    // CIPHER ONE GO
    cipher_args.key_identifier = key_id[0];
    cipher_args.iv = SM2_IDENTIFIER; // just need 16 bytes somewhere to be used as IV
    cipher_args.iv_size = 16;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = clear_buff;
    cipher_args.output = cipher_buff[0];
    cipher_args.input_size = cipher_len;
    cipher_args.output_size = cipher_len;
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    cipher_args.key_identifier = key_id[1];
    cipher_args.output = cipher_buff[1];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    cipher_args.key_identifier = key_id[2];
    cipher_args.output = cipher_buff[2];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

    gen_key_args.key_group = 2;
    // GEN 100 KEY IN KEY GROUP 2
    for (i = 0; i < 100; i++){
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    // CIPHER ONE GO DECRYPT
    cipher_args.key_identifier = key_id[0];
    cipher_args.iv = SM2_IDENTIFIER; // just need 16 bytes somewhere to be used as IV
    cipher_args.iv_size = 16;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.input = cipher_buff[0];
    cipher_args.output = decrypt_buff;
    cipher_args.input_size = cipher_len;
    cipher_args.output_size = cipher_len;
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[1];
    cipher_args.input = cipher_buff[1];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[2];
    cipher_args.input = cipher_buff[2];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    gen_key_args.key_group = 3;
    // GEN 100 KEY IN KEY GROUP 3
    for (i = 0; i < 100; i++){
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    cipher_args.key_identifier = key_id[0];
    cipher_args.input = cipher_buff[0];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[1];
    cipher_args.input = cipher_buff[1];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[2];
    cipher_args.input = cipher_buff[2];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    gen_key_args.key_group = 4;
    // GEN 100 KEY IN KEY GROUP 4
    for (i = 0; i < 100; i++){
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    cipher_args.key_identifier = key_id[0];
    cipher_args.input = cipher_buff[0];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[1];
    cipher_args.input = cipher_buff[1];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    cipher_args.key_identifier = key_id[2];
    cipher_args.input = cipher_buff[2];
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(clear_buff, decrypt_buff, cipher_len), 0);
    memset(decrypt_buff, 0U, 512);

    ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
