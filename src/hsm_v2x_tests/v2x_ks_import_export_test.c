#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: Reuse the sm4 key from ks for encryption and decryption using the same ks imported from NVM

typedef struct {
    uint8_t cipher_buff[2048];
    uint8_t clear_buff[2048];
    uint32_t key_id;
} test_ctx_t;

static uint8_t SM2_IDENTIFIER[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

int v2x_ks_import_export_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    
    op_generate_key_args_t gen_key_args;
    op_cipher_one_go_args_t cipher_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    test_ctx_t ctx;
    uint16_t cipher_len = 512;
    uint32_t i;

    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(ctx.clear_buff, cipher_len), cipher_len);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);
    
    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 0;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // PARAM SM4 KEY_GEN strict_update
    gen_key_args.key_identifier = &ctx.key_id;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    for(i = 0; i < 1000; i++) {
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_UPDATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        // GEN SM4 KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }
    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // CIPHER ONE GO
    cipher_args.key_identifier = ctx.key_id;
    cipher_args.iv = SM2_IDENTIFIER; // just need 16 bytes somewhere to be used as IV
    cipher_args.iv_size = 16;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = ctx.clear_buff;
    cipher_args.output = ctx.cipher_buff;
    cipher_args.input_size = cipher_len;
    cipher_args.output_size = cipher_len;
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    ASSERT_NOT_EQUAL(save_test_ctx(&ctx, sizeof(test_ctx_t), "v2x_ks_imp_exp_test_ctx.bin"), 0);
    
    return TRUE_TEST;
}

int v2x_ks_import_export_001_part2(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    
    op_cipher_one_go_args_t cipher_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv;
    hsm_hdl_t sg0_cipher_hdl;

    uint8_t decrypt_buff[2048];
    test_ctx_t ctx;
    uint16_t cipher_len = 512;

    // LOAD THE TEXT CONTEXT
    ASSERT_NOT_EQUAL(load_test_ctx(&ctx, sizeof(test_ctx_t), "v2x_ks_imp_exp_test_ctx.bin"), 0);

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
    key_store_srv_args.flags = 0;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // CIPHER ONE GO DECRYPT
    cipher_args.key_identifier = ctx.key_id;
    cipher_args.iv = SM2_IDENTIFIER; // just need 16 bytes somewhere to be used as IV
    cipher_args.iv_size = 16;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.input = ctx.cipher_buff;
    cipher_args.output = decrypt_buff;
    cipher_args.input_size = cipher_len;
    cipher_args.output_size = cipher_len;
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
    // CHECK DECRYPTED OUTPUT
    ASSERT_EQUAL(memcmp(ctx.clear_buff, decrypt_buff, cipher_len), 0);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}
