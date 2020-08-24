#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement: one key group should be able to store 100 key

int sm2_key_gen_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_generate_key_args_t gen_key_args;
    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id = 0, i;
    uint8_t buff_out[1024];


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

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = buff_out;

    // GEN 100 KEY IN KEY GROUP 1
    for (i = 0; i < 100; i++){
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    gen_key_args.key_group = 2;
    // GEN 100 KEY IN KEY GROUP 2
    for (i = 0; i < 100; i++){
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    gen_key_args.key_group = 3;
    // GEN 100 KEY IN KEY GROUP 3
    for (i = 0; i < 100; i++){
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    gen_key_args.key_group = 4;
    // GEN 100 KEY IN KEY GROUP 4
    for (i = 0; i < 100; i++){
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE;
}
