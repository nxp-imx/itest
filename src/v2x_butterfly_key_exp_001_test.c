#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement:


int v2x_butterfly_key_exp_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;

    op_butt_key_exp_args_t but_key_exp_args;
    op_generate_key_args_t gen_key_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id;
    uint32_t dest_key_id;
    uint16_t size_pub_key = 0x40;
    //uint16_t size_pub_key_c = 0x43;
    hsm_key_type_t key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    uint8_t pub_key[0x40];
    uint8_t pub_key_but_exp_out[0x40];
    uint8_t hash[0x40];
    uint8_t exp_f_value[0x40];
    uint8_t pr_rec_value[0x40];
    uint8_t pr_rec_size = 0x40;
    uint8_t hash_size = 0x20;
    uint8_t exp_f_size = 0x20;

    clear_v2x_nvm();
    
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

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = size_pub_key;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = key_type;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = HSM_KEY_INFO_MASTER;
    gen_key_args.out_key = pub_key;

    // GEN KEY
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    // BUTTERFLY KEY EXPANSION
    but_key_exp_args.key_identifier = key_id;
    but_key_exp_args.expansion_function_value = exp_f_value;
    but_key_exp_args.hash_value = hash;
    but_key_exp_args.pr_reconstruction_value = pr_rec_value;
    but_key_exp_args.expansion_function_value_size = exp_f_size;
    but_key_exp_args.hash_value_size = hash_size;
    but_key_exp_args.pr_reconstruction_value_size = pr_rec_size;
    but_key_exp_args.flags = HSM_OP_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF | HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE;
    but_key_exp_args.dest_key_identifier = &dest_key_id;
    but_key_exp_args.output = pub_key_but_exp_out;
    but_key_exp_args.output_size = 0x40;
    but_key_exp_args.key_type = key_type;
    but_key_exp_args.key_group = 1;
    but_key_exp_args.key_info = 0U;
    ASSERT_EQUAL(hsm_butterfly_key_expansion(sg0_key_mgmt_srv, &but_key_exp_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE;
}
