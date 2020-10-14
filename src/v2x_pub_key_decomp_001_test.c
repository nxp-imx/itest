#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement: Pub Key decompression on all curves


int v2x_pub_key_decompression_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    
    op_generate_key_args_t gen_key_args;
    op_pub_key_dec_args_t pub_key_dec_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id;
    uint16_t size_pub_key = 0x84;
    uint16_t size_pub_key_c = 0x43;
    hsm_key_type_t key_type = HSM_KEY_TYPE_ECDSA_NIST_P521;
    uint8_t pub_key[0x90];
    uint8_t pub_key_comp[0x90];
    uint8_t pub_key_decomp[0x90];

    clear_v2x_nvm();

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
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = pub_key;

    // GEN KEY
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    memcpy(pub_key_comp, pub_key, size_pub_key_c - 1);
    if ((pub_key[size_pub_key - 1] & 1) == 1U)
        pub_key_comp[size_pub_key_c - 1] = 0x1;
    else
        pub_key_comp[size_pub_key_c - 1] = 0x0;
    
    // PUB KEY DECOMPRESS
    pub_key_dec_args.key = pub_key_comp;
    pub_key_dec_args.out_key = pub_key_decomp;
    pub_key_dec_args.key_size = size_pub_key_c;
    pub_key_dec_args.out_key_size = size_pub_key;
    pub_key_dec_args.key_type = key_type;
    ASSERT_EQUAL(hsm_pub_key_decompression(sg0_sess, &pub_key_dec_args), HSM_NO_ERROR);
    // CHECK IF THE RECOVERED PUB KEY IS EQUAL TO THE ONE GENERATED
    ASSERT_EQUAL(memcmp(pub_key, pub_key_decomp, size_pub_key), 0);
    
    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);

    return TRUE_TEST;
}
