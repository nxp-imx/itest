#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
// requirement: able to recover the PUB key of all supported curves 

#define NB_ALGO 8

typedef struct {
    uint32_t key_id[NB_ALGO];
    uint8_t pub_key[NB_ALGO][0x90];
} test_ctx_t;

hsm_key_type_t algos[NB_ALGO] = {
    HSM_KEY_TYPE_DSA_SM2_FP_256,
    HSM_KEY_TYPE_ECDSA_NIST_P256,
    HSM_KEY_TYPE_ECDSA_NIST_P384,
    HSM_KEY_TYPE_ECDSA_NIST_P521,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384,
};

uint16_t size_pub_key[NB_ALGO] = {
    0x40,
    0x40,
    0x60,
    0x90,
    0x40,
    0x60,
    0x40,
    0x60
};

int v2x_pub_key_recovery_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    
    op_generate_key_args_t gen_key_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    test_ctx_t ctx;
    uint32_t i;

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

    for(i = 0; i < NB_ALGO; i++){
        // PARAM KEY_GEN strict_update
        gen_key_args.key_identifier = &ctx.key_id[i];
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = ctx.pub_key[i];

        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    ASSERT_EQUAL(save_test_ctx(&ctx, sizeof(test_ctx_t), "v2x_pub_key_recovery_001_test_ctx.bin"), 1);
    
    return TRUE_TEST;
}


int v2x_pub_key_recovery_001_part2(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    op_pub_key_recovery_args_t pub_k_rec_args;
    
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv;

    test_ctx_t ctx;
    uint32_t i;
    uint8_t recovered_key[1024];

    // LOAD THE TEXT CONTEXT
    ASSERT_EQUAL(load_test_ctx(&ctx, sizeof(test_ctx_t), "v2x_pub_key_recovery_001_test_ctx.bin"), 1);

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

    for(i = 0; i < NB_ALGO; i++){
        // RECOVERY PUB KEY
        pub_k_rec_args.key_identifier = ctx.key_id[i];
        pub_k_rec_args.out_key = recovered_key;
        pub_k_rec_args.out_key_size = size_pub_key[i];;
        pub_k_rec_args.key_type = algos[i];
        pub_k_rec_args.flags = 0;
        ASSERT_EQUAL(hsm_pub_key_recovery(sg0_key_store_serv, &pub_k_rec_args), HSM_NO_ERROR);
        // CHECK IF THE RECOVERED PUB KEY IS EQUAL TO THE ONE GENERATED
        ASSERT_EQUAL(memcmp(recovered_key, ctx.pub_key[i], size_pub_key[i]), 0);
    }

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}
