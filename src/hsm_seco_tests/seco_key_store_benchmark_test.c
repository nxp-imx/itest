#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define NB_ALGO 7

static hsm_key_type_t algos[NB_ALGO] = {
    //HSM_KEY_TYPE_DSA_SM2_FP_256,
    HSM_KEY_TYPE_ECDSA_NIST_P256,
    HSM_KEY_TYPE_ECDSA_NIST_P384,
    //HSM_KEY_TYPE_ECDSA_NIST_P521,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
    HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
    HSM_KEY_TYPE_AES_128,
    HSM_KEY_TYPE_AES_192,
    HSM_KEY_TYPE_AES_256
};

static uint16_t max_key_by_group[NB_ALGO] = {
    //HSM_KEY_TYPE_DSA_SM2_FP_256,
    101,
    72,
    //HSM_KEY_TYPE_ECDSA_NIST_P521,
    101,
    72,
    169,
    126,
    101
};

static char *key_type_str[NB_ALGO] = {
    //"HSM_KEY_TYPE_DSA_SM2_FP_256",
    "HSM_KEY_TYPE_ECDSA_NIST_P256",
    "HSM_KEY_TYPE_ECDSA_NIST_P384",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256",
    "HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384",
    "HSM_KEY_TYPE_AES_128",
    "HSM_KEY_TYPE_AES_192",
    "HSM_KEY_TYPE_AES_256"
};

// check by key type the max number of key we can store in a key groupe

int seco_key_store_benchmark_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    
    op_generate_key_args_t gen_key_args;
    
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id_0 = 0;
    uint32_t i, j;

    // ITER ON ALL CURVES
    for(i = 0; i < NB_ALGO; i++){

        // REMOVE NVM
        clear_seco_nvm();

        // START NVM
        ASSERT_NOT_EQUAL(start_nvm_seco(), NVM_STATUS_STOPPED);
        
        // SECO SESSION
        args.session_priority = 0;
        args.operating_mode = 0;
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

        j = 0U;
        while (1U) {
            // PARAM KEY_GEN strict_update
            gen_key_args.key_identifier = &key_id_0;
            gen_key_args.out_size = 0U;
            gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
            gen_key_args.key_type = algos[i];
            gen_key_args.key_group = 1;
            gen_key_args.key_info = 0U;
            gen_key_args.out_key = NULL;
            // GEN KEY + STORE IN NVM
            if (hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args) != HSM_NO_ERROR) {
                break;
            }
            j++;
        }

        ITEST_LOG("max number of %s in a key groupe -> %d\n", key_type_str[i], j);
        ASSERT_EQUAL(j, max_key_by_group[i]);

        // CLOSE SRV/SESSION
        ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
        ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
        ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
        ASSERT_NOT_EQUAL(stop_nvm_seco(), NVM_STATUS_STOPPED);
    }
    
    return TRUE_TEST;
}