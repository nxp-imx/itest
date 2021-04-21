#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include "itest.h"

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

int v2x_parallel_sign_gen_key_gen_002(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    
    op_generate_key_args_t gen_key_args, gen_key_args_2;
    op_generate_sign_args_t sg0_sig_gen_args;
    op_verify_sign_args_t sv0_sig_ver_args;  
    op_generate_sign_args_t sg1_sig_gen_args;
    op_verify_sign_args_t sv1_sig_ver_args;
    
    hsm_hdl_t sg0_sess, sg0_sig_gen_serv;
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_hdl_t sg1_sess, sg1_sig_gen_serv;
    hsm_hdl_t sv1_sess, sv1_sig_ver_serv;    
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg1_key_store_serv, sg1_key_mgmt_srv;
    uint32_t dummy_32, dummy_32_2;
    uint32_t key_id_0 = 0;
    uint32_t key_id_1 = 0;
    hsm_verification_status_t status;
    uint8_t pub_key_0[1024];
    uint8_t pub_key_1[1024];
    uint8_t dummy_key[1024];
    uint8_t dummy_key_2[1024];
    uint8_t msg_0[300];
    uint8_t msg_1[300];
    uint8_t sign_out_0[2][1024];
    uint8_t sign_out_1[2][1024];
    uint32_t iter = 2500;
    uint32_t i;

    omp_set_num_threads(6);

    // REMOVE NVM
    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg_0, 300), 300);
    ASSERT_EQUAL(randomize(msg_1, 300), 300);

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

    // SG1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg1_sess), HSM_NO_ERROR);

    // SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv1_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY STORE SG1
    key_store_srv_args.key_store_identifier = (uint32_t) 0x13131313;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg1_sess, &key_store_srv_args, &sg1_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // SIGN GEN OPEN SRV SG0
    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);

    // SIGN VER OPEN SRV SG0
    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess, &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);

    // KEY MGMNT SG1
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg1_key_store_serv, &key_mgmt_srv_args, &sg1_key_mgmt_srv), HSM_NO_ERROR);

    // SIGN GEN OPEN SRV SG1
    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg1_key_store_serv, &sig_gen_srv_args, &sg1_sig_gen_serv), HSM_NO_ERROR);

    // SIGN VER OPEN SRV SG1
    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv1_sess, &sig_ver_srv_args, &sv1_sig_ver_serv), HSM_NO_ERROR);

    for(i = 0; i < NB_ALGO; i++){

        // CREATE a dummy key
        gen_key_args.key_identifier = &dummy_32;
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = dummy_key;
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg1_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

        // CREATE a dummy key 2
        gen_key_args.key_identifier = &dummy_32_2;
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = dummy_key_2;
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

        // PARAM KEY_GEN strict_update
        gen_key_args.key_identifier = &key_id_0;
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = pub_key_0;
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
        
        // PARAM KEY_GEN strict_update
        gen_key_args.key_identifier = &key_id_1;
        gen_key_args.out_size = size_pub_key[i];
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = algos[i];
        gen_key_args.key_group = 1;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = pub_key_1;
        // GEN KEY + STORE IN NVM
        ASSERT_EQUAL(hsm_generate_key(sg1_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

	// GEN THE SIGN TO VERIFY ON SV0
        sg0_sig_gen_args.key_identifier = key_id_0;
        sg0_sig_gen_args.message = msg_0;
        sg0_sig_gen_args.signature = sign_out_0[1];
        sg0_sig_gen_args.message_size = 300;
        sg0_sig_gen_args.signature_size = size_pub_key[i]+1;
        sg0_sig_gen_args.scheme_id = algos_sign[i];
        sg0_sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE; 
        ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sg0_sig_gen_args), HSM_NO_ERROR);

	// GEN THE SIGN TO VERIFY ON SV1
        sg1_sig_gen_args.key_identifier = key_id_1;
        sg1_sig_gen_args.message = msg_1;
        sg1_sig_gen_args.signature = sign_out_1[1];
        sg1_sig_gen_args.message_size = 300;
        sg1_sig_gen_args.signature_size = size_pub_key[i]+1;
        sg1_sig_gen_args.scheme_id = algos_sign[i];
        sg1_sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE; 
        ASSERT_EQUAL(hsm_generate_signature(sg1_sig_gen_serv, &sg1_sig_gen_args), HSM_NO_ERROR);
 
#pragma omp parallel sections
        {
#pragma omp section
            {
                uint32_t j;
                for (j = 0; j < iter; j++) {
		            gen_key_args_2.key_identifier = &dummy_32_2;
		            gen_key_args_2.out_size = size_pub_key[i];
                    gen_key_args_2.flags = HSM_OP_KEY_GENERATION_FLAGS_UPDATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
                    gen_key_args_2.key_type = algos[i];
                    gen_key_args_2.key_group = 1;
                    gen_key_args_2.key_info = 0U;
                    gen_key_args_2.out_key = dummy_key_2;
                    // GEN KEY + STORE IN NVM
                    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args_2), HSM_NO_ERROR);
                }
            }
#pragma omp section
            {
                uint32_t j;
                for (j = 0; j < iter*6; j++) {        
                    sv0_sig_ver_args.key = pub_key_0;
                    sv0_sig_ver_args.message = msg_0;
                    sv0_sig_ver_args.signature = sign_out_0[1];
                    sv0_sig_ver_args.key_size = size_pub_key[i];
                    sv0_sig_ver_args.signature_size = size_pub_key[i]+1;
                    sv0_sig_ver_args.message_size = 300;
                    sv0_sig_ver_args.scheme_id = algos_sign[i];
                    sv0_sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
                    ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sv0_sig_ver_args, &status), HSM_NO_ERROR);
                    ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
                }
            }
#pragma omp section
            {
                uint32_t j;
                for (j = 0; j < iter; j++) {
		            gen_key_args.key_identifier = &dummy_32;
		            gen_key_args.out_size = size_pub_key[i];
                    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_UPDATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
                    gen_key_args.key_type = algos[i];
                    gen_key_args.key_group = 1;
                    gen_key_args.key_info = 0U;
                    gen_key_args.out_key = dummy_key;
                    // GEN KEY + STORE IN NVM
                    ASSERT_EQUAL(hsm_generate_key(sg1_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
                }
            }
#pragma omp section
            {
                uint32_t j;
                for (j = 0; j < iter*6; j++) {
                    sv1_sig_ver_args.key = pub_key_1;
                    sv1_sig_ver_args.message = msg_1;
                    sv1_sig_ver_args.signature = sign_out_1[1];
                    sv1_sig_ver_args.key_size = size_pub_key[i];
                    sv1_sig_ver_args.signature_size = size_pub_key[i]+1;
                    sv1_sig_ver_args.message_size = 300;
                    sv1_sig_ver_args.scheme_id = algos_sign[i];
                    sv1_sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
                    ASSERT_EQUAL(hsm_verify_signature(sv1_sig_ver_serv, &sv1_sig_ver_args, &status), HSM_NO_ERROR);
                    ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
                }
            }
        }
    }
    
    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}
