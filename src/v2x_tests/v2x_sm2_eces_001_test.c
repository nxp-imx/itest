#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: eces encrypt decrypt 

int v2x_sm2_eces_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_generate_key_args_t gen_key_args;
    op_sm2_eces_enc_args_t sm2_eces_enc_args;
    open_svc_sm2_eces_args_t sm2_eces_dec_svc_args;
    op_sm2_eces_dec_args_t sm2_eces_dec_args;
    
    hsm_hdl_t sg0_sess, sv0_sess, sg1_sess, sv1_sess;   
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg1_key_store_serv, sg1_key_mgmt_srv;
    hsm_hdl_t sg0_sm2_eces_hdl, sg1_sm2_eces_hdl;

    const hsm_key_type_t algos = HSM_KEY_TYPE_DSA_SM2_FP_256;
    const uint16_t size_pub_key = 0x40;

    uint32_t key_id_0 = 0;
    uint32_t key_id_1 = 0;
    uint8_t pub_key_0[0x50];
    uint8_t pub_key_1[0x50];
    uint8_t msg_0[300];
    uint8_t msg_1[300];
    uint8_t out_0[500];
    uint8_t out_1[500];
    uint8_t out_2[500];
    uint8_t out_3[500];
    uint8_t dec_out[500];
    uint32_t size_msg_max = 300;
    uint32_t size_msg = 0;

    // REMOVE NVM
    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg_0, size_msg_max), size_msg_max);
    ASSERT_EQUAL(randomize(msg_1, size_msg_max), size_msg_max);

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
    key_store_srv_args.max_updates_number = 666;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg1_sess, &key_store_srv_args, &sg1_key_store_serv), HSM_NO_ERROR);

    // OPEN ECES SRV ON SG0
    sm2_eces_dec_svc_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_sm2_eces_service(sg0_key_store_serv, &sm2_eces_dec_svc_args, &sg0_sm2_eces_hdl), HSM_NO_ERROR);
    // OPEN ECES SRV ON SG1
    ASSERT_EQUAL(hsm_open_sm2_eces_service(sg1_key_store_serv, &sm2_eces_dec_svc_args, &sg1_sm2_eces_hdl), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // KEY MGMNT SG1
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg1_key_store_serv, &key_mgmt_srv_args, &sg1_key_mgmt_srv), HSM_NO_ERROR);

    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = &key_id_0;
    gen_key_args.out_size = size_pub_key;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    gen_key_args.key_type = algos;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = pub_key_0;
    // GEN KEY + STORE IN NVM
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    
    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = &key_id_1;
    gen_key_args.out_size = size_pub_key;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    gen_key_args.key_type = algos;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = pub_key_1;
    // GEN KEY + STORE IN NVM
    ASSERT_EQUAL(hsm_generate_key(sg1_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    for (size_msg = 1; size_msg < size_msg_max; size_msg++) {
        memset(out_0, 0, sizeof(out_0));
        memset(out_1, 0, sizeof(out_1));
        memset(out_2, 0, sizeof(out_2));
        memset(out_3, 0, sizeof(out_3));
        memset(dec_out, 0, sizeof(dec_out));
        // SM2 ECES ENCRYPT ON SV0
        sm2_eces_enc_args.input = msg_0;
        sm2_eces_enc_args.output = out_0;
        sm2_eces_enc_args.pub_key = pub_key_0;
        sm2_eces_enc_args.input_size = size_msg;
        sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
        sm2_eces_enc_args.pub_key_size = size_pub_key;
        sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_enc_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

        // SM2 ECES ENCRYPT ON SV1
        sm2_eces_enc_args.input = msg_0;
        sm2_eces_enc_args.output = out_1;
        sm2_eces_enc_args.pub_key = pub_key_0;
        sm2_eces_enc_args.input_size = size_msg;
        sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
        sm2_eces_enc_args.pub_key_size = size_pub_key;
        sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_enc_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_encryption(sv1_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

        // SM2 ECES ENCRYPT ON SG0
        sm2_eces_enc_args.input = msg_1;
        sm2_eces_enc_args.output = out_2;
        sm2_eces_enc_args.pub_key = pub_key_1;
        sm2_eces_enc_args.input_size = size_msg;
        sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
        sm2_eces_enc_args.pub_key_size = size_pub_key;
        sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_enc_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_encryption(sg0_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

        // SM2 ECES ENCRYPT ON SG1
        sm2_eces_enc_args.input = msg_1;
        sm2_eces_enc_args.output = out_3;
        sm2_eces_enc_args.pub_key = pub_key_1;
        sm2_eces_enc_args.input_size = size_msg;
        sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
        sm2_eces_enc_args.pub_key_size = size_pub_key;
        sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_enc_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_encryption(sg1_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

        // SM2 ECES DECRYPT ON SG0 - ENCRYTPT SV0
        sm2_eces_dec_args.input = out_0;
        sm2_eces_dec_args.output = dec_out; //plaintext
        sm2_eces_dec_args.key_identifier = key_id_0;
        sm2_eces_dec_args.input_size = (size_msg + 97);
        sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t));
        sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_dec_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
        ASSERT_EQUAL(memcmp(dec_out, msg_0, size_msg), 0);

        // SM2 ECES DECRYPT ON SG0 - ENCRYTPT SV1
        sm2_eces_dec_args.input = out_1;
        sm2_eces_dec_args.output = dec_out; //plaintext
        sm2_eces_dec_args.key_identifier = key_id_0;
        sm2_eces_dec_args.input_size = (size_msg + 97);
        sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t));
        sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_dec_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
        ASSERT_EQUAL(memcmp(dec_out, msg_0, size_msg), 0);

        // SM2 ECES DECRYPT ON SG0 - WITH BAD KEY ID
        sm2_eces_dec_args.input = out_2;
        sm2_eces_dec_args.output = dec_out; //plaintext
        sm2_eces_dec_args.key_identifier = key_id_1;
        sm2_eces_dec_args.input_size = (size_msg + 97);
        sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t));
        sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_dec_args.flags = 0;
        ASSERT_NOT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);

        // SM2 ECES DECRYPT ON SG1 - ENCRYTPT SG0
        sm2_eces_dec_args.input = out_2;
        sm2_eces_dec_args.output = dec_out; //plaintext
        sm2_eces_dec_args.key_identifier = key_id_1;
        sm2_eces_dec_args.input_size = (size_msg + 97);
        sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t));
        sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_dec_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_decryption(sg1_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
        ASSERT_EQUAL(memcmp(dec_out, msg_1, size_msg), 0);

        // SM2 ECES DECRYPT ON SG1 - ENCRYTPT SG1
        sm2_eces_dec_args.input = out_3;
        sm2_eces_dec_args.output = dec_out; //plaintext
        sm2_eces_dec_args.key_identifier = key_id_1;
        sm2_eces_dec_args.input_size = (size_msg + 97);
        sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t));
        sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        sm2_eces_dec_args.flags = 0;
        ASSERT_EQUAL(hsm_sm2_eces_decryption(sg1_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
        ASSERT_EQUAL(memcmp(dec_out, msg_1, size_msg), 0);
    }

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_sm2_eces_service(sg0_sm2_eces_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_sm2_eces_service(sg1_sm2_eces_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg1_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg1_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg1_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv1_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}