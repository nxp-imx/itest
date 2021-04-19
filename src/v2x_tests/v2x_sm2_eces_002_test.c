#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: eces encrypt decrypt 

int v2x_sm2_eces_002(void){

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
    // test vector from GB/T32918.5-2017 National Standard of the People’s Republic of China
    /*uint8_t pub_key_tv[0x40] = {0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
                                0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
                                0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
                                0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13};
    uint8_t msg_tv[19] =  {0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
    uint8_t cipher_tv[120] = {0x04, 0xEB, 0xFC, 0x71, 0x8E, 0x8D, 0x17, 0x98, 0x62, 0x04, 0x32, 0x26, 0x8E, 0x77, 0xFE, 0xB6, 0x41, 0x5E, 0x2E, 0xDE, 0x0E, 0x07, 0x3C, 0x0F, 0x4F, 0x64, 0x0E, 0xCD, 0x2E, 0x14, 0x9A, 0x73,
                              0xE8, 0x58, 0xF9, 0xD8, 0x1E, 0x54, 0x30, 0xA5, 0x7B, 0x36, 0xDA, 0xAB, 0x8F, 0x95, 0x0A, 0x3C, 0x64, 0xE6, 0xEE, 0x6A, 0x63, 0x09, 0x4D, 0x99, 0x28, 0x3A, 0xFF, 0x76, 0x7E, 0x12, 0x4D, 0xF0,
                              0x59, 0x98, 0x3C, 0x18, 0xF8, 0x09, 0xE2, 0x62, 0x92, 0x3C, 0x53, 0xAE, 0xC2, 0x95, 0xD3, 0x03, 0x83, 0xB5, 0x4E, 0x39, 0xD6, 0x09, 0xD1, 0x60, 0xAF, 0xCB, 0x19, 0x08, 0xD0, 0xBD, 0x87, 0x66,
                              0x21, 0x88, 0x6C, 0xA9, 0x89, 0xCA, 0x9C, 0x7D, 0x58, 0x08, 0x73, 0x07, 0xCA, 0x93, 0x09, 0x2D, 0x65, 0x1E, 0xFA};*/
    uint8_t msg_0[300];
    uint8_t msg_1[300];
    uint8_t out_0[500];
    uint8_t out_2[500];
    uint8_t dec_out[500];
    uint32_t size_msg = 300;

    // REMOVE NVM
    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg_0, size_msg), size_msg);
    ASSERT_EQUAL(randomize(msg_1, size_msg), size_msg);

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

    // SM2 ECES ENCRYPT ON SV0 -> BAD PUBLIC KEY
    sm2_eces_enc_args.input = msg_0;
    sm2_eces_enc_args.output = out_0;
    sm2_eces_enc_args.pub_key = msg_0;
    sm2_eces_enc_args.input_size = size_msg;
    sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
    sm2_eces_enc_args.pub_key_size = size_pub_key;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;
    ASSERT_EQUAL_W(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_GENERAL_ERROR);

    // SM2 ECES ENCRYPT ON SV0 -> BAD KEY SIZE
    sm2_eces_enc_args.input = msg_0;
    sm2_eces_enc_args.output = out_0;
    sm2_eces_enc_args.pub_key = pub_key_0;
    sm2_eces_enc_args.input_size = size_msg;
    sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
    sm2_eces_enc_args.pub_key_size = 0x0;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;
    ASSERT_EQUAL_W(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_INVALID_PARAM);

    // SM2 ECES ENCRYPT ON SV0 -> BAD OUT SIZE (NOT ALIGNED)
    sm2_eces_enc_args.input = msg_0;
    sm2_eces_enc_args.output = out_0;
    sm2_eces_enc_args.pub_key = pub_key_0;
    sm2_eces_enc_args.input_size = size_msg;
    sm2_eces_enc_args.output_size = (size_msg + 97);
    sm2_eces_enc_args.pub_key_size = size_pub_key;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;
    ASSERT_EQUAL_W(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_INVALID_PARAM);

    // SM2 ECES ENCRYPT ON SV0 -> BAD OUT SIZE
    sm2_eces_enc_args.input = msg_0;
    sm2_eces_enc_args.output = out_0;
    sm2_eces_enc_args.pub_key = pub_key_0;
    sm2_eces_enc_args.input_size = size_msg;
    sm2_eces_enc_args.output_size = 0x0;
    sm2_eces_enc_args.pub_key_size = size_pub_key;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;
    ASSERT_EQUAL_W(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_INVALID_PARAM);

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

    // SM2 ECES DECRYPT ON SG0 - WITH BAD KEY ID
    sm2_eces_dec_args.input = out_2;
    sm2_eces_dec_args.output = dec_out; //plaintext
    sm2_eces_dec_args.key_identifier = key_id_1;
    sm2_eces_dec_args.input_size = (size_msg + 97);
    sm2_eces_dec_args.output_size = size_msg;
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;
    ASSERT_NOT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
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