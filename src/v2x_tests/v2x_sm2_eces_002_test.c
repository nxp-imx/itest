#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: eces encrypt decrypt using test vector form GB/T32918.5-2017

int v2x_sm2_eces_002(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_sm2_eces_enc_args_t sm2_eces_enc_args;
    open_svc_sm2_eces_args_t sm2_eces_dec_svc_args;
    op_sm2_eces_dec_args_t sm2_eces_dec_args;
    
    hsm_hdl_t sg0_sess, sv0_sess;   
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_sm2_eces_hdl;

    const hsm_key_type_t algos = HSM_KEY_TYPE_DSA_SM2_FP_256;
    const uint16_t size_pub_key = 0x40;

    uint32_t key_id_inj = 0;
    // test vector from GB/T32918.5-2017 National Standard of the People’s Republic of China
    uint8_t pub_key_tv[0x40] = {
                                0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
                                0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
                                0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
                                0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
                                };
    uint8_t priv_key_tv[0x20] = {    
                                0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
                                0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8
                                };
    uint8_t msg_tv[20] =  {
                            0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64
                            };
    uint8_t out_0[500];
    uint8_t dec_out[500];
    uint32_t size_msg = 19;

    uint32_t kek_handle;
    uint8_t kek_data[32];
    uint32_t key_size = sizeof(kek_data);

    // REMOVE NVM
    clear_v2x_nvm();

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

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // OPEN ECES SRV ON SG0
    sm2_eces_dec_svc_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_sm2_eces_service(sg0_key_store_serv, &sm2_eces_dec_svc_args, &sg0_sm2_eces_hdl), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    ASSERT_EQUAL(kek_generation(sg0_key_mgmt_srv, kek_data, key_size, &kek_handle), TRUE_TEST);

    // =========== INJECT KEYS FOR AES GCM TEST ================= //
    ASSERT_EQUAL(hsm_key_injection(sg0_key_mgmt_srv, &key_id_inj, algos, priv_key_tv, kek_handle, kek_data, 0x20), TRUE_TEST);

    // SM2 ECES ENCRYPT ON SV0
    sm2_eces_enc_args.input = msg_tv;
    sm2_eces_enc_args.output = out_0;
    sm2_eces_enc_args.pub_key = pub_key_tv;
    sm2_eces_enc_args.input_size = size_msg;
    sm2_eces_enc_args.output_size = (size_msg + 97) + ((sizeof(u_int32_t) - (size_msg + 97) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
    sm2_eces_enc_args.pub_key_size = size_pub_key;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;
    ASSERT_EQUAL(hsm_sm2_eces_encryption(sv0_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

    // SM2 ECES DECRYPT ON SG0
    sm2_eces_dec_args.input = out_0;
    sm2_eces_dec_args.output = dec_out; //plaintext
    sm2_eces_dec_args.key_identifier = key_id_inj;
    sm2_eces_dec_args.input_size = (size_msg + 97);
    sm2_eces_dec_args.output_size = (size_msg) + ((sizeof(u_int32_t) - (size_msg) % sizeof(u_int32_t)) % sizeof(u_int32_t)); // aligned with 32 bits
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;
    ASSERT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(dec_out, msg_tv, size_msg), 0);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_sm2_eces_service(sg0_sm2_eces_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}