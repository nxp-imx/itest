#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

// requirement: test vector SM2 st_butterfly_key_expansion explicit certif

int v2x_st_butterfly_key_exp_002(void)
{

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_pub_key_recovery_args_t pub_k_rec_args;
    //op_butt_key_exp_args_t but_key_exp_args;
    op_st_butt_key_exp_args_t st_butt_key_expansion;

    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id;
    uint32_t key_id_sm4;
    uint32_t dest_key_id;
    hsm_key_type_t key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    hsm_key_type_t key_type_sm4 = HSM_KEY_TYPE_SM4_128;
    uint8_t pub_key_but_exp_out[0x40];

    uint8_t sm2_privk[32] = {
        0x25, 0xd7, 0xd2, 0xe8, 0x01, 0x1e, 0x26, 0x8e, 0x71, 0x04, 0x12, 0x94, 0xbc, 0x45, 0x6b, 0x51,
        0x92, 0xd1, 0x16, 0xfc, 0x90, 0x3a, 0xef, 0xed, 0xd1, 0x84, 0x19, 0x2b, 0x0d, 0xd5, 0xfb, 0x84
    };
    uint8_t sm4_key [0x10] = {
        0x66, 0x0e, 0x23, 0x41, 0xda, 0xd5, 0xa4, 0x76, 0x41, 0x6a, 0xa9, 0x31, 0xa9, 0xcc, 0x22, 0x06
    };
    uint8_t sm2_exp_fct_input[0x10] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x17, 0x36, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00

    };
    uint8_t expected_exp_pubk[0x40] = {
        0xb7, 0x4f, 0x86, 0xd2, 0x1b, 0x91, 0xb9, 0x88, 0xb9, 0x77, 0x8d, 0x84, 0x03, 0x22, 0x21, 0x14,
        0x77, 0x53, 0x9a, 0x42, 0x45, 0x7c, 0xf5, 0x3f, 0x2f, 0x58, 0x9e, 0x54, 0x06, 0xe4, 0x6a, 0xe7,
        0xa9, 0xb8, 0xe1, 0x83, 0x8d, 0x9f, 0xbf, 0xa6, 0xee, 0x81, 0x50, 0x2a, 0x03, 0xa3, 0xb1, 0xe0,
        0x51, 0x03, 0x4d, 0x5e, 0x7c, 0x10, 0x3a, 0xcd, 0x44, 0x91, 0x59, 0xe9, 0xda, 0x80, 0x55, 0x35
    };

    uint8_t pr_rec_size = 0x0;
    uint8_t hash_size = 0x0;
    uint8_t pubk_size = 0x40;
    uint8_t sm2_exp_fct_inpu_sizet = 0x10;
    uint8_t sm4_key_size = 0x10;

    uint32_t kek_handle;
    uint8_t kek_data[32];
    uint32_t key_size = sizeof(kek_data);

    clear_v2x_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t)0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t)0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    ASSERT_EQUAL(isen_kek_generation(sg0_key_mgmt_srv, kek_data, key_size, &kek_handle), TRUE_TEST);

    // =========== INJECT KEYS SM2 KEY ================= //
    ASSERT_EQUAL(isen_hsm_key_injection_custom(sg0_key_mgmt_srv, &key_id, key_type, sm2_privk, kek_handle, kek_data, 32, 1U,
                                               HSM_KEY_INFO_MASTER, HSM_OP_KEY_GENERATION_FLAGS_CREATE), TRUE_TEST);
    // =========== INJECT KEYS SM4 KEY ================= //
    ASSERT_EQUAL(isen_hsm_key_injection_custom(sg0_key_mgmt_srv, &key_id_sm4, key_type_sm4, sm4_key, kek_handle, kek_data, sm4_key_size, 1U,
                                               0U, HSM_OP_KEY_GENERATION_FLAGS_CREATE), TRUE_TEST);

    // STANDALONE BUTTERFLY KEY EXPANSION IMPLICIT_CERTIF
    st_butt_key_expansion.key_identifier = key_id;
    st_butt_key_expansion.expansion_fct_key_identifier = key_id_sm4;
    st_butt_key_expansion.expansion_fct_input = sm2_exp_fct_input;
    st_butt_key_expansion.hash_value = NULL;
    st_butt_key_expansion.pr_reconstruction_value = NULL;
    st_butt_key_expansion.expansion_fct_input_size = sm2_exp_fct_inpu_sizet;
    st_butt_key_expansion.hash_value_size = hash_size;
    st_butt_key_expansion.pr_reconstruction_value_size = pr_rec_size;
    st_butt_key_expansion.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF | HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE;
    st_butt_key_expansion.dest_key_identifier = &dest_key_id;
    st_butt_key_expansion.output = pub_key_but_exp_out;
    st_butt_key_expansion.output_size = pubk_size;
    st_butt_key_expansion.key_type = key_type;
    st_butt_key_expansion.expansion_fct_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    st_butt_key_expansion.key_group = 1;
    st_butt_key_expansion.key_info = 0U;
    ASSERT_EQUAL(hsm_standalone_butterfly_key_expansion(sg0_key_mgmt_srv, &st_butt_key_expansion), HSM_NO_ERROR);
    // CHECK OUTPUT
    ASSERT_EQUAL(memcmp(expected_exp_pubk, pub_key_but_exp_out, pubk_size), 0);

    // RECOVERY PUB KEY
    pub_k_rec_args.key_identifier = dest_key_id;
    pub_k_rec_args.out_key = pub_key_but_exp_out;
    pub_k_rec_args.out_key_size = pubk_size;
    pub_k_rec_args.key_type = key_type;
    pub_k_rec_args.flags = 0;
    ASSERT_EQUAL(hsm_pub_key_recovery(sg0_key_store_serv, &pub_k_rec_args), HSM_NO_ERROR);

    // CHECK OUTPUT: recover the pub key to check private key generated
    ASSERT_EQUAL(memcmp(expected_exp_pubk, pub_key_but_exp_out, pubk_size), 0);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
