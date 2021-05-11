#include <stdio.h>
#include <stdlib.h>
#include "itest.h"


static uint8_t exp_fct_input[16] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x17, 0x36, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
};

static uint8_t exp_fct_privk [16] = {
    0x66, 0x0e, 0x23, 0x41, 0xda, 0xd5, 0xa4, 0x76, 0x41, 0x6a, 0xa9, 0x31, 0xa9, 0xcc, 0x22, 0x06
};

static uint8_t sm2_privk[32] = {
    0x25, 0xd7, 0xd2, 0xe8, 0x01, 0x1e, 0x26, 0x8e, 0x71, 0x04, 0x12, 0x94, 0xbc, 0x45, 0x6b, 0x51,
    0x92, 0xd1, 0x16, 0xfc, 0x90, 0x3a, 0xef, 0xed, 0xd1, 0x84, 0x19, 0x2b, 0x0d, 0xd5, 0xfb, 0x84
};

static uint8_t expected_derived_pubk[0x40] = {
    0xb7, 0x4f, 0x86, 0xd2, 0x1b, 0x91, 0xb9, 0x88, 0xb9, 0x77, 0x8d, 0x84, 0x03, 0x22, 0x21, 0x14,
    0x77, 0x53, 0x9a, 0x42, 0x45, 0x7c, 0xf5, 0x3f, 0x2f, 0x58, 0x9e, 0x54, 0x06, 0xe4, 0x6a, 0xe7,
    0xa9, 0xb8, 0xe1, 0x83, 0x8d, 0x9f, 0xbf, 0xa6, 0xee, 0x81, 0x50, 0x2a, 0x03, 0xa3, 0xb1, 0xe0,
    0x51, 0x03, 0x4d, 0x5e, 0x7c, 0x10, 0x3a, 0xcd, 0x44, 0x91, 0x59, 0xe9, 0xda, 0x80, 0x55, 0x35
};

static uint8_t sig_msg[32] = {
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3
};

int v2x_sm2_st_butt_key_exp_swap_002(void)
{

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_st_butt_key_exp_args_t st_butt_key_exp_args;
    op_generate_key_args_t gen_key_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    op_generate_sign_args_t sig_gen_args;
    op_pub_key_recovery_args_t pub_k_rec_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_sig_gen_serv;
    uint32_t master_key_id;
    uint32_t derived_key_id;
    uint32_t exp_fct_key_id;
    uint32_t key_id;
    hsm_key_type_t key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    uint8_t pub_key_but_exp_out[0x40];
    uint8_t pubk_size = 0x40;
    uint8_t signature[65];

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
    key_store_srv_args.max_updates_number = 0;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);

    // =========== NEGOTIATE KEK FOR KEY INJECTION ================= //
    ASSERT_EQUAL(isen_kek_generation(sg0_key_mgmt_srv, kek_data, key_size, &kek_handle), TRUE_TEST);

    // =========== INJECT KEYS ================= //
    ASSERT_EQUAL(isen_hsm_key_injection_custom(sg0_key_mgmt_srv, &master_key_id, key_type, sm2_privk, kek_handle, kek_data, 32, 1U,
                                               HSM_KEY_INFO_MASTER, HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE| HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION), TRUE_TEST);

    ASSERT_EQUAL(isen_hsm_key_injection_custom(sg0_key_mgmt_srv, &exp_fct_key_id, HSM_KEY_TYPE_SM4_128, exp_fct_privk, kek_handle, kek_data, 16, 2U,
                                               0, HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE| HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION), TRUE_TEST);

    // PARAM KEY_GEN strict_update to guarantee swap
    for (uint32_t i=0; i<4; i++)
    {
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = 0;
        gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
        gen_key_args.key_type = HSM_KEY_TYPE_AES_256;
        gen_key_args.key_group = 3+i;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = 0;
        ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    }


    st_butt_key_exp_args.key_identifier = master_key_id;
    st_butt_key_exp_args.expansion_fct_key_identifier = exp_fct_key_id;
    st_butt_key_exp_args.expansion_fct_input = exp_fct_input;
    st_butt_key_exp_args.hash_value = 0;
    st_butt_key_exp_args.pr_reconstruction_value = 0;
    st_butt_key_exp_args.expansion_fct_input_size = 16;
    st_butt_key_exp_args.hash_value_size = 0;
    st_butt_key_exp_args.pr_reconstruction_value_size = 0;
    st_butt_key_exp_args.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION;
    st_butt_key_exp_args.dest_key_identifier = &derived_key_id;
    st_butt_key_exp_args.output = 0;
    st_butt_key_exp_args.output_size = 0;
    st_butt_key_exp_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    st_butt_key_exp_args.expansion_fct_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    st_butt_key_exp_args.key_group = 9;
    st_butt_key_exp_args.key_info = 0;

    ASSERT_EQUAL(hsm_standalone_butterfly_key_expansion(sg0_key_mgmt_srv, &st_butt_key_exp_args), HSM_NO_ERROR);

    // RECOVERY PUB KEY
    pub_k_rec_args.key_identifier = derived_key_id;
    pub_k_rec_args.out_key = pub_key_but_exp_out;
    pub_k_rec_args.out_key_size = pubk_size;
    pub_k_rec_args.key_type = key_type;
    pub_k_rec_args.flags = 0;
    ASSERT_EQUAL(hsm_pub_key_recovery(sg0_key_store_serv, &pub_k_rec_args), HSM_NO_ERROR);

    // CHECK OUTPUT
    ASSERT_EQUAL(memcmp(expected_derived_pubk, pub_key_but_exp_out, pubk_size), 0);

    sig_gen_args.key_identifier = derived_key_id;
    sig_gen_args.message = sig_msg;
    sig_gen_args.signature = signature;
    sig_gen_args.message_size = 32;
    sig_gen_args.signature_size = 65;
    sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3;
    sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
    ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);

    // CLOSE SRV/SESSION
    ASSERT_EQUAL(hsm_close_signature_generation_service(sg0_sig_gen_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
