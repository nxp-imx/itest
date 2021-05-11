#include <stdio.h>
#include <stdlib.h>
#include "itest.h"


static uint8_t exp_fct_input[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x36, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
};

static uint8_t exp_fct_privk [16] = {
    0xc2, 0x48, 0x14, 0x5f, 0x66, 0x3a, 0x4e, 0x4b, 0x8a, 0x30, 0x70, 0xc3, 0xa9, 0xd5, 0xdb, 0x50
};

static uint8_t sm2_butt_hash [32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static uint8_t sm2_butt_rec_val [32] = {
    0x2e, 0xfb, 0x7b, 0x7b, 0x52, 0x5e, 0x33, 0x7b, 0x90, 0x69, 0xd8, 0x6e, 0x30, 0xac, 0xb5, 0x3e,
    0xb0, 0xbe, 0x83, 0xb1, 0xb0, 0x1c, 0x04, 0xfe, 0x79, 0xe1, 0x18, 0x45, 0x82, 0xf1, 0xc0, 0xc4
};

static uint8_t sm2_privk[32] = {
    0x97, 0x59, 0xeb, 0x5a, 0x47, 0x0d, 0x09, 0x5e, 0x0e, 0xe1, 0xd0, 0xe5, 0xcc, 0x0d, 0xe3, 0xe4,
    0xc7, 0xa2, 0xf8, 0x1f, 0x6e, 0x7e, 0x74, 0xab, 0xe6, 0x23, 0xff, 0xca, 0x8b, 0xce, 0x7b, 0x20
};

static uint8_t expected_derived_pubk[0x40] = {
    0x29, 0x43, 0x38, 0xaa, 0xa6, 0xc4, 0xc0, 0x01, 0x12, 0x6b, 0x61, 0xd0, 0x3e, 0x06, 0x37, 0xcc,
    0x4a, 0xe1, 0x20, 0xcf, 0x39, 0x0f, 0x48, 0xbb, 0x18, 0xfa, 0x74, 0x6b, 0x4e, 0x5a, 0x36, 0x49,
    0x49, 0xbb, 0x3b, 0x8a, 0x87, 0xe6, 0x50, 0x79, 0xdd, 0x37, 0xfa, 0x64, 0x85, 0x33, 0xf0, 0x8a,
    0xc6, 0xce, 0xa0, 0xbe, 0xec, 0xe2, 0xb9, 0x16, 0x08, 0xfc, 0x4b, 0x26, 0xfc, 0xc5, 0xdf, 0xe1
};

int v2x_sm2_st_butt_key_exp_swap_001(void)
{

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_st_butt_key_exp_args_t st_butt_key_exp_args;
    op_generate_key_args_t gen_key_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    op_generate_sign_args_t sig_gen_args;
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
    st_butt_key_exp_args.hash_value = sm2_butt_hash;
    st_butt_key_exp_args.pr_reconstruction_value = sm2_butt_rec_val;
    st_butt_key_exp_args.expansion_fct_input_size = 16;
    st_butt_key_exp_args.hash_value_size = 32;
    st_butt_key_exp_args.pr_reconstruction_value_size = 32;
    st_butt_key_exp_args.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION;
    st_butt_key_exp_args.dest_key_identifier = &derived_key_id;
    st_butt_key_exp_args.output = pub_key_but_exp_out;
    st_butt_key_exp_args.output_size = 64;
    st_butt_key_exp_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    st_butt_key_exp_args.expansion_fct_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    st_butt_key_exp_args.key_group = 9;
    st_butt_key_exp_args.key_info = 0;

    ASSERT_EQUAL(hsm_standalone_butterfly_key_expansion(sg0_key_mgmt_srv, &st_butt_key_exp_args), HSM_NO_ERROR);

    // CHECK OUTPUT
    ASSERT_EQUAL(memcmp(expected_derived_pubk, pub_key_but_exp_out, pubk_size), 0);

    sig_gen_args.key_identifier = derived_key_id;
    sig_gen_args.message = sm2_butt_rec_val;
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
