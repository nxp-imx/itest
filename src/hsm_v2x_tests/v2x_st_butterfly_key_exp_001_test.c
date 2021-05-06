#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

// requirement: test vector SM2 st_butterfly_key_expansion implicit certif

int v2x_st_butterfly_key_exp_001(void)
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

    uint8_t sm2_privk[0x20] = {
        0x97, 0x59, 0xeb, 0x5a, 0x47, 0x0d, 0x09, 0x5e, 0x0e, 0xe1, 0xd0, 0xe5, 0xcc, 0x0d, 0xe3, 0xe4,
        0xc7, 0xa2, 0xf8, 0x1f, 0x6e, 0x7e, 0x74, 0xab, 0xe6, 0x23, 0xff, 0xca, 0x8b, 0xce, 0x7b, 0x20
    };
    uint8_t sm4_key [0x10] = {
        0xc2, 0x48, 0x14, 0x5f, 0x66, 0x3a, 0x4e, 0x4b, 0x8a, 0x30, 0x70, 0xc3, 0xa9, 0xd5, 0xdb, 0x50
    };
    uint8_t hash[0x20] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t sm2_exp_fct_input[0x10] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x36, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t pr_rec_value[0x20] = {
        0x2e, 0xfb, 0x7b, 0x7b, 0x52, 0x5e, 0x33, 0x7b, 0x90, 0x69, 0xd8, 0x6e, 0x30, 0xac, 0xb5, 0x3e,
        0xb0, 0xbe, 0x83, 0xb1, 0xb0, 0x1c, 0x04, 0xfe, 0x79, 0xe1, 0x18, 0x45, 0x82, 0xf1, 0xc0, 0xc4
    };
    uint8_t expected_exp_pubk[0x40] = {
        0x29, 0x43, 0x38, 0xaa, 0xa6, 0xc4, 0xc0, 0x01, 0x12, 0x6b, 0x61, 0xd0, 0x3e, 0x06, 0x37, 0xcc,
        0x4a, 0xe1, 0x20, 0xcf, 0x39, 0x0f, 0x48, 0xbb, 0x18, 0xfa, 0x74, 0x6b, 0x4e, 0x5a, 0x36, 0x49,
        0x49, 0xbb, 0x3b, 0x8a, 0x87, 0xe6, 0x50, 0x79, 0xdd, 0x37, 0xfa, 0x64, 0x85, 0x33, 0xf0, 0x8a,
        0xc6, 0xce, 0xa0, 0xbe, 0xec, 0xe2, 0xb9, 0x16, 0x08, 0xfc, 0x4b, 0x26, 0xfc, 0xc5, 0xdf, 0xe1
    };

    uint8_t pr_rec_size = 0x20;
    uint8_t hash_size = 0x20;
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
    st_butt_key_expansion.hash_value = hash;
    st_butt_key_expansion.pr_reconstruction_value = pr_rec_value;
    st_butt_key_expansion.expansion_fct_input_size = sm2_exp_fct_inpu_sizet;
    st_butt_key_expansion.hash_value_size = hash_size;
    st_butt_key_expansion.pr_reconstruction_value_size = pr_rec_size;
    st_butt_key_expansion.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF | HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE;
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
