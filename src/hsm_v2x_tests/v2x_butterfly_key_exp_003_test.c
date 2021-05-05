#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

// requirement: test vector SM2 butterfly_key_expansion explicit certif

int v2x_butterfly_key_exp_003(void)
{

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    op_pub_key_recovery_args_t pub_k_rec_args;

    op_butt_key_exp_args_t but_key_exp_args;
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id;
    uint32_t dest_key_id;
    hsm_key_type_t key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    uint8_t pub_key_but_exp_out[0x40];

    uint8_t sm2_privk[32] = {
        0x25, 0xd7, 0xd2, 0xe8, 0x01, 0x1e, 0x26, 0x8e, 0x71, 0x04, 0x12, 0x94, 0xbc, 0x45, 0x6b, 0x51,
        0x92, 0xd1, 0x16, 0xfc, 0x90, 0x3a, 0xef, 0xed, 0xd1, 0x84, 0x19, 0x2b, 0x0d, 0xd5, 0xfb, 0x84
    };
    uint8_t exp_f_value[0x20] = {
        0xe2, 0xee, 0xbe, 0x0a, 0x3c, 0xed, 0xf3, 0x43, 0xca, 0x7c, 0xa4, 0x07, 0x74, 0xd9, 0x77, 0x93,
        0x6d, 0xc3, 0xe2, 0x7d, 0xe6, 0x14, 0x1e, 0x25, 0x69, 0x53, 0x2a, 0x5d, 0x7c, 0xcc, 0x7e, 0x34
    };
    uint8_t expected_exp_pubk[0x40] = {
        0xb7, 0x4f, 0x86, 0xd2, 0x1b, 0x91, 0xb9, 0x88, 0xb9, 0x77, 0x8d, 0x84, 0x03, 0x22, 0x21, 0x14,
        0x77, 0x53, 0x9a, 0x42, 0x45, 0x7c, 0xf5, 0x3f, 0x2f, 0x58, 0x9e, 0x54, 0x06, 0xe4, 0x6a, 0xe7,
        0xa9, 0xb8, 0xe1, 0x83, 0x8d, 0x9f, 0xbf, 0xa6, 0xee, 0x81, 0x50, 0x2a, 0x03, 0xa3, 0xb1, 0xe0,
        0x51, 0x03, 0x4d, 0x5e, 0x7c, 0x10, 0x3a, 0xcd, 0x44, 0x91, 0x59, 0xe9, 0xda, 0x80, 0x55, 0x35
    };

    uint8_t pr_rec_size = 0x0;
    uint8_t hash_size = 0x0;
    uint8_t exp_f_size = 0x20;
    uint8_t pubk_size = 0x40;

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

    // =========== INJECT KEYS ================= //
    ASSERT_EQUAL(isen_hsm_key_injection_custom(sg0_key_mgmt_srv, &key_id, key_type, sm2_privk, kek_handle, kek_data, 32, 1U,
                                               HSM_KEY_INFO_MASTER, HSM_OP_KEY_GENERATION_FLAGS_CREATE), TRUE_TEST);

    // BUTTERFLY KEY EXPANSION
    but_key_exp_args.key_identifier = key_id;
    but_key_exp_args.expansion_function_value = exp_f_value;
    but_key_exp_args.hash_value = NULL;
    but_key_exp_args.pr_reconstruction_value = NULL;
    but_key_exp_args.expansion_function_value_size = exp_f_size;
    but_key_exp_args.hash_value_size = hash_size;
    but_key_exp_args.pr_reconstruction_value_size = pr_rec_size;
    but_key_exp_args.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF | HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE;
    but_key_exp_args.dest_key_identifier = &dest_key_id;
    but_key_exp_args.output = pub_key_but_exp_out;
    but_key_exp_args.output_size = pubk_size;
    but_key_exp_args.key_type = key_type;
    but_key_exp_args.key_group = 1;
    but_key_exp_args.key_info = 0U;
    ASSERT_EQUAL(hsm_butterfly_key_expansion(sg0_key_mgmt_srv, &but_key_exp_args), HSM_NO_ERROR);

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
