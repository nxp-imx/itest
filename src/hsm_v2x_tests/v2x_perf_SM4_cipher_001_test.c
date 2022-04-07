#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: sm4 cipher perf test

int v2x_perf_sm4_cipher_001(void){

    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    op_generate_key_args_t gen_key_args;
    op_cipher_one_go_args_t cipher_args;
    op_auth_enc_args_t auth_enc_args;
    
    hsm_hdl_t sg0_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    hsm_hdl_t sg0_cipher_hdl;
    uint32_t key_id_sm4 = 0;
    uint8_t buff_encr[1024];
    uint8_t buff_decr[1024];
    uint8_t msg[1024];
    uint8_t iv[16];
    uint8_t aad[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    uint32_t msg_size, iter, i;
    uint32_t msg_size_lst[] = {16, 304, 608};
    uint32_t ccm_perf[] = {4500U, 1400U, 800U};
    uint32_t cbc_perf[] = {7500U, 2600U, 1550U};
    uint32_t ecb_perf[] = {8750U, 3050U, 1750U};
    timer_perf_t t_perf;

    clear_v2x_nvm();

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg, 128), 128);
    ASSERT_EQUAL(randomize(iv, 16), 16);

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // SG0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);
    
    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0xbad4c0c0;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x0badc0de;
    key_store_srv_args.max_updates_number = 31;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    //OPEN CIPHER SG0
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id_sm4;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;

    // GEN KEY AES_128
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    for (i = 0; i < 3; i++) {
        msg_size = msg_size_lst[i];
        ITEST_LOG("msg size = %d\n", msg_size);
        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            /*========================================================*/
            // CIPHER ONE GO SM4 ECB -> ENCRYPT
            cipher_args.key_identifier = key_id_sm4;
            cipher_args.iv = NULL;
            cipher_args.iv_size = 0;
            cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
            cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
            cipher_args.input = msg;
            cipher_args.output = buff_encr;
            cipher_args.input_size = msg_size;
            cipher_args.output_size = msg_size;
            /* Start the timer */
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 ECB ENCRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, ecb_perf[i]);

        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            // CIPHER ONE GO SM4 ECB -> DECRYPT
            cipher_args.key_identifier = key_id_sm4;
            cipher_args.iv = NULL;
            cipher_args.iv_size = 0;
            cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
            cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
            cipher_args.input = buff_encr;
            cipher_args.output = buff_decr;
            cipher_args.input_size = msg_size;
            cipher_args.output_size = msg_size;
            /* Start the timer */
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 ECB DECRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, ecb_perf[i]);

        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            // CIPHER ONE GO SM4 CBC -> ENCRYPT
            cipher_args.key_identifier = key_id_sm4;
            cipher_args.iv = iv;
            cipher_args.iv_size = 16;
            cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
            cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
            cipher_args.input = msg;
            cipher_args.output = buff_encr;
            cipher_args.input_size = msg_size;
            cipher_args.output_size = msg_size;
            /* Start the timer */
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 CBC ENCRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, cbc_perf[i]);

        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            // CIPHER ONE GO SM4 CBC -> DECRYPT
            cipher_args.key_identifier = key_id_sm4;
            cipher_args.iv = iv;
            cipher_args.iv_size = 16;
            cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_CBC;
            cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
            cipher_args.input = buff_encr;
            cipher_args.output = buff_decr;
            cipher_args.input_size = msg_size;
            cipher_args.output_size = msg_size;
            /* Start the timer */
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 CBC DECRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, cbc_perf[i]);

        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            // AUTH ENC KEY SM4 CCM -> ENCRYPT
            auth_enc_args.key_identifier = key_id_sm4;
            auth_enc_args.iv = iv;
            auth_enc_args.iv_size = 4U;
            auth_enc_args.aad = aad;
            auth_enc_args.aad_size = 16U;
            auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
            auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
            auth_enc_args.input = msg;
            auth_enc_args.output = buff_encr;
            auth_enc_args.input_size = msg_size;
            auth_enc_args.output_size = msg_size + 16U + 12U;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 CCM ENCRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, ccm_perf[i]);

        memset(&t_perf, 0, sizeof(t_perf));
        for (iter = 0; iter < 10000; iter++) {
            // AUTH ENC KEY SM4 CCM -> DECRYPT
            auth_enc_args.key_identifier = key_id_sm4;
            auth_enc_args.iv = buff_encr + msg_size + 16U;
            auth_enc_args.iv_size = 12U;
            auth_enc_args.aad = aad;
            auth_enc_args.aad_size = 16U;
            auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
            auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
            auth_enc_args.input = buff_encr;
            auth_enc_args.output = buff_decr;
            auth_enc_args.input_size = msg_size + 16U;
            auth_enc_args.output_size = msg_size;
            start_timer(&t_perf);
            ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args), HSM_NO_ERROR);
            /* Stop the timer */
            stop_timer(&t_perf);
        }
        ITEST_LOG("SM4 CCM DECRYPT PERF ");
        /* Finalize time to get stats */
        finalize_timer(&t_perf, iter);
        ITEST_CHECK_KPI_OPS(t_perf.op_sec, ccm_perf[i]);
    }
    ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);

    return TRUE_TEST;
}
