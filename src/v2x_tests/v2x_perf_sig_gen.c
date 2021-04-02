#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "v2x_perf.h"

/* Number of iterations */
#define NUM_OPERATIONS  (2000u)
#define MSG_SIZE        (300u)

int v2x_perf_signature_generation(v2x_perf_sig_gen_t *td)
{
    open_session_args_t args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;

    op_generate_key_args_t gen_key_args;
    op_generate_sign_args_t sig_gen_args;

    hsm_hdl_t sg0_sess, sg0_sig_gen_serv;
    hsm_hdl_t sg0_key_store_serv, sg0_key_mgmt_srv;
    uint32_t key_id = 0;
    uint8_t msg_input[2*300];
    uint8_t sign_out[1024];
    uint8_t pub_key[1024];
    uint32_t iter = NUM_OPERATIONS;
    uint32_t idx, idx_test = 0;
    timer_perf_t t_perf;

    // INPUT BUFF AS RANDOM
    ASSERT_EQUAL(randomize(msg_input, 2*MSG_SIZE), 2*MSG_SIZE);
    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);   

    /* Open session on SG0*/
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // KEY STORE SG0
    key_store_srv_args.key_store_identifier = (uint32_t) 0x12121212;
    key_store_srv_args.authentication_nonce = (uint32_t) 0x12345678;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    if (hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv) != HSM_NO_ERROR) {
        key_store_srv_args.flags = 0U;
        ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);
    }

    // KEY MGMNT SG0
    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);

    // SIGN GEN OPEN SRV
    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);
    
    // PARAM KEY_GEN strict_update
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = td->sig_size;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = td->key_type;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = pub_key;
    // GEN KEY + STORE IN NVM
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
    
    ITEST_LOG("\n=== Input: Message ===\n");
    memset(&sig_gen_args, 0, sizeof(sig_gen_args));
    memset(&t_perf, 0, sizeof(t_perf));
    init_timer(&t_perf);

    for (idx = 0; idx < iter; idx++) {
        /* Fill struct data */
        sig_gen_args.key_identifier = key_id;
        sig_gen_args.message = msg_input + idx_test;
        sig_gen_args.signature = sign_out;
        sig_gen_args.message_size = MSG_SIZE; /* Add 1 byte for Ry */
        sig_gen_args.signature_size = td->sig_size + 1;
        sig_gen_args.scheme_id = td->scheme_type;
        sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
        /* Start the timer */
        start_timer(&t_perf);
        /* Call sig ver API */
        ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);
        /* Stop the timer */
        stop_timer(&t_perf);
        /* Restart if end of test vector is achieved */
        if ((idx_test + MSG_SIZE) >= 2*MSG_SIZE)
            idx_test = 0;
        else
            idx_test++;
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    /* Check KPI are matched */
    if (td->test_type == LAT_TEST)
       ITEST_CHECK_KPI_LATENCY(t_perf.max_time_us, td->kpi_latency);
    else
       ITEST_CHECK_KPI_OPS(t_perf.op_sec, td->kpi_ops_per_sec);

    //TODO Check if we need to compute kpi with message digest
    ITEST_LOG("\n=== Input: Digest ===\n");
    memset(&sig_gen_args, 0, sizeof(sig_gen_args));
    memset(&t_perf, 0, sizeof(t_perf));
    init_timer(&t_perf);
    idx_test = 0;

    for (idx = 0; idx < iter; idx++) {
        /* Fill struct data */
        sig_gen_args.key_identifier = key_id;
        sig_gen_args.message = msg_input + idx_test;
        sig_gen_args.signature = sign_out;
        sig_gen_args.message_size = td->dgst_size;
        sig_gen_args.signature_size = td->sig_size + 1; /* Add 1 byte for Ry */
        sig_gen_args.scheme_id = td->scheme_type;
        sig_gen_args.flags = HSM_OP_PREPARE_SIGN_INPUT_DIGEST;
        /* Start the timer */
        start_timer(&t_perf);
        /* Call sig ver API */
        ASSERT_EQUAL(hsm_generate_signature(sg0_sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);
        /* Stop the timer */
        stop_timer(&t_perf);
        /* Restart if end of test vector is achieved */
        if ((idx_test + MSG_SIZE) >= 2*MSG_SIZE)
            idx_test = 0;
        else
            idx_test++;
    }
    /* Finalize time to get stats */
    finalize_timer(&t_perf, iter);
    /* Check KPI are matched for current test type */
    if (td->test_type == LAT_TEST)
       ITEST_CHECK_KPI_LATENCY(t_perf.max_time_us, td->kpi_latency);
    else
       ITEST_CHECK_KPI_OPS(t_perf.op_sec, td->kpi_ops_per_sec);

    /* Close service and session */
    ASSERT_EQUAL(hsm_close_signature_generation_service(sg0_sig_gen_serv),
        HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    
    return TRUE_TEST;
}

static int v2x_perf_sig_gen_sm2_fp_256(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_SM2;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_SM2;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3;
    test_data.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    test_data.key_size = KEY_ECDSA_SM2_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_SM2_SIZE;
    test_data.dgst_size = DGST_SM3_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_nistp256(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_P256;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_P256;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    test_data.key_size = KEY_ECDSA_NIST_P256_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_NIST_P256_SIZE;
    test_data.dgst_size = DGST_SHA_256_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_nistp384(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_P384;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_P384;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_NIST_P384;
    test_data.key_size = KEY_ECDSA_NIST_P384_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_NIST_P384_SIZE;
    test_data.dgst_size = DGST_SHA_384_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_brainpool_r1p256(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_R1_256;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_R1_256;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
    test_data.key_size = KEY_ECDSA_BRAINPOOL_R1_256_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_BRAINPOOL_R1_256_SIZE;
    test_data.dgst_size = DGST_SHA_256_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_brainpool_r1p384(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_R1_384;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_R1_384;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384;
    test_data.key_size = KEY_ECDSA_BRAINPOOL_R1_384_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_BRAINPOOL_R1_384_SIZE;
    test_data.dgst_size = DGST_SHA_384_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_brainpool_t1p256(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_T1_256;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_T1_256;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256;
    test_data.key_size = KEY_ECDSA_BRAINPOOL_T1_256_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_BRAINPOOL_T1_256_SIZE;
    test_data.dgst_size = DGST_SHA_256_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}

static int v2x_perf_sig_gen_brainpool_t1p384(perf_test_t test_type)
{
    v2x_perf_sig_gen_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_T1_384;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_T1_384;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384;
    test_data.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384;
    test_data.key_size = KEY_ECDSA_BRAINPOOL_T1_384_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_BRAINPOOL_T1_384_SIZE;
    test_data.dgst_size = DGST_SHA_384_SIZE;
    test_data.tv_size = MSG_SIZE;
    test_data.test_type = test_type;

    return v2x_perf_signature_generation(&test_data);
}


int v2x_perf_sig_gen_nistp256_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_nistp256(type_test);
}

int v2x_perf_sig_gen_nistp256_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_nistp256(type_test);
}

int v2x_perf_sig_gen_nistp384_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_nistp384(type_test);
}

int v2x_perf_sig_gen_nistp384_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_nistp384(type_test);
}

int v2x_perf_sig_gen_sm2_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_sm2_fp_256(type_test);
}

int v2x_perf_sig_gen_sm2_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_sm2_fp_256(type_test);
}

int v2x_perf_sig_gen_brainpool_r1p256_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_brainpool_r1p256(type_test);
}

int v2x_perf_sig_gen_brainpool_r1p256_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_brainpool_r1p256(type_test);
}

int v2x_perf_sig_gen_brainpool_r1p384_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_brainpool_r1p384(type_test);
}

int v2x_perf_sig_gen_brainpool_r1p384_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_brainpool_r1p384(type_test);
}

int v2x_perf_sig_gen_brainpool_t1p256_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_brainpool_t1p256(type_test);
}

int v2x_perf_sig_gen_brainpool_t1p256_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_brainpool_t1p256(type_test);
}

int v2x_perf_sig_gen_brainpool_t1p384_ops(void)
{
    perf_test_t type_test = OPS_TEST;

    return v2x_perf_sig_gen_brainpool_t1p384(type_test);
}

int v2x_perf_sig_gen_brainpool_t1p384_lat(void)
{
    perf_test_t type_test = LAT_TEST;

    return v2x_perf_sig_gen_brainpool_t1p384(type_test);
}
