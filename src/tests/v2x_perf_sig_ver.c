#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "v2x_perf.h"
#include "test_vectors/tv_verify_nistp256.h"
#include "test_vectors/tv_verify_nistp384.h"

/* Number of iterations */
#define NUM_OPERATIONS  (5000u)

int v2x_perf_signature_verification(v2x_perf_sig_ver_t *td)
{
    open_session_args_t args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    op_verify_sign_args_t sig_ver_args;    
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_verification_status_t status;
    uint32_t iter = NUM_OPERATIONS;
    uint32_t idx, idx_test = 0;
    timer_perf_t t_perf;

    /* Open session on SV0*/
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode =
        HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    /* Open signature verification service */
    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess,
        &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);

    printf("\n=== Input: Message ===\n");
    memset(&sig_ver_args, 0, sizeof(sig_ver_args));
    memset(&t_perf, 0, sizeof(t_perf));

    for (idx = 0; idx < iter; idx++) {
        /* Fill struct data */
        sig_ver_args.key = td->tv[idx_test].public_key;
        sig_ver_args.message = td->tv[idx_test].message;
        sig_ver_args.signature = td->tv[idx_test].signature;
        sig_ver_args.key_size = td->key_size;
        sig_ver_args.signature_size = td->sig_size + 1; /* Add 1 byte for Ry */
        sig_ver_args.message_size = td->tv[idx_test].message_length;
        sig_ver_args.scheme_id = td->scheme_type;
        sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
        /* Start the timer */
        start_timer(&t_perf);
        /* Call sig ver API */
        ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
        /* Stop the timer */
        stop_timer(&t_perf);
        /* Check verification result */
        ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        /* Restart if end of test vector is achieved */
        if (idx_test == (td->tv_size-1))
            idx_test = 0;
        else
            idx_test++;
    }

    print_perf(&t_perf, iter);
    ASSERT_EQUAL((t_perf.max_time_us > td->kpi_latency), 0);
    ASSERT_EQUAL((t_perf.op_sec < td->kpi_ops_per_sec), 0);

    //TODO Check if we need to compute kpi with message digest
    printf("\n=== Input: Digest ===\n");
    memset(&sig_ver_args, 0, sizeof(sig_ver_args));
    memset(&t_perf, 0, sizeof(t_perf));
    idx_test = 0;

    for (idx = 0; idx < iter; idx++) {
        /* Fill struct data */
        sig_ver_args.key = td->tv[idx_test].public_key;
        sig_ver_args.message = td->tv[idx_test].digest;
        sig_ver_args.signature = td->tv[idx_test].signature;
        sig_ver_args.key_size = td->key_size;
        sig_ver_args.signature_size = td->sig_size + 1; /* Add 1 byte for Ry */
        sig_ver_args.message_size = td->dgst_size;
        sig_ver_args.scheme_id = td->scheme_type;
        sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_DIGEST;
        /* Start the timer */
        start_timer(&t_perf);
        ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
        /* Stop the timer */
        stop_timer(&t_perf);
        ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        /* Restart if end of test vector is achieved */
        if (idx_test == (td->tv_size-1))
            idx_test = 0;
        else
            idx_test++;
    }
    print_perf(&t_perf, iter);
    ASSERT_EQUAL((t_perf.max_time_us > td->kpi_latency), 0);
    ASSERT_EQUAL((t_perf.op_sec < td->kpi_ops_per_sec), 0);

    /* Close service and session */
    ASSERT_EQUAL(hsm_close_signature_verification_service(sv0_sig_ver_serv),
        HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    
    return TRUE_TEST;
}

int v2x_perf_sig_ver_nistp256()
{
    v2x_perf_sig_ver_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_VER_P256;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_VER_P256;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
    test_data.key_size = KEY_ECDSA_NIST_P256_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_NIST_P256_SIZE;
    test_data.dgst_size = DGST_NIST_P256_SIZE;
    test_data.tv = test_data_nistp256;
    test_data.tv_size = test_data_size_nistp256;

    return v2x_perf_signature_verification(&test_data);
}

int v2x_perf_sig_ver_nistp384()
{
    v2x_perf_sig_ver_t test_data;

    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_VER_P384;
    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_VER_P384;
    test_data.scheme_type = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384;
    test_data.key_size = KEY_ECDSA_NIST_P384_SIZE;
    test_data.sig_size = SIGNATURE_ECDSA_NIST_P384_SIZE;
    test_data.dgst_size = DGST_NIST_P384_SIZE;
    test_data.tv = test_data_nistp384;
    test_data.tv_size = test_data_size_nistp384;

    return v2x_perf_signature_verification(&test_data);
}

//TODO Add SM2
//int v2x_perf_sig_ver_sm2()
//{
//    v2x_perf_sig_ver_t test_data;
//
//    test_data.kpi_latency = V2X_KPI_LATENCY_US_SIG_VER_SM2;
//    test_data.kpi_ops_per_sec = V2X_KPI_OP_SEC_SIG_VER_SM2;
//    test_data.scheme_type = HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3;
//    test_data.key_size = KEY_ECDSA_SM2_SIZE;
//    test_data.sig_size = SIGNATURE_ECDSA_SM2_SIZE;
//    test_data.dgst_size = DGST_SM3_SIZE;
//    test_data.tv = test_data_sm2;
//    test_data.tv_size = test_data_size_sm2;
//
//    return v2x_perf_signature_verification(&test_data);
//}
