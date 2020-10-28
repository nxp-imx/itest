#include <stdio.h>
#include <stdlib.h>
#include "test_api.h"
#include "test_vectors/tv_verify_nistp256.h"
#include "test_vectors/tv_verify_nistp384.h"

/* Number of iterations */
#define NUM_OPERATIONS  (5000u)

//TODO To be moved in v2x_perf.h

/* KPI THREADSHOLDS */
/* Op/sec */
#define V2X_KPI_OP_SEC_SIG_VER_SM2          (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_P256         (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_P384         (1100u)
/* Latency in us */
#define V2X_KPI_LATENCY_US_SIG_VER_SM2      (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_P256     (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_P384     (5000u)

/* Test data for signature verification perf test */
typedef struct {
    uint32_t kpi_latency;
    uint32_t kpi_ops_per_sec;
    uint32_t scheme_type;
    uint32_t key_size;
    uint32_t sig_size;
    uint32_t dgst_size;
    /* Pointer to the test vector */
    test_data_verify_t *tv;
    uint32_t tv_size;
} v2x_perf_sig_ver_t;


//TODO To be moved in test_api.h
/* Key sizes */
#define KEY_ECDSA_SM2_SIZE              (0x40u)
#define KEY_ECDSA_NIST_P256_SIZE        (0x40u)
#define KEY_ECDSA_NIST_P384_SIZE        (0x60u)
/* Signature sizes */
#define SIGNATURE_ECDSA_SM2_SIZE        (0x40u)
#define SIGNATURE_ECDSA_NIST_P256_SIZE  (0x40u)
#define SIGNATURE_ECDSA_NIST_P384_SIZE  (0x60u)
/* Digest sizes */
#define DGST_SM3_SIZE        (0x20u)
#define DGST_NIST_P256_SIZE  (0x20u)
#define DGST_NIST_P384_SIZE  (0x30u)

int v2x_perf_signature_verification(v2x_perf_sig_ver_t *td)
{
    open_session_args_t args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    op_verify_sign_args_t sig_ver_args;    
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_verification_status_t status;
    uint32_t iter = NUM_OPERATIONS;
    uint32_t idx, idx_test = 0;
    uint32_t operations;
    struct timespec ts1, ts2;
    uint64_t total_time = 0;
    uint64_t max_latency = 0, temp_latency = 0;

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
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
        ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
        /* End the timer */
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
        /* Compute the latency of a single operation */
        CALCULATE_TIME_DIFF_NS(ts1, ts2, temp_latency);
        /* Update max latency if greater */
        if (temp_latency > max_latency)
            max_latency = temp_latency;
        ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        /* Add the latency to the total */
        total_time += temp_latency;
        /* Restart if end of test vector is achieved */
        if (idx_test == (td->tv_size-1))
            idx_test = 0;
        else
            idx_test++;
    }

    printf("MAX LATENCY = %ld us\n", max_latency/1000);
    ASSERT_EQUAL((max_latency/1000) > (td->kpi_latency), 0);
    operations = (uint32_t)((uint64_t)1000000000*((uint64_t)iter)/total_time);
    printf("SIG VER = %d op/sec\n", operations);
    ASSERT_EQUAL((operations) < (td->kpi_ops_per_sec), 0);

    //TODO Check if we need to compute kpi with message digest
    printf("\n=== Input: Digest ===\n");
    memset(&sig_ver_args, 0, sizeof(sig_ver_args));
    idx_test = 0;
    max_latency = 0;
    total_time = 0;

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
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
        ASSERT_EQUAL(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
        /* End the timer */
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
        /* Compute the latency of a single operation */
        CALCULATE_TIME_DIFF_NS(ts1, ts2, temp_latency);
        /* Update max latency if greater */
        if (temp_latency > max_latency)
            max_latency = temp_latency;
        ASSERT_EQUAL(status, HSM_VERIFICATION_STATUS_SUCCESS);
        /* Add the latency to the total */
        total_time += temp_latency;
        /* Restart if end of test vector is achieved */
        if (idx_test == (td->tv_size-1))
            idx_test = 0;
        else
            idx_test++;
    }
    printf("MAX LATENCY = %ld us\n", max_latency/1000);
    ASSERT_EQUAL((max_latency/1000) > (td->kpi_latency), 0);
    operations = (uint32_t)((uint64_t)1000000000*((uint64_t)iter)/total_time);
    printf("SIG VER = %d op/sec\n", operations);
    ASSERT_EQUAL((operations) < (td->kpi_ops_per_sec), 0);

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
