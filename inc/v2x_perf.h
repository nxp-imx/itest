#ifndef __V2X_PERF_H__
#define __V2X_PERF_H__

#include <stdint.h>
#include "test_vectors/common.h"

/* KPI THREADSHOLDS */
/* Op/sec */
#define V2X_KPI_OP_SEC_SIG_VER_SM2                  (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_P256                 (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_P384                 (1100u)
#define V2X_KPI_OP_SEC_SIG_VER_BRAINPOOL_R1_256     (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_BRAINPOOL_R1_384     (1100u)
#define V2X_KPI_OP_SEC_SIG_VER_BRAINPOOL_T1_256     (2500u)
#define V2X_KPI_OP_SEC_SIG_VER_BRAINPOOL_T1_384     (1100u)

#define V2X_KPI_OP_SEC_SIG_GEN_SM2                  (200u)
#define V2X_KPI_OP_SEC_SIG_GEN_P256                 (200u)
#define V2X_KPI_OP_SEC_SIG_GEN_P384                 (80u)
#define V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_R1_256     (160u)
#define V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_R1_384     (80u)
#define V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_T1_256     (160u)
#define V2X_KPI_OP_SEC_SIG_GEN_BRAINPOOL_T1_384     (80u)

/* Latency in us */
#define V2X_KPI_LATENCY_US_SIG_VER_SM2              (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_P256             (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_P384             (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_BRAINPOOL_R1_256 (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_BRAINPOOL_R1_384 (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_BRAINPOOL_T1_256 (5000u)
#define V2X_KPI_LATENCY_US_SIG_VER_BRAINPOOL_T1_384 (5000u)

#define V2X_KPI_LATENCY_US_SIG_GEN_SM2              (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_P256             (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_P384             (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_R1_256 (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_R1_384 (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_T1_256 (5000u)
#define V2X_KPI_LATENCY_US_SIG_GEN_BRAINPOOL_T1_384 (5000u)

/* Type of perf test: Latency or Operation per second */
typedef enum {
    LAT_TEST = 0, /* Latency measure */
    OPS_TEST,     /* Operations/sec measure */
} perf_test_t;

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
    perf_test_t test_type;
} v2x_perf_sig_ver_t;

/* Test data for signature verification perf test */
typedef struct {
    uint32_t kpi_latency;
    uint32_t kpi_ops_per_sec;
    uint32_t scheme_type;
    uint32_t key_type;
    uint32_t key_size;
    uint32_t sig_size;
    uint32_t dgst_size;
    /* Pointer to the test vector */
    uint32_t tv_size;
    perf_test_t test_type;
} v2x_perf_sig_gen_t;

#endif /* __V2X_PERF_H__*/
