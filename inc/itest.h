#ifndef TEST_API_H
#define TEST_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "hsm_api.h"
#include "seco_nvm.h"

/*===========Test API============*/
#define QXP 0x1
#define QM  0x2
#define DXL 0x4

#define TRUE_TEST 1
#define FALSE_TEST 0

/*======================ASSERT FAILURE ABORT======================*/
#define ASSERT_TRUE(x)  if (!x) {printf("Fail ==> #x expected True => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_FALSE(x) if (x) {printf("Fail ==> #x expected False => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_EQUAL(x, y) \
    if ( (x) != (y)) { \
        printf("assert_equal Fail ==> "); \
        printf("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y); \
        printf(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }
#define ASSERT_NOT_EQUAL(x, y) \
    if ( (x) == (y)) { \
        printf("assert_not_equal Fail ==> "); \
        printf("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y); \
        printf(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }

/*======================ASSERT FAILURE CONTINUE======================*/
#define ASSERT_TRUE_W(x)  if (!x) {printf("Fail ==> #x expected True => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_FALSE_W(x) if (x) {printf("Fail ==> #x expected False => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_EQUAL_W(x, y) \
    if ( (x) != (y)) { \
        printf("assert_equal Fail ==> "); \
        printf("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y); \
        printf(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }
#define ASSERT_NOT_EQUAL_W(x, y) \
    if ( (x) == (y)) { \
        printf("assert_not_equal Fail ==> "); \
        printf("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y); \
        printf(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }

#define ITEST_CHECK_KPI_LATENCY(got, thr) \
do { \
    printf("KPI: Max Latency [us]: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) > (thr), 0); \
} \
while(0)

#define ITEST_CHECK_KPI_OPS(got, thr) \
do { \
    printf("KPI: Operations per second: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) < (thr), 0); \
} \
while(0)

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

typedef struct {
    struct timespec ts1; // for total iterations
    struct timespec ts2; // for total iterations
    uint64_t time_us;
    uint64_t min_time_us;
    uint64_t max_time_us;
    uint32_t nb_iter;
    uint32_t op_sec;
    uint32_t t_per_op;
} timer_perf_t;

typedef struct{
    int (*tc_ptr)(void);
    char *name;
    int target;
} testsuite;

typedef struct{
    char *test_name;
    int nb_assert_fails;
    testsuite *ts;

    char *ker_dl_link;
    char *ram_dl_link;
    char *mod_dl_link;
    char *dtb_dl_link;
    char *ts_dl_link;
    char *bootimg_dl_link;
} itest_ctx_t;

/*==============NVM==============*/
hsm_err_t start_nvm_seco(void);
hsm_err_t start_nvm_v2x(void);
hsm_err_t stop_nvm_v2x(void);
uint32_t clear_v2x_nvm(void);
/*===========TEST CTX============*/
size_t save_test_ctx(void *ctx, size_t count, char *file);
size_t load_test_ctx(void *ctx, size_t count, char *file);
size_t randomize(void *out, size_t count);
/*==============PERF=============*/
void init_timer(timer_perf_t *timer);
void start_timer(timer_perf_t *timer);
void stop_timer(timer_perf_t *timer);
void finalize_timer(timer_perf_t *timer, uint32_t nb_iter);
uint64_t timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2);
void print_perf(timer_perf_t *timer);
/*===============================*/

/*==========Tests list===========*/
int v2x_chunk_swap_001(void);
int v2x_rng_srv_001(void);
int v2x_ks_import_export_001(void);
int v2x_ks_import_export_001_part2(void);
int v2x_ks_bad_auth_001(void);
int v2x_ks_no_update_001(void);
int v2x_ks_no_update_001_part2(void);
int v2x_ks_update_001(void);
int v2x_ks_update_001_part2(void);
int v2x_pub_key_recovery_001(void);
int v2x_pub_key_recovery_001_part2(void);
int v2x_cipher_aes_ecb_cbc_001(void);
int v2x_pub_key_decompression_001(void);
int v2x_auth_enc_test(void);
int v2x_butterfly_key_exp_001(void);
int v2x_parallel_sign_gen_ver_001(void);
int v2x_cipher_ccm_perf(void);
int v2x_sign_gen_verify_perf(void);
int v2x_perf_sig_ver_nistp256_ops(void);
int v2x_perf_sig_ver_nistp384_ops(void);
int v2x_perf_sig_ver_sm2_ops(void);
int v2x_perf_sig_ver_nistp256_lat(void);
int v2x_perf_sig_ver_nistp384_lat(void);
int v2x_perf_sig_ver_sm2_lat(void);
/*===============================*/

#endif

