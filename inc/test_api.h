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
#define ASSERT_TRUE(x)  if (!x) {printf("Fail ==> #x expected True => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGINT);}
#define ASSERT_FALSE(x) if (x) {printf("Fail ==> #x expected False => " );printf(#x);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGINT);}
#define ASSERT_EQUAL(x, y) if ( x != y) {printf("assert_equal Fail ==> ");printf(#x);printf(" != ");printf(#y);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGINT);}
#define ASSERT_NOT_EQUAL(x, y) if ( x == y) {printf("assert_not_equal Fail ==> ");printf(#x);printf(" == ");printf(#y);printf(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGINT);}

typedef struct {
    struct timespec ts1; // for total iterations
    struct timespec ts2; // for total iterations
    struct timespec ts_last; // for latency
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
    int cur_test;
    int nb_fails;
} contex;

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
void start_timer(timer_perf_t *timer);
void timer_latency_start(timer_perf_t *timer);
void timer_latency_stop(timer_perf_t *timer);
void stop_timer(timer_perf_t *timer, uint32_t nb_iter);
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
/*===============================*/

#endif

