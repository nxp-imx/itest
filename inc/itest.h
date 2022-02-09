#ifndef TEST_API_H
#define TEST_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "hsm_api.h"
#include "she_api.h"
#include "../src/seco_os_abs.h"
#include "seco_nvm.h"

/*===========Test API============*/
#define QXP_C0 0x1
#define QXP_B0 0x2
#define DXL_A1 0x4
#define DXL_B0 0x8
#define DBG    0x10
#define FIPS   0x80

#define TRUE_TEST 1
#define FALSE_TEST 0

/* Log macros and functions */
void outputLog(const char *const format, ...);

#define ITEST_LOG(...)  outputLog(__VA_ARGS__)

/*======================ASSERT FAILURE ABORT======================*/
#define ASSERT_TRUE(x)  if (!x) {ITEST_LOG("Fail ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_FALSE(x) if (x) {ITEST_LOG("Fail ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_EQUAL(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }
#define ASSERT_NOT_EQUAL(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }

#define ASSERT_TRUE_HIGH_API(x)  if (!x) {ITEST_LOG("Fail in subsequence ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);break;}
#define ASSERT_FALSE_HIGH_API(x) if (x) {ITEST_LOG("Fail in subsequence ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);break;}

#define ASSERT_EQUAL_HIGH_API(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail in subsequence ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        break; \
    }
#define ASSERT_NOT_HIGH_API(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail in subsequence ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        break; \
    }


/*======================ASSERT FAILURE CONTINUE======================*/
#define ASSERT_TRUE_W(x)  if (!x) {ITEST_LOG("Fail ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_FALSE_W(x) if (x) {ITEST_LOG("Fail ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_EQUAL_W(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }
#define ASSERT_NOT_EQUAL_W(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }

#define ITEST_CHECK_KPI_LATENCY(got, thr) \
do { \
    ITEST_LOG("KPI: Max Latency [us]: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) > (thr), 0); \
} \
while(0)

#define ITEST_CHECK_KPI_OPS(got, thr) \
do { \
    ITEST_LOG("KPI: Operations per second: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) < (thr), 0); \
} \
while(0)

/* Key sizes */
#define KEY_ECDSA_SM2_SIZE                    (0x40u)
#define KEY_ECDSA_NIST_P256_SIZE              (0x40u)
#define KEY_ECDSA_NIST_P384_SIZE              (0x60u)
#define KEY_ECDSA_BRAINPOOL_R1_256_SIZE       (0x40u)
#define KEY_ECDSA_BRAINPOOL_R1_384_SIZE       (0x60u)
#define KEY_ECDSA_BRAINPOOL_T1_256_SIZE       (0x40u)
#define KEY_ECDSA_BRAINPOOL_T1_384_SIZE       (0x60u)
/* Signature sizes */
#define SIGNATURE_ECDSA_SM2_SIZE              (0x40u)
#define SIGNATURE_ECDSA_NIST_P256_SIZE        (0x40u)
#define SIGNATURE_ECDSA_NIST_P384_SIZE        (0x60u)
#define SIGNATURE_ECDSA_BRAINPOOL_R1_256_SIZE (0x40u)
#define SIGNATURE_ECDSA_BRAINPOOL_R1_384_SIZE (0x60u)
#define SIGNATURE_ECDSA_BRAINPOOL_T1_256_SIZE (0x40u)
#define SIGNATURE_ECDSA_BRAINPOOL_T1_384_SIZE (0x60u)
/* Digest sizes */
#define DGST_SM3_SIZE        (0x20u)
#define DGST_NIST_P256_SIZE  (0x20u)
#define DGST_NIST_P384_SIZE  (0x30u)
#define DGST_SHA_256_SIZE    (0x20u)
#define DGST_SHA_384_SIZE    (0x30u)

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
    int target;
} itest_ctx_t;

/*==============NVM==============*/
hsm_err_t start_nvm_seco(void);
hsm_err_t start_nvm_v2x(void);
hsm_err_t start_nvm_she_seco(void);
hsm_err_t stop_nvm_v2x(void);
hsm_err_t stop_nvm_seco(void);
hsm_err_t stop_nvm_she_seco(void);
uint32_t clear_v2x_nvm(void);
uint32_t clear_seco_nvm(void);
uint32_t clear_she_seco_nvm(void);
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
/*==========LOW LEVEL API========*/
uint32_t send_signed_msg(char *path);
uint32_t send_msg(uint32_t *msg, uint32_t size, uint32_t mu_id, uint8_t nmi);
uint32_t rcv_msg(uint32_t *msg, uint32_t size, uint32_t mu_id);
uint32_t send_rcv_msg(uint32_t *msg_in, uint32_t *msg_out, uint32_t size_in, uint32_t size_out, uint32_t mu_id, uint8_t nmi);
/*==========HIGH LEVEL SENTINEL API*/
int get_key_param(hsm_key_type_t key_type,hsm_signature_scheme_id_t *scheme_id, uint16_t *size_pubk, uint16_t *size_privk);
int isen_kek_generation(hsm_hdl_t sg0_key_mgmt_srv, uint8_t *kek_data, uint32_t key_size, uint32_t *kek_handle);
int isen_hsm_key_injection_custom(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type,
                           uint8_t *key_in, uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size,
                           uint16_t key_group, hsm_key_info_t key_info, hsm_op_key_gen_flags_t flags);
int isen_hsm_key_injection(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in,
                        uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size);

#endif
