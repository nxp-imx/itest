/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */

#ifndef TEST_API_H
#define TEST_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "hsm_api.h"
#include "common/global_info.h"
#include "common/perf.h"
#ifdef V2X_SHE_MU
#include "she_api.h"
#include "internal/she_key.h"
#endif

#define MU_CHANNEL_PLAT_SHE       (0x01u)

/*===========Test API============*/
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

typedef struct {
	struct timespec ts1; // for total iterations
	struct timespec ts2; // for total iterations
	double time_us;
	double min_time_us;
	double max_time_us;
	uint32_t nb_iter;
	uint32_t op_sec;
	double t_per_op;
	double fw_t;
	double lib_request_t;
	double lib_response_t;
	uint32_t session_hdl;
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

/*===========CIPHER============*/
hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier, uint8_t *input,
		 uint8_t *output, uint32_t block_size, uint8_t *iv,
		 uint16_t iv_size, hsm_op_cipher_one_go_algo_t algo,
		 hsm_op_cipher_one_go_flags_t flags, uint32_t session_hdl);
/*===========AUTH TEST============*/
hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo,
		    hsm_op_auth_enc_flags_t flags, uint32_t session_hdl);
#ifdef V2X_SHE_MU
/*===========V2X_SHE KEY UPDATE============*/
void key_update_test(she_hdl_t utils_handle);
#endif
size_t randomize(void *out, size_t count);
/*==============PERF=============*/
void init_timer(timer_perf_t *timer);
void start_timer(timer_perf_t *timer);
void stop_timer(timer_perf_t *timer);
void finalize_timer(timer_perf_t *timer, uint32_t nb_iter);
double timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2);
void print_perf(timer_perf_t *timer, uint32_t nb_iter);

#endif
