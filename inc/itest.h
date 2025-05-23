/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2025 NXP
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
#define NUM_SOCS 10

#define TRUE_TEST 0
#define FALSE_TEST -1

/* Log macros and functions */
void outputLog(const char *const format, ...);

extern uint16_t soc;

#ifdef V2X_SHE_MU
extern she_hdl_t she_session_hdl, key_store_hdl;
#else
extern hsm_hdl_t hsm_session_hdl, hsm_session_hdl2, key_store_hdl;
#endif

#define ITEST_LOG(...)  outputLog(__VA_ARGS__)

/*======================ASSERT FAILURE ABORT======================*/
#define ASSERT_EQUAL(x, y) \
    if ( (x) != (y)) { \
	ITEST_LOG(" @%s line:%d\n", __FILE__, __LINE__); \
	return -1; \
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
	int supported_board;
	int board[NUM_SOCS];
} testsuite;

typedef struct{
	char *test_name;
	int nb_assert_fails;
	testsuite *ts;
	int board;
} itest_ctx_t;

/*========OPEN KEY STORE========*/
hsm_err_t hsm_open_key_store(hsm_hdl_t hsm_session_hdl,
			     hsm_hdl_t *key_store_hdl);
/*=====GENERATE KEY REQUEST======*/
hsm_err_t hsm_generate_key_request(hsm_hdl_t key_mgmt_hdl, uint32_t *key_id,
				   uint16_t out_size, hsm_key_group_t key_group,
				   hsm_key_type_t key_type, hsm_op_key_gen_flags_t flags,
#ifdef PSA_COMPLIANT
				   hsm_key_lifetime_t key_lifetime,
				   hsm_key_usage_t key_usage,
				   hsm_permitted_algo_t permitted_algo,
				   hsm_bit_key_sz_t bit_key_sz,
				   hsm_key_lifecycle_t key_lifecycle,
#else
				   hsm_key_info_t key_info,
#endif
				   uint8_t *out_key);
/*=====GENERATE KEY PERF======*/
hsm_err_t hsm_generate_key_perf(hsm_hdl_t key_mgmt_hdl, uint32_t key_id,
				uint16_t out_size, hsm_key_group_t key_group,
				hsm_key_type_t key_type, uint8_t *out_key,
#ifdef PSA_COMPLIANT
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
				hsm_bit_key_sz_t bit_key_sz,
				hsm_key_lifecycle_t key_lifecycle,
#else
				hsm_key_info_t key_info,
#endif
				timer_perf_t *t_perf);
/*===========CIPHER============*/
hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		      uint8_t *input, uint8_t *output, uint32_t block_size,
		      uint8_t *iv, uint16_t iv_size,
		      hsm_op_cipher_one_go_algo_t algo,
		      hsm_op_cipher_one_go_flags_t flags, uint32_t session_hdl);
/*===========AUTH TEST============*/
hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo,
		    hsm_op_auth_enc_flags_t flags, uint32_t session_hdl);
hsm_err_t auth_random_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
			   uint8_t *input, uint32_t input_size,
			   uint8_t *output, uint32_t output_size, uint8_t *iv,
			   uint16_t iv_size, uint8_t *aad, uint16_t aad_size,
			   hsm_op_auth_enc_algo_t algo,
			   hsm_op_auth_enc_flags_t flags);
/*===========CMAC============*/
hsm_err_t cmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    hsm_op_mac_one_go_algo_t algo, uint8_t *payload,
		    uint32_t payload_size, uint8_t *mac,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl);
/*===========HMAC============*/
hsm_err_t hmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    uint8_t *payload, uint32_t payload_size,
		    uint8_t *mac, uint32_t mac_size,
		    hsm_op_mac_one_go_algo_t algorithm,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl);
#ifdef V2X_SHE_MU
/*===========V2X_SHE KEY UPDATE============*/
she_err_t key_update_test(she_hdl_t utils_handle);
she_err_t she_cmac_test(she_hdl_t mac_hdl, uint32_t key_identifier,
			uint8_t *payload, uint16_t payload_size,
			uint8_t *mac, hsm_op_mac_flags_t flags,
			uint32_t session_hdl);
#endif
/*===========ASN1 DER to RAW ENCODING======*/
void parse_der_to_raw(uint8_t *sign, int len_component_der,
		      int len_component_raw, int raw_component_start_index,
		      int len_component_index);
void decode_signature(int pub_key_len, uint8_t *sign);
size_t randomize(void *out, size_t count);
/*==============PERF=============*/
void init_timer(timer_perf_t *timer);
void start_timer(timer_perf_t *timer);
void stop_timer(timer_perf_t *timer);
void finalize_timer(timer_perf_t *timer, uint32_t nb_iter);
double timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2);
void print_perf(timer_perf_t *timer, uint32_t nb_iter);
void finalize_timer_rsa(timer_perf_t *timer, uint32_t nb_iter);
void print_perf_rsa(timer_perf_t *timer, uint32_t nb_iter);
#endif
