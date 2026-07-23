/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2026 NXP
 */

#ifndef TEST_API_H
#define TEST_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#ifndef ENABLED_PRIME
#include "common/global_info.h"
#include "common/perf.h"
#endif
#define NUM_SOCS 20
#define MAX_SOC_VAL 10
#define SOC_IMX941  0x9410
#define SOC_IMX942  0x9420
#define SOC_IMX943  0x9430
#define SOC_IMX952  0x9520

#define TRUE_TEST 0
#define FALSE_TEST -1

/* Log macros and functions */
void outputLog(const char *const format, ...);

extern uint16_t soc, soc_rev;
extern uint8_t board_type;

#define ITEST_LOG(...)  outputLog(__VA_ARGS__)

typedef struct {
	struct timespec ts1; // for total iterations
	struct timespec ts2; // for total iterations
	double time_us;
	double min_time_us;
	double max_time_us;
	uint64_t nb_iter;
	uint64_t op_sec;
	double t_per_op;
	double fw_t;
	double lib_request_t;
	double lib_response_t;
	uint32_t session_hdl;
} timer_perf_t;

typedef struct{
	uint16_t soc;
	uint16_t soc_rev;
	uint8_t board_type;
} board_info;

typedef struct{
	int (*tc_ptr)(void);
	char *name;
	board_info board[NUM_SOCS];
} testsuite;

typedef struct{
	char *test_name;
	int nb_assert_fails;
	testsuite *ts;
	uint16_t soc;
	uint16_t soc_rev;
	uint8_t board_type;
#ifdef ENABLED_PRIME
	uint16_t burst_size;
	uint32_t iterations;
#endif
} itest_ctx_t;

extern itest_ctx_t itest_ctx;

uint16_t get_soc(void);
void print_help(void);

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
#endif
