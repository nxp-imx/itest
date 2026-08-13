// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "itest.h"
#include "version.h"
#include "imx8_tests_list.h"
#ifdef V2X_SHE_MU
#include "she/she_functions.h"
#elif !defined(ENABLED_PRIME)
#include "hsm/hsm_functions.h"
#else
#include "prime/prime_functions.h"
#endif

uint16_t soc, soc_rev;
uint8_t board_type;

/* Itest ctx*/
itest_ctx_t itest_ctx = {0};
/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

static inline void print_version(void)
{
	ITEST_LOG("itest %d.%d commit: %s %s\n",
		  Itest_VERSION_MAJOR, Itest_VERSION_MINOR, GIT_SHA1, GIT_DATE);
}

static inline void print_stats(void)
{
	ITEST_LOG("+------------------------------------------------------\n");
	ITEST_LOG("Tests Run  : %d\n", total_run);
	ITEST_LOG("Tests Fail : %d\n", fails);
	ITEST_LOG("itest done!\n");
}

void print_test_suite(testsuite *ts)
{
	int i = 0, j = 0;
	for (i = 0; ts[i].tc_ptr != NULL; i++) {
		for (j = 0; ts[i].board[j].soc != 0; j++) {
			if (ts[i].board[j].soc == itest_ctx.soc &&
			    ts[i].board[j].board_type == itest_ctx.board_type &&
			    ts[i].board[j].soc_rev == itest_ctx.soc_rev) {
				ITEST_LOG("%s\n", ts[i].name);
				break;
			}
		}
	}
}

static _Noreturn void catch_failure(int signo) {
#ifdef V2X_SHE_MU
	if (key_store_hdl)
		she_close_key_store_service(key_store_hdl);

	she_close_session(she_session_hdl);
#elif defined(ENABLED_PRIME)
	if (serv_hdl)
		prime_close_service(serv_hdl);
#else
	if (key_store_hdl)
		hsm_close_key_store_service(key_store_hdl);

	hsm_close_session(hsm_session_hdl);

	/* close the second session hdl if opened */
	if (hsm_session_hdl2) {
		hsm_close_session(hsm_session_hdl2);
	}
#endif
	_exit(signo);
}

static void catch_failure_continue(int signo) {
	(void)(signo);
}

static int itest_init(void)
{
	soc = get_soc();
	itest_ctx.test_name = NULL;
	itest_ctx.nb_assert_fails = 0;
	itest_ctx.ts = imx8_ts;
	itest_ctx.soc = soc;
	itest_ctx.soc_rev = soc_rev;
	itest_ctx.board_type = board_type;

	return 0;
}

int main(int argc, char *argv[]){
	int i = 0, j = 0;
	int status = 0, valid_usage = 0, valid_test = 0, valid_board = 0;
	int c = 0;
	int print_ts = 0, ret = 0;

	/* Print itest version at the beginning of the test */
	print_version();

	ret = itest_init();
	if (ret) {
		ITEST_LOG("itest init failed\n");
		return 1;
	}

	opterr = 0;

#ifdef ENABLED_PRIME
	if (argc < 2 || argc > 7 || strlen(argv[1]) != 2 ||
	   (argc > 3 && strlen(argv[3]) != 2) ||
	   (argc > 5 && strlen(argv[5]) != 2)) {
#else
	if (argc < 2 || argc > 3 || strlen(argv[1]) != 2) {
#endif
		print_help();
		return 1;
	}


#ifdef ENABLED_PRIME
	while ((c = getopt(argc, argv, ":hlvt:b:i:")) != -1) {
		int16_t burst_sz;
		int32_t iterations;
#else
	while ((c = getopt(argc, argv, ":hlvt:")) != -1) {
#endif
		valid_usage = 1;
		switch (c) {
		case 't':
			itest_ctx.test_name = optarg;
			break;
#ifdef ENABLED_PRIME
		case 'b':
			burst_sz = atoi(optarg);
			if (!itest_ctx.test_name || burst_sz <= 0 ||
			    burst_sz > BURST_SZ) {
				print_help();
				return 1;
			}
			itest_ctx.burst_size = burst_sz;
			break;
		case 'i':
			iterations = atoi(optarg);
			if (!itest_ctx.test_name || iterations <= 0 ||
			    iterations > NUM_OPERATIONS) {
				print_help();
				return 1;
			}
			itest_ctx.iterations = iterations;
			break;
#endif
		case 'v':
			if (argc > 2) {
				print_help();
				return 1;
			}
			print_version();
			return 0;
		case 'l':
			if (argc > 2) {
				print_help();
				return 1;
			}
			print_ts = 1;
			break;
		case 'h':
			print_help();
			if (argc > 2)
				return 1;
			return 0;
		case ':':
			ITEST_LOG("Option -%c requires an argument.\n", optopt);
			print_help();
			return 1;
		case '?':
			ITEST_LOG("Unknown option character.\n");
			print_help();
			return 1;
		default:
			abort();
		}
	}

	if (valid_usage == 0) {
		print_help();
		return 1;
	}

	if (print_ts == 1) {
		print_test_suite(itest_ctx.ts);
		return 0;
	}

	if (itest_ctx.test_name == NULL) {
		ITEST_LOG("No tests provided! Please, insert a test:\n");
		print_test_suite(itest_ctx.ts);
		return 1;
	}
	if ((signal(SIGINT, catch_failure) == SIG_ERR)
	|| (signal(SIGUSR1, catch_failure_continue) == SIG_ERR)) {
		ITEST_LOG("An error occurred while setting a signal handler.\n");
		return 1;
	}
	for (i = 0; itest_ctx.ts[i].tc_ptr != NULL; i++) {
		if (!strcmp(itest_ctx.ts[i].name, itest_ctx.test_name)) {
			for (j = 0; itest_ctx.ts[i].board[j].soc != 0; j++) {
				if (itest_ctx.ts[i].board[j].soc == itest_ctx.soc &&
				    itest_ctx.ts[i].board[j].board_type == itest_ctx.board_type &&
				     itest_ctx.ts[i].board[j].soc_rev == itest_ctx.soc_rev) {
					valid_board = 1;
					break;
				}
			}

			if (!valid_board) {
				ITEST_LOG("###############################");
				ITEST_LOG("########################\n");
				ITEST_LOG("# BOARD NOT SUPPORTED FOR THE TEST: %s\n",
					  itest_ctx.ts[i].name);
				ITEST_LOG("###############################");
				ITEST_LOG("########################\n");
				fails++;
				break;
			}
			valid_test = 1;
			ITEST_LOG("#######################################");
			ITEST_LOG("################\n");
			ITEST_LOG("# Running test: %s\n", itest_ctx.ts[i].name);
			ITEST_LOG("########################################");
			ITEST_LOG("###############\n");
			total_run++;
			status = itest_ctx.ts[i].tc_ptr();
			ITEST_LOG("#######################################");
			ITEST_LOG("################\n");
			if (status || (itest_ctx.nb_assert_fails > 0)) {
				ITEST_LOG("%s: FAIL\n",
					  itest_ctx.test_name);
				fails++;
			} else
				ITEST_LOG("%s: PASS\n", itest_ctx.test_name);
		}
	}

	if (!valid_test) {
		ITEST_LOG("\nProvided test not present in test suite, ");
		ITEST_LOG("please add from the following:\n");
		print_test_suite(itest_ctx.ts);
		return 1;
	}

	print_stats();

	return fails;
}
