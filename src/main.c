// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "itest.h"
#include "version.h"
#include "imx8_tests_list.h"

/* Itest ctx*/
itest_ctx_t itest_ctx;
/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

uint16_t soc;

static inline void print_version()
{
	ITEST_LOG("itest %d.%d commit: %s %s\n",
		  Itest_VERSION_MAJOR, Itest_VERSION_MINOR, GIT_SHA1, GIT_DATE);
}

static inline void print_stats()
{
	ITEST_LOG("+------------------------------------------------------\n");
	ITEST_LOG("Tests Run  : %d\n", total_run);
	ITEST_LOG("Tests Fail : %d\n", fails);
	ITEST_LOG("itest done!\n");
}
static void print_help(void) {
	ITEST_LOG("\nitest Help Menu:\n\n");
	ITEST_LOG("$ ./itest [OPTION] <argument>\n\n");
	ITEST_LOG("OPTIONS:\n");
	ITEST_LOG("  -h : Print this help\n");
	ITEST_LOG("  -v : Print test suite version\n");
	ITEST_LOG("  -l : List all tests\n");
	ITEST_LOG("  -t < test_name > : Run test test_name\n");
}

void print_test_suite(testsuite *ts){
	int i;

	for (i = 0; ts[i].tc_ptr != NULL; i++) {
		if ((ts[i].target & itest_ctx.target) == itest_ctx.target)
			ITEST_LOG("%s\n", ts[i].name);
	}
}

static void catch_failure(int signo) {
	fails++;
	ITEST_LOG("FAIL: tests interrupted by signal %d\n", signo);
	print_stats();
	sleep(2);
	exit(signo);
}

static void catch_failure_continue(int signo) {
	(void)(signo);
	itest_ctx.nb_assert_fails++;
}

static void itest_init(void) {
	open_session_args_t open_session_args = {0};
#ifdef PSA_COMPLIANT
	hsm_hdl_t hsm_session_hdl;

	open_session_args.mu_type = HSM1;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	soc = se_get_soc_id();
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);
#else
	she_hdl_t she_session_hdl;

	open_session_args.mu_type = V2X_SHE;
	ASSERT_EQUAL(she_open_session(&open_session_args, &she_session_hdl),
		     SHE_NO_ERROR);
	soc = se_get_soc_id();
	ASSERT_EQUAL(she_close_session(she_session_hdl), SHE_NO_ERROR);
#endif
	itest_ctx.test_name = NULL;
	itest_ctx.nb_assert_fails = 0;
	itest_ctx.ts = imx8_ts;
	itest_ctx.target = soc;
}

int main(int argc, char *argv[]){
        
	int i = 0;
	int status = 0, valid_usage = 0, valid_test = 0;
	int c;
	int print_ts = 0;

	itest_init();
	opterr = 0;

	if (argc < 2 || argc > 3 || strlen(argv[1]) != 2) {
		print_help();
		return 1;
	}

	while ((c = getopt(argc, argv, ":hlvt:")) != -1) {
		valid_usage = 1;
		switch (c) {
		case 't':
			itest_ctx.test_name = optarg;
			break;
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
			fprintf(stderr, "Option -%c requires an argument.\n",
				optopt);
			print_help();
			return 1;
		case '?':
			fprintf(stderr, "Unknown option character.\n");
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

	/* Print itest version at the beginning of the test */
	print_version();
	if (itest_ctx.test_name == NULL) {
		ITEST_LOG("No tests provided! Please, insert a test:\n");
		print_test_suite(itest_ctx.ts);
		return 1;
	}
	if ((signal(SIGINT, catch_failure) == SIG_ERR)
	|| (signal(SIGUSR1, catch_failure_continue) == SIG_ERR)) {
		fputs("An error occurred while setting a signal handler.\n",
		      stderr);
		return 1;
	}
	for (i = 0; itest_ctx.ts[i].tc_ptr != NULL; i++) {
		if (!strcmp(itest_ctx.ts[i].name, itest_ctx.test_name)) {
			if (!(itest_ctx.ts[i].target & itest_ctx.target)) {
				ITEST_LOG("###############################");
				ITEST_LOG("########################\n");
				ITEST_LOG("# BAD TARGET FOR TEST: %s\n",
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
			if (!status || (itest_ctx.nb_assert_fails > 0)) {
				ITEST_LOG("%s: FAIL ===> %d fails\n",
					  itest_ctx.test_name,
					  itest_ctx.nb_assert_fails);
				fails++;
			} else
				ITEST_LOG("%s: PASS\n", itest_ctx.test_name);
		}
	}

	if (!valid_test) {
		ITEST_LOG("\nProvided test not present in test suite, ",
			  itest_ctx.test_name);
		ITEST_LOG("please add from the following:\n");
		print_test_suite(itest_ctx.ts);
		return 1;
	}

	print_stats();

	return fails;
}
