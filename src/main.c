// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "itest.h"
#include "version.h"
#include "imx8_tests_list.h"

uint16_t soc;
#define MAX_SOC_VAL 10

#ifdef V2X_SHE_MU
she_hdl_t she_session_hdl, key_store_hdl;
#else
hsm_hdl_t hsm_session_hdl, hsm_session_hdl2, key_store_hdl;
#endif

/* Itest ctx*/
itest_ctx_t itest_ctx = {0};
/* Used to store total test run and test failures */
static int total_run = 0, fails = 0;

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

void print_test_suite(testsuite *ts)
{
	int i = 0, j = 0;
	for (i = 0; ts[i].tc_ptr != NULL; i++) {
		for (j = 0; j < ts[i].supported_board; j++) {
			if (ts[i].board[j] == itest_ctx.board)
				ITEST_LOG("%s\n", ts[i].name);
		}
	}
}

static void catch_failure(int signo) {
	int err = 0;
	fails++;
	ITEST_LOG("FAIL: tests interrupted by signal %d\n", signo);
#ifdef V2X_SHE_MU
	if (key_store_hdl)
		err = she_close_key_store_service(key_store_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_close_key_store_service failed err:0x%x\n", err);
		return;
	}

	err = she_close_session(she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_close_session failed err:0x%x\n", err);
		return;
	}
#else
	if (key_store_hdl)
		err = hsm_close_key_store_service(key_store_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_key_store_service failed err:0x%x\n", err);
		return;
	}

	err = hsm_close_session(hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_session failed err:0x%x\n", err);
		return;
	}

	/* close the second session hdl if opened */
	if (hsm_session_hdl2) {
		hsm_close_session(hsm_session_hdl2);
		if (err != HSM_NO_ERROR)
			printf("hsm_close_session failed for hdl2 err:0x%x\n",
					err);
	}
#endif
	print_stats();
	exit(signo);
}

static void catch_failure_continue(int signo) {
	(void)(signo);
	itest_ctx.nb_assert_fails++;
}

static int itest_init(void)
{
	open_session_args_t open_session_args = {0};
	char soc_val[MAX_SOC_VAL];
	int err = 0;

	FILE *file = fopen("/sys/devices/soc0/soc_id", "r");

	if (file == NULL) {
		perror("Error opening the /sys/devices/soc0/soc_id file");
		return -1;
	}

	if (fgets(soc_val, MAX_SOC_VAL, file) == NULL) {
		perror("Error reading the /sys/devices/soc0/soc_id file");
		fclose(file);
		return -1;
	}

	fclose(file);

	soc_val[strcspn(soc_val, "\t\n")] = 0;

	if (strcmp(soc_val, "i.MX8ULP") == 0)
		soc = SOC_IMX8ULP;
#ifndef PSA_COMPLIANT
	else if (strcmp(soc_val, "i.MX8DXL") == 0)
		soc = SOC_IMX8DXL;
#endif
	else if (strcmp(soc_val, "i.MX91") == 0)
		soc = SOC_IMX91;
	else if (strcmp(soc_val, "i.MX93") == 0)
		soc = SOC_IMX93;
	else if (strcmp(soc_val, "i.MX943") == 0)
		soc = SOC_IMX943;
	else if (strcmp(soc_val, "i.MX95") == 0)
		soc = SOC_IMX95;
	else {
		perror("Undefined SOC\n");
		return -1;
	}

#ifdef V2X_SHE_MU
	she_hdl_t she_session_hdl = 0;

	/* Only SHE1 MU supported on iMX943 platform */
	if (soc == SOC_IMX943)
		open_session_args.mu_type = V2X_SHE1;

	else
		open_session_args.mu_type = V2X_SHE; // Use SHE1 to run on seco MU
	err = she_open_session(&open_session_args, &she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_open_session failed err:0x%x\n", err);
		return -1;
	}

	if (soc == SOC_IMX95)
		soc = se_get_soc_rev();

	if (soc == SOC_IMX8DXL)
		soc = se_get_board_type();
	err = she_close_session(she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_close_session failed err:0x%x\n", err);
		return -1;
	}
#else
	hsm_hdl_t hsm_session_hdl = 0;

#ifdef PSA_COMPLIANT
	open_session_args.mu_type = HSM1;
#else
	/* Open session for SV0 channel on V2X HSM */
	open_session_args.mu_type = V2X_SV0;
#endif
	err = hsm_open_session(&open_session_args, &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		return -1;
	}

	if (soc == SOC_IMX95)
		soc = se_get_soc_rev();

#ifndef PSA_COMPLIANT
	if (soc == SOC_IMX8DXL)
		soc = se_get_board_type();
#endif
	err = hsm_close_session(hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_session failed err:0x%x\n", err);
		return -1;
	}
#endif
	itest_ctx.test_name = NULL;
	itest_ctx.nb_assert_fails = 0;
	itest_ctx.ts = imx8_ts;
	itest_ctx.board = soc;

	return 0;
}

int main(int argc, char *argv[]){
	int i = 0, j = 0;
	int status = 0, valid_usage = 0, valid_test = 0, valid_board = 0;
	int c = 0;
	int print_ts = 0, ret = 0;

	ret = itest_init();
	if (ret) {
		ITEST_LOG("itest init failed\n");
		return -1;
	}

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
			for (j = 0; j < itest_ctx.ts[i].supported_board; j++) {
				if (itest_ctx.ts[i].board[j] == itest_ctx.board) {
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
