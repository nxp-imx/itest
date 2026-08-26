// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "she/she_functions.h"

/* Number of iterations */
#define NUM_OPERATIONS  (3000u)

she_hdl_t she_session_hdl, key_store_hdl;

uint16_t get_soc(void)
{
	she_hdl_t she_session_hdl = 0;
	open_session_args_t open_session_args = {0};
	char soc_val[MAX_SOC_VAL];
	int err = 0;

	FILE *file = fopen("/sys/devices/soc0/soc_id", "r");

	if (file == NULL) {
		perror("Error opening the /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fgets(soc_val, MAX_SOC_VAL, file) == NULL) {
		perror("Error reading the /sys/devices/soc0/soc_id file");
		if (fclose(file) != 0)
			perror("Error closing the /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fclose(file) != 0)
		printf("Error closing the /sys/devices/soc0/soc_id file");

	soc_val[strcspn(soc_val, "\t\n")] = 0;

	if (strcmp(soc_val, "i.MX943") == 0)
		soc = SOC_IMX943;
	else if (strcmp(soc_val, "i.MX8DXL") == 0)
		soc = SOC_IMX8DXL;
	else if (strcmp(soc_val, "i.MX91") == 0)
		soc = SOC_IMX91;
	else if (strcmp(soc_val, "i.MX93") == 0)
		soc = SOC_IMX93;
	else if (strcmp(soc_val, "i.MX8ULP") == 0)
		soc = SOC_IMX8ULP;
	else if (strcmp(soc_val, "i.MX95") == 0)
		soc = SOC_IMX95;
	else if (strcmp(soc_val, "i.MX952") == 0)
		soc = SOC_IMX952;
	else if (strcmp(soc_val, "i.MX937") == 0)
		soc = SOC_IMX937;
	else if (strcmp(soc_val, "i.MX941") == 0)
		soc = SOC_IMX941;
	else if (strcmp(soc_val, "i.MX942") == 0)
		soc = SOC_IMX942;
	else {
		perror("Undefined SOC\n");
		return 1;
	}

	/* Only SHE1 MU supported on iMX94x platforms */
	if ((soc & SOC_MASK_IMX94) == SOC_IMX94)
		open_session_args.mu_type = V2X_SHE1;

	else
		open_session_args.mu_type = V2X_SHE; // Use SHE1 to run on seco MU
	err = she_open_session(&open_session_args, &she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_open_session failed err:0x%x\n", err);
		return 1;
	}

	soc_rev = se_get_soc_rev();
	board_type = se_get_board_type();

	err = she_close_session(she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_close_session failed err:0x%x\n", err);
		return 1;
	}

	return soc;
}

void print_help(void)
{
	ITEST_LOG("\nitest_v2x Help Menu:\n\n");
	ITEST_LOG("$ ./itest_v2x [OPTION] <argument>\n\n");
	ITEST_LOG("OPTIONS:\n");
	ITEST_LOG("  -h : Print this help\n");
	ITEST_LOG("  -v : Print test suite version\n");
	ITEST_LOG("  -l : List all tests\n");
	ITEST_LOG("  -t < test_name > : Run test test_name\n");
}

she_err_t she_cmac_test(she_hdl_t mac_hdl, uint32_t key_identifier,
			uint8_t *payload, uint32_t payload_size,
			uint8_t *mac, hsm_op_mac_flags_t flags,
			uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go = {0};
	she_mac_verification_status_t status;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, iter = NUM_OPERATIONS;
	she_err_t err = 0;

	mac_one_go.algorithm = SHE_OP_MAC_ONE_GO_ALGO_CMAC;
	mac_one_go.key_identifier = key_identifier;
	mac_one_go.flags = flags;
	mac_one_go.mac = mac;
	mac_one_go.mac_size = SHE_MAC_SIZE;
	mac_one_go.payload = payload;
	mac_one_go.payload_size = payload_size;

	t_perf.session_hdl = session_hdl;
	for (i = 0; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = she_mac_one_go(mac_hdl, &mac_one_go, &status);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
	}

	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);
	return err;
}

she_err_t key_update_test(she_hdl_t utils_handle)
{
	she_err_t err = 0;
	op_key_update_ext_args_t key_update_args = {0};

	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = { 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x44};

	uint8_t m2_1[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
		0x17, 0x36, 0x34, 0x5a,
		0x16, 0x78, 0x57, 0x2d,
		0xf7, 0x1f, 0x22, 0xec,
		0x4a, 0xaf, 0x2f, 0xed,
		0xcd, 0x28, 0xa6, 0xfc,
		0xb4, 0xe4, 0x11, 0xd3,
		0x04, 0xb5, 0x53, 0x1f};

	uint8_t m3_1[SHE_KEY_SIZE_IN_BYTES] = {0xf0, 0xe9, 0x29, 0x9c,
		0x43, 0xf9, 0xbe, 0xc6,
		0x0a, 0x83, 0x10, 0xad,
		0xdf, 0x25, 0xba, 0xba};

	uint8_t m2_5[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
		0x17, 0x36, 0x34, 0x5a,
		0x16, 0x78, 0x57, 0x2d,
		0xf7, 0x1f, 0x22, 0xec,
		0x4a, 0xaf, 0x2f, 0xed,
		0xcd, 0x28, 0xa6, 0xfc,
		0xb4, 0xe4, 0x11, 0xd3,
		0x04, 0xb5, 0x53, 0x1f};

	uint8_t m3_5[SHE_KEY_SIZE_IN_BYTES] = {0x87, 0x7b, 0x6b, 0x2f,
		0x90, 0xbb, 0x2d, 0x10,
		0x4b, 0xb5, 0x0e, 0x57,
		0x6c, 0x3a, 0xc3, 0xf7};

	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};

	key_update_args.key_id = SHE_KEY_1;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_1;
	key_update_args.m3 = m3_1;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_1);
	key_update_args.m3_size = sizeof(m3_1);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_args);
	if (err) {
		printf("she_key_update failed err:0x%x\n", err);
		return err;
	}

	m1[15] = 0x88;
	memset(&key_update_args, 0, sizeof(key_update_args));

	key_update_args.key_id = SHE_KEY_5;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_5;
	key_update_args.m3 = m3_5;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_5);
	key_update_args.m3_size = sizeof(m3_5);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_args);
	if (err)
		printf("she_key_update failed err:0x%x\n", err);
	return err;
}
