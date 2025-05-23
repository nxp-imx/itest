// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAC_SIZE	16
#define MAX_PAYLOAD_SIZE 2048
#define NUM_PAYLOAD_SIZE 5

int v2x_cmac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	op_open_utils_args_t utils_args = {0};
	open_svc_mac_args_t mac_args = {0};
	she_err_t err = 0, key_store_load = 0;
	uint8_t mac[SHE_MAC_SIZE] = {0};
	uint8_t message[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {16, 64, 256, 1024, 2048};
	uint8_t num_payload = NUM_PAYLOAD_SIZE;

	/* Since 2k message size not supported on IMX8DXL */
	if (soc == IMX8DXL_DL3)
		num_payload -= 1;

	ASSERT_EQUAL(randomize(message, sizeof(message)), sizeof(message));

	/* Only SHE1 MU supported on iMX943 platform */
	if (soc == SOC_IMX943)
		open_session_args.mu_type = V2X_SHE1;
	else
		open_session_args.mu_type = V2X_SHE; // Use SHE1 to run on seco MU

	// SHE OPEN SESSION
	err = she_open_session(&open_session_args, &she_session_hdl);
	if (err != SHE_NO_ERROR) {
		printf("she_open_session failed err:0x%x\n", err);
		goto out;
	}

	/* Support for only single keystore on i.MX8DXL, whereas 5 on i.MX95 */
	key_store_args.key_store_identifier = 0x1;
	key_store_args.authentication_nonce = 0xbec00001;
	key_store_args.max_updates_number = 300;
	key_store_args.flags = KEY_STORE_OPEN_FLAGS_CREATE |
			       KEY_STORE_OPEN_FLAGS_SHE |
			       KEY_STORE_OPEN_FLAGS_STRICT_OPERATION |
			       KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;
	key_store_args.min_mac_length = 32;
	key_store_args.max_updates_number   = 300;


	// SHE OPEN KEY STORE
	err = she_open_key_store_service(she_session_hdl,
					 &key_store_args);
	if (err != SHE_NO_ERROR) {
		if (err == SHE_KEY_STORE_CONFLICT || err == SHE_ID_CONFLICT) {
			key_store_args.flags = KEY_STORE_OPEN_FLAGS_SHE;
			err = she_open_key_store_service(she_session_hdl,
							 &key_store_args);
			if (err != SHE_NO_ERROR) {
				printf("she_open_key_store_service failed err:0x%x\n",
					err);
				goto out;
			}
			key_store_load = 1;
		} else {
			printf("she_open_key_store_service failed err:0x%x\n",
				err);
			goto out;
		}
	}

	key_store_hdl = key_store_args.key_store_hdl;

	// SHE OPEN UTILS
	err = she_open_utils(key_store_hdl, &utils_args);
	if (err != SHE_NO_ERROR) {
		printf("she_open_utils failed err:0x%x\n", err);
		goto out;
	}

	err = she_open_mac_service(key_store_hdl, &mac_args);
	if (err != SHE_NO_ERROR) {
		printf("she_open_mac_service failed err:0x%x\n", err);
		goto out;
	}

	// SHE KEY UPDATE
	if (!key_store_load)
		key_update_test(utils_args.utils_handle);

	for (int i = 0; i < num_payload; i++) {
		ITEST_LOG("CMAC aes 128 generation for 1s on %d byte blocks: ",	payload_size[i]);
		err = she_cmac_test(mac_args.mac_serv_hdl, SHE_KEY_5, message,
				    payload_size[i], mac,
				    MAC_OP_FLAGS_MAC_GENERATION,
				    she_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("CMAC aes 128 verification for 1s on %d byte blocks: ", payload_size[i]);
		err = she_cmac_test(mac_args.mac_serv_hdl, SHE_KEY_5, message,
				    payload_size[i], mac,
				    MAC_OP_FLAGS_MAC_VERIFICATION,
				    she_session_hdl);
		if (err)
			goto out;
	}
out:
	if (mac_args.mac_serv_hdl)
		she_close_mac_service(mac_args.mac_serv_hdl);
	if (utils_args.utils_handle)
		she_close_utils(utils_args.utils_handle);
	if (key_store_hdl)
		she_close_key_store_service(key_store_hdl);
	she_close_session(she_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
