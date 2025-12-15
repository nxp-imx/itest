// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "prime/prime_functions.h"

#define NUM_LOAD_KEYS	64
#define KEY_SZ		0x80

int load_hmac_key(void)
{
	prime_err_t err = 0;
	hmac_key_t key_args = {0};
	uint32_t i = 0;
	uint8_t hmac_key[KEY_SZ] = {0};
	open_service_args_t op_serv_args = {0};
	uint8_t sha_algo = CRYPTO_AUTH_SHA_521;

	/* open prime service */
	op_serv_args.serv_type = SERVICE_TYPE_ALL;
	serv_hdl = prime_open_service(&op_serv_args, &serv_hdl);

	ASSERT_EQUAL(randomize(hmac_key, sizeof(hmac_key)), sizeof(hmac_key));

	for (i = 0; i < NUM_LOAD_KEYS; i++) {
		/* load hmac key */
		key_args.keylen = KEY_SZ;
		key_args.key = hmac_key;
		key_args.keyslot = i;
		key_args.sha_algo = sha_algo;
		err = prime_auth_init(&key_args);
		if (err) {
			ITEST_LOG("HMAC_SHA512 LOAD 64 Keys failed err: 0x%x\n", err);
			goto out;
		}
	}

out:
	/* close prime service */
	prime_close_service(serv_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
