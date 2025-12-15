// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include "prime/prime_functions.h"

#define NUM_LOAD_KEYS	64
#define KEY_SZ		0x20

int load_aes_key(void)
{
	int err = 0;
	aes_key_t key_args = {0};
	uint32_t t = 0;
	uint8_t aes_key[KEY_SZ] = {0};
	open_service_args_t op_serv_args = {0};

	/* open prime service */
	op_serv_args.serv_type = SERVICE_TYPE_ALL;
	serv_hdl = prime_open_service(&op_serv_args, &serv_hdl);

	ASSERT_EQUAL(randomize(aes_key, sizeof(aes_key)), sizeof(aes_key));

	for (t = 0; t < NUM_LOAD_KEYS; t++) {
		/* load aes key */
		key_args.keylen = KEY_SZ;
		key_args.key = aes_key;
		key_args.keyslot = t;
		err = prime_cipher_init(&key_args);
		if (err) {
			ITEST_LOG("Load 64 AES Keys failed err: 0x%x\n", err);
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
