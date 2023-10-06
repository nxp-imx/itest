/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Max public key size is 132 byte for P521 */
#define MAX_KEY_SIZE     (0x84)
/*
 * Max size for msg is 332 bytes.
 *  for SM2 test:
 *   - 300 bytes of message
 *   -  32 bytes of z_dgst
 */
#define MAX_MSG_SIZE     (332)
/* MAX_KEY_SIZE + 1 byte for Ry */
#define MAX_SIG_SIZE     ((MAX_KEY_SIZE) + 1)
/* Digest size is half of publick key size */
#define MAX_DGST_SIZE    (MAX_KEY_SIZE/2)

typedef struct {
    int curve;
    uint8_t message[MAX_MSG_SIZE];
    uint32_t message_length;
    uint8_t digest[MAX_DGST_SIZE];
    uint8_t public_key[MAX_KEY_SIZE];
    uint8_t signature[MAX_SIG_SIZE];
} test_data_verify_t;

#define SM4_CCM_NONCE_SIZE (12)

#define SM4_CCM_KEY_SIZE (16)


typedef struct {
    int algo;
    uint8_t message[MAX_MSG_SIZE];
    uint32_t message_length;
    uint8_t encrypted_data[MAX_MSG_SIZE];
    uint32_t encrypted_length;
    uint8_t nonce[SM4_CCM_NONCE_SIZE];
    uint32_t nonce_length;
    uint8_t sm4_key[SM4_CCM_KEY_SIZE];
} test_data_cipher_t;

#endif /* __COMMON_H__ */
