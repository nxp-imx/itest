/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef SM4_ED_H
#define SM4_ED_H

typedef struct sm4_data {
    uint8_t block_e[SM4_BLOCK_SIZE*64];
    uint8_t block_d[SM4_BLOCK_SIZE*64];
    SM4_KEY key;
    uint8_t iv[SM4_BLOCK_SIZE];
    int nb_block;
} sm4_data;

int sm4_one_go(char *in, char *out, uint32_t size, sm4_data *sm4d, char *mode);

#endif