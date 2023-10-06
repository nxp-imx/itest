// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "openssl/opensslconf.h"
#include "openssl/e_os2.h"
#include "crypto/sm4.h"
#include "crypto_utils/sm4_ed.h"

int xor_iv(uint8_t *iv, uint8_t *in, uint32_t bs){
    uint32_t i;

    for(i = 0; i < bs; i++){
	*in ^= *iv;
	in++;
	iv++;
    }
    return 0;
}

int read_chunck(char *in, uint32_t size, sm4_data *sm4d){
    uint32_t count = size <= SM4_BLOCK_SIZE * 64 ? size : SM4_BLOCK_SIZE * 64;
    
    memset(sm4d->block_e, 0, SM4_BLOCK_SIZE * 64);
    if (in)
        memcpy(in, sm4d->block_e, count);
    else{
        fprintf(stderr, "sm4: fail to load data...\n");
        return 1;
    }
    sm4d->nb_block = count / SM4_BLOCK_SIZE + ((count % SM4_BLOCK_SIZE) != 0 ? 1 : 0) ;
    return count;
}

/*==============================================================
==========================SM4-ECB===============================
===============================================================*/

int sm4_ecb_e_chunck(sm4_data *sm4d){
    int i, off;
    uint8_t *in, *out;

    in = sm4d->block_e;
    out = sm4d->block_d;
    for(i = 0; i < sm4d->nb_block; i++){
	off = SM4_BLOCK_SIZE * i;
	ossl_sm4_encrypt(in + off, out + off, &sm4d->key);
    }
    return i;
}

int sm4_ecb_d_chunck(sm4_data *sm4d){
    int i, off;
    uint8_t *in, *out;

    out = sm4d->block_d;
    in = sm4d->block_e;
    for(i = 0; i < sm4d->nb_block; i++){
	off = SM4_BLOCK_SIZE * i;
	ossl_sm4_decrypt(in + off, out + off, &sm4d->key);
    }
    return i;
}

/*==============================================================
==========================SM4-CBC===============================
===============================================================*/

int sm4_cbc_e_chunck(sm4_data *sm4d){
    int i, off;
    uint8_t *in, *out;

    in = sm4d->block_e;
    out = sm4d->block_d;
    for(i = 0; i < sm4d->nb_block; i++){
	off = SM4_BLOCK_SIZE * i;
	xor_iv(sm4d->iv, in+off, sizeof(uint8_t) * SM4_BLOCK_SIZE);
	ossl_sm4_encrypt(in + off, out + off, &sm4d->key);
	memcpy(sm4d->iv, out+off, sizeof(uint8_t) * SM4_BLOCK_SIZE);
    }
    return i;
}

int sm4_cbc_d_chunck(sm4_data *sm4d){
    int i, off;
    uint8_t *in, *out;

    in = sm4d->block_e;
    out = sm4d->block_d;
    for(i = 0; i < sm4d->nb_block; i++){
	off = SM4_BLOCK_SIZE * i;
	ossl_sm4_decrypt(in + off, out + off, &sm4d->key);
	xor_iv(sm4d->iv, out+off, sizeof(uint8_t) * SM4_BLOCK_SIZE);
	memcpy(sm4d->iv, in+off, sizeof(uint8_t) * SM4_BLOCK_SIZE);
    }
    return i;
}

int sm4_one_go(char *in, char *out, uint32_t size, sm4_data *sm4d, char *mode){
    int chunck_size = 0;
    int (*cipher)(sm4_data *);

    if(mode == NULL)
	    cipher = sm4_ecb_e_chunck;
    else if(!strcmp(mode, "sm4_ecb_d"))
	    cipher = sm4_ecb_d_chunck;
    else if(!strcmp(mode, "sm4_ecb_e"))
	    cipher = sm4_ecb_e_chunck;
    else if(!strcmp(mode, "sm4_cbc_d"))
	    cipher = sm4_cbc_d_chunck;
    else if(!strcmp(mode, "sm4_cbc_e"))
	    cipher = sm4_cbc_e_chunck;
    else
	    cipher = sm4_ecb_e_chunck;
    while(size != 0){
        chunck_size -= read_chunck(in, size, sm4d);
        size -= chunck_size;
        in += chunck_size;
	    cipher(sm4d);
	    memcpy(out, sm4d->block_d, sm4d->nb_block * SM4_BLOCK_SIZE);
        out += chunck_size;
    }
    return 0;
}

