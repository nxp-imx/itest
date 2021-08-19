/*
 * Copyright 2020 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "itest.h"

static uint8_t  SM2_test_message[300] = {
    // Note that the first 32 Bytes are the "Z" value that can be retrieved with hsm_sm2_get_z()
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

static uint8_t SM3_HASH[32] = {
    0x52, 0x1d, 0xa1, 0x93, 0x21, 0xcb, 0x3a, 0xfc, 0xb5, 0x13, 0x25, 0x45, 0x7f, 0x8f, 0x15, 0x89,
    0xdc, 0x60, 0xfa, 0xf0, 0x87, 0xf2, 0xcf, 0x8f, 0xf3, 0xe2, 0x8d, 0x8b, 0xde, 0x28, 0x97, 0x8e,
};

/*static uint8_t ECDSA_SigVer_SM2_Q[64] = {
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};*/

static uint8_t SM2_IDENTIFIER[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static uint8_t SM2_PUBK[64] = {
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};

static uint8_t SM2_Z[32] = {
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3
};

/*static uint8_t gcm_auth_data[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};*/

/*static uint8_t iv_gcm[16] = {
    0x18, 0x33, 0x23, 0x01, 0xFF, 0x99, 0x72, 0x1A, 0xBB, 0xEF, 0xA3, 0x22
};*/

uint8_t ecies_input[16] = {
    0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74, 0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
};

uint8_t ecies_p1[32] = {
    0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F, 0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
    0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA, 0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9
};

uint8_t ecc_p256_pubk[2*32] = {
    0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
    0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
    0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
    0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9
};

uint8_t sm2_ke_input[2*64] = {
    // initiator static public key
    0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 0xB5, 0xFA, 0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07,
    0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56, 0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB,
    0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 0x36, 0xC5, 0xC7, 0x99, 0x20, 0x62, 0xE9, 0xCD,
    0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA, 0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D,
    // initiator ephemeral public key
    0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB,
    0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6, 0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
    0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D,
    0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4, 0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F
};

uint8_t sm2_kdf_input[2*32] = {
    // Za
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    // Zb
    0xB5 ,0x24 ,0xF5 ,0x52 ,0xCD ,0x82 ,0xB8 ,0xB0 ,0x28 ,0x47 ,0x6E ,0x00 ,0x5C ,0x37 ,0x7F ,0xB1,
    0x9A ,0x87 ,0xE6 ,0xFC ,0x68 ,0x2D ,0x48 ,0xBB ,0x5D ,0x42 ,0xE3 ,0xD9 ,0xB9 ,0xEF ,0xFE ,0x76,
};

/* test vectors for butterfly key expansion */
uint8_t sm2_exp_fct_input[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x36, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
};

uint8_t sm2_butt_hash_val [32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

uint8_t sm2_butt_rec_val [32] = {
    0x2e, 0xfb, 0x7b, 0x7b, 0x52, 0x5e, 0x33, 0x7b, 0x90, 0x69, 0xd8, 0x6e, 0x30, 0xac, 0xb5, 0x3e,
    0xb0, 0xbe, 0x83, 0xb1, 0xb0, 0x1c, 0x04, 0xfe, 0x79, 0xe1, 0x18, 0x45, 0x82, 0xf1, 0xc0, 0xc4
};

uint8_t p256_exp_fct_input[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x7D, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
};

uint8_t sm4_ccm_nonce [12] = {
    0x72, 0x43, 0x52, 0x3C, 0x65, 0x17, 0x8B, 0x96, 0x68, 0x37, 0xA3, 0x6F
};

uint8_t sm4_ccm_ptx [23] = {
    0x03, 0x80, 0x14, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xA0, 0xA1, 0xA2,
    0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9
};

uint8_t sm4_ccm_ctx_tag [23+16] = {
    0xFB, 0x78, 0x40, 0x15, 0x24, 0xCA, 0x9C, 0x2D, 0x68, 0x3B, 0xC4, 0xE9, 0x5D, 0xDC, 0x71, 0xB8,
    0x28, 0x07, 0x77, 0x81, 0xAA, 0x8E, 0x3F, 0xE8, 0x1C, 0xE4, 0xDE, 0x21, 0x38, 0x76, 0x49, 0x19,
    0x59, 0xEE, 0x87, 0x63, 0xE2, 0x21, 0x55
};

uint8_t sm4_ccm_key[16] = {
    0xCA, 0x44, 0xEF, 0x8D, 0xF3, 0x25, 0xAB, 0xB3, 0x8D, 0xAC, 0x37, 0x43, 0xDD, 0x32, 0x43, 0xDF
};


uint8_t work_area[128] = {0};
uint8_t work_area2[128] = {0};
uint8_t work_area3[128] = {0};
uint8_t work_area4[128] = {0};

typedef struct {
    char *tag;
    hsm_hdl_t key_mgmt_srv;
    hsm_hdl_t sig_gen_serv;
    hsm_hdl_t sig_ver_serv;
    uint8_t *sig_area;
    uint8_t *pubk_area;
} sig_thread_args_t;

static void *sig_loop_thread(void *arg)
{

    op_generate_sign_args_t sig_gen_args;
    op_verify_sign_args_t sig_ver_args;
    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;
    hsm_verification_status_t status;
    int i;

    sig_thread_args_t *args = (sig_thread_args_t *)arg;
    if (!args)
        return NULL;

    for (i=0 ; i<200; i++) {
        /* generate and verify a SM2 signature - use alternatively create and update flags. */
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = 64;
        gen_key_args.flags = ((i%4 == 0) ? HSM_OP_KEY_GENERATION_FLAGS_CREATE : HSM_OP_KEY_GENERATION_FLAGS_UPDATE);
        gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        gen_key_args.key_group = 12;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = args->pubk_area;
        ASSERT_EQUAL(hsm_generate_key(args->key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
        // printf("%s err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", args->tag, err, args->key_mgmt_srv);

        sig_gen_args.key_identifier = key_id;
        sig_gen_args.message = SM2_test_message;
        sig_gen_args.signature = args->sig_area;
        sig_gen_args.message_size = 300;
        sig_gen_args.signature_size = 65;
        sig_gen_args.scheme_id = 0x43;
        sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
        ASSERT_EQUAL(hsm_generate_signature(args->sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);
        // printf("%s err: 0x%x hsm_generate_signature hdl: 0x%08x\n", args->tag, err, args->sig_gen_serv);

        sig_ver_args.key = args->pubk_area;
        sig_ver_args.message = SM2_test_message;
        sig_ver_args.signature = args->sig_area;
        sig_ver_args.key_size = 64;
        sig_ver_args.signature_size = 65;
        sig_ver_args.message_size = 300;
        sig_ver_args.scheme_id = 0x43;
        sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
        ASSERT_EQUAL(hsm_verify_signature(args->sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
    }

    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("P256 Compressed signature \n");
    ITEST_LOG("-----------------------------------------------------\n");
    /* generate and verify a P256 signature - use alternatively create and update flags. */
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = args->pubk_area;
    ASSERT_EQUAL(hsm_generate_key(args->key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    sig_gen_args.key_identifier = key_id;
    sig_gen_args.message = SM2_test_message;
    sig_gen_args.signature = args->sig_area;
    sig_gen_args.message_size = 300;
    sig_gen_args.signature_size = 65;
    sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
    sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE | HSM_OP_GENERATE_SIGN_FLAGS_COMPRESSED_POINT;
    ASSERT_EQUAL(hsm_generate_signature(args->sig_gen_serv, &sig_gen_args), HSM_NO_ERROR);

    sig_ver_args.key = args->pubk_area;
    sig_ver_args.message = SM2_test_message;
    sig_ver_args.signature = args->sig_area;
    sig_ver_args.key_size = 64;
    sig_ver_args.signature_size = 65;
    sig_ver_args.message_size = 300;
    sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
    sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;
    ASSERT_EQUAL( hsm_verify_signature(args->sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);

    pthread_exit(NULL);
    return NULL;
}

typedef struct {
    char *tag;
    hsm_hdl_t key_mgmt_srv;
    hsm_hdl_t cipher_hdl;
    uint8_t *cipher_area;
    uint8_t *clear_area;
} cipher_thread_args_t;

static void *cipher_loop_thread(void *arg)
{

    op_cipher_one_go_args_t cipher_args;
    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;
    int i;

    cipher_thread_args_t *args = (cipher_thread_args_t *)arg;
    if (!args)
        return NULL;

    for (i=0 ; i<200; i++) {
        memset(args->cipher_area, 0, 128);
        memset(args->clear_area, 0, 128);
        /* generate and verify a SM2 signature - use alternatively create and update flags. */
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = 0;
        gen_key_args.flags = ((i%4 == 0) ? HSM_OP_KEY_GENERATION_FLAGS_CREATE : HSM_OP_KEY_GENERATION_FLAGS_UPDATE);
        gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
        gen_key_args.key_group = 14;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = NULL;
        ASSERT_EQUAL(hsm_generate_key(args->key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);
        // printf("%s err: 0x%x hsm_generate_key hdl: 0x%08x\n", args->tag, err, args->key_mgmt_srv);
   
        cipher_args.key_identifier = key_id;
        cipher_args.iv = ((i%2 == 0) ? SM2_IDENTIFIER : NULL); // just need 16 bytes somewhere to be used as IV
        cipher_args.iv_size = ((i%2 == 0) ? 16 : 0);
        cipher_args.cipher_algo = ((i%2 == 0) ? HSM_CIPHER_ONE_GO_ALGO_SM4_CBC : HSM_CIPHER_ONE_GO_ALGO_SM4_ECB);
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = SM2_test_message;
        cipher_args.output = args->cipher_area;
        cipher_args.input_size = 128;
        cipher_args.output_size = 128;
        ASSERT_EQUAL(hsm_cipher_one_go(args->cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // printf("%s err: 0x%x hsm_cipher_one_go ENCRYPT hdl: 0x%08x\n", args->tag, err, args->cipher_hdl);

        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = args->cipher_area;
        cipher_args.output = args->clear_area;
        // other args unchanged
        ASSERT_EQUAL(hsm_cipher_one_go(args->cipher_hdl, &cipher_args), HSM_NO_ERROR);
        // printf("%s err: 0x%x hsm_cipher_one_go DECRYPT hdl: 0x%08x\n", args->tag, err, args->cipher_hdl);

        ASSERT_EQUAL(memcmp(SM2_test_message, args->clear_area, 128), 0);
    }

    pthread_exit(NULL);
    return NULL;
}


int v2x_all_services(void)
{
    open_session_args_t args;

    open_svc_hash_args_t hash_srv_args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    open_svc_rng_args_t rng_srv_args;
    open_svc_key_generic_crypto_args_t key_generic_crypto_args;

    op_hash_one_go_args_t hash_args;
    op_sm2_get_z_args_t get_z_args;
    op_sm2_eces_enc_args_t sm2_eces_enc_args;
    

    open_svc_sm2_eces_args_t sm2_eces_dec_svc_args;
    op_sm2_eces_dec_args_t sm2_eces_dec_args;
    op_get_random_args_t rng_get_random_args;
    op_manage_key_args_t mng_key_args;
    op_ecies_enc_args_t op_ecies_enc_args;
    op_ecies_dec_args_t op_ecies_dec_args;

    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg1_sess, sv1_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_sig_gen_serv, sg0_key_mgmt_srv, sg0_cipher_hdl;
    hsm_hdl_t sg1_key_store_serv, sg1_sig_gen_serv, sg1_key_mgmt_srv, sg1_cipher_hdl;
    hsm_hdl_t sv0_rng_serv, sv1_rng_serv, sg0_rng_serv, sg1_rng_serv;
    hsm_hdl_t sv0_sig_ver_serv;
    hsm_hdl_t sv1_sig_ver_serv;
    hsm_hdl_t hash_serv;
    hsm_hdl_t sg0_sm2_eces_hdl, sg1_sm2_eces_hdl;
    hsm_hdl_t key_generic_crypto;

    op_key_generic_crypto_args_t key_generic_crypto_srv_args;
    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;
    uint32_t key_id_sm4 = 0;
    uint32_t master_key_id = 0;
    uint32_t exp_fct_key_id = 0;

    pthread_t sig1, sig2;
    sig_thread_args_t args1, args2;
    cipher_thread_args_t cipher_args1, cipher_args2;
    op_pub_key_recovery_args_t pub_k_rec_args;

    op_key_exchange_args_t key_exch;
    op_cipher_one_go_args_t cipher_args;

    open_svc_mac_args_t mac_srv_args;
    hsm_hdl_t sg0_mac_hdl;
    op_mac_one_go_args_t mac_one_go;
    hsm_mac_verification_status_t mac_status;
    op_auth_enc_args_t auth_enc_gcm;

    op_st_butt_key_exp_args_t st_butt_key_expansion;


    uint8_t recovered_key[256];
    uint8_t rng_out_buff[4096];

    srand (time (NULL));

    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Starting storage manager \n");
    ITEST_LOG("---------------------------------------------------\n");

    // REMOVE NVM
    clear_v2x_nvm();

    // START NVM
    ASSERT_NOT_EQUAL(start_nvm_v2x(), NVM_STATUS_STOPPED);

    // SG0
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Opening sessions \n");
    ITEST_LOG("---------------------------------------------------\n");
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg0_sess), HSM_NO_ERROR);

    // SV0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    // SG1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sg1_sess), HSM_NO_ERROR);

    // //SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv1_sess), HSM_NO_ERROR);

    // opening services for signature generation/verif on SG0 and SG1

    key_store_srv_args.key_store_identifier = 1234;
    key_store_srv_args.authentication_nonce = 1234;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    ASSERT_EQUAL(hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv), HSM_NO_ERROR);

    key_store_srv_args.key_store_identifier = 5678;
    key_store_srv_args.authentication_nonce = 5678;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    ASSERT_EQUAL(hsm_open_key_store_service(sg1_sess, &key_store_srv_args, &sg1_key_store_serv), HSM_NO_ERROR);

    key_mgmt_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_key_management_service(sg1_key_store_serv, &key_mgmt_srv_args, &sg1_key_mgmt_srv), HSM_NO_ERROR);

    sig_gen_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_signature_generation_service(sg1_key_store_serv, &sig_gen_srv_args, &sg1_sig_gen_serv), HSM_NO_ERROR);

    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess, &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv1_sess, &sig_ver_srv_args, &sv1_sig_ver_serv), HSM_NO_ERROR);


    // SM2 signature test: generate a signature and verify it
    //
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM2 signature generation and verification in parallel\n");
    ITEST_LOG("---------------------------------------------------\n");
    args1.tag = "HIGH_P";
    args1.key_mgmt_srv = sg0_key_mgmt_srv;
    args1.sig_gen_serv = sg0_sig_gen_serv;
    args1.sig_ver_serv = sv0_sig_ver_serv;
    args1.sig_area = work_area;
    args1.pubk_area = work_area2;
    (void)pthread_create(&sig1, NULL, sig_loop_thread, &args1);
    ITEST_LOG("started signature High prio thread\n");

    args2.tag = "LOW_P ";
    args2.key_mgmt_srv = sg1_key_mgmt_srv;
    args2.sig_gen_serv = sg1_sig_gen_serv;
    args2.sig_ver_serv = sv1_sig_ver_serv;
    args2.sig_area = work_area3;
    args2.pubk_area = work_area4;
    (void)pthread_create(&sig2, NULL, sig_loop_thread, &args2);
    ITEST_LOG("started signature Low prio thread\n");

    pthread_join(sig1, NULL);
    ITEST_LOG("completed signature High prio thread\n");

    pthread_join(sig2, NULL);
    ITEST_LOG("completed signature Low prio thread\n");

    // RNG srv tests
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("RNG test\n");
    ITEST_LOG("---------------------------------------------------\n");
    rng_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_rng_service(sv0_sess, &rng_srv_args, &sv0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sv1_sess, &rng_srv_args, &sv1_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sg0_sess, &rng_srv_args, &sg0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_rng_service(sg1_sess, &rng_srv_args, &sg1_rng_serv), HSM_NO_ERROR);

    rng_get_random_args.output = rng_out_buff;
    rng_get_random_args.random_size = 3;
    ASSERT_EQUAL(hsm_get_random(sv0_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 176;
    ASSERT_EQUAL(hsm_get_random(sv1_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 2050;
    ASSERT_EQUAL(hsm_get_random(sg0_rng_serv, &rng_get_random_args), HSM_NO_ERROR);
    rng_get_random_args.random_size = 4096;
    ASSERT_EQUAL(hsm_get_random(sg1_rng_serv, &rng_get_random_args), HSM_NO_ERROR);

    // SM3 hash test

    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM3 hash test\n");
    ITEST_LOG("---------------------------------------------------\n");
    hash_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_hash_service(sv0_sess, &hash_srv_args, &hash_serv), HSM_NO_ERROR);

    hash_args.input = SM2_test_message;
    hash_args.output = work_area;
    hash_args.input_size = sizeof(SM2_test_message);
    hash_args.output_size = 32;
    hash_args.algo = 0x11;
    hash_args.flags = 0;

    ASSERT_EQUAL(hsm_hash_one_go(hash_serv, &hash_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(SM3_HASH, work_area, sizeof(SM3_HASH)), 0);

    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM2 get Z test\n");
    ITEST_LOG("---------------------------------------------------\n");
    get_z_args.public_key = SM2_PUBK;
    get_z_args.identifier = SM2_IDENTIFIER;
    get_z_args.z_value = work_area;
    get_z_args.public_key_size = 64;
    get_z_args.id_size = 16;
    get_z_args.z_size = 32;
    get_z_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    get_z_args.flags = 0;

    ASSERT_EQUAL(hsm_sm2_get_z(sv0_sess, &get_z_args), HSM_NO_ERROR);

    ASSERT_EQUAL(memcmp(SM2_Z, work_area, sizeof(SM2_Z)), 0);

    // SM4 test
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM4 encrypt/decrypt test\n");
    ITEST_LOG("---------------------------------------------------\n");
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_cipher_service(sg1_key_store_serv, &cipher_srv_args, &sg1_cipher_hdl), HSM_NO_ERROR);

    cipher_args1.tag = "HIGH_P";
    cipher_args1.key_mgmt_srv = sg0_key_mgmt_srv;
    cipher_args1.cipher_hdl = sg0_cipher_hdl;
    cipher_args1.cipher_area = work_area;
    cipher_args1.clear_area = work_area2;
    (void)pthread_create(&sig1, NULL, cipher_loop_thread, &cipher_args1);
    ITEST_LOG("started cipher High prio thread\n");

    cipher_args2.tag = "LOW_P ";
    cipher_args2.key_mgmt_srv = sg1_key_mgmt_srv;
    cipher_args2.cipher_hdl = sg1_cipher_hdl;
    cipher_args2.cipher_area = work_area3;
    cipher_args2.clear_area = work_area4;
    (void)pthread_create(&sig2, NULL, cipher_loop_thread, &cipher_args2);
    ITEST_LOG("started cipher Low prio thread\n");

    pthread_join(sig1, NULL);
    ITEST_LOG("completed cipher High prio thread\n");

    pthread_join(sig2, NULL);
    ITEST_LOG("completed cipher Low prio thread\n");

    // SM2 eces encrypt and decrypt
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM2 ECES test\n");
    ITEST_LOG("---------------------------------------------------\n");

    sm2_eces_dec_svc_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_sm2_eces_service(sg0_key_store_serv, &sm2_eces_dec_svc_args, &sg0_sm2_eces_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_open_sm2_eces_service(sg1_key_store_serv, &sm2_eces_dec_svc_args, &sg1_sm2_eces_hdl), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2; // public key needed for the encryption
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    sm2_eces_enc_args.input = SM2_test_message;
    sm2_eces_enc_args.output = work_area;
    sm2_eces_enc_args.pub_key = work_area2;
    sm2_eces_enc_args.input_size = 16;
    sm2_eces_enc_args.output_size = 128; // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
    sm2_eces_enc_args.pub_key_size = 64;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;

    ASSERT_EQUAL(hsm_sm2_eces_encryption(sg0_sess, &sm2_eces_enc_args), HSM_NO_ERROR);

    sm2_eces_dec_args.input = work_area;
    sm2_eces_dec_args.output = work_area3; //plaintext
    sm2_eces_dec_args.key_identifier = key_id;
    sm2_eces_dec_args.input_size = 113;
    sm2_eces_dec_args.output_size = 16;
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;

    ASSERT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(SM2_test_message, work_area3, 16), 0);

    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Public key recovery\n");
    ITEST_LOG("---------------------------------------------------\n");

    pub_k_rec_args.key_identifier = key_id;
    pub_k_rec_args.out_key = recovered_key;
    pub_k_rec_args.out_key_size = 64;
    pub_k_rec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    pub_k_rec_args.flags = 0;

    ASSERT_EQUAL(hsm_pub_key_recovery(sg0_key_store_serv, &pub_k_rec_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(recovered_key, work_area2, 64), 0);


    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("key deletion test\n");
    ITEST_LOG("---------------------------------------------------\n");

    /* Test deletion of last generated key. */
    mng_key_args.key_identifier = &key_id;
    mng_key_args.kek_identifier = 0;
    mng_key_args.input_size = 0;
    mng_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
    mng_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    mng_key_args.key_group = 12;
    mng_key_args.key_info = 0;
    mng_key_args.input_data = NULL;

    ASSERT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &mng_key_args), HSM_NO_ERROR);

    /* Try to use again this key: an error is expected. */
    sm2_eces_dec_args.input = work_area;
    sm2_eces_dec_args.output = work_area3; //plaintext
    sm2_eces_dec_args.key_identifier = key_id;
    sm2_eces_dec_args.input_size = 113;
    sm2_eces_dec_args.output_size = 16;
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;

    ASSERT_NOT_EQUAL(hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args), HSM_NO_ERROR);


    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("key delete with key group check test \n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2; // public key needed for the encryption
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    /* Test deletion of last generated key with bad key group */
    mng_key_args.key_identifier = &key_id;
    mng_key_args.kek_identifier = 0;
    mng_key_args.input_size = 0;
    mng_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
    mng_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    mng_key_args.key_group = 10;
    mng_key_args.key_info = 0;
    mng_key_args.input_data = NULL;

    ASSERT_NOT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &mng_key_args), HSM_NO_ERROR);

    /* Test deletion of last generated key with the right key group */
    mng_key_args.key_identifier = &key_id;
    mng_key_args.kek_identifier = 0;
    mng_key_args.input_size = 0;
    mng_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
    mng_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    mng_key_args.key_group = 12;
    mng_key_args.key_info = 0;
    mng_key_args.input_data = NULL;

    ASSERT_EQUAL(hsm_manage_key(sg0_key_mgmt_srv, &mng_key_args), HSM_NO_ERROR);


    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("ecies test\n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2; // public key needed for the encryption
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    op_ecies_enc_args.input = ecies_input;
    op_ecies_enc_args.pub_key = work_area2;
    op_ecies_enc_args.p1 = ecies_p1;
    op_ecies_enc_args.p2 = NULL;
    op_ecies_enc_args.output = work_area;
    op_ecies_enc_args.input_size = 16;
    op_ecies_enc_args.p1_size = 32;
    op_ecies_enc_args.p2_size = 0;
    op_ecies_enc_args.pub_key_size = 2*32;
    op_ecies_enc_args.mac_size = 16;
    op_ecies_enc_args.out_size = 3*32;
    op_ecies_enc_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_enc_args.flags = 0u;
    op_ecies_enc_args.reserved= 0u;
    ASSERT_EQUAL(hsm_ecies_encryption(sg0_sess, &op_ecies_enc_args), HSM_NO_ERROR);

    op_ecies_dec_args.key_identifier = key_id;
    op_ecies_dec_args.input = work_area;
    op_ecies_dec_args.p1 = ecies_p1;
    op_ecies_dec_args.p2 = NULL;
    op_ecies_dec_args.output = work_area3;
    op_ecies_dec_args.input_size = 3*32;
    op_ecies_dec_args.output_size = 16;
    op_ecies_dec_args.p1_size = 32;
    op_ecies_dec_args.p2_size = 0;
    op_ecies_dec_args.mac_size = 16;
    op_ecies_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_dec_args.flags = 0;
    ASSERT_EQUAL(hsm_ecies_decryption(sg0_cipher_hdl, &op_ecies_dec_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(ecies_input, work_area3, 16), 0);


    // Key exchange to create a KEK
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Key exchange KEK derivation \n");
    ITEST_LOG("---------------------------------------------------\n");
    key_exch.key_identifier =0;
    key_exch.shared_key_identifier_array = work_area2;
    key_exch.ke_input = ecc_p256_pubk;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = 0;
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 32;
    key_exch.shared_key_info = HSM_KEY_INFO_KEK;
    key_exch.shared_key_type = HSM_KEY_TYPE_AES_256;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_ECDH_NIST_P256;
    key_exch.kdf_algorithm = HSM_KDF_ONE_STEP_SHA_256;
    key_exch.ke_input_size = 64;
    key_exch.ke_output_size = 64;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 0;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE | HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL;
    key_exch.signed_message = NULL;
    key_exch.signed_msg_size = 0;

    ASSERT_EQUAL(hsm_key_exchange(sg0_key_mgmt_srv, &key_exch), HSM_NO_ERROR);

    // SM2 Key exchange
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM2 Key exchange \n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    key_exch.key_identifier = key_id;
    key_exch.shared_key_identifier_array = (uint8_t *)&key_id_sm4;
    key_exch.ke_input = sm2_ke_input;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = sm2_kdf_input; // Za|| Zb
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 12;
    key_exch.shared_key_info = 0;
    key_exch.shared_key_type = HSM_KEY_TYPE_SM4_128;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_SM2_FP_256;
    key_exch.kdf_algorithm = HSM_KDF_ALG_FOR_SM2;
    key_exch.ke_input_size = 64 *2;
    key_exch.ke_output_size = 64 * 2;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 32*2;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE;
    key_exch.signed_message = NULL;
    key_exch.signed_msg_size = 0;

    ASSERT_EQUAL(hsm_key_exchange(sg0_key_mgmt_srv, &key_exch), HSM_NO_ERROR);


    // SM4 test with the derived key
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM4 encrypt test with derived key \n");
    ITEST_LOG("---------------------------------------------------\n");
    cipher_srv_args.flags = 0U;
    ASSERT_EQUAL(hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl), HSM_NO_ERROR);

    cipher_args.key_identifier = key_id_sm4;
    cipher_args.iv = 0;
    cipher_args.iv_size = 0;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = SM2_test_message;
    cipher_args.output = work_area3;
    cipher_args.input_size = 16;
    cipher_args.output_size = 16;
    ASSERT_EQUAL(hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args), HSM_NO_ERROR);

    key_exch.key_identifier = key_id;
    key_exch.shared_key_identifier_array = work_area2;
    key_exch.ke_input = sm2_ke_input;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = sm2_kdf_input; // Za|| Zb
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 12;
    key_exch.shared_key_info = 0;
    key_exch.shared_key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_SM2_FP_256;
    key_exch.kdf_algorithm = HSM_KDF_ALG_FOR_SM2;
    key_exch.ke_input_size = 64 *2;
    key_exch.ke_output_size = 64 * 2;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 32*2;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE | HSM_OP_KEY_EXCHANGE_FLAGS_STRICT_OPERATION;
    key_exch.signed_message = NULL;
    key_exch.signed_msg_size = 0;

    ASSERT_EQUAL(hsm_key_exchange(sg0_key_mgmt_srv, &key_exch), HSM_NO_ERROR);


    // mac test
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("MAC ONE GO Test \n");
    ITEST_LOG("---------------------------------------------------\n");
    mac_srv_args.flags = 0u;
    ASSERT_EQUAL(hsm_open_mac_service(sg0_key_store_serv, &mac_srv_args, &sg0_mac_hdl), HSM_NO_ERROR);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
    mac_one_go.payload = SM2_test_message;
    mac_one_go.mac = work_area2;
    mac_one_go.payload_size = 32u;
    mac_one_go.mac_size = 16u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
    mac_one_go.payload = SM2_test_message;
    mac_one_go.mac = work_area2;
    mac_one_go.payload_size = 32u;
    mac_one_go.mac_size = 8u;
    ASSERT_EQUAL(hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status), HSM_NO_ERROR);


    // AES GCM test
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("AES GCM Test \n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &SM2_test_message[256];
    auth_enc_gcm.iv_size = 4;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_gcm.input = SM2_test_message;
    auth_enc_gcm.output = work_area3;
    auth_enc_gcm.input_size = 32;
    auth_enc_gcm.output_size = 32+16+12;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &work_area3[32+16];
    auth_enc_gcm.iv_size = 12;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_gcm.input = work_area3;
    auth_enc_gcm.output = work_area4;
    auth_enc_gcm.input_size = 32 +16;
    auth_enc_gcm.output_size = 32;

    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(SM2_test_message, work_area4, 32), 0);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &SM2_test_message[256];
    auth_enc_gcm.iv_size = 4;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
    auth_enc_gcm.input = SM2_test_message;
    auth_enc_gcm.output = work_area3;
    auth_enc_gcm.input_size = 32;
    auth_enc_gcm.output_size = 32+16+12;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &work_area3[32+16];
    auth_enc_gcm.iv_size = 12;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_gcm.input = work_area3;
    auth_enc_gcm.output = work_area4;
    auth_enc_gcm.input_size = 32 +16;
    auth_enc_gcm.output_size = 32;

    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(SM2_test_message, work_area4, 32), 0);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = NULL;
    auth_enc_gcm.iv_size = 0;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_gcm.input = SM2_test_message;
    auth_enc_gcm.output = work_area3;
    auth_enc_gcm.input_size = 32;
    auth_enc_gcm.output_size = 32+16+12;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &work_area3[32+16];
    auth_enc_gcm.iv_size = 12;
    auth_enc_gcm.aad = &SM2_test_message[128];
    auth_enc_gcm.aad_size = 16;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_gcm.input = work_area3;
    auth_enc_gcm.output = work_area4;
    auth_enc_gcm.input_size = 32 +16;
    auth_enc_gcm.output_size = 32;

    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(SM2_test_message, work_area4, 32), 0);

// Standalone butterfly key expansion
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Standalone butterfly key expansion Test \n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &master_key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = HSM_KEY_INFO_MASTER;
    gen_key_args.out_key = work_area2;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    gen_key_args.key_identifier = &exp_fct_key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    st_butt_key_expansion.key_identifier = master_key_id;
    st_butt_key_expansion.expansion_fct_key_identifier = exp_fct_key_id;
    st_butt_key_expansion.expansion_fct_input = sm2_exp_fct_input;
    st_butt_key_expansion.hash_value = sm2_butt_hash_val;
    st_butt_key_expansion.pr_reconstruction_value = sm2_butt_rec_val;
    st_butt_key_expansion.expansion_fct_input_size = 16;
    st_butt_key_expansion.hash_value_size = 32;
    st_butt_key_expansion.pr_reconstruction_value_size = 32;
    st_butt_key_expansion.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF;
    st_butt_key_expansion.dest_key_identifier = &key_id;
    st_butt_key_expansion.output = work_area;
    st_butt_key_expansion.output_size = 64;
    st_butt_key_expansion.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    st_butt_key_expansion.expansion_fct_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    st_butt_key_expansion.key_group = 1;
    st_butt_key_expansion.key_info = 0;
    ASSERT_EQUAL(hsm_standalone_butterfly_key_expansion(sg0_key_mgmt_srv, &st_butt_key_expansion), HSM_NO_ERROR);

    gen_key_args.key_identifier = &master_key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = HSM_KEY_INFO_MASTER;
    gen_key_args.out_key = work_area2;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    gen_key_args.key_identifier = &exp_fct_key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 1;
    gen_key_args.key_info = 0;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    st_butt_key_expansion.key_identifier = master_key_id;
    st_butt_key_expansion.expansion_fct_key_identifier = exp_fct_key_id;
    st_butt_key_expansion.expansion_fct_input = p256_exp_fct_input;
    st_butt_key_expansion.hash_value = 0;
    st_butt_key_expansion.pr_reconstruction_value = 0;
    st_butt_key_expansion.expansion_fct_input_size = 16;
    st_butt_key_expansion.hash_value_size = 0;
    st_butt_key_expansion.pr_reconstruction_value_size = 0;
    st_butt_key_expansion.flags = HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE | HSM_OP_ST_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF;
    st_butt_key_expansion.dest_key_identifier = &key_id;
    st_butt_key_expansion.output = work_area;
    st_butt_key_expansion.output_size = 64;
    st_butt_key_expansion.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    st_butt_key_expansion.expansion_fct_algo = HSM_CIPHER_ONE_GO_ALGO_AES_ECB;
    st_butt_key_expansion.key_group = 1;
    st_butt_key_expansion.key_info = 0;
    ASSERT_EQUAL(hsm_standalone_butterfly_key_expansion(sg0_key_mgmt_srv, &st_butt_key_expansion), HSM_NO_ERROR);

    // SM4 CCM
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("SM4 CCM Test \n");
    ITEST_LOG("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
    gen_key_args.key_group = 2U;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = NULL;
    auth_enc_gcm.iv_size = 0;
    auth_enc_gcm.aad = NULL;
    auth_enc_gcm.aad_size = 0;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT | HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
    auth_enc_gcm.input = sm4_ccm_ptx;
    auth_enc_gcm.output = work_area3;
    auth_enc_gcm.input_size = 23;
    auth_enc_gcm.output_size = 23+16+12;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);

    auth_enc_gcm.key_identifier = key_id;
    auth_enc_gcm.iv = &work_area3[23+16];
    auth_enc_gcm.iv_size = 12;
    auth_enc_gcm.aad = NULL;
    auth_enc_gcm.aad_size = 0;
    auth_enc_gcm.ae_algo = HSM_AUTH_ENC_ALGO_SM4_CCM;
    auth_enc_gcm.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_gcm.input = work_area3;
    auth_enc_gcm.output = work_area4;
    auth_enc_gcm.input_size = 23 + 16;
    auth_enc_gcm.output_size = 23;
    ASSERT_EQUAL(hsm_auth_enc(sg0_cipher_hdl, &auth_enc_gcm), HSM_NO_ERROR);

    // Key Generic crypto service
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Key Generic crypto service  \n");
    ITEST_LOG("---------------------------------------------------\n");

    key_generic_crypto_args.flags = 0u;
    ASSERT_EQUAL(hsm_open_key_generic_crypto_service(sg0_sess, &key_generic_crypto_args, &key_generic_crypto), HSM_NO_ERROR);

    key_generic_crypto_srv_args.key = sm4_ccm_key;
    key_generic_crypto_srv_args.key_size = 16u;
    key_generic_crypto_srv_args.iv = sm4_ccm_nonce;
    key_generic_crypto_srv_args.iv_size = 12u;
    key_generic_crypto_srv_args.aad = NULL;
    key_generic_crypto_srv_args.aad_size = 0u;
    key_generic_crypto_srv_args.tag_size = 16u;
    key_generic_crypto_srv_args.crypto_algo = HSM_KEY_GENERIC_ALGO_SM4_CCM;
    key_generic_crypto_srv_args.flags = HSM_KEY_GENERIC_FLAGS_ENCRYPT;
    key_generic_crypto_srv_args.input = sm4_ccm_ptx;
    key_generic_crypto_srv_args.output = work_area3;
    key_generic_crypto_srv_args.input_size = 23;
    key_generic_crypto_srv_args.output_size = 23+16;
    ASSERT_EQUAL(hsm_key_generic_crypto(key_generic_crypto, &key_generic_crypto_srv_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(sm4_ccm_ctx_tag, work_area3, 23+16), 0);

    key_generic_crypto_srv_args.key = sm4_ccm_key;
    key_generic_crypto_srv_args.key_size = 16u;
    key_generic_crypto_srv_args.iv = sm4_ccm_nonce;
    key_generic_crypto_srv_args.iv_size = 12u;
    key_generic_crypto_srv_args.aad = NULL;
    key_generic_crypto_srv_args.aad_size = 0u;
    key_generic_crypto_srv_args.tag_size = 16u;
    key_generic_crypto_srv_args.crypto_algo = HSM_KEY_GENERIC_ALGO_SM4_CCM;
    key_generic_crypto_srv_args.flags = HSM_KEY_GENERIC_FLAGS_DECRYPT;
    key_generic_crypto_srv_args.input = sm4_ccm_ctx_tag;
    key_generic_crypto_srv_args.output = work_area4;
    key_generic_crypto_srv_args.input_size = 23 +16;
    key_generic_crypto_srv_args.output_size = 23;
    ASSERT_EQUAL(hsm_key_generic_crypto(key_generic_crypto, &key_generic_crypto_srv_args), HSM_NO_ERROR);
    ASSERT_EQUAL(memcmp(sm4_ccm_ptx, work_area4, 23), 0);

    // Close all services and sessions
    ITEST_LOG("\n---------------------------------------------------\n");
    ITEST_LOG("Closing services and sessions\n");
    ITEST_LOG("---------------------------------------------------\n");

    ASSERT_EQUAL(hsm_close_hash_service(hash_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_signature_verification_service(sv0_sig_ver_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_signature_verification_service(sv1_sig_ver_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_signature_generation_service(sg0_sig_gen_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_signature_generation_service(sg1_sig_gen_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_sm2_eces_service(sg0_sm2_eces_hdl), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_sm2_eces_service(sg1_sm2_eces_hdl), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_mac_service(sg0_mac_hdl), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_key_management_service(sg0_key_mgmt_srv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_management_service(sg1_key_mgmt_srv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_key_store_service(sg0_key_store_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_key_store_service(sg1_key_store_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_rng_service(sv0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_rng_service(sv1_rng_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_rng_service(sg0_rng_serv), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_rng_service(sg1_rng_serv), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_key_generic_crypto_service(key_generic_crypto), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_session(sg0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sg1_sess), HSM_NO_ERROR);
    ASSERT_EQUAL(hsm_close_session(sv1_sess), HSM_NO_ERROR);
    ASSERT_NOT_EQUAL(stop_nvm_v2x(), NVM_STATUS_STOPPED);
    return TRUE_TEST;
}
