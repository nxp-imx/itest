#ifndef TEST_API_H
#define TEST_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "hsm_api.h"
#include "she_api.h"
#include "../src/seco_os_abs.h"
#include "seco_nvm.h"

/*===========Test API============*/
#define QXP_C0 0x1
#define QXP_B0 0x2
#define DXL_A1 0x4

#define TRUE_TEST 1
#define FALSE_TEST 0

/* Log macros and functions */
void outputLog(const char *const format, ...);

#define ITEST_LOG(...)  outputLog(__VA_ARGS__)

/*======================ASSERT FAILURE ABORT======================*/
#define ASSERT_TRUE(x)  if (!x) {ITEST_LOG("Fail ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_FALSE(x) if (x) {ITEST_LOG("Fail ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);raise(SIGINT);while(1);}
#define ASSERT_EQUAL(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }
#define ASSERT_NOT_EQUAL(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGINT); \
        while(1); \
    }

#define ASSERT_TRUE_HIGH_API(x)  if (!x) {ITEST_LOG("Fail in subsequence ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);break;}
#define ASSERT_FALSE_HIGH_API(x) if (x) {ITEST_LOG("Fail in subsequence ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__);break;}

#define ASSERT_EQUAL_HIGH_API(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail in subsequence ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        break; \
    }
#define ASSERT_NOT_HIGH_API(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail in subsequence ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        break; \
    }


/*======================ASSERT FAILURE CONTINUE======================*/
#define ASSERT_TRUE_W(x)  if (!x) {ITEST_LOG("Fail ==> #x expected True => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_FALSE_W(x) if (x) {ITEST_LOG("Fail ==> #x expected False => " );ITEST_LOG(#x);ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); while(1) raise(SIGUSR1);}
#define ASSERT_EQUAL_W(x, y) \
    if ( (x) != (y)) { \
        ITEST_LOG("assert_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X != 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }
#define ASSERT_NOT_EQUAL_W(x, y) \
    if ( (x) == (y)) { \
        ITEST_LOG("assert_not_equal Fail ==> "); \
        /*ITEST_LOG("0x%08X = 0x%08X", (unsigned int)x, (unsigned int)y);*/ \
        ITEST_LOG(" @%s line:%d\n",__FILE__,__LINE__); \
        raise(SIGUSR1); \
    }

#define ITEST_CHECK_KPI_LATENCY(got, thr) \
do { \
    ITEST_LOG("KPI: Max Latency [us]: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) > (thr), 0); \
} \
while(0)

#define ITEST_CHECK_KPI_OPS(got, thr) \
do { \
    ITEST_LOG("KPI: Operations per second: %d/%d (Got/Threshold)\n", (uint32_t)got, (uint32_t)thr); \
    ASSERT_EQUAL_W((got) < (thr), 0); \
} \
while(0)

/* Key sizes */
#define KEY_ECDSA_SM2_SIZE                    (0x40u)
#define KEY_ECDSA_NIST_P256_SIZE              (0x40u)
#define KEY_ECDSA_NIST_P384_SIZE              (0x60u)
#define KEY_ECDSA_BRAINPOOL_R1_256_SIZE       (0x40u)
#define KEY_ECDSA_BRAINPOOL_R1_384_SIZE       (0x60u)
#define KEY_ECDSA_BRAINPOOL_T1_256_SIZE       (0x40u)
#define KEY_ECDSA_BRAINPOOL_T1_384_SIZE       (0x60u)
/* Signature sizes */
#define SIGNATURE_ECDSA_SM2_SIZE              (0x40u)
#define SIGNATURE_ECDSA_NIST_P256_SIZE        (0x40u)
#define SIGNATURE_ECDSA_NIST_P384_SIZE        (0x60u)
#define SIGNATURE_ECDSA_BRAINPOOL_R1_256_SIZE (0x40u)
#define SIGNATURE_ECDSA_BRAINPOOL_R1_384_SIZE (0x60u)
#define SIGNATURE_ECDSA_BRAINPOOL_T1_256_SIZE (0x40u)
#define SIGNATURE_ECDSA_BRAINPOOL_T1_384_SIZE (0x60u)
/* Digest sizes */
#define DGST_SM3_SIZE        (0x20u)
#define DGST_NIST_P256_SIZE  (0x20u)
#define DGST_NIST_P384_SIZE  (0x30u)
#define DGST_SHA_256_SIZE    (0x20u)
#define DGST_SHA_384_SIZE    (0x30u)

typedef struct {
    struct timespec ts1; // for total iterations
    struct timespec ts2; // for total iterations
    uint64_t time_us;
    uint64_t min_time_us;
    uint64_t max_time_us;
    uint32_t nb_iter;
    uint32_t op_sec;
    uint32_t t_per_op;
} timer_perf_t;

typedef struct{
    int (*tc_ptr)(void);
    char *name;
    int target;
} testsuite;

typedef struct{
    char *test_name;
    int nb_assert_fails;
    testsuite *ts;

    char *ker_dl_link;
    char *ram_dl_link;
    char *mod_dl_link;
    char *dtb_dl_link;
    char *ts_dl_link;
    char *bootimg_dl_link;
} itest_ctx_t;

/*==============NVM==============*/
hsm_err_t start_nvm_seco(void);
hsm_err_t start_nvm_v2x(void);
hsm_err_t start_nvm_she_seco(void);
hsm_err_t stop_nvm_v2x(void);
hsm_err_t stop_nvm_seco(void);
hsm_err_t stop_nvm_she_seco(void);
uint32_t clear_v2x_nvm(void);
uint32_t clear_seco_nvm(void);
uint32_t clear_she_seco_nvm(void);
/*===========TEST CTX============*/
size_t save_test_ctx(void *ctx, size_t count, char *file);
size_t load_test_ctx(void *ctx, size_t count, char *file);
size_t randomize(void *out, size_t count);
/*==============PERF=============*/
void init_timer(timer_perf_t *timer);
void start_timer(timer_perf_t *timer);
void stop_timer(timer_perf_t *timer);
void finalize_timer(timer_perf_t *timer, uint32_t nb_iter);
uint64_t timespec_elapse_usec(struct timespec *ts1, struct timespec *ts2);
void print_perf(timer_perf_t *timer);
/*==========LOW LEVEL API========*/
uint32_t send_msg(uint32_t *msg, uint32_t size, uint32_t mu_id, uint8_t nmi);
uint32_t rcv_msg(uint32_t *msg, uint32_t size, uint32_t mu_id);
uint32_t send_rcv_msg(uint32_t *msg_in, uint32_t *msg_out, uint32_t size_in, uint32_t size_out, uint32_t mu_id, uint8_t nmi);
/*==========HIGH LEVEL SENTINEL API*/
int get_key_param(hsm_key_type_t key_type,hsm_signature_scheme_id_t *scheme_id, uint16_t *size_pubk, uint16_t *size_privk);
int isen_kek_generation(hsm_hdl_t sg0_key_mgmt_srv, uint8_t *kek_data, uint32_t key_size, uint32_t *kek_handle);
int isen_hsm_key_injection(hsm_hdl_t sg0_key_mgmt_srv, uint32_t *key_id, hsm_key_type_t key_type, uint8_t *key_in,
                        uint32_t kek_handle, uint8_t *kek_data, uint32_t key_size);
/*==========Tests list===========*/
int v2x_chunk_swap_001(void);
int v2x_rng_srv_001(void);
int v2x_ks_import_export_001(void);
int v2x_ks_import_export_001_part2(void);
int v2x_ks_bad_auth_001(void);
int v2x_ks_no_update_001(void);
int v2x_ks_no_update_001_part2(void);
int v2x_ks_update_001(void);
int v2x_ks_update_001_part2(void);
int v2x_pub_key_recovery_001(void);
int v2x_pub_key_recovery_001_part2(void);
int v2x_cipher_aes_ecb_cbc_001(void);
int v2x_aes_gcm_iv_001(void);
int v2x_pub_key_decompression_001(void);
int v2x_auth_enc_test(void);
int v2x_butterfly_key_exp_001(void);
int v2x_parallel_sign_gen_ver_001(void);
int v2x_parallel_sign_gen_key_gen_001(void);
int v2x_parallel_sign_gen_key_gen_002(void);
int v2x_rex_stress_v2xp_001(void);
int v2x_prepare_signature_001(void);
int v2x_prepare_signature_002(void);
int v2x_prepare_signature_003(void);
int v2x_cipher_ccm_perf(void);
int v2x_sign_gen_verify_perf(void);
int v2x_hash_one_go_all_001(void);
int v2x_ks_create_bad_id_001(void);
int v2x_sm2_eces_001(void);
int v2x_sm2_eces_002(void);
int v2x_sm2_eces_003(void);

int v2x_perf_sig_gen_nistp256_ops(void);
int v2x_perf_sig_gen_nistp256_lat(void);
int v2x_perf_sig_gen_nistp384_ops(void);
int v2x_perf_sig_gen_nistp384_lat(void);
int v2x_perf_sig_gen_sm2_ops(void);
int v2x_perf_sig_gen_sm2_lat(void);
int v2x_perf_sig_gen_brainpool_r1p256_ops(void);
int v2x_perf_sig_gen_brainpool_r1p256_lat(void);
int v2x_perf_sig_gen_brainpool_r1p384_ops(void);
int v2x_perf_sig_gen_brainpool_r1p384_lat(void);
int v2x_perf_sig_gen_brainpool_t1p256_ops(void);
int v2x_perf_sig_gen_brainpool_t1p256_lat(void);
int v2x_perf_sig_gen_brainpool_t1p384_ops(void);
int v2x_perf_sig_gen_brainpool_t1p384_lat(void);
int v2x_perf_sig_ver_nistp256_ops(void);
int v2x_perf_sig_ver_nistp384_ops(void);
int v2x_perf_sig_ver_sm2_ops(void);
int v2x_perf_sig_ver_nistp256_lat(void);
int v2x_perf_sig_ver_nistp384_lat(void);
int v2x_perf_sig_ver_sm2_lat(void);
int v2x_perf_sig_ver_brainpool_r1p256_ops(void);
int v2x_perf_sig_ver_brainpool_r1p256_lat(void);
int v2x_perf_sig_ver_brainpool_r1p384_ops(void);
int v2x_perf_sig_ver_brainpool_r1p384_lat(void);
int v2x_perf_sig_ver_brainpool_t1p256_ops(void);
int v2x_perf_sig_ver_brainpool_t1p256_lat(void);
int v2x_perf_sig_ver_brainpool_t1p384_ops(void);
int v2x_perf_sig_ver_brainpool_t1p384_lat(void);
int v2x_perf_pub_key_decompression_nistp256(void);
int v2x_perf_pub_key_reconstruction_nistp256(void);

// seco hsm
int seco_ks_import_export_001(void);
int seco_ks_import_export_001_part2(void);
int seco_ks_bad_auth_001(void);
int seco_aes_gcm_iv_001(void);
int seco_auth_enc_test(void);
int seco_prepare_signature_001(void);
int seco_prepare_signature_002(void);
int seco_prepare_signature_003(void);
// seco she
int seco_she_load_key_001(void);
/*===============================*/
int v2x_ping_all_mu(void);
int openssl_sanity(void);
#endif
