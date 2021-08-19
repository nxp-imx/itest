#ifndef IMX8_TESTS_LIST_H
#define IMX8_TESTS_LIST_H

#include "itest.h"

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
int v2x_auth_enc_sm4_ccm_test(void);
int v2x_butterfly_key_exp_001(void);
int v2x_butterfly_key_exp_002(void);
int v2x_butterfly_key_exp_003(void);
int v2x_st_butterfly_key_exp_001(void);
int v2x_st_butterfly_key_exp_002(void);
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
int v2x_pub_key_reconstruction_sm2(void);
int v2x_sm2_st_butt_key_exp_swap_001(void);
int v2x_sm2_st_butt_key_exp_swap_002(void);
int v2x_generic_crypto_sm4_ccm_test(void);
int v2x_st_butt_key_exp_swap_001(void);
int v2x_all_services(void);

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
int v2x_heap_walk_sv0(void);
int v2x_heap_walk_sv1(void);
int v2x_heap_walk_sg0(void);
int v2x_heap_walk_sg1(void);
int v2x_heap_walk_v2xs(void);
int v2x_disable_cg(void);
int v2x_enable_cg(void);
int v2x_call_stack_v2xp(void);
int v2x_call_stack_v2xs(void);
int v2x_sched_stat_v2xp(void);
int v2x_sched_stat_v2xs(void);
int openssl_sanity(void);

testsuite imx8_ts[] = {
/*=========================================================================================================================
====================================================== V2X ================================================================
=========================================================================================================================*/
    {v2x_chunk_swap_001,                     "v2x_chunk_swap_001",                     DXL_A1 | DXL_B0},
    {v2x_rng_srv_001,                        "v2x_rng_srv_001",                        DXL_A1 | DXL_B0},
    {v2x_ks_import_export_001,               "v2x_ks_import_export_001",               DXL_A1 | DXL_B0},
    {v2x_ks_import_export_001_part2,         "v2x_ks_import_export_001_part2",         DXL_A1 | DXL_B0},
    {v2x_ks_create_bad_id_001,               "v2x_ks_create_bad_id_001",               DXL_A1 | DXL_B0},
    {v2x_ks_bad_auth_001,                    "v2x_ks_bad_auth_001",                    DXL_A1 | DXL_B0},
    {v2x_ks_no_update_001,                   "v2x_ks_no_update_001",                   DXL_A1 | DXL_B0},
    {v2x_ks_no_update_001_part2,             "v2x_ks_no_update_001_part2",             DXL_A1 | DXL_B0},
    {v2x_ks_update_001,                      "v2x_ks_update_001",                      DXL_A1 | DXL_B0},
    {v2x_ks_update_001_part2,                "v2x_ks_update_001_part2",                DXL_A1 | DXL_B0},
    {v2x_prepare_signature_001,              "v2x_prepare_signature_001",              DXL_A1 | DXL_B0},
    {v2x_prepare_signature_002,              "v2x_prepare_signature_002",              DXL_A1 | DXL_B0},
    {v2x_prepare_signature_003,              "v2x_prepare_signature_003",              DXL_A1 | DXL_B0},
    {v2x_hash_one_go_all_001,                "v2x_hash_one_go_all_001",                DXL_A1 | DXL_B0},
    {v2x_sm2_eces_001,                       "v2x_sm2_eces_001",                       DXL_A1 | DXL_B0},
    {v2x_sm2_eces_002,                       "v2x_sm2_eces_002",                       DXL_A1 | DXL_B0},
    {v2x_sm2_eces_003,                       "v2x_sm2_eces_003",                       DXL_A1 | DXL_B0},
    {v2x_pub_key_reconstruction_sm2,         "v2x_pub_key_reconstruction_sm2",         DXL_A1 | DXL_B0},
    {v2x_pub_key_recovery_001,               "v2x_pub_key_recovery_001",               DXL_A1 | DXL_B0},
    {v2x_pub_key_recovery_001_part2,         "v2x_pub_key_recovery_001_part2",         DXL_A1 | DXL_B0},
    {v2x_cipher_aes_ecb_cbc_001,             "v2x_cipher_aes_ecb_cbc_001",             DXL_A1 | DXL_B0},
    {v2x_aes_gcm_iv_001,                     "v2x_aes_gcm_iv_001",                     DXL_A1 | DXL_B0},
    {v2x_auth_enc_test,                      "v2x_auth_enc_test",                      DXL_A1 | DXL_B0},
    {v2x_auth_enc_sm4_ccm_test,              "v2x_auth_enc_sm4_ccm_test",              DXL_A1 | DXL_B0},
    {v2x_pub_key_decompression_001,          "v2x_pub_key_decompression_001",          DXL_A1 | DXL_B0},
    {v2x_butterfly_key_exp_001,              "v2x_butterfly_key_exp_001",              DXL_A1 | DXL_B0},
    {v2x_butterfly_key_exp_002,              "v2x_butterfly_key_exp_002",              DXL_A1 | DXL_B0},
    {v2x_butterfly_key_exp_003,              "v2x_butterfly_key_exp_003",              DXL_A1 | DXL_B0},
    {v2x_st_butterfly_key_exp_001,           "v2x_st_butterfly_key_exp_001",           DXL_A1 | DXL_B0},
    {v2x_st_butterfly_key_exp_002,           "v2x_st_butterfly_key_exp_002",           DXL_A1 | DXL_B0},
    {v2x_sm2_st_butt_key_exp_swap_001,       "v2x_sm2_st_butt_key_exp_swap_001",       DXL_A1 | DXL_B0},
    {v2x_sm2_st_butt_key_exp_swap_002,       "v2x_sm2_st_butt_key_exp_swap_002",       DXL_A1 | DXL_B0},
    {v2x_st_butt_key_exp_swap_001,           "v2x_st_butt_key_exp_swap_001",           DXL_A1 | DXL_B0},
    //{v2x_parallel_sign_gen_key_gen_001,      "v2x_parallel_sign_gen_key_gen_001",      DXL_A1 | DXL_B0},  //NVM issue in // stress test
    //{v2x_parallel_sign_gen_key_gen_002,      "v2x_parallel_sign_gen_key_gen_002",      DXL_A1 | DXL_B0},  //NVM issue in // stress test
    {v2x_parallel_sign_gen_ver_001,          "v2x_parallel_sign_gen_ver_001",          DXL_A1 | DXL_B0},
    {v2x_rex_stress_v2xp_001,                "v2x_rex_stress_v2xp_001",                DXL_A1 | DXL_B0},
    {v2x_cipher_ccm_perf,                    "v2x_cipher_ccm_perf",                    DXL_A1 | DXL_B0},
    {v2x_sign_gen_verify_perf,               "v2x_sign_gen_verify_perf",               DXL_A1 | DXL_B0},
    {v2x_generic_crypto_sm4_ccm_test,        "v2x_generic_crypto_sm4_ccm_test",        DXL_A1 | DXL_B0},
    {v2x_all_services,                       "v2x_all_services",                       DXL_A1 | DXL_B0},
    {v2x_ping_all_mu,                        "v2x_ping_all_mu",                        DXL_A1 | DXL_B0},

/*=========================================================================================================================
====================================================== SECO ===============================================================
=========================================================================================================================*/

    {seco_ks_import_export_001,              "seco_ks_import_export_001",              DXL_A1 | DXL_B0 | QXP_C0},
    {seco_ks_import_export_001_part2,        "seco_ks_import_export_001_part2",        DXL_A1 | DXL_B0 | QXP_C0},
    {seco_ks_bad_auth_001,                   "seco_ks_bad_auth_001",                   DXL_A1 | DXL_B0 | QXP_C0},
    {seco_aes_gcm_iv_001,                    "seco_aes_gcm_iv_001",                    DXL_A1 | DXL_B0 | QXP_C0},
    {seco_auth_enc_test,                     "seco_auth_enc_test",                     DXL_A1 | DXL_B0 | QXP_C0},
    {seco_prepare_signature_001,             "seco_prepare_signature_001",             DXL_A1 | DXL_B0 | QXP_C0},
    {seco_prepare_signature_002,             "seco_prepare_signature_002",             DXL_A1 | DXL_B0 | QXP_C0},
    {seco_prepare_signature_003,             "seco_prepare_signature_003",             DXL_A1 | DXL_B0 | QXP_C0},
    {seco_she_load_key_001,                  "seco_she_load_key_001",                  DXL_A1 | DXL_B0 | QXP_C0 | QXP_B0},

/*=========================================================================================================================
====================================================== V2X PERF ===========================================================
=========================================================================================================================*/

    {v2x_perf_sig_gen_nistp256_ops,          "v2x_perf_sig_gen_nistp256_ops",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_nistp256_lat,          "v2x_perf_sig_gen_nistp256_lat",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_nistp384_ops,          "v2x_perf_sig_gen_nistp384_ops",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_nistp384_lat,          "v2x_perf_sig_gen_nistp384_lat",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_sm2_ops,               "v2x_perf_sig_gen_sm2_ops",               DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_sm2_lat,               "v2x_perf_sig_gen_sm2_lat",               DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_r1p256_ops,  "v2x_perf_sig_gen_brainpool_r1p256_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_r1p256_lat,  "v2x_perf_sig_gen_brainpool_r1p256_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_r1p384_ops,  "v2x_perf_sig_gen_brainpool_r1p384_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_r1p384_lat,  "v2x_perf_sig_gen_brainpool_r1p384_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_t1p256_ops,  "v2x_perf_sig_gen_brainpool_t1p256_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_t1p256_lat,  "v2x_perf_sig_gen_brainpool_t1p256_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_t1p384_ops,  "v2x_perf_sig_gen_brainpool_t1p384_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_gen_brainpool_t1p384_lat,  "v2x_perf_sig_gen_brainpool_t1p384_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_r1p256_ops,  "v2x_perf_sig_ver_brainpool_r1p256_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_r1p256_lat,  "v2x_perf_sig_ver_brainpool_r1p256_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_r1p384_ops,  "v2x_perf_sig_ver_brainpool_r1p384_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_r1p384_lat,  "v2x_perf_sig_ver_brainpool_r1p384_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_t1p256_ops,  "v2x_perf_sig_ver_brainpool_t1p256_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_t1p256_lat,  "v2x_perf_sig_ver_brainpool_t1p256_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_t1p384_ops,  "v2x_perf_sig_ver_brainpool_t1p384_ops",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_brainpool_t1p384_lat,  "v2x_perf_sig_ver_brainpool_t1p384_lat",  DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_nistp256_ops,          "v2x_perf_sig_ver_nistp256_ops",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_nistp384_ops,          "v2x_perf_sig_ver_nistp384_ops",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_sm2_ops,               "v2x_perf_sig_ver_sm2_ops",               DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_sm2_lat,               "v2x_perf_sig_ver_sm2_lat",               DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_nistp256_lat,          "v2x_perf_sig_ver_nistp256_lat",          DXL_A1 | DXL_B0},
    {v2x_perf_sig_ver_nistp384_lat,          "v2x_perf_sig_ver_nistp384_lat",          DXL_A1 | DXL_B0},
    {v2x_perf_pub_key_decompression_nistp256, "v2x_perf_pub_key_decompression_nistp256", DXL_A1 | DXL_B0},
    {v2x_perf_pub_key_reconstruction_nistp256, "v2x_perf_pub_key_reconstruction_nistp256", DXL_A1 | DXL_B0},

/*=========================================================================================================================
======================================================= DBG CMD ===========================================================
=========================================================================================================================*/

    {openssl_sanity,                         "openssl_sanity",                         DXL_A1 | DXL_B0 | QXP_C0 | QXP_B0 | DBG},
    {v2x_heap_walk_sv0,                      "v2x_heap_walk_sv0",                      DBG},
    {v2x_heap_walk_sv1,                      "v2x_heap_walk_sv1",                      DBG},
    {v2x_heap_walk_sg0,                      "v2x_heap_walk_sg0",                      DBG},
    {v2x_heap_walk_sg1,                      "v2x_heap_walk_sg1",                      DBG},
    {v2x_heap_walk_v2xs,                     "v2x_heap_walk_v2xs",                     DBG},
    {v2x_disable_cg,                         "v2x_disable_cg",                         DBG},
    {v2x_enable_cg,                          "v2x_enable_cg",                          DBG},
    {v2x_call_stack_v2xp,                    "v2x_call_stack_v2xp",                    DBG},
    {v2x_call_stack_v2xs,                    "v2x_call_stack_v2xs",                    DBG},
    {v2x_sched_stat_v2xp,                    "v2x_sched_stat_v2xp",                    DBG},
    {v2x_sched_stat_v2xs,                    "v2x_sched_stat_v2xs",                    DBG},

    {NULL, NULL, DXL_A1},
};
#endif
