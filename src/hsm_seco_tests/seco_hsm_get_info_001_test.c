#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
// requirement: Reuse the AES key from ks for encryption and decryption using the same ks imported from NVM

int seco_hsm_get_info_001(void){

    open_session_args_t args;
    op_get_info_args_t get_info_args;
    hsm_hdl_t sess;

    uint32_t user_id;
    uint8_t uid_chip;
    uint16_t monotonic_cnt;
    uint16_t lc;
    uint32_t vers;
    uint32_t vers_ext;
    uint8_t fips;
    
    // SECO OPEN SESSION
    args.session_priority = 0;
    args.operating_mode = 0;
    ASSERT_EQUAL(hsm_open_session(&args, &sess), HSM_NO_ERROR);

    get_info_args.user_sab_id = &user_id;
    get_info_args.chip_unique_id = &uid_chip;
    get_info_args.chip_monotonic_counter = &monotonic_cnt;
    get_info_args. chip_life_cycle = &lc;
    get_info_args.version = &vers;
    get_info_args.version_ext = &vers_ext;
    get_info_args.fips_mode = &fips;
    ASSERT_EQUAL(hsm_get_info(sess, &get_info_args), HSM_NO_ERROR);

    ASSERT_EQUAL(hsm_close_session(sess), HSM_NO_ERROR);
    return TRUE_TEST;
}

