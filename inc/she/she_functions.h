/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef SHE_FUNCTIONS_H
#define SHE_FUNCTIONS_H

#include "hsm_api.h"
#include "common/global_info.h"
#include "common/perf.h"
#include "she_api.h"
#include "internal/she_key.h"

#define MU_CHANNEL_PLAT_SHE       (0x01u)

extern she_hdl_t she_session_hdl, key_store_hdl;

/*===========V2X_SHE KEY UPDATE============*/
she_err_t key_update_test(she_hdl_t utils_handle);
she_err_t she_cmac_test(she_hdl_t mac_hdl, uint32_t key_identifier,
			uint8_t *payload, uint16_t payload_size,
			uint8_t *mac, hsm_op_mac_flags_t flags,
			uint32_t session_hdl);
#endif
