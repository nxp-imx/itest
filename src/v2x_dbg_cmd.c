#include "itest.h"

typedef struct {
    uint32_t uheader;
    uint16_t request_bm;
    uint16_t param;
} v2x_dbg_req_t;

#define V2XP_DBG_REQ_CLK_GATING_DISABLE ((uint16_t)(1UL << 0))
#define V2XP_DBG_REQ_CLK_GATING_ENABLE  ((uint16_t)(1UL << 1))
#define V2XP_DBG_REQ_SCHED_STATUS       ((uint16_t)(1UL << 2))
#define V2XP_DBG_REQ_CALL_STACK         ((uint16_t)(1UL << 3))
#define V2XP_DBG_REQ_HEAP_WALK          ((uint16_t)(1UL << 4))

#define V2XP_DBG_REQ_PRIMARY            ((uint16_t)(1UL << 14))
#define V2XP_DBG_REQ_SECONDARY          ((uint16_t)(1UL << 15))

typedef struct {
    uint32_t uheader;
    uint32_t rsp_code;
} v2x_dbg_ind_t;

#define SV0 0
#define SV1 1
#define SG0 3
#define SG1 4

static int v2x_heap_walk(uint16_t mu, uint16_t pri_sec) {

    v2x_dbg_req_t req;
    v2x_dbg_ind_t rsp;

    req.request_bm = V2XP_DBG_REQ_HEAP_WALK | (pri_sec == 0 ? V2XP_DBG_REQ_PRIMARY : V2XP_DBG_REQ_SECONDARY);

    switch (mu)
    {
    case SV0:
        req.uheader = 0x18BB0202;
        ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SV0, 0), sizeof(v2x_dbg_ind_t));
        break;
    case SV1:
        req.uheader = 0x19BB0202;
        ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SV1, 0), sizeof(v2x_dbg_ind_t));
        break;
    case SG0:
        req.uheader = 0x1DBB0202;
        ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SG0, 0), sizeof(v2x_dbg_ind_t));
        break;
    case SG1:
        req.uheader = 0x1EBB0202;
        ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SG1, 0), sizeof(v2x_dbg_ind_t));
        break;    
    default:
        break;
    }
    return TRUE_TEST;
}

static int v2x_disable_cg_(uint16_t disable) {

    v2x_dbg_req_t req;
    v2x_dbg_ind_t rsp;

    req.request_bm = disable == 0 ? V2XP_DBG_REQ_CLK_GATING_DISABLE : V2XP_DBG_REQ_CLK_GATING_ENABLE;

    req.uheader = 0x18BB0202;
    ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SV0, 0), sizeof(v2x_dbg_ind_t));

    return TRUE_TEST;
}

static int v2x_call_stack_(uint16_t pri_sec) {

    v2x_dbg_req_t req;
    v2x_dbg_ind_t rsp;

    req.request_bm = V2XP_DBG_REQ_CALL_STACK | (pri_sec == 0 ? V2XP_DBG_REQ_PRIMARY : V2XP_DBG_REQ_SECONDARY);

    req.uheader = 0x18BB0202;
    ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SV0, 0), sizeof(v2x_dbg_ind_t));

    return TRUE_TEST;
}

static int v2x_sched_stat_(uint16_t pri_sec) {

    v2x_dbg_req_t req;
    v2x_dbg_ind_t rsp;

    req.request_bm = V2XP_DBG_REQ_SCHED_STATUS | (pri_sec == 0 ? V2XP_DBG_REQ_PRIMARY : V2XP_DBG_REQ_SECONDARY);

    req.uheader = 0x18BB0202;
    ASSERT_EQUAL(send_rcv_msg((uint32_t *)&req, (uint32_t *)&rsp, sizeof(v2x_dbg_req_t), sizeof(v2x_dbg_ind_t), MU_CHANNEL_V2X_SV0, 0), sizeof(v2x_dbg_ind_t));

    return TRUE_TEST;
}

int v2x_heap_walk_sv0(void) {
    return v2x_heap_walk(SV0, 0);
}

int v2x_heap_walk_sv1(void) {
    return v2x_heap_walk(SV1, 0);
}

int v2x_heap_walk_sg0(void) {
    return v2x_heap_walk(SG0, 0);
}

int v2x_heap_walk_sg1(void) {
    return v2x_heap_walk(SG1, 0);
}

int v2x_heap_walk_v2xs(void) {
    return v2x_heap_walk(SG1, 1);
}

int v2x_disable_cg(void) {
    return v2x_disable_cg_(0);
}

int v2x_enable_cg(void) {
    return v2x_disable_cg_(0);
}

int v2x_call_stack_v2xp(void) {
    return v2x_call_stack_(0);
}

int v2x_call_stack_v2xs(void) {
    return v2x_call_stack_(1);
}

int v2x_sched_stat_v2xp(void) {
    return v2x_sched_stat_(0);
}

int v2x_sched_stat_v2xs(void) {
    return v2x_sched_stat_(1);
}