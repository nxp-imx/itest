#include "itest.h"


// proof of concept
int v2x_ping_all_mu(void) {

    uint32_t ping_sv0 = 0x18010102;
    uint32_t ping_sv1 = 0x19010102;
    uint32_t ping_sg0 = 0x1d010102;
    uint32_t ping_sg1 = 0x1e010102;
    uint32_t ping_v2x_she = 0x1a010102;
    uint32_t ping_rsp[2] = {0, 0};

    ASSERT_EQUAL(send_rcv_msg(&ping_sv0, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SV0, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sv0, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SV0, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sv0, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SV0, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sv0, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SV0, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sv1, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SV1, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sg0, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SG0, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_sg1, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SG1, 0), sizeof(ping_rsp));
    ASSERT_EQUAL(send_rcv_msg(&ping_v2x_she, ping_rsp, sizeof(uint32_t), sizeof(ping_rsp), MU_CHANNEL_V2X_SHE, 0), sizeof(ping_rsp));

    return TRUE_TEST;
}