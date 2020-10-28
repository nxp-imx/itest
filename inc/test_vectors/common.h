
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdint.h>

#define MAX_KEY_SIZE                                                    (66)

typedef struct {
    int curve;
    uint8_t message[300];
    uint32_t message_length;
    uint8_t digest[MAX_KEY_SIZE];
    uint8_t public_key[MAX_KEY_SIZE*2];
    uint8_t signature[MAX_KEY_SIZE*2];
} test_data_verify_t;

static inline double get_current_time(void) {
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);

    return now.tv_sec + now.tv_nsec * 1E-9;
}

#endif /* __COMMON_H__ */
