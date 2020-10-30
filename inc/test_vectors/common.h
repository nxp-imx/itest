
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

/* Max size is 48 byte for P384 */
#define MAX_KEY_SIZE    (48)

typedef struct {
    int curve;
    uint8_t message[300];
    uint32_t message_length;
    uint8_t digest[MAX_KEY_SIZE];
    uint8_t public_key[MAX_KEY_SIZE*2];
    uint8_t signature[MAX_KEY_SIZE*2];
} test_data_verify_t;

#endif /* __COMMON_H__ */
