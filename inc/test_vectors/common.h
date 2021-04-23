
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Max public key size is 96 byte for P384 */
#define MAX_KEY_SIZE     (96)
/*
 * Max size for msg is 332 bytes.
 *  for SM2 test:
 *   - 300 bytes of message
 *   -  32 bytes of z_dgst
 */
#define MAX_MSG_SIZE     (332)
/* MAX_KEY_SIZE + 1 byte for Ry */
#define MAX_SIG_SIZE     ((MAX_KEY_SIZE) + 1)
/* Digest size is half of publick key size */
#define MAX_DGST_SIZE    (MAX_KEY_SIZE/2)

typedef struct {
    int curve;
    uint8_t message[MAX_MSG_SIZE];
    uint32_t message_length;
    uint8_t digest[MAX_DGST_SIZE];
    uint8_t public_key[MAX_KEY_SIZE];
    uint8_t signature[MAX_SIG_SIZE];
} test_data_verify_t;

#endif /* __COMMON_H__ */
