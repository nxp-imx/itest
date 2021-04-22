#ifndef CIPHER_AES_H
#define CIPHER_AES_H

#define ICRYPTO_AES_128_ECB 0x0
#define ICRYPTO_AES_128_CBC 0x1
#define ICRYPTO_AES_128_GCM 0x2

#define ICRYPTO_AES_192_ECB 0x10
#define ICRYPTO_AES_192_CBC 0x11
#define ICRYPTO_AES_192_GCM 0x12

#define ICRYPTO_AES_256_ECB 0x20
#define ICRYPTO_AES_256_CBC 0x21
#define ICRYPTO_AES_256_GCM 0x22

#define ICRYPTO_SM4_128_ECB 0x30
#define ICRYPTO_SM4_128_CBC 0x31

int icrypto_cipher_one_go(unsigned char *in, unsigned char *out, int size_in, char cipher, unsigned char *key, unsigned char *iv);

#endif