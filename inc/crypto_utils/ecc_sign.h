#ifndef ECC_SIGN_H
#define ECC_SIGN_H

int icrypto_generate_key_pair(int curve, unsigned char *outpub, int *size_pub, unsigned char *outpriv, int *size_priv);
// if dgst is null -> input as digest
int icrypto_generate_signature(int curve, unsigned char *privk, int size_privk, unsigned char *in, int size, char *dgst, unsigned char *out_sign, int *sign_size);
int icrypto_verify_signature(int curve, unsigned char *pubk, int size_pubk, unsigned char *privk, int size_privk, unsigned char *in, int size, char *dgst, unsigned char *out_sign, int sign_size);
int icrypto_ECDH_compute_key(unsigned char *ecdh_secret, int ecdh_secret_size, unsigned char *remote_pubk, int pubk_size, int curve, unsigned char *privk, int size_privk);

#endif