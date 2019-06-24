/**
 * \file sm4.h
 */
#ifndef SM4_HUI_H_
#define SM4_HUI_H_

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0



#ifdef __cplusplus
extern "C" {
#endif




void SetKey_SM4(unsigned long Extendkey[32], unsigned char key[16], int EncOrDec);

void Crypto_ECB_SM4(unsigned char *input, int inputLen, unsigned char *Key, int EncOrDec, unsigned char *output);

void Crypto_CBC_SM4(unsigned char *input, int inputLen, unsigned char *key, int EncOrDec, unsigned char *output, unsigned char IV[16]);



#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
