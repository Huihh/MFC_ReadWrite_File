#ifndef _PYDES_H
#define _PYDES_H


#define MODE_ENCRYPT 1
#define MODE_DECRYPT 0

void Lib_Des(unsigned char *input,unsigned char *output,unsigned char *key,int mode);
void Lib_DES3_16(unsigned char *dat,unsigned char *key,int mode);
void Lib_DES3_24(unsigned char *dat,unsigned char *key,int mode);
void Lib_DES(unsigned char *dat,unsigned char *key,int mode);

void Lib_Des16(unsigned char *input,unsigned char *output,unsigned char *deskey,int mode);
void Lib_Des24(unsigned char *input,unsigned char *output,unsigned char *deskey,int mode);

void Lib_Des16CBC(unsigned char *input,int inputLen, unsigned char *output,unsigned char *deskey,int mode);
void Lib_Des16ECB(unsigned char *input,unsigned char *output,unsigned char *deskey,int mode);
void s_DesInit(void);

void Lib_Des3_16Mac(unsigned char *key,unsigned char *mdat,int length);


void Lib_Des16ECB_Huihh(unsigned char *input, int inputLen, unsigned char *deskey, int mode, unsigned char *output);
void Lib_Des16CBC_Huihh(unsigned char *input,int inputLen, unsigned char *deskey,int mode, unsigned char *output, unsigned char *iv);
void Lib_Des3_16Mac_Huihh(unsigned char *inbuf, int length, unsigned char *key, unsigned char *outbuf, unsigned char *iv);
void Lib_Des1_8Mac_Huihh(unsigned char *inbuf, int length, unsigned char *key, unsigned char *outbuf, unsigned char *iv);

#endif
