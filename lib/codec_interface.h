/*
 * Encryption codec class C interface
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#ifndef CODEC_INTERFACE_H_
#define CODEC_INTERFACE_H_

#   ifdef __cplusplus
extern "C" 
{
#   endif

    void initializeBotan();

    void* initializeNewCodec(void *db);

    void* initializeFromOtherCodec(const void *otherCodec, void *db);

    void generateWriteKey(void *codec, const char *userPassword,
                          int passwordLength);

    void dropWriteKey(void *codec);

    void setWriteIsRead(void *codec);

    void setReadIsWrite(void *codec);

    unsigned char* codecEncrypt(void *codec, int page, unsigned char *data,
                                unsigned int useWriteKey);

    void codecDecrypt(void *codec, int page, unsigned char *data);

    void setPageSize(void *codec, int pageSize);

    unsigned int hasReadKey(void *codec);

    unsigned int hasWriteKey(void *codec);

    void* getDB(void *codec);

    void deleteCodec(void *codec);

#   ifdef __cplusplus
}
#   endif

#endif
