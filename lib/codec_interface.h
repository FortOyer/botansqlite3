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
    typedef unsigned char Bool;
#   endif

    void InitializeBotan();

    void* InitializeNewCodec(void *db);

    void* InitializeFromOtherCodec(const void *otherCodec, void *db);

    void GenerateWriteKey(void *codec, const char *userPassword, int passwordLength);

    void DropWriteKey(void *codec);

    void SetWriteIsRead(void *codec);

    void SetReadIsWrite(void *codec);

    unsigned char* Encrypt(void *codec, int page, unsigned char *data, Bool useWriteKey);

    void Decrypt(void *codec, int page, unsigned char *data);

    void SetPageSize(void *codec, int pageSize);

    Bool HasReadKey(void *codec);

    Bool HasWriteKey(void *codec);

    void* GetDB(void *codec);

    const char* GetAndResetError(void *codec);

    void DeleteCodec(void *codec);

#   ifdef __cplusplus
}
#   endif

#endif
