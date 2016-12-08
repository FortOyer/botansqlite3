/*
 * Encryption codec class C interface
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#include "codec_interface.h"

#include "codec.h"

void* initializeNewCodec(void* db)
{
    return new Codec(db);
}

void* initializeFromOtherCodec(const void* otherCodec, void* db)
{
    return new Codec(static_cast<const Codec*>(otherCodec), db);
}

void generateWriteKey(void* codec, const char* userPassword, int passwordLength)
{
    static_cast<Codec*>(codec)->generateWriteKey(userPassword, passwordLength);
}

void dropWriteKey(void* codec)
{
    static_cast<Codec*>(codec)->dropWriteKey();
}

void setWriteIsRead(void* codec)
{
    static_cast<Codec*>(codec)->setWriteIsRead();
}

void setReadIsWrite(void* codec)
{
    static_cast<Codec*>(codec)->setReadIsWrite();
}

unsigned char* codecEncrypt(void* codec, int page, unsigned char* data,
                            unsigned int useWriteKey)
{
    return static_cast<Codec*>(codec)->encrypt(page, data, useWriteKey);
}

void codecDecrypt(void* codec, int page, unsigned char* data)
{
    static_cast<Codec*>(codec)->decrypt(page, data);
}

void setPageSize(void* codec, int pageSize)
{
    static_cast<Codec*>(codec)->setPageSize(pageSize);
}

unsigned int hasReadKey(void* codec)
{
    return static_cast<Codec*>(codec)->hasReadKey();
}

unsigned int hasWriteKey(void* codec)
{
    return static_cast<Codec*>(codec)->hasWriteKey();
}

void* getDB(void* codec)
{
    return static_cast<Codec*>(codec)->getDB();
}

void deleteCodec(void *codec)
{
    delete static_cast<Codec*>(codec);
}
