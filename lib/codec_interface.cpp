/*
 * Encryption codec class C interface
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#include "codec_interface.h"

#include "codec.h"

void* InitializeNewCodec(void *db) {
    return new Codec(db);
}

void* InitializeFromOtherCodec(const void *otherCodec, void *db) {
    return new Codec(static_cast<const Codec*>(otherCodec), db);
}

void GenerateWriteKey(void *codec, const char *userPassword, int passwordLength) {
    static_cast<Codec*>(codec)->GenerateWriteKey(userPassword, passwordLength);
}

void DropWriteKey(void *codec) {
    static_cast<Codec*>(codec)->DropWriteKey();
}

void SetWriteIsRead(void *codec) {
    static_cast<Codec*>(codec)->SetWriteIsRead();
}

void SetReadIsWrite(void *codec) {
    static_cast<Codec*>(codec)->SetReadIsWrite();
}

unsigned char* Encrypt(void *codec, int page, unsigned char *data, Bool useWriteKey) {
    return static_cast<Codec*>(codec)->Encrypt(page, data, useWriteKey);
}

void Decrypt(void *codec, int page, unsigned char *data) {
    static_cast<Codec*>(codec)->Decrypt(page, data);
}

void SetPageSize(void *codec, int pageSize) {
    static_cast<Codec*>(codec)->SetPageSize(pageSize);
}

Bool HasReadKey(void *codec) {
    return static_cast<Codec*>(codec)->HasReadKey();
}

Bool HasWriteKey(void *codec) {
    return static_cast<Codec*>(codec)->HasWriteKey();
}

void* GetDB(void *codec) {
    return static_cast<Codec*>(codec)->GetDB();
}

const char* GetAndResetError(void *codec)
{
    return static_cast<Codec*>(codec)->GetAndResetError();
}

void DeleteCodec(void *codec) {
    Codec* deleteThisCodec = static_cast<Codec*>(codec);
    delete deleteThisCodec;
}
