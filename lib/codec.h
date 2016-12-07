/*
 * Codec class for SQLite3 encryption codec.
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#ifndef CODEC_H_
#define CODEC_H_

#include <string>
#include <memory>
#include <botan/botan.h>
#include <botan/pipe.h>
#include <botan/loadstor.h>
#include <botan/filters.h>

using namespace std;
using namespace Botan;

/*These constants can be used to tweak the codec behavior as follows
 *Note that once you've encrypted a database with these settings,
 *recompiling with any different settings will give you a library that
 *cannot read that database, even given the same passphrase.*/

//BLOCK_CIPHER_STR: Cipher and mode used for encrypting the database
//make sure to add "/NoPadding" for modes that use padding schemes
const string BLOCK_CIPHER_STR = "Twofish/XTS";

//KEY_SIZE: Size of the encryption key. Note that XTS splits the key
//between two ciphers, so if you're using XTS, double the intended key
//size. (ie, "AES-128/XTS" should have a 256 bit KEY_SIZE)
const size_t KEY_SIZE = 512/8; //512 bit, 64 byte key. (256 bit XTS key)

//PBKDF_STR: Key derivation function used to derive both the encryption
//and IV derivation keys from the given database passphrase
const string PBKDF_STR = "PBKDF2(SHA-256)";

//PBKDF_ITERATIONS: Number of hash iterations used in the key derivation
//process.
const size_t PBKDF_ITERATIONS = 10000;

//SALT_STR: Hard coded salt used to derive the key from the passphrase.
const string SALT_STR = "&g#nB'9]";

//MAC_STR: CMAC used to derive the IV that is used for db page
//encryption
const string MAC_STR = "CMAC(Twofish)";

//IV_DERIVATION_KEY_SIZE: Size of the key used with the CMAC (MAC_STR)
//above.
const size_t IV_DERIVATION_KEY_SIZE = 256/8; //256 bit, 32 byte key


class Codec
{
public:
    Codec(void* db);
    Codec(const Codec* other, void* db);

    void GenerateWriteKey(const char* userPassword, int passwordLength);
    void DropWriteKey();
    void SetWriteIsRead();
    void SetReadIsWrite();

    unsigned char* Encrypt(int page, unsigned char* data, bool useWriteKey);
    void Decrypt(int page, unsigned char *data);

    void SetPageSize(int pageSize) { m_pageSize = pageSize; }

    bool HasReadKey() const { return m_hasReadKey; }
    bool HasWriteKey() const { return m_hasWriteKey; }
    void* GetDB() { return m_db; }
    const char* GetAndResetError();

private:
    Codec(void* db, bool hasReadKey, bool hasWriteKey, SymmetricKey readKey, SymmetricKey writeKey,
          SymmetricKey ivReadKey, SymmetricKey ivWriteKey);

    InitializationVector GetIVForPage(u32bit page, bool useWriteKey);

private:
    bool m_hasReadKey;
    bool m_hasWriteKey;

    void* m_db;

    const char* m_botanErrorMsg;

    std::unique_ptr<unsigned char[]> m_page;
    int m_pageSize;

    SymmetricKey m_readKey;
    SymmetricKey m_writeKey;
    SymmetricKey m_ivReadKey;
    SymmetricKey m_ivWriteKey;

    Keyed_Filter* m_encipherFilter;
    Pipe m_encipherPipe;

    Keyed_Filter* m_decipherFilter;
    Pipe m_decipherPipe;

    MAC_Filter* m_cmac;
    Pipe m_macPipe;
};

#endif
