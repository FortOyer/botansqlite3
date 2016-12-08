/*
 * Codec class for SQLite3 encryption codec.
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#include "codec.h"

#include <botan/init.h>
#include <botan/lookup.h>
#include <botan/pbkdf.h>

Codec::Codec(void *db) :
    Codec(db, false, false, SymmetricKey(), SymmetricKey(), SymmetricKey(), SymmetricKey())
{ }

//Only used to copy main db key for an attached db
Codec::Codec(const Codec* other, void *db) :
    Codec(db, other->m_hasReadKey, other->m_hasWriteKey, other->m_readKey, other->m_ivReadKey,
          other->m_writeKey, other->m_ivWriteKey)
{ }

Codec::Codec(void* db, bool hasReadKey, bool hasWriteKey, SymmetricKey readKey, SymmetricKey writeKey,
             SymmetricKey ivReadKey, SymmetricKey ivWriteKey) :
    m_hasReadKey(hasReadKey),
    m_hasWriteKey(hasWriteKey),
    m_db(db),

    m_page(nullptr),
    m_pageSize(0),

    m_readKey(readKey),
    m_writeKey(writeKey),
    m_ivReadKey(ivReadKey),
    m_ivWriteKey(ivWriteKey),

    m_encipherFilter(get_cipher(BLOCK_CIPHER_STR, ENCRYPTION)),
    m_encipherPipe(m_encipherFilter),

    m_decipherFilter(get_cipher(BLOCK_CIPHER_STR, DECRYPTION)),
    m_decipherPipe(m_decipherFilter),
    m_cmac(new MAC_Filter(MAC_STR)),
    m_macPipe(m_cmac)
{ }

void Codec::setPageSize(int pageSize)
{
    // Delete old memory. Replace with new memory.
    m_page = std::unique_ptr<unsigned char[]>(new unsigned char[pageSize]);
    m_pageSize = pageSize;
}

void Codec::generateWriteKey(const char* userPassword, int passwordLength)
{
    std::unique_ptr<PBKDF> pbkdf(Botan::PBKDF::create(PBKDF_STR));

    SymmetricKey masterKey =
        pbkdf->derive_key(KEY_SIZE + IV_DERIVATION_KEY_SIZE,
        std::string(userPassword, passwordLength),
        reinterpret_cast<const uint8_t*>(SALT_STR.c_str()),
        SALT_STR.length(),
        PBKDF_ITERATIONS);

    m_writeKey = SymmetricKey(masterKey.bits_of().data(), KEY_SIZE);

    m_ivWriteKey = SymmetricKey(masterKey.bits_of().data() + KEY_SIZE,
                                IV_DERIVATION_KEY_SIZE);

    m_hasWriteKey = true;
}

void Codec::dropWriteKey()
{
    m_hasWriteKey = false;
}

void Codec::setReadIsWrite()
{
    m_readKey = m_writeKey;
    m_ivReadKey = m_ivWriteKey;
    m_hasReadKey = m_hasWriteKey;
}

void Codec::setWriteIsRead()
{
    m_writeKey = m_readKey;
    m_ivWriteKey = m_ivReadKey;
    m_hasWriteKey = m_hasReadKey;
}

unsigned char* Codec::encrypt(int page, unsigned char* data, bool useWriteKey)
{
    memcpy(m_page.get(), data, m_pageSize);

    m_encipherFilter->set_key(useWriteKey ? m_writeKey : m_readKey);
    m_encipherFilter->set_iv(getIVForPage(page, useWriteKey));
    m_encipherPipe.process_msg(m_page.get(), m_pageSize);
    m_encipherPipe.read(m_page.get(), 
                        m_encipherPipe.remaining(Pipe::LAST_MESSAGE),
                        Pipe::LAST_MESSAGE);

    return m_page.get(); //return location of newly ciphered data
}

void Codec::decrypt(int page, unsigned char *data)
{
    m_decipherFilter->set_key(m_readKey);
    m_decipherFilter->set_iv(getIVForPage(page, false));
    m_decipherPipe.process_msg(data, m_pageSize);
    m_decipherPipe.read(data,
                        m_decipherPipe.remaining(Pipe::LAST_MESSAGE),
                        Pipe::LAST_MESSAGE);
}

InitializationVector Codec::getIVForPage(u32bit page, bool useWriteKey)
{
    static unsigned char* intiv[4];
    store_le(page, reinterpret_cast<byte*>(intiv));
    m_cmac->set_key(useWriteKey ? m_ivWriteKey : m_ivReadKey);
    m_macPipe.process_msg(reinterpret_cast<byte*>(intiv), 4);
    return m_macPipe.read_all(Pipe::LAST_MESSAGE);
}


