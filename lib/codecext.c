/*
 * Encryption codec implementation
 * (C) 2010 Olivier de Gaalon
 * (C) 2016 Archibald Neil MacDonald
 *
 * Distributed under the terms of the Botan license
 */

#include <sqlite3.c>

#include "codec_interface.h"

/**
* Under regular `see` sqlite, this is the encryption activation module.
* @param info activation key normally used. In this case does not do anything. 
*/
void sqlite3_activate_see(const char* info) { }

/**
* Free the encryption codec, called for pager.c
* Used as a callback.
* @param codec address of passed in codec.
*/
void sqlite3PagerFreeCodec(void* codec)
{
    deleteCodec(codec);
}

/**
* Set the page size to the codec, callback for pager.c
* @param codec address of passed in codec.
* @param pageSize size of all pages in this database.
* @param reserve reserved page space used by sqlite extensions. Ignored.
*/
void sqlite3CodecSizeChange(void* codec, int pageSize, int reserve)
{
    setPageSize(codec, pageSize);
}

/**
* Encrypt/Decrypt functionality, callback for pager.c
* @param codec address of codec.
* @param data the raw data to decrypt.
* @param pageNum the current page number.
* @param mode dictates the behaviour of the encrypt/decrypt.
* @return unecrypted data.
*/
void* sqlite3Codec(void* codec, void* data, Pgno pageNum, int mode)
{
    void* outData = data;

    //Db is encrypted
    if (NULL != codec)
    {
        switch(mode)
        {
        case 0: // Undo a "case 7" journal file encryption
        case 2: // Reload a page
        case 3: // Load a page
            if (hasReadKey(codec))
            {
                codecDecrypt(codec, pageNum, (unsigned char*) data);
            }
            break;
        case 6: // Encrypt a page for the main database file
            if (hasWriteKey(codec))
            {
                outData = codecEncrypt(codec, pageNum, (unsigned char*) data,
                                       1);
            }
            break;
        case 7: // Encrypt a page for the journal file
        /*
        * Under normal circumstances, the readkey is the same as the writekey. 
        * However, when the database is being rekeyed, the readkey is not the 
        * same as the writekey.
        * (The writekey is the "destination key" for the rekey operation and the
        * readkey is the key the db is currently encrypted with)
        * Therefore, for case 7, when the rollback is being written, 
        * always encrypt using the database's readkey, which is guaranteed to be
        * the same key that was used to read and write the original data.
        */
            if (hasReadKey(codec))
            {
                outData = codecEncrypt(codec, pageNum, (unsigned char*) data,
                                       0);
            }
            break;
        }
    }

    return outData;
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey)
{
    void* pCodec;

    if (NULL == zKey || nKey <= 0)
    {
        // No key specified, could mean either use the main db's encryption or
        // no encryption
        if (0 != nDb && nKey < 0)
        {
            //Is an attached database, therefore use the key of main database,
            // if main database is encrypted
            void* pMainCodec = sqlite3PagerGetCodec(
                sqlite3BtreePager(db->aDb[0].pBt));

            if (NULL != pMainCodec)
            {
                pCodec = initializeFromOtherCodec(pMainCodec, db);
                sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt),
                                     sqlite3Codec,
                                     sqlite3CodecSizeChange,
                                     sqlite3PagerFreeCodec,
                                     pCodec);
            }
        }
    }
    else
    {
        // Key specified, setup encryption key for database
        pCodec = initializeNewCodec(db);
        generateWriteKey(pCodec, (const char*) zKey, nKey);
        setReadIsWrite(pCodec);
        sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt),
                             sqlite3Codec,
                             sqlite3CodecSizeChange,
                             sqlite3PagerFreeCodec, pCodec);
    }

    return SQLITE_OK;
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey)
{
    // The unencrypted password is not stored for security reasons
    // therefore always return NULL
    *zKey = NULL;
    *nKey = -1;
}

int sqlite3_key_v2(sqlite3* db, const char* zDbName, const void* zKey, int nKey)
{
    //We don't use zDbName (though maybe we could...). Pass-through to the old
    // sqlite_key
    return sqlite3_key(db, zKey, nKey);
}

int sqlite3_rekey_v2(sqlite3* db, const char* zDbName, const void* zKey, int nKey)
{
    //We don't use zDbName (though maybe we could...). Pass-through to the old
    // sqlite_rekey
    return sqlite3_rekey(db, zKey, nKey);
}

int sqlite3_key(sqlite3* db, const void* zKey, int nKey)
{
    // The key is only set for the main database, not the temp database
    return sqlite3CodecAttach(db, 0, zKey, nKey);
}

int sqlite3_rekey(sqlite3* db, const void* zKey, int nKey)
{
    // Changes the encryption key for an existing database.
    int rc = SQLITE_ERROR;
    Btree* pbt = db->aDb[0].pBt;
    Pager* pPager = sqlite3BtreePager(pbt);
    void* pCodec = sqlite3PagerGetCodec(pPager);

    if ((NULL == zKey || 0 == nKey) && NULL == pCodec)
    {
        // Database not encrypted and key not specified. Do nothing
        return SQLITE_OK;
    }

    if (NULL == pCodec)
    {
        // Database not encrypted, but key specified. Encrypt database
        pCodec = initializeNewCodec(db);
        generateWriteKey(pCodec, (const char*) zKey, nKey);

        sqlite3PagerSetCodec(pPager, sqlite3Codec, sqlite3CodecSizeChange,
                             sqlite3PagerFreeCodec, pCodec);
    }
    else if (NULL == zKey || 0 == nKey)
    {
        // Database encrypted, but key not specified. Decrypt database
        // Keep read key, drop write key
        dropWriteKey(pCodec);
    }
    else
    {
        // Database encrypted and key specified. Re-encrypt database with new key
        // Keep read key, change write key to new key
        generateWriteKey(pCodec, (const char*) zKey, nKey);
    }

    // Start transaction
    rc = sqlite3BtreeBeginTrans(pbt, 1);
    if (rc == SQLITE_OK)
    {
        // Rewrite all pages using the new encryption key (if specified)
        int nPageCount = -1;
        sqlite3PagerPagecount(pPager, &nPageCount);
        Pgno nPage = (Pgno) nPageCount;

        Pgno nSkip = PAGER_MJ_PGNO(pPager);
        DbPage *pPage;

        Pgno n;
        for (n = 1; rc == SQLITE_OK && n <= nPage; ++n)
        {
            if (n == nSkip)
            {
                continue;
            }

            rc = sqlite3PagerGet(pPager, n, &pPage, 0);

            if (!rc)
            {
                rc = sqlite3PagerWrite(pPage);
                sqlite3PagerUnref(pPage);
            }
            else
            {
                sqlite3ErrorWithMsg(db, SQLITE_ERROR, "%s", 
                                    "Error while rekeying database page. "
                                    "Transaction Canceled.");
            }
        }
    }
    else
    {
        sqlite3ErrorWithMsg(db, SQLITE_ERROR, "%s",
                            "Error beginning rekey transaction. "
                            "Make sure that the current encryption key is "
                            "correct.");
    }

    if (rc == SQLITE_OK)
    {
        // All good, commit
        rc = sqlite3BtreeCommit(pbt);

        if (rc == SQLITE_OK)
        {
            //Database rekeyed and committed successfully, update read key
            if (hasWriteKey(pCodec))
            {
                setReadIsWrite(pCodec);
            }
            else //No write key == no longer encrypted
            {
                sqlite3PagerSetCodec(pPager, NULL, NULL, NULL, NULL);
            }
        }
        else
        {
            //TODO: can't trigger this, not sure if rollback is needed, 
            // reference implementation didn't rollback
            sqlite3ErrorWithMsg(db, SQLITE_ERROR, "%s",
                "Could not commit rekey transaction.");
        }
    }
    else
    {
        // Rollback, rekey failed
        sqlite3BtreeRollback(pbt, SQLITE_ERROR, 1);

        // go back to read key
        if (hasReadKey(pCodec))
        {
            setWriteIsRead(pCodec);
        }
        else //Database wasn't encrypted to start with
        {
            sqlite3PagerSetCodec(pPager, NULL, NULL, NULL, NULL);
        }
    }

    return rc;
}
