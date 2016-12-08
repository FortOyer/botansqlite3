# Build instructions for BotanSqlite3


## Requirements

1. Botan 1.11.0 or later
2. SQLite3 amalgamation source, version 3.15.02.0 or later (previous versions may work, some will need minor changes)

## Building Linux

1. If desired, codec.h can be modified to tweak the encryption algothrithms and parameters. (Defaults to Twofish/XTS with 256 bit key)

2. Within the top level folder: ``mkdir build && cd build``

3. ``cmake .. -DBOTAN_LIB_DIR:PATH=<BOTAN_LIBRARY_PATH> -DBOTAN_INCLUDE_DIR:PATH=<BOTAN_INCLUDE_DIRECTORY>``

4. ``make``

## Building Windows 64bit

1. If desired, codec.h can be modified to tweak the encryption algothrithms and parameters. (Defaults to Twofish/XTS with 256 bit key)

2. Within the top level folder: ``mkdir build && cd build``

3. ``cmake -G "Visual Studio 12 2013 Win64" .. -DBOTAN_LIB_DIR:PATH=<BOTAN_LIBRARY_PATH> -DBOTAN_INCLUDE_DIR:PATH=<BOTAN_INCLUDE_DIRECTORY>``

4. Navigate to the build directory. Open up ``botansqlite3.sln``.

5. Build through visual studio.

## Testing

1. Run the test
      $ ./test_sqlite
2. Look for "All seems good"
