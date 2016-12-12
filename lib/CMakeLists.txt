project(lib_botansqlite3)

SET(CMAKE_CXX_STANDARD 11)

SET(SQLITE_DIR ${CMAKE_SOURCE_DIR}/sqlite3)

include (GenerateExportHeader)

add_library(sqlite3 SHARED
            codecext.c
            codec.cpp
            codec_interface.cpp
)

target_include_directories(sqlite3 PUBLIC  ${SQLITE_DIR})
target_include_directories(sqlite3 PRIVATE ${BOTAN_INCLUDE_DIR}
                                           ${PROJECT_BINARY_DIR}) # Find sqlite3_export.h

target_compile_definitions(sqlite3 PUBLIC
                           -DSQLITE_HAS_CODEC
)

target_compile_definitions(sqlite3 PRIVATE
                           -DSQLITE_ENABLE_FTS4
                           -DSQLITE_ENABLE_FTS5
                           -DSQLITE_ENABLE_JSON1
                           -DSQLITE_ENABLE_RTREE
                           -DSQLITE_ENABLE_EXPLAIN_COMMENTS
                           -DSQLITE_HAS_CODEC
)

GENERATE_EXPORT_HEADER(sqlite3
            EXPORT_MACRO_NAME SQLITE_API
            EXPORT_FILE_NAME sqlite3_export.h
)

if(WIN32)
    target_link_libraries(sqlite3 optimized ${BOTAN_LIB_DIR}/botan.lib debug ${BOTAN_LIB_DIR}/botand.lib)
    set_target_properties(sqlite3 PROPERTIES DEBUG_POSTFIX "d")
else()
    target_link_libraries(sqlite3 dl ${BOTAN_LIB_DIR}/libbotan-1.11.so)
endif()