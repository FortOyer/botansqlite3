project(lib_botansqlite3)

SET(CMAKE_CXX_STANDARD 11)

SET(SQLITE_DIR ${CMAKE_SOURCE_DIR}/sqlite3)

include (GenerateExportHeader)

SET (PATCH_COMMAND patch)
SET (PATCH_ARGS -p0 -o ${PROJECT_SOURCE_DIR}/sqlite3_patched.c -i ${PROJECT_SOURCE_DIR}/sqlite3-amalgamation.patch)

execute_process(COMMAND ${PATCH_COMMAND} ${PATCH_ARGS}
                WORKING_DIRECTORY ${SQLITE_DIR}
)

add_library(sqlite3 SHARED
            sqlite3_patched.c
            codec.cpp
            codec_interface.cpp
)

target_include_directories(sqlite3 PUBLIC  ${SQLITE_DIR})
target_include_directories(sqlite3 PRIVATE ${BOTAN_INCLUDE_DIR})
target_include_directories(sqlite3 PRIVATE ${PROJECT_BINARY_DIR}) # Find sqlite3_export.h

target_compile_definitions(sqlite3 PRIVATE
                           -DSQLITE_ENABLE_FTS4
                           -DSQLITE_ENABLE_FTS5
                           -DSQLITE_ENABLE_JSON1
                           -DSQLITE_ENABLE_RTREE
                           -DSQLITE_ENABLE_EXPLAIN_COMMENTS
)

GENERATE_EXPORT_HEADER(sqlite3
             EXPORT_MACRO_NAME SQLITE_API
             EXPORT_FILE_NAME sqlite3_Export.h
)

if(WIN32)
    target_link_libraries(sqlite3 optimized ${BOTAN_LIB_DIR}/botan.lib debug ${BOTAN_LIB_DIR}/botand.lib)
    set_target_properties(sqlite3 PROPERTIES DEBUG_POSTFIX "d")
else()
    target_link_libraries(sqlite3 ${BOTAN_LIB_DIR}/botan.so)
endif()