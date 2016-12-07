project(test_botansqlite3)

add_executable(test_sqlite3 
               test_sqlite.cpp)

target_link_libraries(test_sqlite3 sqlite3)
