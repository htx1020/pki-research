
include_directories(./code)

add_definitions("-DTEST_REQ")
add_definitions("-DTEST_P12")

set(code 
    ./code/main.cpp
    ./code/reqgen.c
    ./code/p12parse.cpp
    ./code/pkcs_tool.cpp
    )
message(${code})
add_executable(certKit ${code})
target_link_libraries(certKit crypto)
