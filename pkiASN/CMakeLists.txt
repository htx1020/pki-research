project(ProjectName)
cmake_minimum_required(VERSION 3.16)


include_directories(/usr/local/share/asn1c/)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/easyme)

add_compile_options("-g")
link_directories(${CMAKE_SOURCE_DIR}/lib)
add_executable(cert  ${CMAKE_SOURCE_DIR}/main.c ${CMAKE_SOURCE_DIR}/easyme/easyasn1.c)
target_link_libraries(cert asncodec)
