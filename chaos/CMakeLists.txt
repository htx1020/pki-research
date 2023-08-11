cmake_minimum_required(VERSION 3.0)
project(chaos)

#编译选项
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 5.1. 定义函数，用于递归添加头文件                                                                                                                                       function(include_sub_directories_recursively root_dir)
function(include_directories_recursively root_dir)
    if (IS_DIRECTORY ${root_dir})               # 当前路径是一个目录吗，是的话就加入到包含目录
        message("include dir: " ${root_dir})
        include_directories(${root_dir})
    endif()

    file(GLOB ALL_SUB RELATIVE ${root_dir} ${root_dir}/*) # 获得当前目录下的所有文件，让如ALL_SUB列表中
    foreach(sub ${ALL_SUB})
        if (IS_DIRECTORY ${root_dir}/${sub})
            include_directories_recursively(${root_dir}/${sub}) # 对子目录递归调用，包含
        endif()
    endforeach()
endfunction()

include_directories_recursively(${CMAKE_SOURCE_DIR}/code)
include_directories(./code)

set(DIR_LIB_OPENSSL ~/workspace/generic_deplibs/3rd/openssl)
include_directories(${DIR_LIB_OPENSSL}/include/)
find_library(LINK_LIB_CRYPTO NAMES crypto PATHS ${DIR_LIB_OPENSSL}/lib)

set(DIR_LIB_OPENSSL ~/workspace/generic_deplibs/3rd/sqlite3)
include_directories(${DIR_LIB_OPENSSL}/include/)
find_library(LINK_LIB_FUSION NAMES fusion PATHS ${DIR_LIB_OPENSSL}/lib)

add_definitions("-DTEST_REQ")
#add_definitions("-DTEST_P12")

file(GLOB_RECURSE SRCS_C    "./code/*.c")
file(GLOB_RECURSE SRCS_CPP  "./code/*.cpp")

add_executable(${PROJECT_NAME} ${SRCS_C} ${SRCS_CPP})
target_link_libraries(${PROJECT_NAME} 
    ${LINK_LIB_CRYPTO}
    ${LINK_LIB_FUSION}
    dl
    pthread
    stdc++fs
    )
