cmake_minimum_required(VERSION 3.26)

project(example)

set(CMAKE_CXX_STANDARD 20)

add_definitions(-D_OUT_PUT_LOG)

aux_source_directory(${PROJECT_SOURCE_DIR} SRC)

add_executable(example ${SRC})
