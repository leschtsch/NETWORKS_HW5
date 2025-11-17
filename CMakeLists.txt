CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

PROJECT(NETWORKS_HW5)

SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)
SET(CMAKE_CXX_COMPILER clang++)
SET(CMAKE_CXX_STANDARD 23)
SET(CMAKE_CXX_FLAGS "-O2")

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/)

ADD_LIBRARY(options STATIC src/options.cpp)
ADD_LIBRARY(get_chunk_size STATIC src/get_chunk_size.cpp)
ADD_LIBRARY(tls_send_receive STATIC src/tls_send_receive.cpp)
LINK_LIBRARIES(options get_chunk_size tls_send_receive ssl crypto)

ADD_EXECUTABLE(tls_server src/tls_server.cpp)
ADD_EXECUTABLE(tls_client src/tls_client.cpp)
