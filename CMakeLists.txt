cmake_minimum_required(VERSION 3.18)

project(network_panel)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC_LIST)

add_executable(
    app
    main.cpp
    ${SRC_LIST}
)

target_link_libraries(
    app
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

target_include_directories(
    app
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(
    app
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/output
)