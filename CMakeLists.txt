cmake_minimum_required(VERSION 3.18)

project(network_panel)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC_LIST)

if(NOT WIN32)
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

endif()

add_executable(netpanel_client 
    client/client_main.cpp
    src/device_identity.cpp
    src/device_discovery.cpp
    src/tool.cpp
    src/task_record.cpp
)

target_include_directories(netpanel_client PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(netpanel_client PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

set_target_properties(
    netpanel_client
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/output
)
if(WIN32)
    target_compile_definitions(netpanel_client PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
    target_link_libraries(netpanel_client PRIVATE ws2_32 iphlpapi advapi32 shell32 crypt32)
    if(MINGW)
        target_link_options(netpanel_client PRIVATE -static-libgcc -static-libstdc++)
        target_compile_options(netpanel_client PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
    endif()
endif()
