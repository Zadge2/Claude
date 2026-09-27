cmake_minimum_required(VERSION 3.20)
project(admintool VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "admintool targets Windows only (use MSVC, or a MinGW-w64 toolchain file when cross-compiling).")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(admintool
    src/main.cpp
    src/args.cpp
    src/output.cpp
    src/util.cpp
    src/sysinfo.cpp
    src/users.cpp
    src/services.cpp
    src/logs.cpp
)

target_compile_definitions(admintool PRIVATE
    UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00   # Windows 10+
)

target_link_libraries(admintool PRIVATE netapi32 advapi32 wevtapi psapi)

if(MSVC)
    target_compile_options(admintool PRIVATE /W4 /permissive- /utf-8)
    # Request elevation-aware manifest behaviour: run as invoker, admin actions report access denied.
    target_link_options(admintool PRIVATE /MANIFESTUAC:level='asInvoker')
else()
    target_compile_options(admintool PRIVATE -Wall -Wextra -Wpedantic)
    # MinGW: use wmain entry point and link the C++ runtime statically for a self-contained exe.
    target_link_options(admintool PRIVATE -municode -static)
endif()

install(TARGETS admintool RUNTIME DESTINATION bin)
