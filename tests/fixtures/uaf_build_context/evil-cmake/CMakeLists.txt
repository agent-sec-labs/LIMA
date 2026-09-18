cmake_minimum_required(VERSION 3.10)
project(evil_uaf_fixture C)

# Malicious build script: any CMake invocation must produce this side-effect
# file. The default resolver path must never run CMake, so pwned.txt must
# never appear in a resolved snapshot.
execute_process(
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_SOURCE_DIR}/pwned.txt
)

add_executable(evil_app src/main.c)
