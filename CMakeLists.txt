cmake_minimum_required(VERSION 3.21)
project(msrkit LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(msrkit STATIC
    src/msrkit.cpp
    asm/shellcode.asm
)

target_include_directories(msrkit PUBLIC include)

target_compile_options(msrkit PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:/W4 /guard:cf->
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Release>>:/O2>
)

target_link_libraries(msrkit PUBLIC
    ntdll cfgmgr32 psapi
)

add_executable(msrkit-cli cli/main.cpp)
target_link_libraries(msrkit-cli PRIVATE msrkit)
target_compile_options(msrkit-cli PRIVATE /W4 /guard:cf-)
