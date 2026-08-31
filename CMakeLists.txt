cmake_minimum_required(VERSION 3.21)
project(msrkit LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(msrkit STATIC
    src/msrkit.cpp
    asm/syscall_gate.asm
)

target_include_directories(msrkit PUBLIC include)

target_compile_options(msrkit PRIVATE
    /W4 /GS- /guard:cf-
    $<$<CONFIG:Release>:/O2>
)

target_link_libraries(msrkit PUBLIC
    ntdll cfgmgr32 psapi
)

add_executable(msrkit-cli cli/main.cpp)
target_link_libraries(msrkit-cli PRIVATE msrkit)
target_compile_options(msrkit-cli PRIVATE /W4 /GS- /guard:cf-)
