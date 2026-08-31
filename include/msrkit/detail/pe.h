#pragma once
#include <msrkit/detail/constants.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Psapi.h>
#include <intrin.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

namespace
{
    struct PreparedImage final
    {
        std::vector<std::uint8_t> data;
        std::uintptr_t entry_rva  = 0;
        std::size_t image_size = 0;
    };

    class M_PE final
    {
        private:
            static std::uintptr_t GET_NTOSKRNL_BASE()
            {
                LPVOID DRIVER_LIST[1];
                DWORD BYTES_NEEDED = 0;

                if (!EnumDeviceDrivers(DRIVER_LIST, sizeof(DRIVER_LIST), &BYTES_NEEDED) || BYTES_NEEDED == 0)
                {
                    return 0;
                }

                return (std::uintptr_t)DRIVER_LIST[0];
            }

            static bool FIX_COOKIE(std::uint8_t* IMAGE_BASE)
            {
                const auto DOS_HEADER = (PIMAGE_DOS_HEADER)IMAGE_BASE;
                const auto NT_HEADER  = (PIMAGE_NT_HEADERS64)(IMAGE_BASE + DOS_HEADER->e_lfanew);

                const auto& CONFIG_DIRECTORY = NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

                if (!CONFIG_DIRECTORY.VirtualAddress || !CONFIG_DIRECTORY.Size)
                {
                    const auto SECTION_TABLE = IMAGE_FIRST_SECTION(NT_HEADER);

                    for (WORD i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++)
                    {
                        if (!(SECTION_TABLE[i].Characteristics & IMAGE_SCN_MEM_WRITE))
                        {
                            continue;
                        }

                        std::uint8_t* SECTION_BASE = IMAGE_BASE + SECTION_TABLE[i].VirtualAddress;
                        DWORD SECTION_SIZE = SECTION_TABLE[i].Misc.VirtualSize;

                        for (DWORD OFFSET = 0; OFFSET + 8 <= SECTION_SIZE; OFFSET += 8)
                        {
                            if (*(std::uint64_t*)(SECTION_BASE + OFFSET) == SECURITY_COOKIE_SENTINEL)
                            {
                                std::uint64_t COOKIE_VALUE = __rdtsc() ^ (std::uint64_t)IMAGE_BASE;
                                if (COOKIE_VALUE == SECURITY_COOKIE_SENTINEL) COOKIE_VALUE++;
                                *(std::uint64_t*)(SECTION_BASE + OFFSET) = COOKIE_VALUE;
                                return true;
                            }
                        }
                    }

                    return true;
                }

                const auto LOAD_CONFIG = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(IMAGE_BASE + CONFIG_DIRECTORY.VirtualAddress);

                if (LOAD_CONFIG->SecurityCookie)
                {
                    std::uintptr_t COOKIE_RVA = LOAD_CONFIG->SecurityCookie - NT_HEADER->OptionalHeader.ImageBase;
                    std::uint64_t* COOKIE_PTR = (std::uint64_t*)(IMAGE_BASE + COOKIE_RVA);

                    std::uint64_t NEW_COOKIE = __rdtsc() ^ (std::uint64_t)IMAGE_BASE;
                    if (NEW_COOKIE == SECURITY_COOKIE_SENTINEL) NEW_COOKIE++;

                    *COOKIE_PTR = NEW_COOKIE;
                }

                return true;
            }

            static bool FIX_RELOC(std::uint8_t* IMAGE_BASE, std::uintptr_t TARGET_BASE)
            {
                const auto DOS_HEADER = (PIMAGE_DOS_HEADER)IMAGE_BASE;
                const auto NT_HEADER  = (PIMAGE_NT_HEADERS64)(IMAGE_BASE + DOS_HEADER->e_lfanew);

                const auto& RELOC_DIRECTORY = NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

                if (!RELOC_DIRECTORY.VirtualAddress || !RELOC_DIRECTORY.Size)
                {
                    return true;
                }

                std::int64_t RELOC_DELTA = (std::int64_t)(TARGET_BASE - NT_HEADER->OptionalHeader.ImageBase);
                if (RELOC_DELTA == 0) return true;

                auto RELOC_BLOCK = (PIMAGE_BASE_RELOCATION)(IMAGE_BASE + RELOC_DIRECTORY.VirtualAddress);
                const auto RELOC_END = (std::uint8_t*)RELOC_BLOCK + RELOC_DIRECTORY.Size;

                while ((std::uint8_t*)RELOC_BLOCK < RELOC_END && RELOC_BLOCK->SizeOfBlock > 0)
                {
                    DWORD ENTRY_COUNT = (RELOC_BLOCK->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    USHORT* RELOC_ENTRIES = (USHORT*)((std::uint8_t*)RELOC_BLOCK + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < ENTRY_COUNT; i++)
                    {
                        USHORT RELOC_TYPE   = RELOC_ENTRIES[i] >> 12;
                        USHORT RELOC_OFFSET = RELOC_ENTRIES[i] & 0xFFF;

                        if (RELOC_TYPE == IMAGE_REL_BASED_DIR64)
                        {
                            auto TARGET_ADDRESS = (std::uint64_t*)(IMAGE_BASE + RELOC_BLOCK->VirtualAddress + RELOC_OFFSET);
                            *TARGET_ADDRESS += RELOC_DELTA;
                        }
                    }

                    RELOC_BLOCK = (PIMAGE_BASE_RELOCATION)((std::uint8_t*)RELOC_BLOCK + RELOC_BLOCK->SizeOfBlock);
                }

                return true;
            }

            static bool FIX_IMPORT(std::uint8_t* IMAGE_BASE)
            {
                const auto DOS_HEADER = (PIMAGE_DOS_HEADER)IMAGE_BASE;
                const auto NT_HEADER  = (PIMAGE_NT_HEADERS64)(IMAGE_BASE + DOS_HEADER->e_lfanew);

                const auto& IMPORT_DIRECTORY = NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

                if (!IMPORT_DIRECTORY.VirtualAddress || !IMPORT_DIRECTORY.Size)
                {
                    return true;
                }

                LPVOID DRIVER_LIST[1024];
                DWORD BYTES_NEEDED = 0;
                EnumDeviceDrivers(DRIVER_LIST, sizeof(DRIVER_LIST), &BYTES_NEEDED);
                const DWORD DRIVER_COUNT = BYTES_NEEDED / sizeof(LPVOID);

                char NAME_BUFFER[256];
                auto IMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)(IMAGE_BASE + IMPORT_DIRECTORY.VirtualAddress);

                while (IMPORT_DESCRIPTOR->Name)
                {
                    const char* MODULE_NAME = (const char*)(IMAGE_BASE + IMPORT_DESCRIPTOR->Name);

                    std::uintptr_t MODULE_BASE = 0;

                    for (DWORD i = 0; i < DRIVER_COUNT; i++)
                    {
                        if (GetDeviceDriverBaseNameA(DRIVER_LIST[i], NAME_BUFFER, sizeof(NAME_BUFFER)) &&
                            _stricmp(NAME_BUFFER, MODULE_NAME) == 0)
                        {
                            MODULE_BASE = (std::uintptr_t)DRIVER_LIST[i];
                            break;
                        }
                    }

                    HMODULE LOCAL_MODULE = LoadLibraryExA(
                        MODULE_NAME,
                        nullptr,
                        DONT_RESOLVE_DLL_REFERENCES
                    );

                    if (!MODULE_BASE || !LOCAL_MODULE)
                    {
                        if (LOCAL_MODULE) FreeLibrary(LOCAL_MODULE);
                        return false;
                    }

                    auto IAT_THUNK = (PIMAGE_THUNK_DATA64)(IMAGE_BASE + IMPORT_DESCRIPTOR->FirstThunk);

                    auto ORIGINAL_THUNK = IMPORT_DESCRIPTOR->OriginalFirstThunk
                        ? (PIMAGE_THUNK_DATA64)(IMAGE_BASE + IMPORT_DESCRIPTOR->OriginalFirstThunk)
                        : IAT_THUNK;

                    while (ORIGINAL_THUNK->u1.AddressOfData)
                    {
                        if (ORIGINAL_THUNK->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                        {
                            const auto IMPORT_ORDINAL = (USHORT)(ORIGINAL_THUNK->u1.Ordinal & 0xFFFF);

                            const FARPROC PROC_ADDRESS = GetProcAddress(
                                LOCAL_MODULE,
                                (LPCSTR)(std::uintptr_t)IMPORT_ORDINAL
                            );

                            IAT_THUNK->u1.Function = PROC_ADDRESS
                                ? MODULE_BASE + ((std::uintptr_t)PROC_ADDRESS - (std::uintptr_t)LOCAL_MODULE)
                                : 0;
                        }
                        else
                        {
                            const auto IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)(
                                IMAGE_BASE + ORIGINAL_THUNK->u1.AddressOfData
                            );

                            const FARPROC PROC_ADDRESS = GetProcAddress(
                                LOCAL_MODULE,
                                IMPORT_BY_NAME->Name
                            );

                            IAT_THUNK->u1.Function = PROC_ADDRESS
                                ? MODULE_BASE + ((std::uintptr_t)PROC_ADDRESS - (std::uintptr_t)LOCAL_MODULE)
                                : 0;
                        }

                        if (!IAT_THUNK->u1.Function)
                        {
                            FreeLibrary(LOCAL_MODULE);
                            return false;
                        }

                        IAT_THUNK++;
                        ORIGINAL_THUNK++;
                    }

                    FreeLibrary(LOCAL_MODULE);
                    IMPORT_DESCRIPTOR++;
                }

                return true;
            }

            static bool PREPARE_IMAGE(const char* IMAGE_PATH, std::uintptr_t TARGET_BASE, PreparedImage* OUTPUT)
            {
                const HANDLE FILE_HANDLE = CreateFileA(
                    IMAGE_PATH,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );

                if (FILE_HANDLE == INVALID_HANDLE_VALUE)
                {
                    return false;
                }

                LARGE_INTEGER FILE_SIZE;

                if (!GetFileSizeEx(FILE_HANDLE, &FILE_SIZE) || FILE_SIZE.QuadPart == 0)
                {
                    CloseHandle(FILE_HANDLE);
                    return false;
                }

                std::vector<std::uint8_t> FILE_DATA((std::size_t)FILE_SIZE.QuadPart);
                DWORD BYTES_READ;

                ReadFile(
                    FILE_HANDLE,
                    FILE_DATA.data(),
                    (DWORD)FILE_DATA.size(),
                    &BYTES_READ,
                    nullptr
                );
                CloseHandle(FILE_HANDLE);

                if (BYTES_READ != (DWORD)FILE_DATA.size())
                {
                    return false;
                }

                const auto DOS_HEADER = (PIMAGE_DOS_HEADER)FILE_DATA.data();

                if (DOS_HEADER->e_magic != IMAGE_DOS_SIGNATURE)
                {
                    return false;
                }

                const auto NT_HEADER = (PIMAGE_NT_HEADERS64)(FILE_DATA.data() + DOS_HEADER->e_lfanew);

                if (NT_HEADER->Signature != IMAGE_NT_SIGNATURE)
                {
                    return false;
                }

                OUTPUT->image_size = NT_HEADER->OptionalHeader.SizeOfImage;
                OUTPUT->entry_rva  = NT_HEADER->OptionalHeader.AddressOfEntryPoint;
                OUTPUT->data.resize(OUTPUT->image_size, 0);

                std::memcpy(
                    OUTPUT->data.data(),
                    FILE_DATA.data(),
                    NT_HEADER->OptionalHeader.SizeOfHeaders
                );

                const auto SECTION_TABLE = IMAGE_FIRST_SECTION(NT_HEADER);

                for (WORD i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++)
                {
                    if (SECTION_TABLE[i].SizeOfRawData > 0)
                    {
                        std::memcpy(
                            OUTPUT->data.data() + SECTION_TABLE[i].VirtualAddress,
                            FILE_DATA.data() + SECTION_TABLE[i].PointerToRawData,
                            (std::min)(SECTION_TABLE[i].SizeOfRawData, SECTION_TABLE[i].Misc.VirtualSize)
                        );
                    }
                }

                if (!FIX_COOKIE(OUTPUT->data.data()))
                {
                    return false;
                }

                if (!FIX_RELOC(OUTPUT->data.data(), TARGET_BASE))
                {
                    return false;
                }

                if (!FIX_IMPORT(OUTPUT->data.data()))
                {
                    return false;
                }

                return true;
            }

            friend class ::MSRK::M_DRIVERMAP;
            friend bool ::MSRK::INIT(const char*, HANDLE);
    };
}
