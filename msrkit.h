#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <winternl.h>
#include <windows.h>
#include <cfgmgr32.h>

#define MSRK_OK                 0
#define MSRK_ERR_LSTAR_READ     1
#define MSRK_ERR_KERNEL_BASE    2
#define MSRK_ERR_GADGETS        3
#define MSRK_ERR_DRIVER_LOAD    4

namespace MSRK
{
    struct MAPPING final
    {
        std::uintptr_t address;

        MAPPING() : address(0) {}
        explicit MAPPING(std::uintptr_t addr) : address(addr) {}
        explicit operator bool() const { return address != 0; }
        explicit operator std::uintptr_t() const { return address; }
    };

    
    class M_FUNCTION final
    {
    public:
        static void* CALL(const char* EXPORT_NAME, const std::uint64_t* Args, std::uint8_t ARGS_COUNT);
        static void* CALL_AT(std::uintptr_t ADDRESS_FUNCTION, const std::uint64_t* Args, std::uint8_t ARGS_COUNT);

    private:
        template<typename... Args> friend void* CALL(const char* EXPORT_NAME, Args... args);
        template<typename... Args> friend void* CALL_AT(std::uintptr_t ADDRESS_FUNCTION, Args... args);
        
        friend class M_DRIVERMAP;
    };


    class M_DRIVERMAP final
    {
    public:
        static MAPPING MAP(const char* DRIVER_PATH, const std::uint64_t* Args, std::uint8_t ARGS_COUNT);
        static void UNMAP(MAPPING MAP_HANDLE);

    private:
        template<typename... Args> friend MAPPING MAP(const char* DRIVER_PATH, Args... args);
                                   friend void UNMAP(MAPPING MAP_HANDLE);
    };

    // userland
    template<typename... Args>
    inline void* CALL(const char* EXPORT_NAME, Args... args)
    {
        static_assert(sizeof...(Args) <= 16, "max 16 args");
        if constexpr (sizeof...(Args) == 0)
        {
            return M_FUNCTION::CALL(EXPORT_NAME, nullptr, 0);
        }
        else
        {
            std::uint64_t arr[] = { (std::uint64_t)(args)... };
            return M_FUNCTION::CALL(EXPORT_NAME, arr, sizeof...(Args));
        }
    }

    template<typename... Args>
    inline LPVOID CALL_AT(std::uintptr_t ADDRESS_FUNCTION, Args... args)
    {
        static_assert(sizeof...(Args) <= 16, "max 16 args");
        if constexpr (sizeof...(Args) == 0)
        {
            return M_FUNCTION::CALL_AT(ADDRESS_FUNCTION, nullptr, 0);
        }
        else
        {
            std::uint64_t arr[] = { (std::uint64_t)(args)... };
            return M_FUNCTION::CALL_AT(ADDRESS_FUNCTION, arr, sizeof...(Args));
        }
    }


    template<typename... Args>
    inline MAPPING MAP(const char* DRIVER_PATH, Args... args)
    {
        static_assert(sizeof...(Args) <= 2, "max 2 args");
        if constexpr (sizeof...(Args) == 0)
        {
            return M_DRIVERMAP::MAP(DRIVER_PATH, nullptr, 0);
        }
        else
        {
            std::uint64_t arr[] = { (std::uint64_t)(args)... };
            return M_DRIVERMAP::MAP(DRIVER_PATH, arr, sizeof...(Args));
        }
    }

    inline void UNMAP(MAPPING MAP_HANDLE)
    {
        M_DRIVERMAP::UNMAP(MAP_HANDLE);
    }

    bool INIT(const wchar_t* DRIVER_PATH, HANDLE DRIVER_HANDLE = nullptr);
    int  GET_LAST_ERROR();
    void CLEANUP();

}
