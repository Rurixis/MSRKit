#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define MSRK_OK                 0
#define MSRK_ERR_LSTAR_READ     1
#define MSRK_ERR_KERNEL_BASE    2
#define MSRK_ERR_GADGETS        3
#define MSRK_ERR_PREPARE        4
#define MSRK_ERR_HVCI           5

namespace MSRK
{

class M_DRIVERMAP;

class M_FUNCTION final
{
    public:
        static void*     CALL(const char* EXPORT_NAME, const std::uint64_t* Args, int ARGS_COUNT);
        static void*     CALL_AT(std::uintptr_t ADDRESS_FUNCTION, const std::uint64_t* Args, int ARGS_COUNT);

    private:
        template<typename... Args> friend void* CALL(const char* EXPORT_NAME, Args... args);
        template<typename... Args> friend void* CALL_AT(std::uintptr_t ADDRESS_FUNCTION, Args... args);
        friend class M_DRIVERMAP;
};

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
inline void* CALL_AT(std::uintptr_t ADDRESS_FUNCTION, Args... args)
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


class M_DRIVERMAP final
{
    public:
        static std::uintptr_t MAP(const char* DRIVER_PATH, const std::uint64_t* Args, int ARGS_COUNT);
        static void UNMAP(std::uintptr_t BASE_ADDRESS);

    private:
        template<typename... Args> friend std::uintptr_t MAP(const char* DRIVER_PATH, Args... args);
        friend void UNMAP(std::uintptr_t BASE_ADDRESS);
};

template<typename... Args>
inline std::uintptr_t MAP(const char* DRIVER_PATH, Args... args)
{
    static_assert(sizeof...(Args) <= 2, "max 2 entry args");
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

void UNMAP(std::uintptr_t BASE_ADDRESS);
bool INIT(const char* DRIVER_PATH, HANDLE DRIVER_HANDLE = nullptr);
int  GET_LAST_ERROR();
void CLEANUP();

}
