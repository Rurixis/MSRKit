#include "../msrkit.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

static void PRINT_USAGE()
{
    std::printf(
        "msrkit - kernel execution toolkit\n\n"
        "Usage:\n"
        "  msrkit <driver.sys> call <ExportName> [args...]\n"
        "  msrkit <driver.sys> call_at <address> [args...]\n"
        "  msrkit <driver.sys> map <unsigned.sys> [args...]\n"
    );
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        PRINT_USAGE();
        return 1;
    }

    const char* DRIVER_PATH = argv[1];
    const char* COMMAND     = argv[2];

    if (!MSRK::INIT(DRIVER_PATH))
    {
        std::printf("[-] INIT failed: error %d\n", MSRK::GET_LAST_ERROR());
        return 1;
    }

    if (std::strcmp(COMMAND, "call") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing export name\n");
            MSRK::CLEANUP();
            return 1;
        }

        std::uint64_t ARGS[16] = {};
        int NARGS = 0;

        for (int I = 4; I < argc && NARGS < 16; I++, NARGS++)
        {
            ARGS[NARGS] = std::strtoull(argv[I], nullptr, 0);
        }

        void* RESULT = MSRK::M_FUNCTION::CALL(argv[3], ARGS, NARGS);
        std::printf("[+] %s = 0x%llX\n", argv[3], (std::uint64_t)(std::uintptr_t)RESULT);

        MSRK::CLEANUP();
        return 0;
    }

    if (std::strcmp(COMMAND, "call_at") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing address\n");
            MSRK::CLEANUP();
            return 1;
        }

        std::uintptr_t ADDRESS = (std::uintptr_t)std::strtoull(argv[3], nullptr, 0);
        std::uint64_t ARGS[16] = {};
        int NARGS = 0;

        for (int I = 4; I < argc && NARGS < 16; I++, NARGS++)
        {
            ARGS[NARGS] = std::strtoull(argv[I], nullptr, 0);
        }

        void* RESULT = MSRK::M_FUNCTION::CALL_AT(ADDRESS, ARGS, NARGS);
        std::printf("[+] 0x%llX = 0x%llX\n", (std::uint64_t)ADDRESS, (std::uint64_t)(std::uintptr_t)RESULT);

        MSRK::CLEANUP();
        return 0;
    }

    if (std::strcmp(COMMAND, "map") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing driver path\n");
            MSRK::CLEANUP();
            return 1;
        }

        std::uint64_t ARGS[16] = {};
        int NARGS = 0;

        for (int I = 4; I < argc && NARGS < 16; I++, NARGS++)
        {
            ARGS[NARGS] = std::strtoull(argv[I], nullptr, 0);
        }

        std::uintptr_t BASE = MSRK::M_DRIVERMAP::MAP(argv[3], ARGS, NARGS);

        if (!BASE)
        {
            std::printf("[-] MAP failed\n");
            MSRK::CLEANUP();
            return 1;
        }

        std::printf("[+] mapped at 0x%llX\n", (std::uint64_t)BASE);

        MSRK::CLEANUP();
        return 0;
    }

    PRINT_USAGE();
    MSRK::CLEANUP();
    return 1;
}
