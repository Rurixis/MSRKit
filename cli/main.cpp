#include "../msrkit.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

static void USAGE()
{
    std::printf(
        "msrkit - kernel execution toolkit\n\n"
        "Usage:\n"
        "  msrkit <driver.sys> call <ExportName> [args...]\n"
        "  msrkit <driver.sys> call_at <address> [args...]\n"
        "  msrkit <driver.sys> map <unsigned.sys> [args...]\n"
        "  msrkit <driver.sys> unmap <address>\n"
    );
}

static void parse_args(int start_index, int argc, char* argv[], std::uint64_t* args, std::uint8_t& nargs)
{
    nargs = 0;
    for (int i = start_index; i < argc && nargs < 16; i++, nargs++)
    {
        args[nargs] = std::strtoull(argv[i], nullptr, 0);
    }
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        USAGE();
        return 0;
    }

    wchar_t DRIVER_PATH[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, DRIVER_PATH, MAX_PATH);
    const char* COMMAND = argv[2];

    if (!MSRK::INIT(DRIVER_PATH))
    {
        std::printf("[-] INIT failed: error %d\n", MSRK::GET_LAST_ERROR());
        return 1;
    }

    struct MsrCleanup { ~MsrCleanup() { MSRK::CLEANUP(); } } cleanup;

    if (std::strcmp(COMMAND, "call") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing export name\n");
            return 1;
        }

        std::uint64_t ARGS[16] = {};
        std::uint8_t NARGS = 0;
        parse_args(4, argc, argv, ARGS, NARGS);

        void* RESULT = MSRK::M_FUNCTION::CALL(argv[3], ARGS, NARGS);
        std::printf("[+] %s = 0x%llX\n", argv[3], (std::uint64_t)(std::uintptr_t)RESULT);
        return 0;
    }

    if (std::strcmp(COMMAND, "call_at") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing address\n");
            return 1;
        }

        std::uintptr_t ADDRESS = (std::uintptr_t)std::strtoull(argv[3], nullptr, 0);
        std::uint64_t ARGS[16] = {};
        std::uint8_t NARGS = 0;
        parse_args(4, argc, argv, ARGS, NARGS);

        void* RESULT = MSRK::M_FUNCTION::CALL_AT(ADDRESS, ARGS, NARGS);
        std::printf("[+] 0x%llX = 0x%llX\n", (std::uint64_t)ADDRESS, (std::uint64_t)(std::uintptr_t)RESULT);
        return 0;
    }

    if (std::strcmp(COMMAND, "map") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing driver path\n");
            return 1;
        }

        int NARGS = argc - 4;
        if (NARGS > 2)
        {
            std::printf("[-] max 2 entry args\n");
            return 1;
        }

        MSRK::MAPPING BASE;
        switch (NARGS)
        {
            case 0:
                BASE = MSRK::MAP(argv[3]);
                break;
            case 1:
                BASE = MSRK::MAP(argv[3], std::strtoull(argv[4], nullptr, 0));
                break;
            case 2:
                BASE = MSRK::MAP(argv[3], std::strtoull(argv[4], nullptr, 0), std::strtoull(argv[5], nullptr, 0));
                break;
        }

        if (!BASE)
        {
            std::printf("[-] MAP failed\n");
            return 1;
        }

        std::printf("[+] mapped at 0x%llX\n", (std::uint64_t)(std::uintptr_t)BASE);
        return 0;
    }

    if (std::strcmp(COMMAND, "unmap") == 0)
    {
        if (argc < 4)
        {
            std::printf("[-] missing address\n");
            return 1;
        }

        MSRK::MAPPING ADDRESS((std::uintptr_t)std::strtoull(argv[3], nullptr, 0));
        MSRK::UNMAP(ADDRESS);
        std::printf("[+] unmapped 0x%llX\n", (std::uint64_t)ADDRESS);
        return 0;
    }

    USAGE();
    return 1;
}
