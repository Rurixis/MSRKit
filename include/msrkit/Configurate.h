#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DRIVER_SERVICE_NAME   L"AmdTools64"
#define DRIVER_DEVICE_ID      L"Root\\AmdTools64\\0000"
#define DRIVER_HWID           L"Root\\AmdTools64\0"
#define IOCTL_READ_MSR        0xFFF02804
#define IOCTL_WRITE_MSR       0xFFF02808

static GUID DRIVER_GUID =
{
    0x1232175B, 0x1C34, 0x41FD,
    { 0xB1, 0x01, 0x34, 0x2D, 0x47, 0xB8, 0x28, 0xAC }
};

#pragma pack(push, 1)
struct MSR_IO_DATA
{
    ULONG     MSR_REGISTER;
    ULONGLONG value;
    ULONG     core_index;
    ULONG     reserved;
};
#pragma pack(pop)
