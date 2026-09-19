#pragma once

#include <sdkddkver.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cfgmgr32.h>
#include <combaseapi.h>

#include "Configurate.h"

#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

using pfnNtLoadDriver        = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using pfnNtUnloadDriver      = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using pfnRtlAdjustPrivilege  = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
using pfnRtlInitUnicodeString = VOID(NTAPI*)(PUNICODE_STRING, PCWSTR);

class U_PnP final
{
public:
    static bool SETUP_DEVNODE()
    {
        wchar_t GUID_STR[64];
        if (StringFromGUID2(DRIVER_GUID, GUID_STR, 64) == 0) return false;

        DEVINST ParentDevNode = 0;
        DEVINST DevNodeHANDLE = 0;

        if (CM_Locate_DevNodeW(&ParentDevNode, nullptr, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) return false;

        CONFIGRET CR_RETURN = CM_Create_DevNodeW(
            &DevNodeHANDLE,
            DRIVER_DEVICE_ID,
            ParentDevNode,
            CM_CREATE_DEVNODE_NORMAL
        );

        if (CR_RETURN == CR_ALREADY_SUCH_DEVINST)
        {
            CR_RETURN = CM_Locate_DevNodeW(
                &DevNodeHANDLE,
                DRIVER_DEVICE_ID,
                CM_LOCATE_DEVNODE_NORMAL
            );
        }
        if (CR_RETURN != CR_SUCCESS) return false;

        CM_Add_IDW(
            DevNodeHANDLE,
            DRIVER_HWID,
            CM_ADD_ID_HARDWARE
        );

        const DWORD SERVICE_NAME_BYTES = (DWORD)((wcslen(DRIVER_SERVICE_NAME) + 1) * sizeof(wchar_t));
        const DWORD GUID_STR_BYTES = (DWORD)((wcslen(GUID_STR) + 1) * sizeof(wchar_t));

        CM_Set_DevNode_Registry_PropertyW(
            DevNodeHANDLE,
            CM_DRP_SERVICE,
            DRIVER_SERVICE_NAME,
            SERVICE_NAME_BYTES,
            0
        );

        CM_Set_DevNode_Registry_PropertyW(
            DevNodeHANDLE,
            CM_DRP_CLASSGUID,
            GUID_STR,
            GUID_STR_BYTES,
            0
        );

        wchar_t EXISTING_DRIVER[128] = {};
        ULONG EXISTING_SIZE = sizeof(EXISTING_DRIVER);
        bool NEED_CLASS_KEY = true;

        if (CM_Get_DevNode_Registry_PropertyW(DevNodeHANDLE, CM_DRP_DRIVER,
            nullptr, EXISTING_DRIVER, &EXISTING_SIZE, 0) == CR_SUCCESS && EXISTING_DRIVER[0])
        {
            wchar_t VERIFY_PATH[MAX_PATH];
            swprintf_s(VERIFY_PATH, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", EXISTING_DRIVER);
            HKEY VERIFY_KEY = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, VERIFY_PATH, 0, KEY_READ, &VERIFY_KEY) == ERROR_SUCCESS)
            {
                RegCloseKey(VERIFY_KEY);
                NEED_CLASS_KEY = false;
            }
        }

        if (NEED_CLASS_KEY)
        {
            wchar_t CLASS_KEY_PATH[MAX_PATH];
            swprintf_s(CLASS_KEY_PATH, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", GUID_STR);

            HKEY CLASS_KEY = nullptr;
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, CLASS_KEY_PATH, 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &CLASS_KEY, nullptr) == ERROR_SUCCESS)
            {
                wchar_t CLASS_NAME[] = L"AmdTools";
                RegSetValueExW(CLASS_KEY, L"Class", 0, REG_SZ, (const BYTE*)CLASS_NAME, sizeof(CLASS_NAME));
                RegSetValueExW(CLASS_KEY, L"ClassGUID", 0, REG_SZ, (const BYTE*)GUID_STR, GUID_STR_BYTES);

                DWORD NEXT_INDEX = 0;
                wchar_t SUB_NAME[MAX_PATH];
                DWORD SUB_SIZE = MAX_PATH;

                for (DWORD i = 0; RegEnumKeyExW(CLASS_KEY, i, SUB_NAME, &SUB_SIZE, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS; i++)
                {
                    DWORD VAL = (DWORD)wcstoul(SUB_NAME, nullptr, 10);
                    if (VAL >= NEXT_INDEX)
                        NEXT_INDEX = VAL + 1;
                    SUB_SIZE = MAX_PATH;
                }

                wchar_t SUBKEY_INDEX[16];
                swprintf_s(SUBKEY_INDEX, L"%04lu", NEXT_INDEX);

                HKEY INSTANCE_KEY = nullptr;
                if (RegCreateKeyExW(CLASS_KEY, SUBKEY_INDEX, 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &INSTANCE_KEY, nullptr) == ERROR_SUCCESS)
                {
                    RegSetValueExW(INSTANCE_KEY, L"Service", 0, REG_SZ,
                        (const BYTE*)DRIVER_SERVICE_NAME, SERVICE_NAME_BYTES);
                    RegSetValueExW(INSTANCE_KEY, L"MatchingDeviceId", 0, REG_SZ,
                        (const BYTE*)DRIVER_HWID, (DWORD)((wcslen(DRIVER_HWID) + 1) * sizeof(wchar_t)));
                    RegCloseKey(INSTANCE_KEY);
                }

                RegCloseKey(CLASS_KEY);

                wchar_t DRIVER_VALUE[128];
                swprintf_s(DRIVER_VALUE, L"%s\\%04lu", GUID_STR, NEXT_INDEX);

                CM_Set_DevNode_Registry_PropertyW(
                    DevNodeHANDLE, CM_DRP_DRIVER,
                    DRIVER_VALUE, (DWORD)((wcslen(DRIVER_VALUE) + 1) * sizeof(wchar_t)), 0);
            }
        }

        DWORD ZERO_FLAGS = 0;
        CM_Set_DevNode_Registry_PropertyW(
            DevNodeHANDLE,
            CM_DRP_CONFIGFLAGS,
            &ZERO_FLAGS,
            sizeof(ZERO_FLAGS),
            0
        );

        CM_Setup_DevNode(DevNodeHANDLE, CM_SETUP_DEVNODE_READY);
        return CM_Reenumerate_DevNode(ParentDevNode, CM_REENUMERATE_NORMAL) == CR_SUCCESS;
    }

    static void REMOVE_DEVNODE()
    {
        DEVINST DevNodeHANDLE = 0;

        if (CM_Locate_DevNodeW(&DevNodeHANDLE, DRIVER_DEVICE_ID, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
        {
            wchar_t DRV_VAL[128] = {};
            ULONG DRV_SIZE = sizeof(DRV_VAL);
            CM_Get_DevNode_Registry_PropertyW(DevNodeHANDLE, CM_DRP_DRIVER,
                nullptr, DRV_VAL, &DRV_SIZE, 0);

            CM_Query_And_Remove_SubTreeW(DevNodeHANDLE, nullptr, nullptr, 0, CM_REMOVE_NO_RESTART);

            if (DRV_VAL[0])
            {
                wchar_t CLASS_INST[MAX_PATH];
                swprintf_s(CLASS_INST, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", DRV_VAL);
                RegDeleteTreeW(HKEY_LOCAL_MACHINE, CLASS_INST);
            }
        }
    }

    static HANDLE OPEN_INTERFACE()
    {
        ULONG DEVICE_INTERFACE_SIZE = 0;
        wchar_t DEVICE_INTERFACE[512] = {};

        if (CM_Get_Device_Interface_List_SizeW(&DEVICE_INTERFACE_SIZE, &DRIVER_GUID, nullptr, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS || DEVICE_INTERFACE_SIZE <= 1 || DEVICE_INTERFACE_SIZE > 512)
        {
            return INVALID_HANDLE_VALUE;
        }

        if (CM_Get_Device_Interface_ListW(&DRIVER_GUID, nullptr, DEVICE_INTERFACE, DEVICE_INTERFACE_SIZE, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
        {
            return INVALID_HANDLE_VALUE;
        }

        return CreateFileW(
            DEVICE_INTERFACE,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr
        );
    }
};

class M_BOOTSTRAP final
{
private:
    static HMODULE GET_NTDLL()
    {
        static HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        return hNtdll;
    }

    static bool ACQUIRE_PRIVILEGE()
    {
        auto fRtlAdjustPrivilege = (pfnRtlAdjustPrivilege)GetProcAddress(GET_NTDLL(), "RtlAdjustPrivilege");
        if (!fRtlAdjustPrivilege) return false;

        BOOLEAN WAS_ENABLED = FALSE;
        return fRtlAdjustPrivilege(10, TRUE, FALSE, &WAS_ENABLED) == STATUS_SUCCESS;
    }

    static bool CREATE_REGISTRY_ENTRY(const wchar_t* FULL_PATH)
    {
        wchar_t SERVICES_KEY[MAX_PATH];
        swprintf_s(SERVICES_KEY, L"SYSTEM\\CurrentControlSet\\Services\\%s", DRIVER_SERVICE_NAME);

        HKEY KEY_HANDLE = nullptr;
        LSTATUS regStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &KEY_HANDLE, nullptr);

        if (regStatus != ERROR_SUCCESS) return false;

        wchar_t NT_PATH[MAX_PATH];
        swprintf_s(NT_PATH, L"\\??\\%s", FULL_PATH);

        DWORD TYPE_VALUE = 1, START_VALUE = 3, ERROR_VALUE = 0;

        RegSetValueExW(KEY_HANDLE, L"ImagePath",    0, REG_EXPAND_SZ, (const BYTE*)NT_PATH, (DWORD)((wcslen(NT_PATH) + 1) * sizeof(wchar_t)));
        RegSetValueExW(KEY_HANDLE, L"Type",         0, REG_DWORD,     (const BYTE*)&TYPE_VALUE, sizeof(DWORD));
        RegSetValueExW(KEY_HANDLE, L"Start",        0, REG_DWORD,     (const BYTE*)&START_VALUE, sizeof(DWORD));
        RegSetValueExW(KEY_HANDLE, L"ErrorControl", 0, REG_DWORD,     (const BYTE*)&ERROR_VALUE, sizeof(DWORD));

        RegCloseKey(KEY_HANDLE);
        return true;
    }

    static void DELETE_REGISTRY_ENTRY()
    {
        wchar_t SERVICES_KEY[MAX_PATH];
        swprintf_s(SERVICES_KEY, L"SYSTEM\\CurrentControlSet\\Services\\%s", DRIVER_SERVICE_NAME);
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, SERVICES_KEY);
    }

    static NTSTATUS LOAD_NT()
    {
        wchar_t REG_PATH[MAX_PATH];
        swprintf_s(REG_PATH, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", DRIVER_SERVICE_NAME);

        HMODULE ntdll = GET_NTDLL();
        auto fRtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        auto fNtLoadDriver = (pfnNtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

        if (!fRtlInitUnicodeString || !fNtLoadDriver) return STATUS_UNSUCCESSFUL;

        UNICODE_STRING DRIVER_REG = {};
        fRtlInitUnicodeString(&DRIVER_REG, REG_PATH);

        return fNtLoadDriver(&DRIVER_REG);
    }

    static NTSTATUS UNLOAD_NT()
    {
        wchar_t REG_PATH[MAX_PATH];
        swprintf_s(REG_PATH, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", DRIVER_SERVICE_NAME);

        HMODULE ntdll = GET_NTDLL();
        auto fRtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        auto fNtUnloadDriver = (pfnNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");

        if (!fRtlInitUnicodeString || !fNtUnloadDriver) return STATUS_UNSUCCESSFUL;

        UNICODE_STRING DRIVER_REG = {};
        fRtlInitUnicodeString(&DRIVER_REG, REG_PATH);

        return fNtUnloadDriver(&DRIVER_REG);
    }

    friend HANDLE LOAD_DRIVER(const wchar_t* DRIVER_PATH);
    friend bool   UNLOAD_DRIVER();
};


inline HANDLE LOAD_DRIVER(const wchar_t* DRIVER_PATH)
{
    wchar_t FULL_PATH[MAX_PATH] = {};
    GetFullPathNameW(DRIVER_PATH, MAX_PATH, FULL_PATH, nullptr);

    if (GetFileAttributesW(FULL_PATH) == INVALID_FILE_ATTRIBUTES) return INVALID_HANDLE_VALUE;
    if (!M_BOOTSTRAP::ACQUIRE_PRIVILEGE()) return INVALID_HANDLE_VALUE;
    if (!M_BOOTSTRAP::CREATE_REGISTRY_ENTRY(FULL_PATH)) return INVALID_HANDLE_VALUE;

    U_PnP::SETUP_DEVNODE();

    NTSTATUS STATUS = M_BOOTSTRAP::LOAD_NT();

    if (STATUS != STATUS_SUCCESS && STATUS != STATUS_IMAGE_ALREADY_LOADED && STATUS != STATUS_OBJECT_NAME_COLLISION)
    {
        M_BOOTSTRAP::DELETE_REGISTRY_ENTRY();
        return INVALID_HANDLE_VALUE;
    }

    HANDLE PNP_HANDLE = U_PnP::OPEN_INTERFACE();

    if (PNP_HANDLE == INVALID_HANDLE_VALUE)
    {
        UNLOAD_DRIVER();
    }

    return PNP_HANDLE;
}

inline bool UNLOAD_DRIVER()
{
    U_PnP::REMOVE_DEVNODE();

    NTSTATUS STATUS = M_BOOTSTRAP::UNLOAD_NT();
    M_BOOTSTRAP::DELETE_REGISTRY_ENTRY();

    return STATUS == STATUS_SUCCESS;
}