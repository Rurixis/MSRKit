#pragma once

#include "Configurate.h"

#include <cstdio>
#include <cfgmgr32.h>
#pragma comment(lib, "cfgmgr32.lib")

class M_BOOTSTRAP final
{
    private:
        static HANDLE OPEN_SYMLINK()
        {
            wchar_t SYMLINK_PATH[MAX_PATH];
            swprintf_s(SYMLINK_PATH, L"\\\\.\\%s", DRIVER_SERVICE_NAME);

            return CreateFileW(
                SYMLINK_PATH,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );
        }

        static bool SETUP_DEVNODE()
        {
            DEVINST ParentDevNode = 0;
            DEVINST DevNodeHANDLE = 0;

            CM_Locate_DevNodeW(
                &ParentDevNode,
                nullptr,
                CM_LOCATE_DEVNODE_NORMAL
            );

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
            if (CR_RETURN != CR_SUCCESS)
            {
                return false;
            }

            CM_Add_IDW(
                DevNodeHANDLE,
                DRIVER_HWID,
                CM_ADD_ID_HARDWARE
            );

            CM_Set_DevNode_Registry_PropertyW(
                DevNodeHANDLE,
                CM_DRP_SERVICE,
                DRIVER_SERVICE_NAME,
                sizeof(DRIVER_SERVICE_NAME),
                0
            );

            return CM_Setup_DevNode(DevNodeHANDLE, CM_SETUP_DEVNODE_READY) == CR_SUCCESS;
        }

        static HANDLE OPEN_INTERFACE()
        {
            ULONG DEVICE_INTERFACE_SIZE = 0;
            wchar_t DEVICE_INTERFACE[512];

            CM_Get_Device_Interface_List_SizeW(
                &DEVICE_INTERFACE_SIZE,
                &DRIVER_GUID,
                nullptr,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            if (DEVICE_INTERFACE_SIZE <= 1 || DEVICE_INTERFACE_SIZE > 512)
            {
                return INVALID_HANDLE_VALUE;
            }

            CM_Get_Device_Interface_ListW(
                &DRIVER_GUID,
                nullptr,
                DEVICE_INTERFACE,
                DEVICE_INTERFACE_SIZE,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            return CreateFileW(
                DEVICE_INTERFACE,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr
            );

        }

        friend HANDLE LOAD_DRIVER(const wchar_t* DRIVER_PATH);
};


inline HANDLE LOAD_DRIVER(const wchar_t* DRIVER_PATH)
{
    wchar_t FULL_PATH[MAX_PATH] = {};
    GetFullPathNameW(
        DRIVER_PATH,
        MAX_PATH,
        FULL_PATH,
        nullptr
    );

    SC_HANDLE SERVICE_CONTROL_HANDLE = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CREATE_SERVICE
    );

    if (!SERVICE_CONTROL_HANDLE)
    {
        return INVALID_HANDLE_VALUE;
    }

    SC_HANDLE SERVICE_HANDLE = CreateServiceW(
        SERVICE_CONTROL_HANDLE,
        DRIVER_SERVICE_NAME,
        DRIVER_SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        FULL_PATH,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!SERVICE_HANDLE && GetLastError() == ERROR_SERVICE_EXISTS)
    {
        SERVICE_HANDLE = OpenServiceW(SERVICE_CONTROL_HANDLE, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    }

    CloseServiceHandle(SERVICE_CONTROL_HANDLE);

    if (!SERVICE_HANDLE)
    {
        return INVALID_HANDLE_VALUE;
    }

    bool STARTED = StartServiceW(SERVICE_HANDLE, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(SERVICE_HANDLE);

    if (STARTED)
    {
        HANDLE DRIVER_HANDLE = M_BOOTSTRAP::OPEN_SYMLINK();

        if (DRIVER_HANDLE != INVALID_HANDLE_VALUE)
        {
            return DRIVER_HANDLE;
        }
    }

    if (!M_BOOTSTRAP::SETUP_DEVNODE())
    {
        return INVALID_HANDLE_VALUE;
    }

    return M_BOOTSTRAP::OPEN_INTERFACE();
}


class M_TEARDOWN final
{
    private:
        static bool STOP_SERVICE()
        {
            SC_HANDLE SERVICE_CONTROL_HANDLE = OpenSCManagerW(
                nullptr,
                nullptr,
                SC_MANAGER_ALL_ACCESS
            );

            if (!SERVICE_CONTROL_HANDLE)
            {
                return false;
            }

            SC_HANDLE SERVICE_HANDLE = OpenServiceW(
                SERVICE_CONTROL_HANDLE,
                DRIVER_SERVICE_NAME,
                SERVICE_ALL_ACCESS
            );

            CloseServiceHandle(SERVICE_CONTROL_HANDLE);

            if (!SERVICE_HANDLE)
            {
                return false;
            }

            SERVICE_STATUS SERVICE_STATE = {};
            ControlService(
                SERVICE_HANDLE,
                SERVICE_CONTROL_STOP,
                &SERVICE_STATE
            );

            CloseServiceHandle(SERVICE_HANDLE);

            return true;
        }

        friend bool UNLOAD_DRIVER();
};


inline bool UNLOAD_DRIVER()
{
    return M_TEARDOWN::STOP_SERVICE();
}
