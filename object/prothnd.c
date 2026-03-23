#include "prothnd.h"
#include "..\core\syscall.h"
#pragma once
#include <Windows.h>
#include <winternl.h>

//
// Safe fallback NT definitions for missing enums
//

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 0x1e  // 30
#endif

#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger 0x11    // 17
#endif

#ifndef SystemKernelDebuggerInformation
#define SystemKernelDebuggerInformation 0x23 // 35
#endif

#ifndef ObjectHandleFlagInformation
#define ObjectHandleFlagInformation 0x04 // 4
#endif

bool ProtectedHandle()
{
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "a");
    if (hMutex) {
        ULONG flag = HANDLE_FLAG_PROTECT_FROM_CLOSE;
        DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flag, sizeof(ULONG));

        __try {
            CloseHandle(hMutex);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ULONG flags = 0;
            DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
            DbgNtClose(hMutex);
            return TRUE;
        }

#pragma warning (disable: 6001)
        ULONG flags = 0;
        DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
        DbgNtClose(hMutex);
#pragma warning (default: 6001)
    }
    return FALSE;
}
