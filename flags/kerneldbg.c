#include "kerneldbg.h"
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

static inline BOOL SharedUserData()
{
    const ULONG_PTR UserSharedData = 0x7FFE0000;

    const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4);

    const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
    const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;

    if (KdDebuggerEnabled || !KdDebuggerNotPresent)
        return TRUE;

    return FALSE;
}

bool KernelDebugger() {
    bool sharedUserDataResult = SharedUserData();

    if (sharedUserDataResult) {
        return true;
    }

    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo = { 0 };

    NTSTATUS status = DbgNtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
        &SystemInfo,
        sizeof(SystemInfo),
        NULL);

    return (((NTSTATUS)(status)) >= 0)
        ? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
        : false;
}
