#include "dbgobjhandle.h"
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

bool DebugObjectHandle(const HANDLE hProcess) 
{
    HANDLE hDebugObject = NULL;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugObjectHandle,
        &hDebugObject,
        sizeof(HANDLE),
        (PULONG)1
    );

    if (status != STATUS_ACCESS_VIOLATION) {
        return TRUE;
    }

    if (hDebugObject != NULL) {
        return TRUE;
    }

    return FALSE;
}
