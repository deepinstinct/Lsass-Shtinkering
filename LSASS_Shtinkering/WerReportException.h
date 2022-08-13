#pragma once
#include "Utils.h"
#include "ntddk.h"
#include <sstream>
#include <ntstatus.h>

using std::to_string;
using std::to_wstring;

BOOL ReportExceptionToWer(DWORD ProcessPid, HANDLE ProcessHandle);