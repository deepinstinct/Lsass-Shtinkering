#pragma once
#include <string>
#include <stdexcept>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

using std::endl;
using std::wcout;
using std::string;
using std::wstring;
using std::runtime_error;

DWORD GetLsassPid();
BOOL IsLocalSystem();
DWORD GetFirstThread(DWORD Pid);
void PrintCrashDampLocation();