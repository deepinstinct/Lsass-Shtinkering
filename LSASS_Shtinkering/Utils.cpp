/*
Copyright (C) 2023 Asaf Gilboa, Ron Ben-Yizhak

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "Utils.h"

DWORD GetServicePid(const wstring& ServiceName)
{
	const SC_HANDLE controlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (nullptr == controlManagerHandle)
		throw runtime_error("Connecting to Service Control Manager failed");

	const SC_HANDLE serviceHandle = OpenServiceW(controlManagerHandle, ServiceName.c_str(), SERVICE_QUERY_STATUS);
	CloseServiceHandle(controlManagerHandle);
	if (nullptr == serviceHandle)
		throw runtime_error("Opening service handle failed");

	SERVICE_STATUS_PROCESS procInfo;
	DWORD bytesNeeded;
	if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&procInfo), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
	{
		CloseServiceHandle(serviceHandle);
		throw runtime_error("Querying service status failed");
	}

	CloseServiceHandle(serviceHandle);
	return procInfo.dwProcessId;
}

DWORD GetLsassPid()
{
	return GetServicePid(L"samss");
}

BOOL IsLocalSystem()
{
	const HANDLE tokenHandle = GetCurrentProcessToken();
	DWORD tokenInformationSize = 0;
	GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenInformationSize);

	// The first call should fail because the buffer pointer is null. It is made to retrieve the required size of the buffer
	if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
		throw runtime_error("Getting buffer size from GetTokenInformation failed");

	// Allocate the memory required to store the info
	const auto tokenInfoBuffer = new uint8_t[tokenInformationSize];

	// Call GetTokenInformation again with a pointer to a buffer
	if (!GetTokenInformation(tokenHandle, TokenUser, tokenInfoBuffer, tokenInformationSize, &tokenInformationSize))
	{
		delete[] tokenInfoBuffer;
		throw runtime_error("Retrieving info from GetTokenInformation failed");
	}

	const auto tokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfoBuffer);
	const BOOL isSystem = IsWellKnownSid(tokenUser->User.Sid, WinLocalSystemSid);
	delete[] tokenInfoBuffer;
	return isSystem;
}

DWORD GetFirstThread(const DWORD Pid)
{
	const HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (INVALID_HANDLE_VALUE == snapshotHandle)
		throw runtime_error("Creating threads snapshot failed");

	DWORD threadId = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(snapshotHandle, &threadEntry))
	{
		do {
			if (threadEntry.th32OwnerProcessID == Pid) {
				threadId = threadEntry.th32ThreadID;
			}
		} while (Thread32Next(snapshotHandle, &threadEntry));

	}

	CloseHandle(snapshotHandle);
	return threadId;
}

void PrintCrashDampLocation()
{
	DWORD bufferSize = 32767;
	std::wstring environmentVariable;
	environmentVariable.resize(bufferSize);
	bufferSize = GetEnvironmentVariableW(L"LocalAppData", &environmentVariable[0], bufferSize);
	if (!bufferSize)
		throw runtime_error("Retrieving %LocalAppData% failed");
	environmentVariable.resize(bufferSize);
	environmentVariable.append(L"\\CrashDumps");
	std::wcout << L"[*] Crash dumps directory: " << environmentVariable << endl;
}
