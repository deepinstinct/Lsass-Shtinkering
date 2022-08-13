#include "WerReportException.h"

NTSTATUS SignalStartWerSvc()
{
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	HMODULE ntdllHandle = GetModuleHandle(L"ntdll.dll");
	const auto NtUpdateWnfStateData = reinterpret_cast<NtUpdateWnfStateData_func>(GetProcAddress(ntdllHandle, "NtUpdateWnfStateData"));

	if (NtUpdateWnfStateData)
	{
		__int64 werWnfStateName = 0x41940B3AA3BC0875; // WNF_WER_SERVICE_START
		wcout << L"        [-] NtUpdateWnfStateData() for WNF_WER_SERVICE_START" << endl;
		ntstatus = NtUpdateWnfStateData(&werWnfStateName, nullptr, 0, nullptr, nullptr, 0, 0);
	}
	else
	{
		// Alternative to WNF (before Win8 for example)
		const auto EtwEventWriteNoRegistration = reinterpret_cast<EtwEventWriteNoRegistration_func>(GetProcAddress(ntdllHandle, "EtwEventWriteNoRegistration"));
		if (nullptr == EtwEventWriteNoRegistration)
			return ntstatus;

		constexpr GUID feedbackServiceTriggerProviderGuid = { 0xe46eead8, 0xc54, 0x4489, {0x98, 0x98, 0x8f, 0xa7, 0x9d, 0x5, 0x9e, 0xe} };
		EVENT_DESCRIPTOR eventDescriptor;
		RtlZeroMemory(&eventDescriptor, sizeof(EVENT_DESCRIPTOR));

		wcout << L"        [-] EtwEventWriteNoRegistration() for {E46EEAD8-0C54-4489-9898-8FA79D059E0E}" << endl;

		ntstatus = EtwEventWriteNoRegistration(&feedbackServiceTriggerProviderGuid, &eventDescriptor, 0, nullptr);
	}

	return ntstatus;
}

NTSTATUS WaitForWerSvc()
{
	constexpr auto name = L"\\KernelObjects\\SystemErrorPortReady";
	UNICODE_STRING objectName;
	objectName.Buffer = const_cast<PWSTR>(name);
	objectName.Length = 0x46;
	objectName.MaximumLength = 0x48;

	OBJECT_ATTRIBUTES objectAttributes;
	objectAttributes.ObjectName = &objectName;
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.RootDirectory = nullptr;
	objectAttributes.Attributes = 0;
	objectAttributes.SecurityDescriptor = nullptr;
	objectAttributes.SecurityQualityOfService = nullptr;

	wcout << L"        [-] NtOpenEvent() for \"\\KernelObjects\\SystemErrorPortReady\"" << endl;

	HANDLE hEvent;
	NTSTATUS ntstatus = NtOpenEvent(&hEvent, EVENT_QUERY_STATE | SYNCHRONIZE, &objectAttributes);
	
	if (!NT_SUCCESS(ntstatus))
		throw runtime_error("WaitForWerSvc()->NtOpenEvent() failed");

	wcout << L"        [-] NtWaitForSingleObject() for hEvent" << endl;

	ntstatus = NtWaitForSingleObject(hEvent, FALSE, nullptr);
	NtClose(hEvent);
	return ntstatus;
}

NTSTATUS SendMessageToWerService(ReportExceptionWerAlpcMessage* SendingMessage, ReportExceptionWerAlpcMessage* ReceivingMessage)
{
	wcout << L"    [-] SignalStartWerSvc()" << endl;
	NTSTATUS ntstatus = SignalStartWerSvc();
	wcout << L"        [-] NTSTATUS: 0x" << ntstatus << endl;
	if (!NT_SUCCESS(ntstatus))
		throw runtime_error("Signaling WER to start failed");

	wcout << L"    [-] WaitForWerSvc()" << endl;
	ntstatus = WaitForWerSvc();
	wcout << L"        [-] NTSTATUS: 0x" << ntstatus << endl;
	
	if (!NT_SUCCESS(ntstatus))
		throw runtime_error("Waiting for WER to start failed");

	

	HMODULE ntdllHandle = GetModuleHandle(L"ntdll.dll");
	auto ZwAlpcConnectPort = reinterpret_cast<NtAlpcConnectPort_func>(GetProcAddress(ntdllHandle, "ZwAlpcConnectPort"));
	auto NtAlpcSendWaitReceivePort = reinterpret_cast<NtAlpcSendWaitReceivePort_func>(GetProcAddress(ntdllHandle, "NtAlpcSendWaitReceivePort"));

	UNICODE_STRING alpcWerPortString;
	RtlInitUnicodeString(&alpcWerPortString, L"\\WindowsErrorReportingServicePort");

	HANDLE portHandle;
	OBJECT_ATTRIBUTES objectAttributes;
	ALPC_PORT_ATTRIBUTES portAttributes;
	PORT_MESSAGE connectionMessage;

	objectAttributes.Length = sizeof(objectAttributes);
	objectAttributes.RootDirectory = nullptr;
	objectAttributes.Attributes = 0;
	objectAttributes.ObjectName = nullptr;
	objectAttributes.SecurityDescriptor = nullptr;
	objectAttributes.SecurityQualityOfService = nullptr;

	memset(&portAttributes, 0, sizeof(portAttributes));
	portAttributes.MaxMessageLength = sizeof(ReportExceptionWerAlpcMessage);

	ntstatus = ZwAlpcConnectPort(&portHandle, &alpcWerPortString, &objectAttributes, &portAttributes, ALPC_MSGFLG_SYNC_REQUEST, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
	wcout << L"    [-] ZwAlpcConnectPort() for \"\\WindowsErrorReportingServicePort\" NTSTATUS: 0x" << ntstatus << endl;
	if (!NT_SUCCESS(ntstatus))
		throw runtime_error("ZwAlpcConnectPort failed");

	SIZE_T bufLength = sizeof(ReportExceptionWerAlpcMessage);
	ntstatus = NtAlpcSendWaitReceivePort(portHandle, ALPC_MSGFLG_SYNC_REQUEST, reinterpret_cast<PPORT_MESSAGE>(SendingMessage), nullptr, reinterpret_cast<PPORT_MESSAGE>(ReceivingMessage), &bufLength, nullptr, nullptr);
	NtClose(portHandle);
	std::cout << "    [-] NtAlpcSendWaitReceivePort() NTSTATUS: 0x" << std::hex << ntstatus << endl;
	std::cout << "    [-] Received message NtStatusErrorCode: 0x" << ReceivingMessage->NtStatusErrorCode << endl;

	// Check that the ntstatus from the call and in the received message indicate success
	if (NT_SUCCESS(ntstatus) && STATUS_TIMEOUT != ntstatus)
	{
		if (!NT_SUCCESS(ReceivingMessage->NtStatusErrorCode))
			throw runtime_error("ReceivingMessage->NtStatusErrorCode indicates a fail");
	}
	else
		throw runtime_error("NtAlpcSendWaitReceivePort failed");

	return ntstatus;
}

BOOL ReportExceptionToWer(DWORD ProcessPid, HANDLE ProcessHandle)
{
	// Create exception details
	EXCEPTION_RECORD exceptionRecord = {};
	_EXCEPTION_POINTERS exceptionPointers = {};
	CONTEXT context = {};
	exceptionRecord.ExceptionCode = STATUS_UNSUCCESSFUL;
	exceptionPointers.ExceptionRecord = &exceptionRecord;
	exceptionPointers.ContextRecord = &context;

	// Create hRecoveryEVent & hCompletionEvent
	_SECURITY_ATTRIBUTES eventAttributes = { sizeof(_SECURITY_ATTRIBUTES) , nullptr, TRUE };

	HANDLE hRecoveryEvent = CreateEventW(&eventAttributes, TRUE, 0, nullptr);
	HANDLE hCompletionEvent = CreateEventW(&eventAttributes, TRUE, 0, nullptr);

	// Create the file mapping
	const HANDLE hFileMapping = CreateFileMappingW(GetCurrentProcess(), &eventAttributes, PAGE_READWRITE, 0, sizeof(MappedViewStruct), nullptr);
	HANDLE mappedView = MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	// Prepare the MappedViewStruct
	MappedViewStruct mps = {};
	mps.Size = sizeof(MappedViewStruct);
	mps.ExceptionPointers = &exceptionPointers;
	mps.hCompletionEvent = hCompletionEvent;
	mps.hRecoveryEvent = hRecoveryEvent;
	mps.NtErrorCode = E_FAIL;
	mps.NtStatusErrorCode = STATUS_UNSUCCESSFUL;
	mps.TickCount = GetTickCount();
	mps.TargetProcessPid = ProcessPid;
	mps.hTargetProcess = ProcessHandle;
	mps.TargetThreadTid = GetFirstThread(ProcessPid);
	mps.hTargetThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, mps.TargetThreadTid);

	// Print MappedViewStruct members
	wcout << L"[*] MappedViewStruct:" << endl;
	wcout << L"    [-] Size: 0x"              << mps.Size              << endl;
	wcout << L"    [-] ExceptionPointers: 0x" << mps.ExceptionPointers << endl;
	wcout << L"    [-] hCompletionEvent: 0x"  << mps.hCompletionEvent  << endl;
	wcout << L"    [-] hRecoveryEvent: 0x"    << mps.hRecoveryEvent    << endl;
	wcout << L"    [-] NtErrorCode: 0x"       << mps.NtErrorCode       << endl;
	wcout << L"    [-] NtStatusErrorCode: 0x" << mps.NtStatusErrorCode << endl;
	wcout << L"    [-] TickCount: 0x"         << mps.TickCount         << endl;
	wcout << L"    [-] TargetProcessPID: 0x"  << mps.TargetProcessPid  << endl;
	wcout << L"    [-] hTargetProcess: 0x"    << mps.hTargetProcess    << endl;
	wcout << L"    [-] TargetThreadTID: 0x"   << mps.TargetThreadTid   << endl;
	wcout << L"    [-] hTargetThread: 0x"     << mps.hTargetThread     << endl;

	// Prepare the ALPC request
	ReportExceptionWerAlpcMessage sendingMessage = {};
	sendingMessage.PortMessage.u1.s1.TotalLength = sizeof(ReportExceptionWerAlpcMessage);
	sendingMessage.PortMessage.u1.s1.DataLength = sizeof(ReportExceptionWerAlpcMessage) - sizeof(PORT_MESSAGE);
	sendingMessage.MessageType = WerSvcMessageId::RequestReportUnhandledException;
	sendingMessage.Flags = 0;
	sendingMessage.hFileMapping = hFileMapping;
	sendingMessage.hCompletionEvent = hCompletionEvent;
	sendingMessage.hRecoveryEvent = hRecoveryEvent;
	sendingMessage.hFileMapping2 = hFileMapping;
	sendingMessage.hTargetProcess = mps.hTargetProcess;
	sendingMessage.hTargetThread = mps.hTargetThread;
	sendingMessage.TargetProcessId = mps.TargetProcessPid;

	// Prepare the ALPC response
	ReportExceptionWerAlpcMessage receivingMessage = {};
	receivingMessage.PortMessage.u1.s1.TotalLength = sizeof(ReportExceptionWerAlpcMessage);
	receivingMessage.PortMessage.u1.s1.DataLength = sizeof(ReportExceptionWerAlpcMessage) - sizeof(PORT_MESSAGE);

	// Copy the struct into the mapped view
	RtlCopyMemory(mappedView, &mps, sizeof(mps));

	wcout << L"[*] SendMessageToWerService()" << endl;

	// Send the request and get the response from the ALPC server
	NTSTATUS werNtstatus = SendMessageToWerService(&sendingMessage, &receivingMessage);

	CloseHandle(mappedView);
	CloseHandle(hFileMapping);
	CloseHandle(hCompletionEvent);
	CloseHandle(hRecoveryEvent);

	// Did we fail to send the ALPC message?
	if (STATUS_SUCCESS != werNtstatus)
		throw runtime_error("SendMessageToWERService failed");

	// Did the operation not succeed on WerSvc side?
	if (STATUS_SUCCESS != receivingMessage.NtStatusErrorCode)
	{
		std::stringstream messageStream;
		messageStream << "receivingMessage.NtStatusErrorCode is 0x";
		messageStream << std::hex << to_string(receivingMessage.NtStatusErrorCode);
		string errorMessage = messageStream.str();
		throw runtime_error(errorMessage.c_str());
	}

	// Check if message type indicates failure
	if (WerSvcMessageId::ReplyReportUnhandledExceptionFailure != receivingMessage.MessageType)
	{
		std::stringstream messageStream;
		messageStream << "receivingMessage.MessageType is 0x";
		messageStream << std::hex << to_string(receivingMessage.NtStatusErrorCode);
		string errorMessage = messageStream.str();
		throw runtime_error(errorMessage.c_str());
		
	}

	// The reply consists of a handle to the spawned WerFault.exe process
	auto werFaultProcessHandle = reinterpret_cast<HANDLE>(receivingMessage.Flags);

	wcout << L"[*] Waiting for WerFault.exe to exit..." << endl;

	// Wait for WeFault to exit
	while (TRUE)
	{
		NTSTATUS ntstatus = NtWaitForSingleObject(werFaultProcessHandle, TRUE, nullptr);

		// Was there was either a timeout or a failure
		if (STATUS_TIMEOUT == ntstatus || ntstatus < 0)
			break;

		// If there wasn't a failure,
		// did we return because of an APC or because the wait was aborted?
		if (STATUS_USER_APC != ntstatus && STATUS_ALERTED != ntstatus)
		{
			ntstatus = STATUS_SUCCESS;
			break;
		}

	}
	return TRUE;
}