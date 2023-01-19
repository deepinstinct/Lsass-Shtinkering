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

#ifndef __NTDLL_H__
#define __NTDLL_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <Windows.h>

#ifndef _NTDLL_SELF_                            // Auto-insert the library
#pragma comment(lib, "Ntdll.lib")
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define EVENT_QUERY_STATE 0x0001
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000

typedef short CSHORT;
typedef struct _QUAD
{
	union
	{
		INT64 UseThisFieldToCopy;
		float DoNotUseThisField;
	};
} QUAD, * PQUAD;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;

} CLIENT_ID, * PCLIENT_ID;

typedef struct PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		QUAD DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

struct ReportExceptionWerAlpcMessage
{
	PORT_MESSAGE PortMessage;
	DWORD MessageType;
	NTSTATUS NtStatusErrorCode;
	DWORD Flags;
	DWORD TargetProcessId;
	HANDLE hFileMapping;
#ifndef _WIN64
	DWORD Filler0;
#endif
	HANDLE hRecoveryEvent;
#ifndef _WIN64
	DWORD Filler1;
#endif
	HANDLE hCompletionEvent;
#ifndef _WIN64
	DWORD Filler2;
#endif
	HANDLE hFileMapping2;
#ifndef _WIN64
	DWORD Filler3;
#endif
	HANDLE hTargetProcess;
#ifndef _WIN64
	DWORD Filler4;
#endif
	HANDLE hTargetThread;
#ifndef _WIN64
	DWORD Filler5;
#endif
	DWORD Filler6[324];
};

struct MappedViewStruct
{
	DWORD Size;
	DWORD TargetProcessPid;
	DWORD TargetThreadTid;
	DWORD Filler0[39];
	_EXCEPTION_POINTERS* ExceptionPointers;
#ifndef _WIN64
	DWORD Filler1;
#endif
	DWORD NtErrorCode;
	DWORD Filler2;
	HANDLE hTargetProcess;
#ifndef _WIN64
	DWORD Filler3;
#endif
	HANDLE hTargetThread;
#ifndef _WIN64
	DWORD Filler4;
#endif
	HANDLE hRecoveryEvent;
#ifndef _WIN64
	DWORD Filler5;
#endif
	HANDLE hCompletionEvent;
#ifndef _WIN64
	DWORD Filler6;
#endif
	DWORD Filler7;
	DWORD Filler8;
	DWORD Null01;
	DWORD Null02;
	DWORD NtStatusErrorCode;
	DWORD Null03;
	DWORD TickCount;
	DWORD Unk101;
};

typedef struct _WNF_TYPE_ID {
	GUID	TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;
typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;
typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;
typedef ULONG LOGICAL;
typedef ULONG* PLOGICAL;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T MaxMessageLength;
	SIZE_T MemoryBandwidth;
	SIZE_T MaxPoolUsage;
	SIZE_T MaxSectionSize;
	SIZE_T MaxViewSize;
	SIZE_T MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

enum WerSvcMessageId
{
	RequestReportUnhandledException = 0x20000000,
	ReplyReportUnhandledExceptionSuccess = 0x20000001,
	ReplyReportUnhandledExceptionFailure = 0x20000002,
	RequestSilentProcessExit = 0x30000000,
	ResponseSilentProcessExitSuccess = 0x30000001,
	ResponseSilentProcessExitFailure = 0x30000002
};

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
	IN  HANDLE Handle
);

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
);

typedef NTSTATUS
(NTAPI* NtUpdateWnfStateData_func)(
	_In_ PVOID StateName,
	_In_reads_bytes_opt_(Length) const VOID* Buffer,
	_In_opt_ ULONG Length,
	_In_opt_ PCWNF_TYPE_ID TypeId,
	_In_opt_ const VOID* ExplicitScope,
	_In_ WNF_CHANGE_STAMP MatchingChangeStamp,
	_In_ LOGICAL CheckStamp);

#include <evntcons.h>
typedef ULONG(__stdcall* EtwEventWriteNoRegistration_func)(
	_In_ LPCGUID ProviderId,
	_In_ PCEVENT_DESCRIPTOR EventDescriptor,
	_In_ ULONG UserDataCount,
	_In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

typedef LONG(WINAPI* NtAlpcSendWaitReceivePort_func)(
	_In_ HANDLE 	PortHandle,
	_In_ ULONG 	Flags,
	_In_reads_bytes_opt_(SendingMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendingMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendingMessageMessageAttributes,
	PPORT_MESSAGE 	ReceiveMessage,
	_Inout_opt_ PSIZE_T 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout);

typedef LONG(WINAPI* NtAlpcConnectPort_func)(
	_Out_ PHANDLE 	PortHandle,
	_In_ PUNICODE_STRING 	PortName,
	_In_opt_ POBJECT_ATTRIBUTES 	ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES 	PortAttributes,
	_In_ ULONG 	Flags,
	_In_opt_ PSID 	RequiredServerSid,
	_Inout_ PPORT_MESSAGE 	ConnectionMessage,
	_Inout_opt_ PULONG 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	OutMessageAttributes,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	InMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __NTDLL_H__
