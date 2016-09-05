#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <ctype.h>
#include <time.h>
#include "utility.h"

/* locate the user32 exports */
DWORD _ptrGetWindowThreadProcessId = (DWORD)	GetProcedureAddress(USER32, "GetWindowThreadProcessId") + 5;
DWORD _ptrGetCursorPos = (DWORD)				GetProcedureAddress(USER32, "GetCursorPos") + 5;
DWORD _ptrPostMessageA = (DWORD)				GetProcedureAddress(USER32, "PostMessageA") + 5;
DWORD _ptrPostMessageW = (DWORD)				GetProcedureAddress(USER32, "PostMessageW") + 5;
DWORD _ptrSendMessageA = (DWORD)				GetProcedureAddress(USER32, "SendMessageA") + 5;
DWORD _ptrSendMessageW = (DWORD)				GetProcedureAddress(USER32, "SendMessageW") + 5;

/* locate the ntdll exports */
DWORD _ptrNtFlushInstructionCache = (DWORD)		GetProcedureAddress(NTDLL, "NtFlushInstructionCache") + 5;
DWORD _ptrNtOpenProcess	= (DWORD)				GetProcedureAddress(NTDLL, "NtOpenProcess") + 5;
DWORD _ptrNtProtectVirtualMemory = (DWORD)		GetProcedureAddress(NTDLL, "NtProtectVirtualMemory") + 5;
DWORD _ptrNtReadVirtualMemory = (DWORD)			GetProcedureAddress(NTDLL, "NtReadVirtualMemory") + 5;
DWORD _ptrNtWriteVirtualMemory = (DWORD)		GetProcedureAddress(NTDLL, "NtWriteVirtualMemory") + 5;
DWORD _ptrNtQueryInformationProcess	= (DWORD)	GetProcedureAddress(NTDLL, "NtQueryInformationProcess") + 5;
DWORD _ptrNtQuerySystemInformation = (DWORD)	GetProcedureAddress(NTDLL, "NtQuerySystemInformation") + 5;
DWORD _ptrNtClose = (DWORD)						GetProcedureAddress(NTDLL, "NtClose") + 5;

/* declare the ntdll syscall offsets */
DWORD _oNtFlushInstructionCache =		NtSyscallIndex("NtFlushInstructionCache");
DWORD _oNtOpenProcess =					NtSyscallIndex("NtOpenProcess");
DWORD _oNtProtectVirtualMemory =		NtSyscallIndex("NtProtectVirtualMemory");
DWORD _oNtReadVirtualMemory =			NtSyscallIndex("NtReadVirtualMemory");
DWORD _oNtWriteVirtualMemory =			NtSyscallIndex("NtWriteVirtualMemory");
DWORD _oNtQueryInformationProcess =		NtSyscallIndex("NtQueryInformationProcess");
DWORD _oNtQuerySystemInformation =		NtSyscallIndex("NtQuerySystemInformation");
DWORD _oNtClose =						NtSyscallIndex("NtClose");

#pragma region GetModuleHandle

extern "C" __declspec(dllexport) HMODULE extGetModuleHandleA(LPCSTR lpModuleName)
{
	return GetModHandleA(lpModuleName);
}

extern "C" __declspec(dllexport) HMODULE extGetModuleHandleW(LPWSTR lpModuleName)
{
	return GetModHandleW(lpModuleName);
}

#pragma endregion

#pragma region GetWindowThreadProcessId

__declspec(naked) BOOL WINAPI _GetWindowThreadProcessId(_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp    dword ptr ds : [_ptrGetWindowThreadProcessId]
	}
}


extern "C" __declspec(dllexport) BOOL WINAPI extGetWindowThreadProcessId(_In_ HWND hWnd, _Out_opt_ LPDWORD lpdwProcessId)
{
	return _GetWindowThreadProcessId(hWnd, lpdwProcessId);
}

#pragma endregion

#pragma region GetCursorPos

__declspec(naked) BOOL WINAPI _GetCursorPos(
	_Out_ LPPOINT lpPoint
) {
	__asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		jmp dword ptr ds : [_ptrGetCursorPos]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extGetCursorPos(_Out_ LPPOINT lpPoint)
{
	return _GetCursorPos(lpPoint);
}

#pragma endregion

#pragma region PostMessageA

__declspec(naked) BOOL WINAPI _PostMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp    dword ptr ds : [_ptrPostMessageA]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extPostMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return _PostMessageA(hWnd, uMsg, wParam, lParam);
}

#pragma endregion

#pragma region PostMessageW

__declspec(naked) BOOL WINAPI _PostMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp    dword ptr ds : [_ptrPostMessageW]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extPostMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return _PostMessageW(hWnd, uMsg, wParam, lParam);
}

#pragma endregion

#pragma region SendMessageA

__declspec(naked) BOOL WINAPI _SendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp    dword ptr ds : [_ptrSendMessageA]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extSendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return _SendMessageA(hWnd, uMsg, wParam, lParam);
}

#pragma endregion

#pragma region SendMessageW

__declspec(naked) BOOL WINAPI _SendMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	__asm
	{
		mov    edi, edi
		push   ebp
		mov    ebp, esp
		jmp    dword ptr ds : [_ptrSendMessageW]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extSendMessageW(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return _SendMessageW(hWnd, uMsg, wParam, lParam);
}

#pragma endregion

#pragma region NtFlushInstructionCache

__declspec(naked) NTSTATUS NTAPI _NtFlushInstructionCache(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG NumberOfBytesToFlush)
{
	__asm
	{
		mov eax, [_oNtFlushInstructionCache]
		jmp dword ptr ds : [_ptrNtFlushInstructionCache]
	}
}

#pragma endregion

#pragma region NtOpenProcess

__declspec(naked) NTSTATUS NTAPI _NtOpenProcess
(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
) {
	__asm
	{
		mov eax, [_oNtOpenProcess]
		jmp    dword ptr ds : [_ptrNtOpenProcess]
	}
}

extern "C" __declspec(dllexport) HANDLE WINAPI extOpenProcess(DWORD pId)
{
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pId;
	cid.UniqueThread = 0;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	HANDLE hProcess;
	if (!NT_SUCCESS(_NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid)))
	{
		return 0;
	}
	return hProcess;
}

#pragma endregion

#pragma region NtProtectVirtualMemory

__declspec(naked) NTSTATUS NTAPI _NtProtectVirtualMemory(IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection)
{
	__asm
	{
		mov eax, [_oNtProtectVirtualMemory]
		jmp dword ptr ds : [_ptrNtProtectVirtualMemory]
	}
}

#pragma endregion

#pragma region NtReadVirtualMemory

__declspec(naked) NTSTATUS NTAPI _NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
{
	__asm
	{
		mov eax, [_oNtReadVirtualMemory]
		jmp    dword ptr ds : [_ptrNtReadVirtualMemory]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extReadMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
{
	NTSTATUS ntStat = _NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	return NT_SUCCESS(ntStat);
}

#pragma endregion

#pragma region NtWriteVirtualMemory

__declspec(naked) NTSTATUS NTAPI _NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, CONST VOID *Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
	__asm
	{
		mov eax, [_oNtWriteVirtualMemory]
		jmp    dword ptr ds : [_ptrNtWriteVirtualMemory]
	}
}

extern "C" __declspec(dllexport) BOOL NTAPI extWriteMemory(HANDLE hProcess, PVOID lpBaseAddress, CONST VOID* lpBuffer, SIZE_T nSize, PSIZE_T lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue;
	SIZE_T RegionSize;
	PVOID Base;
	BOOLEAN UnProtect;

	/* Set parameters for protect call */
	RegionSize = nSize;
	Base = lpBaseAddress;

	/* Check the current status */
	Status = _NtProtectVirtualMemory(hProcess,
		&Base,
		&RegionSize,
		PAGE_EXECUTE_READWRITE,
		&OldValue);

	if (NT_SUCCESS(Status))
	{
		/* Check if we are unprotecting */
		UnProtect = OldValue & (PAGE_READWRITE |
			PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE |
			PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!UnProtect)
		{
			/* Set the new protection */
			Status = _NtProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Write the memory */
			Status = _NtWriteVirtualMemory(hProcess,
				lpBaseAddress,
				(LPVOID)lpBuffer,
				nSize,
				&nSize);

			/* In Win32, the parameter is optional, so handle this case */
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

			if (!NT_SUCCESS(Status))
			{
				return FALSE;
			}

			/* Flush the ITLB */
			_NtFlushInstructionCache(hProcess, lpBaseAddress, nSize);
			return TRUE;
		}

		/* Check if we were read only */
		if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
		{
			/* Restore protection and fail */
			_NtProtectVirtualMemory(hProcess,
				&Base,
				&RegionSize,
				OldValue,
				&OldValue);

			/* Note: This is what Windows returns and code depends on it */
			return STATUS_ACCESS_VIOLATION;
		}

		/* Otherwise, do the write */
		Status = _NtWriteVirtualMemory(hProcess,
			lpBaseAddress,
			(LPVOID)lpBuffer,
			nSize,
			&nSize);

		/* In Win32, the parameter is optional, so handle this case */
		if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;

		/* And restore the protection */
		_NtProtectVirtualMemory(hProcess,
			&Base,
			&RegionSize,
			OldValue,
			&OldValue);

		if (!NT_SUCCESS(Status))
		{
			/* Note: This is what Windows returns and code depends on it */
			return STATUS_ACCESS_VIOLATION;
		}

		/* Flush the ITLB */
		_NtFlushInstructionCache(hProcess, lpBaseAddress, nSize);
		return TRUE;
	}

	return FALSE;
}

#pragma endregion

#pragma region NtQueryInformationProcess

__declspec(naked) NTSTATUS NTAPI _NtQueryInformationProcess(
	__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength)
{
	__asm
	{
		mov eax, [_oNtQueryInformationProcess]
		jmp dword ptr ds : [_ptrNtQueryInformationProcess]
	}
}

// to implement export for NtQueryInformationProcess

#pragma endregion

#pragma region NtQuerySystemInformation

__declspec(naked) NTSTATUS NTAPI _NtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength)
{
	__asm
	{
		mov eax, [_oNtQuerySystemInformation]
		jmp dword ptr ds : [_ptrNtQuerySystemInformation]
	}
}

// to implement export for NtQuerySystemInformation

#pragma endregion

#pragma region NtClose

__declspec(naked) NTSTATUS NTAPI _NtClose(HANDLE hObject)
{
	__asm
	{
		mov eax, _oNtClose
		jmp dword ptr ds : [_ptrNtClose]
	}
}

extern "C" __declspec(dllexport) BOOL WINAPI extCloseHandle(HANDLE hObject)
{
	__try
	{
		return _NtClose(hObject) == 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* it was invalid, who cares? 
			it was either already closed or never opened to begin with, nothing to clean up. 
			*/

		return true;
	}
}

#pragma endregion

#pragma region GetProcessBaseAddress

DWORD NTAPI GetProcessBaseAddress (HANDLE hProcess)
{
	PEB _PEB;
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG dwLength;

	NTSTATUS ntStat = _NtQueryInformationProcess(hProcess, ProcessBasicInformation,
		(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);

	SetLastError(ntStat);

	if (ntStat != 0) 
	{
		return 0;
	}

	ULONG dwBytesRead = 0;
	if (!NT_SUCCESS(_NtReadVirtualMemory(hProcess, pbi.PebBaseAddress,
		&_PEB, sizeof(PEB), &dwBytesRead)) || dwBytesRead < sizeof(PEB)) return 0;

	return (DWORD)_PEB.ImageBaseAddress;
}

extern "C" __declspec(dllexport) DWORD NTAPI extGetProcessBaseAddress(HANDLE hProcess)
{
	return GetProcessBaseAddress(hProcess);
}

#pragma endregion

#pragma region GetProcessImageSize

DWORD NTAPI GetProcessImageSize(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG dwLength;

	NTSTATUS ntStat = _NtQueryInformationProcess(hProcess, ProcessBasicInformation,
		(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);

	SetLastError(ntStat);
	if (ntStat != 0)
	{
		return 0;
	}

	HANDLE hSnap;
	MODULEENTRY32 xModule;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)pbi.UniqueProcessId);
	xModule.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnap, &xModule))
	{
		_NtClose(hSnap);
		return (DWORD)xModule.modBaseSize;
	}
	_NtClose(hSnap);
	return 0;
}

extern "C" __declspec(dllexport) DWORD NTAPI extGetProcessImageSize(HANDLE hProcess)
{
	return GetProcessImageSize(hProcess);
}

#pragma endregion

#pragma region GetProcessActive

extern "C" __declspec(dllexport) BOOL WINAPI extGetProcessActive(HANDLE hProcess)
{
	DWORD exitCode;
	if (!GetExitCodeProcess(hProcess, &exitCode))
	{
		return false;
	}

	if (exitCode == STILL_ACTIVE)
	{
		return true;
	}

	return false;
}

#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		/*
		LOG_NORMAL("I'm attached.\tLocations of syscalls:");
		LOG_NORMAL("NtOpenProcess: %x", _oNtOpenProcess);
		LOG_NORMAL("NtWriteVirtualMemory: %x", _oNtWriteVirtualMemory);
		*/
	}
	return TRUE;
}