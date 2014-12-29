#include "Stdafx.h"
#pragma unmanaged
__declspec(naked) void ProcessAPCQueue()
{
	__asm
	{
		mov eax, 0x0000017E
		mov ecx, 0x00000002
		lea edx, [esp + 0x04]
		call fs : [0x000000C0]
		add esp, 0x04
	}
}

__declspec(naked) void ProcessAPCQueue_PreserveECX()
{
	__asm
	{
		push ecx
		mov eax, 0x0000017E
		mov ecx, 0x00000002
		lea edx, [esp + 0x04]
		call fs : [0x000000C0]
		add esp, 0x04
		pop ecx
	}
}

unsigned char* GetRealFunction(unsigned char* fPtr, unsigned char firstByte)
{
RECHECK_ASM:
	if (fPtr[0] != firstByte)
	{
		switch (fPtr[0])
		{
			// jmp/call by pointer
			case 0xFF:
			{
				fPtr = PBYTE(PDWORD(PDWORD(&fPtr[0x2])[0])[0]);
				break;
			}
			// jmp/call by offset
			case 0xE8:
			case 0xE9:
			{
				fPtr = &PBYTE(&fPtr[0x5])[PINT(&fPtr[0x1])[0]];
				goto RECHECK_ASM;
			}
			default:
				break;
		}
	}
	return fPtr;
}

void BuildInlineSysCall(unsigned char* buffer, bool preserveECX)
{
	auto asmBytes = GetRealFunction(preserveECX ? PBYTE(ProcessAPCQueue_PreserveECX) : PBYTE(ProcessAPCQueue), preserveECX ? 0x51 : 0xB8);
	auto realSyscall = GetRealFunction(PBYTE(NTDLL::NtTestAlert), 0xB8);

	if (preserveECX)
	{
		memcpy(buffer, asmBytes, 0x1A);
		reinterpret_cast<PDWORD>(&buffer[0x2])[0] = reinterpret_cast<PDWORD>(&realSyscall[0x1])[0];
		reinterpret_cast<PDWORD>(&buffer[0x7])[0] = reinterpret_cast<PDWORD>(&realSyscall[0x6])[0];

	}
	else
	{
		memcpy(buffer, asmBytes, 0x18);
		reinterpret_cast<PDWORD>(&buffer[0x1])[0] = reinterpret_cast<PDWORD>(&realSyscall[0x1])[0];
		reinterpret_cast<PDWORD>(&buffer[0x6])[0] = reinterpret_cast<PDWORD>(&realSyscall[0x6])[0];
	}
}

DWORD GetMainThreadHandle(DWORD pid, PHANDLE hThread)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	THREADENTRY32 tEntry;
	tEntry.dwSize = sizeof(THREADENTRY32);
	DWORD result = 0;
	DWORD currentPID = pid;
	for (BOOL success = Thread32First(hThreadSnapshot, &tEntry);
		!result && success && GetLastError() != ERROR_NO_MORE_FILES;
		success = Thread32Next(hThreadSnapshot, &tEntry))
	{
		if (tEntry.th32OwnerProcessID == currentPID)
		{
			result = tEntry.th32ThreadID;
		}
	}
	CloseHandle(hThreadSnapshot);
	NTDLL::CLIENT_ID cid{ (HANDLE)pid, (HANDLE)result };
	NTDLL::OBJECT_ATTRIBUTES objAtts;
	InitializeObjectAttributes(objAtts, NULL, NULL, NULL, NULL);
	return NTDLL::NtOpenThread(hThread, THREAD_ALL_ACCESS, &objAtts, &cid);
}
#pragma managed