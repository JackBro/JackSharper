// This is the main DLL file.

#include "stdafx.h"

namespace JackSharper
{
	JackSharper::JackSharper(int pid, bool threadCreation)
	{
		NTDLL::CLIENT_ID cid{ (HANDLE)pid, NULL };
		NTDLL::OBJECT_ATTRIBUTES objAtts;
		InitializeObjectAttributes(objAtts, NULL, NULL, NULL, NULL);
		ACCESS_MASK flags = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
		if (threadCreation) flags |= PROCESS_CREATE_THREAD;
		HANDLE procHandle;
		auto status = NTDLL::NtOpenProcess(&procHandle, flags, &objAtts, &cid);
		if (status)
			throw gcnew Exception("NtOpenProcess ERROR: 0x" + status.ToString("X8"));
		_hProc = procHandle;
		_pid = pid;
	}

	void JackSharper::HijackMainThreadWithVtable(IntPtr virtualFunc, IntPtr vtable)
	{
		auto nativeFunction = virtualFunc.ToPointer();
		auto nativeVtable = vtable.ToPointer();
		unsigned char buffer[0x1F];
		BuildInlineSysCall(buffer, true);
		buffer[0x1A] = 0xE9;

		// Retrieve a handle to the target process's main thread.
		HANDLE hThread;
		auto status = GetMainThreadHandle(_pid, &hThread);
		if (status)
			throw gcnew Exception("NtOpenThread ERROR: 0x" + status.ToString("X8"));
		hijackedThread = hThread;

		PVOID cave = NULL;
		SIZE_T caveSize = 0x1000;
		
		// Allocate memory for our syscall asm.
		status = NTDLL::NtAllocateVirtualMemory(_hProc, &cave, NULL, &caveSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (status)
			throw gcnew Exception("NtAllocateVirtualMemory ERROR: 0x" + status.ToString("X8"));
		
		// Calculate the appropriate value for our jmp instruction. (destination address - next source instruction address)
		auto jmpDist = INT(nativeFunction) - INT(&reinterpret_cast<PBYTE>(cave)[0x1F]);
		SIZE_T bytesWritten;

		// Fill with int 3's for safety
		unsigned char* caveFill = new unsigned char[caveSize];
		FillMemory(caveFill, caveSize, 0xCC);

		status = NTDLL::NtWriteVirtualMemory(_hProc, cave, caveFill, caveSize, &bytesWritten);
		delete[] caveFill;
		if (status)
			throw gcnew Exception("NtWriteVirtualMemory ERROR: 0x" + status.ToString("X8"));

		// Write our asm into the remote process.
		status = NTDLL::NtWriteVirtualMemory(_hProc, cave, buffer, 0x1B, &bytesWritten);
		if (status)
			throw gcnew Exception("NtWriteVirtualMemory ERROR: 0x" + status.ToString("X8"));
		
		// Append the asm block with the calculated jmp value.
		status = NTDLL::NtWriteVirtualMemory(_hProc, &reinterpret_cast<PBYTE>(cave)[0x1B], &jmpDist, 0x4, &bytesWritten);
		if (status)
			throw gcnew Exception("NtWriteVirtualMemory ERROR: 0x" + status.ToString("X8"));

		// Change protection on the vtable to allow for writes.
		auto vtablePtr = nativeVtable;
		SIZE_T vtableSze = 0x4;
		ULONG oldprotect;
		status = NTDLL::NtProtectVirtualMemory(_hProc, &vtablePtr, &vtableSze, PAGE_READWRITE, &oldprotect);
		if (status)
			throw gcnew Exception("NtProtectVirtualMemory ERROR: 0x" + status.ToString("X8"));

		// Write the pointer to our syscall into the vtable.
		// This completes the pseudo-hook, the remote thread will now accept APCs
		status = NTDLL::NtWriteVirtualMemory(_hProc, nativeVtable, &cave, 0x4, &bytesWritten);
		if (status)
			throw gcnew Exception("NtWriteVirtualMemory ERROR: 0x" + status.ToString("X8"));

	}

	void JackSharper::InjectDll(String^ dllPath)
	{
		if (!hijackedThread)
			return;

		// Allocate memory for our dll file path.
		PVOID nativeDllPath = NULL;
		SIZE_T dllPathSize = 0x1000;
		auto status = NTDLL::NtAllocateVirtualMemory(_hProc, &nativeDllPath, NULL, &dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (status)
			throw gcnew Exception("NtAllocateVirtualMemory ERROR: 0x" + status.ToString("X8"));

		// Write the path into our remote process.
		SIZE_T bytesWritten;
		auto localPathPtr = Marshal::StringToHGlobalAnsi(dllPath);
		status = NTDLL::NtWriteVirtualMemory(_hProc, nativeDllPath, localPathPtr.ToPointer(), dllPath->Length, &bytesWritten);
		if (status)
			throw gcnew Exception("NtWriteVirtualMemory ERROR: 0x" + status.ToString("X8"));

		// Get an accurate address for LoadLibraryA. We do this because ACLayers.dll is the devil.
		auto llFuncName = "LoadLibraryA";
		NTDLL::ANSI_STRING loadLibName;
		NTDLL::RtlInitAnsiString(&loadLibName, llFuncName);
		void* RealLoadLibraryA;
		status = NTDLL::LdrGetProcedureAddress(GetModuleHandleA("kernel32.dll"), &loadLibName, NULL, &RealLoadLibraryA);
		if (status)
			throw gcnew Exception("LdrGetProcedureAddress ERROR: 0x" + status.ToString("X8"));

		// Tell the remote thread to execute LoadLibraryA. 
		// NOTE: Use QueueUserAPC to call a function with 1 arg.
		//		 Use NtQueueApcThread to call a function with 3 args.
		QueueUserAPC((PAPCFUNC)RealLoadLibraryA, hijackedThread, (ULONG_PTR)nativeDllPath);
	}

}
