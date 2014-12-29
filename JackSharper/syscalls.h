////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Raw asm for syscall to process queued APCs. </summary>
///
/// <remarks>	DevNull, 12/28/2014. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////

void ProcessAPCQueue();

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Raw asm for syscall to process queued APCs. Preserves ECX for use with __thiscall. </summary>
///
/// <remarks>	DevNull, 12/28/2014. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////

void ProcessAPCQueue_PreserveECX();

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Builds inline system call. </summary>
///
/// <remarks>	DevNull, 12/28/2014. </remarks>
///
/// <param name="buffer" type="unsigned char*">	[in,out] If non-null, the buffer. </param>
/// <param name="preserveECX" type="bool">	   	true to preserve ecx. </param>
////////////////////////////////////////////////////////////////////////////////////////////////////

void BuildInlineSysCall(unsigned char* buffer, bool preserveECX);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Opens a handle to the main thread of a remote process. </summary>
///
/// <remarks>	DevNull, 12/28/2014. </remarks>
///
/// <param name="pid" type="DWORD">		 	The PID. </param>
/// <param name="hThread" type="PHANDLE">	The thread. </param>
///
/// <returns>	The main thread handle. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD GetMainThreadHandle(DWORD pid, PHANDLE hThread);