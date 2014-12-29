// JackSharper.h

#pragma once

using namespace System;
using namespace System::Runtime::InteropServices;
using namespace System::Diagnostics;

namespace JackSharper 
{
	public ref class JackSharper
	{
	private:
		initonly HANDLE _hProc;
		initonly int _pid;
		HANDLE hijackedThread = NULL;
	public:
		property IntPtr ProcHandle
		{
			IntPtr get()
			{
				return (IntPtr)_hProc;
			}
		};

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>	Constructor. </summary>
		///
		/// <remarks>	DevNull, 12/28/2014. </remarks>
		///
		/// <param name="pid" type="int">			 	The PID. </param>
		/// <param name="threadCreation" type="bool">	true for thread creation. </param>
		////////////////////////////////////////////////////////////////////////////////////////////////////

		JackSharper(int pid, bool threadCreation);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>	Hijack main thread with vtable. </summary>
		///
		/// <remarks>	DevNull, 12/28/2014. </remarks>
		///
		/// <param name="virtualFunc" type="IntPtr">	The virtual function. </param>
		/// <param name="vtable" type="IntPtr">			The vtable. </param>
		////////////////////////////////////////////////////////////////////////////////////////////////////

		void HijackMainThreadWithVtable(IntPtr virtualFunc, IntPtr vtable);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>	Inject DLL. </summary>
		///
		/// <remarks>	DevNull, 12/28/2014. </remarks>
		///
		/// <param name="dllPath" type="String^">	Full pathname of the DLL file. </param>
		////////////////////////////////////////////////////////////////////////////////////////////////////

		void InjectDll(String^ dllPath);
	};
}
