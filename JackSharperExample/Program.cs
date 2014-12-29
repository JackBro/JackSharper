using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace JackSharperExample
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>   This is a simple test program that uses a hijacked thread to inject a test dll.
    ///             This is highly PoC at it's current stage
    ///             Don't be surprised if you see dangling handles and non-deallocated buffers </summary>
    /// 
    ///
    /// <remarks>   DevNull, 12/28/2014. </remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    class Program
    {
        static void Main(string[] args)
        {
            var dllPath = Directory.GetCurrentDirectory();
            for (var i = 0; i < 3; i++)
            {
                dllPath = Path.GetDirectoryName(dllPath);
            }
#if DEBUG
            dllPath += "\\Debug\\TestDll.dll";
#else
            dllPath += "\\Release\\TestDll.dll";
#endif
            var proc = Process.GetProcessesByName("ffxiv").FirstOrDefault();
            if (proc == default(Process))
                return;

            if (!File.Exists(dllPath))
                return;

            var derp = new JackSharper.JackSharper(proc.Id, false);

            // I'm using the first pointer in the Entity class vtable.
            // It's a small function that returns the entity type, and is called constantly.
            var sigscan = new SigScan(proc, proc.MainModule.BaseAddress, proc.MainModule.ModuleMemorySize);
            var vtableAsm =
                sigscan.FindPattern(
                    new byte[]
                    {
                        0x00, 0x00, 0x68, 0x90, 0x01, 0x00, 0x00, 0x6A, 0x08, 0x50, 0xE8, 0x0, 0x0, 0x0, 0x0, 0x83, 0xC4,
                        0x0C, 0x5F, 0xC7
                    }, "xxxxxxxxxxx????xxxxx", -0x17);

            var vtableBytes = new byte[4];
            var virtualFunctionBytes = new byte[4];
            int bRead;
            SigScan.ReadProcessMemory(derp.ProcHandle, vtableAsm, vtableBytes, 4, out bRead);
            var vtable = new IntPtr(BitConverter.ToInt32(vtableBytes, 0));
            SigScan.ReadProcessMemory(derp.ProcHandle, vtable, virtualFunctionBytes, 4, out bRead);
            var virtualFunction = new IntPtr(BitConverter.ToInt32(virtualFunctionBytes, 0));

            derp.HijackMainThreadWithVtable(virtualFunction, vtable);
            derp.InjectDll(dllPath + "\x0");
        }
    }
}
