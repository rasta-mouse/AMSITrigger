using System;
using System.Runtime.InteropServices;

namespace AmsiTrigger
{
    class NativeMethods
    {
        [DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out AMSI_RESULT result);

        public enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_DETECTED = 32768
        }
    }
}