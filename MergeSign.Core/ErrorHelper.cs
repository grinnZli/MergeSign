using System.Runtime.InteropServices;
using System.Text;

namespace MergeSign.Core;

public static class ErrorHelper
{
    private const int BufferSize = 1024;

    public static string GetLastErrorMessage()
    {
        return FormatWin32Error(Marshal.GetLastWin32Error());
    }

    public static string GetLastErrorMessageWithCode()
    {
        int errorCode = Marshal.GetLastWin32Error();
        return $"{FormatWin32Error(errorCode)} (код {errorCode}, 0x{errorCode:X8})";
    }

    public static string FormatWin32Error(int errorCode)
    {
        var buffer = new StringBuilder(BufferSize);

        uint length = NativeMethods.FormatMessageW(
            NativeMethods.FORMAT_MESSAGE_FROM_SYSTEM
                | NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS
                | NativeMethods.FORMAT_MESSAGE_MAX_WIDTH_MASK,
            IntPtr.Zero,
            (uint)errorCode,
            0,
            buffer,
            (uint)buffer.Capacity,
            IntPtr.Zero);

        if (length == 0)
        {
            return $"Неизвестная ошибка Win32 (код {errorCode}).";
        }

        return buffer.ToString().Trim();
    }
}
