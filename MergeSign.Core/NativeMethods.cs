using System.Runtime.InteropServices;
using System.Text;

namespace MergeSign.Core;

/// <summary>
/// P/Invoke-объявления CryptMsg* из crypt32.dll (wincrypt.h) и FormatMessage
/// из kernel32.dll. Сигнатуры сверены с документацией Microsoft Learn.
/// </summary>
internal static partial class NativeMethods
{
    // Тип кодирования сообщения (wincrypt.h)
    internal const uint X509_ASN_ENCODING = 0x00000001;
    internal const uint PKCS_7_ASN_ENCODING = 0x00010000;

    // Флаги CryptMsgOpenToDecode
    internal const uint CMSG_DETACHED_FLAG = 0x00000004;

    // Тип сообщения CryptMsgOpenToDecode (dwMsgType)
    internal const uint CMSG_SIGNED = 0x00000002;

    // Тип имени сертификата CertGetNameString (wincrypt.h)
    internal const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

    // Хеширование через КриптоПро CSP (advapi32.dll)
    internal const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
    internal const uint PROV_GOST_2012_256 = 80;
    internal const uint CALG_GOST3411_2012_256 = 0x00008021;
    internal const uint HP_HASHVAL = 0x00000002;

    // Параметры CryptGetProvParam (wincrypt.h + расширение КриптоПро)
    internal const uint PP_NAME = 4;
    internal const uint PP_VERSION = 5;
    internal const uint PP_VERSION_EX = 0x0000008A;
    internal const string GOST_2012_256_PROVIDER =
        "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider";

    // Параметры CryptMsgGetParam (wincrypt.h)
    internal const uint CMSG_CONTENT_PARAM = 2;
    internal const uint CMSG_SIGNER_COUNT_PARAM = 5;
    internal const uint CMSG_SIGNER_CERT_INFO_PARAM = 7;
    internal const uint CMSG_CERT_COUNT_PARAM = 11;
    internal const uint CMSG_CERT_PARAM = 12;
    internal const uint CMSG_COMPUTED_HASH_PARAM = 22;
    internal const uint CMSG_ENCODED_MESSAGE = 29;
    internal const uint CMSG_CMS_SIGNER_INFO_PARAM = 39;

    // Типы управления CryptMsgControl (wincrypt.h)
    internal const uint CMSG_CTRL_DEL_SIGNER = 7;
    internal const uint CMSG_CTRL_ADD_CERT = 10;
    internal const uint CMSG_CTRL_DEL_CERT = 11;
    internal const uint CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20;

    // Флаги FormatMessage (winbase.h)
    internal const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    internal const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
    internal const uint FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF;

    [DllImport("crypt32.dll", SetLastError = true)]
    internal static extern IntPtr CryptMsgOpenToDecode(
        uint dwMsgEncodingType,
        uint dwFlags,
        uint dwMsgType,
        IntPtr hCryptProv,
        IntPtr pRecipientInfo,
        IntPtr pStreamInfo);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgUpdate(
        IntPtr hCryptMsg,
        byte[] pbData,
        uint cbData,
        [MarshalAs(UnmanagedType.Bool)] bool fFinal);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        uint dwParamType,
        uint dwIndex,
        IntPtr pvData,
        ref uint pcbData);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgControl(
        IntPtr hCryptMsg,
        uint dwFlags,
        uint dwCtrlType,
        IntPtr pvCtrlPara);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgClose(IntPtr hCryptMsg);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr CertCreateCertificateContext(
        uint dwCertEncodingType,
        byte[] pbCertEncoded,
        uint cbCertEncoded);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint CertGetNameString(
        IntPtr pCertContext,
        uint dwType,
        uint dwFlags,
        IntPtr pvTypePara,
        [Out] StringBuilder? pszNameString,
        uint cchNameString);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptAcquireContextW(
        out IntPtr phProv,
        string? szContainer,
        string? szProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptGetProvParam(
        IntPtr hProv,
        uint dwParam,
        StringBuilder? pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi,
        EntryPoint = "CryptGetProvParam")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptGetProvParamRaw(
        IntPtr hProv,
        uint dwParam,
        byte[]? pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCreateHash(
        IntPtr hProv,
        uint Algid,
        IntPtr hKey,
        uint dwFlags,
        out IntPtr phHash);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptHashData(
        IntPtr hHash,
        byte[] pbData,
        uint dwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptGetHashParam(
        IntPtr hHash,
        uint dwParam,
        byte[]? pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptDestroyHash(IntPtr hHash);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern uint FormatMessageW(
        uint dwFlags,
        IntPtr lpSource,
        uint dwMessageId,
        uint dwLanguageId,
        StringBuilder lpBuffer,
        uint nSize,
        IntPtr arguments);

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_DATA_BLOB
    {
        internal uint cbData;
        internal IntPtr pbData;
    }
}
