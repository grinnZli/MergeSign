using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace MergeSign.Core;

public static class CmsMerger
{
    public const string Gost2012_256Oid = "1.2.643.7.1.1.2.2";
    public const string Gost2012_512Oid = "1.2.643.7.1.1.2.3";
    public const string Gost94Oid = "1.2.643.2.2.9";
    public const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    public const string Sha1Oid = "1.3.14.3.2.26";
    public const string MessageDigestAttributeOid = "1.2.840.113549.1.9.4";

    public static IntPtr ReadSignature(string filePath)
    {
        byte[] data = File.ReadAllBytes(filePath);

        IntPtr hCryptMsg = OpenAndUpdate(data, NativeMethods.CMSG_DETACHED_FLAG, out int detachedError);
        if (hCryptMsg != IntPtr.Zero)
        {
            return hCryptMsg;
        }

        hCryptMsg = OpenAndUpdate(data, 0, out int plainError);
        if (hCryptMsg != IntPtr.Zero)
        {
            return hCryptMsg;
        }

        string prefix = data.Length >= 4
            ? Convert.ToHexString(data, 0, 4)
            : Convert.ToHexString(data);

        throw new CryptographicException(
            $"Не удалось открыть файл подписи (размер {data.Length} байт, начало {prefix}). " +
            $"С CMSG_DETACHED_FLAG: {ErrorHelper.FormatWin32Error(detachedError)}. " +
            $"Без флага: {ErrorHelper.FormatWin32Error(plainError)}.");
    }

    public static int GetSignatureCount(string filePath)
    {
        IntPtr hCryptMsg = ReadSignature(filePath);

        try
        {
            return GetSignerCount(hCryptMsg);
        }
        finally
        {
            CloseSignature(hCryptMsg);
        }
    }

    public static byte[] ExtractEmbeddedContent(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Не указан путь к файлу подписи.", nameof(filePath));
        }

        byte[] data = File.ReadAllBytes(filePath);

        IntPtr hCryptMsg = OpenAndUpdate(data, 0, out int error);
        if (hCryptMsg == IntPtr.Zero)
        {
            throw new CryptographicException(
                "Не удалось открыть присоединённую подпись: " +
                ErrorHelper.FormatWin32Error(error));
        }

        try
        {
            byte[] content = GetParamBytes(
                hCryptMsg, NativeMethods.CMSG_CONTENT_PARAM, 0);

            if (content.Length == 0)
            {
                throw new CryptographicException(
                    "Вложенное содержимое отсутствует. " +
                    "Вероятно, это отсоединённая подпись.");
            }

            return content;
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                "Не удалось извлечь вложенное содержимое: " + ex.Message, ex);
        }
        finally
        {
            CloseSignature(hCryptMsg);
        }
    }

    public static List<string> SplitSignatures(string filePath, string outputBasePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Не указан путь к файлу подписи.", nameof(filePath));
        }

        if (string.IsNullOrWhiteSpace(outputBasePath))
        {
            throw new ArgumentException(
                "Не указано базовое имя выходных файлов.", nameof(outputBasePath));
        }

        byte[] data = File.ReadAllBytes(filePath);

        IntPtr hProbe = OpenAndUpdate(data, 0, out int openError);
        if (hProbe == IntPtr.Zero)
        {
            throw new CryptographicException(
                "Не удалось открыть файл подписи: " +
                ErrorHelper.FormatWin32Error(openError));
        }

        int count;
        bool hasEmbeddedContent;

        try
        {
            count = GetSignerCount(hProbe);

            try
            {
                hasEmbeddedContent = GetParamBytes(
                    hProbe, NativeMethods.CMSG_CONTENT_PARAM, 0).Length > 0;
            }
            catch (CryptographicException)
            {
                hasEmbeddedContent = false;
            }
        }
        finally
        {
            CloseSignature(hProbe);
        }

        if (count <= 1)
        {
            throw new InvalidOperationException(
                $"В файле «{Path.GetFileName(filePath)}» " +
                $"{(count == 0 ? "нет подписей" : "только одна подпись")}.");
        }

        string directory = Path.GetDirectoryName(Path.GetFullPath(outputBasePath))
            ?? Directory.GetCurrentDirectory();
        string baseName = Path.GetFileNameWithoutExtension(outputBasePath);

        if (string.IsNullOrWhiteSpace(baseName))
        {
            baseName = Path.GetFileNameWithoutExtension(filePath);
        }

        var outputPaths = new List<string>(count);

        for (int keepIndex = 0; keepIndex < count; keepIndex++)
        {
            IntPtr hCryptMsg = hasEmbeddedContent
                ? OpenAndUpdate(data, 0, out int decodeError)
                : OpenForSplit(data, out decodeError);

            if (hCryptMsg == IntPtr.Zero)
            {
                throw new CryptographicException(
                    $"Не удалось открыть файл подписи для выделения подписи " +
                    $"№{keepIndex + 1}: {ErrorHelper.FormatWin32Error(decodeError)}");
            }

            byte[] encodedMessage;

            try
            {
                int certificateCount = (int)GetParamUInt32(
                    hCryptMsg, NativeMethods.CMSG_CERT_COUNT_PARAM);

                int targetCertificateIndex = certificateCount > 0
                    ? FindSignerCertificateIndex(
                        hCryptMsg, keepIndex, certificateCount)
                    : -1;

                byte[]? expectedCertificate = targetCertificateIndex >= 0
                    ? GetParamBytes(
                        hCryptMsg,
                        NativeMethods.CMSG_CERT_PARAM,
                        (uint)targetCertificateIndex)
                    : null;

                for (int index = count - 1; index >= 0; index--)
                {
                    if (index != keepIndex)
                    {
                        DeleteSigner(hCryptMsg, index);
                    }
                }

                if (targetCertificateIndex >= 0)
                {
                    for (int index = certificateCount - 1; index >= 0; index--)
                    {
                        if (index != targetCertificateIndex)
                        {
                            DeleteCertificate(hCryptMsg, index);
                        }
                    }
                }

                if (GetSignerCount(hCryptMsg) != 1)
                {
                    throw new CryptographicException(
                        "После разделения в сообщении должна остаться одна подпись.");
                }

                if (expectedCertificate is not null)
                {
                    byte[] actualCertificate = GetParamBytes(
                        hCryptMsg, NativeMethods.CMSG_CERT_PARAM, 0);

                    if (!actualCertificate.AsSpan().SequenceEqual(
                            expectedCertificate))
                    {
                        throw new CryptographicException(
                            $"Сертификат в разделённом файле №{keepIndex + 1} " +
                            "не соответствует выбранной подписи.");
                    }
                }

                encodedMessage = GetParamBytes(
                    hCryptMsg, NativeMethods.CMSG_ENCODED_MESSAGE, 0);
            }
            finally
            {
                CloseSignature(hCryptMsg);
            }

            string outputPath = Path.Combine(
                directory, $"{baseName}_{keepIndex + 1}.sig");

            VerifySplitMessage(encodedMessage, keepIndex, outputPath);
            File.WriteAllBytes(outputPath, encodedMessage);
            outputPaths.Add(outputPath);
        }

        return outputPaths;
    }

    private static IntPtr OpenForSplit(byte[] data, out int error)
    {
        IntPtr hCryptMsg = OpenAndUpdate(
            data, NativeMethods.CMSG_DETACHED_FLAG, out error);

        if (hCryptMsg != IntPtr.Zero)
        {
            return hCryptMsg;
        }

        return OpenAndUpdate(data, 0, out error);
    }

    private static void DeleteSigner(IntPtr hCryptMsg, int index)
    {
        IntPtr pIndex = Marshal.AllocHGlobal(sizeof(int));

        try
        {
            Marshal.WriteInt32(pIndex, index);

            if (!NativeMethods.CryptMsgControl(
                    hCryptMsg,
                    0,
                    NativeMethods.CMSG_CTRL_DEL_SIGNER,
                    pIndex))
            {
                throw new CryptographicException(
                    $"Не удалось удалить подпись №{index + 1} " +
                    $"(CMSG_CTRL_DEL_SIGNER): " +
                    ErrorHelper.GetLastErrorMessageWithCode());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pIndex);
        }
    }

    private static void DeleteCertificate(IntPtr hCryptMsg, int index)
    {
        IntPtr pIndex = Marshal.AllocHGlobal(sizeof(int));

        try
        {
            Marshal.WriteInt32(pIndex, index);

            if (!NativeMethods.CryptMsgControl(
                    hCryptMsg,
                    0,
                    NativeMethods.CMSG_CTRL_DEL_CERT,
                    pIndex))
            {
                throw new CryptographicException(
                    $"Не удалось удалить сертификат №{index + 1} " +
                    $"(CMSG_CTRL_DEL_CERT): " +
                    ErrorHelper.GetLastErrorMessageWithCode());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pIndex);
        }
    }

    private static int FindSignerCertificateIndex(
        IntPtr hCryptMsg, int signerIndex, int certificateCount)
    {
        IntPtr pCertInfo = GetParamNative(
            hCryptMsg,
            NativeMethods.CMSG_SIGNER_CERT_INFO_PARAM,
            (uint)signerIndex);

        try
        {
            var certInfo = Marshal.PtrToStructure<CertInfoHeader>(pCertInfo);
            byte[] issuer = CopyBlob(certInfo.Issuer);
            byte[] serialNumber = CopyBlob(certInfo.SerialNumber);

            if (issuer.Length == 0 || serialNumber.Length == 0)
            {
                return -1;
            }

            for (int index = 0; index < certificateCount; index++)
            {
                byte[] certificateBytes = GetParamBytes(
                    hCryptMsg, NativeMethods.CMSG_CERT_PARAM, (uint)index);

                try
                {
                    using var certificate = new X509Certificate2(certificateBytes);

                    if (certificate.GetSerialNumber().AsSpan().SequenceEqual(
                            serialNumber)
                        && certificate.IssuerName.RawData.AsSpan().SequenceEqual(
                            issuer))
                    {
                        return index;
                    }
                }
                catch (CryptographicException)
                {
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pCertInfo);
        }

        return -1;
    }

    private static byte[] CopyBlob(NativeMethods.CRYPT_DATA_BLOB blob)
    {
        if (blob.cbData == 0 || blob.pbData == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        byte[] result = new byte[(int)blob.cbData];
        Marshal.Copy(blob.pbData, result, 0, result.Length);
        return result;
    }

    private static void VerifySplitMessage(
        byte[] encodedMessage, int index, string outputPath)
    {
        IntPtr hCryptMsg = OpenAndUpdate(encodedMessage, 0, out int error);

        if (hCryptMsg == IntPtr.Zero)
        {
            throw new CryptographicException(
                $"Не удалось проверить разделённую подпись №{index + 1} " +
                $"({Path.GetFileName(outputPath)}): " +
                ErrorHelper.FormatWin32Error(error));
        }

        try
        {
            if (GetSignerCount(hCryptMsg) != 1)
            {
                throw new CryptographicException(
                    $"Разделённая подпись №{index + 1} содержит не одну подпись.");
            }
        }
        finally
        {
            CloseSignature(hCryptMsg);
        }
    }

    private static IntPtr OpenAndUpdate(byte[] data, uint flags, out int error)
    {
        error = 0;

        IntPtr hCryptMsg = NativeMethods.CryptMsgOpenToDecode(
            NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
            flags,
            0,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);

        if (hCryptMsg == IntPtr.Zero)
        {
            error = Marshal.GetLastWin32Error();
            return IntPtr.Zero;
        }

        if (!NativeMethods.CryptMsgUpdate(hCryptMsg, data, (uint)data.Length, true))
        {
            error = Marshal.GetLastWin32Error();
            NativeMethods.CryptMsgClose(hCryptMsg);
            return IntPtr.Zero;
        }

        return hCryptMsg;
    }

    public static int GetSignerCount(IntPtr hCryptMsg)
    {
        return (int)GetParamUInt32(hCryptMsg, NativeMethods.CMSG_SIGNER_COUNT_PARAM);
    }

    public static (byte[] SignerInfoBytes, byte[] CertificateBytes) GetSignerInfo(
        IntPtr hCryptMsg, int index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        byte[] signerInfoBytes = GetParamBytes(
            hCryptMsg, NativeMethods.CMSG_CMS_SIGNER_INFO_PARAM, (uint)index);
        byte[] certificateBytes = GetParamBytes(
            hCryptMsg, NativeMethods.CMSG_CERT_PARAM, (uint)index);

        return (signerInfoBytes, certificateBytes);
    }

    public static List<(byte[] SignerInfoBytes, byte[] CertificateBytes)> ExtractAllSignatures(
        IntPtr hCryptMsg)
    {
        int count = GetSignerCount(hCryptMsg);
        var signatures = new List<(byte[] SignerInfoBytes, byte[] CertificateBytes)>(count);

        for (int i = 0; i < count; i++)
        {
            signatures.Add(GetSignerInfo(hCryptMsg, i));
        }

        return signatures;
    }

    public static byte[] GetSignatureHash(IntPtr hCryptMsg, int index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return GetParamBytes(hCryptMsg, NativeMethods.CMSG_COMPUTED_HASH_PARAM, (uint)index);
    }

    public static byte[] GetMessageDigest(string filePath, int index)
    {
        return GetMessageDigest(File.ReadAllBytes(filePath), index);
    }

    public static byte[] GetMessageDigest(byte[] signatureBytes, int index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        var cms = new SignedCms();

        try
        {
            cms.Decode(signatureBytes);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                "SignedCms не смог разобрать подпись (возможно, ГОСТ не поддерживается): " +
                ex.Message,
                ex);
        }

        if (index >= cms.SignerInfos.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                $"В подписи только {cms.SignerInfos.Count} подписантов.");
        }

        SignerInfo signer = cms.SignerInfos[index];

        foreach (CryptographicAttributeObject attribute in signer.SignedAttributes)
        {
            if (string.Equals(
                    attribute.Oid.Value,
                    MessageDigestAttributeOid,
                    StringComparison.Ordinal))
            {
                if (attribute.Values.Count == 0)
                {
                    break;
                }

                return DecodeOctetString(attribute.Values[0].RawData);
            }
        }

        throw new CryptographicException(
            $"В подписи №{index + 1} не найден атрибут messageDigest ({MessageDigestAttributeOid}).");
    }

    private static byte[] DecodeOctetString(byte[] encoded)
    {
        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            byte[] value = reader.ReadOctetString();
            reader.ThrowIfNotEmpty();
            return value;
        }
        catch (AsnContentException)
        {
            return encoded;
        }
    }

    public static void MergeSignatures(List<SignerData> signaturesToMerge, string outputFilePath)
    {
        ArgumentNullException.ThrowIfNull(signaturesToMerge);

        if (signaturesToMerge.Count == 0)
        {
            throw new ArgumentException("Список подписей пуст.", nameof(signaturesToMerge));
        }

        if (string.IsNullOrWhiteSpace(outputFilePath))
        {
            throw new ArgumentException(
                "Не указан путь к выходному файлу.", nameof(outputFilePath));
        }

        SignerData baseSigner = signaturesToMerge[0];
        string baseFullPath = Path.GetFullPath(baseSigner.SourceFilePath);
        IntPtr hBase = ReadSignature(baseSigner.SourceFilePath);
        byte[] encodedMessage;

        try
        {
            for (int i = 1; i < signaturesToMerge.Count; i++)
            {
                SignerData signer = signaturesToMerge[i];

                // Все подписи базового файла уже присутствуют в базовом сообщении.
                if (string.Equals(
                        Path.GetFullPath(signer.SourceFilePath),
                        baseFullPath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                AddSignerFromFile(hBase, signer);
            }

            encodedMessage = GetParamBytes(
                hBase, NativeMethods.CMSG_ENCODED_MESSAGE, 0);
        }
        finally
        {
            CloseSignature(hBase);
        }

        File.WriteAllBytes(outputFilePath, encodedMessage);
    }

    private static void AddSignerFromFile(IntPtr hBase, SignerData signer)
    {
        IntPtr hSource = ReadSignature(signer.SourceFilePath);

        try
        {
            int signerCount = GetSignerCount(hSource);
            if (signer.Index < 0 || signer.Index >= signerCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(signer),
                    $"В файле «{Path.GetFileName(signer.SourceFilePath)}» " +
                    $"только {signerCount} подписей, запрошен индекс {signer.Index}.");
            }

            IntPtr pSignerInfo = GetParamNative(
                hSource, NativeMethods.CMSG_CMS_SIGNER_INFO_PARAM, (uint)signer.Index);

            try
            {
                if (!NativeMethods.CryptMsgControl(
                        hBase,
                        0,
                        NativeMethods.CMSG_CTRL_ADD_CMS_SIGNER_INFO,
                        pSignerInfo))
                {
                    string error = ErrorHelper.GetLastErrorMessageWithCode();

                    throw new CryptographicException(
                        $"Не удалось добавить подпись №{signer.Index + 1} из «" +
                        $"{Path.GetFileName(signer.SourceFilePath)}» " +
                        $"(CMSG_CTRL_ADD_CMS_SIGNER_INFO): {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pSignerInfo);
            }

            byte[] certificateBytes = GetParamBytes(
                hSource, NativeMethods.CMSG_CERT_PARAM, (uint)signer.Index);

            if (!ContainsCertificate(hBase, certificateBytes))
            {
                AddCertificate(hBase, certificateBytes);
            }
        }
        finally
        {
            CloseSignature(hSource);
        }
    }

    private static void AddCertificate(IntPtr hCryptMsg, byte[] certificateBytes)
    {
        if (certificateBytes.Length == 0)
        {
            throw new CryptographicException("Сертификат подписи пуст.");
        }

        GCHandle pinnedCertificate = GCHandle.Alloc(
            certificateBytes, GCHandleType.Pinned);

        try
        {
            var blob = new NativeMethods.CRYPT_DATA_BLOB
            {
                cbData = (uint)certificateBytes.Length,
                pbData = pinnedCertificate.AddrOfPinnedObject()
            };

            IntPtr pBlob = Marshal.AllocHGlobal(
                Marshal.SizeOf<NativeMethods.CRYPT_DATA_BLOB>());

            try
            {
                Marshal.StructureToPtr(blob, pBlob, false);

                if (!NativeMethods.CryptMsgControl(
                        hCryptMsg,
                        0,
                        NativeMethods.CMSG_CTRL_ADD_CERT,
                        pBlob))
                {
                    string error = ErrorHelper.GetLastErrorMessageWithCode();

                    throw new CryptographicException(
                        "Не удалось добавить сертификат " +
                        $"(CMSG_CTRL_ADD_CERT): {error}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pBlob);
            }
        }
        finally
        {
            pinnedCertificate.Free();
        }
    }

    private static bool ContainsCertificate(IntPtr hCryptMsg, byte[] certificateBytes)
    {
        uint count = GetParamUInt32(hCryptMsg, NativeMethods.CMSG_CERT_COUNT_PARAM);

        for (uint i = 0; i < count; i++)
        {
            byte[] existing = GetParamBytes(
                hCryptMsg, NativeMethods.CMSG_CERT_PARAM, i);

            if (existing.AsSpan().SequenceEqual(certificateBytes))
            {
                return true;
            }
        }

        return false;
    }

    private static IntPtr GetParamNative(IntPtr hCryptMsg, uint paramType, uint index)
    {
        uint size = 0;

        if (!NativeMethods.CryptMsgGetParam(
                hCryptMsg, paramType, index, IntPtr.Zero, ref size))
        {
            throw new CryptographicException(
                $"Не удалось определить размер параметра CMSG (0x{paramType:X}): " +
                ErrorHelper.GetLastErrorMessageWithCode());
        }

        if (size == 0)
        {
            throw new CryptographicException(
                $"Параметр CMSG (0x{paramType:X}) пуст.");
        }

        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        uint actualSize = size;

        if (!NativeMethods.CryptMsgGetParam(
                hCryptMsg, paramType, index, buffer, ref actualSize))
        {
            string error = ErrorHelper.GetLastErrorMessageWithCode();
            Marshal.FreeHGlobal(buffer);

            throw new CryptographicException(
                $"Не удалось получить параметр CMSG (0x{paramType:X}): {error}");
        }

        return buffer;
    }

    public static byte[] ComputeDocumentHash(string filePath, string hashAlgorithmOid)
    {
        byte[] data = File.ReadAllBytes(filePath);

        switch (hashAlgorithmOid)
        {
            case Gost2012_256Oid:
                return ComputeGostHash(data, NativeMethods.CALG_GOST3411_2012_256);

            case Sha256Oid:
                return SHA256.HashData(data);

            case Sha1Oid:
                return SHA1.HashData(data);

            default:
                throw new NotSupportedException(
                    $"Алгоритм хеширования {hashAlgorithmOid} не поддерживается.");
        }
    }

    public static bool CheckCryptoProInstalled()
    {
        IntPtr hProv = IntPtr.Zero;

        try
        {
            return NativeMethods.CryptAcquireContextW(
                out hProv,
                null,
                NativeMethods.GOST_2012_256_PROVIDER,
                NativeMethods.PROV_GOST_2012_256,
                NativeMethods.CRYPT_VERIFYCONTEXT);
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (hProv != IntPtr.Zero)
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
            }
        }
    }

    public static (string? Name, string? Version) GetCryptoProDetails()
    {
        IntPtr hProv = IntPtr.Zero;

        try
        {
            if (!NativeMethods.CryptAcquireContextW(
                    out hProv,
                    null,
                    NativeMethods.GOST_2012_256_PROVIDER,
                    NativeMethods.PROV_GOST_2012_256,
                    NativeMethods.CRYPT_VERIFYCONTEXT))
            {
                return (null, null);
            }

            string name = ReadProviderName(hProv) ?? "КриптоПро (имя не определено)";
            string? version = GetCryptoProVersion(hProv);

            return (name, version);
        }
        catch (Exception)
        {
            return (null, null);
        }
        finally
        {
            if (hProv != IntPtr.Zero)
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
            }
        }
    }

    public static string? GetCryptoProProviderName()
    {
        return GetCryptoProDetails().Name;
    }

    public static string? GetCryptoProVersion(IntPtr hProv)
    {
        if (hProv == IntPtr.Zero)
        {
            return null;
        }

        string? version = ReadProviderVersion(hProv);

        if (string.IsNullOrWhiteSpace(version))
        {
            version = ReadVersionFromRegistry();
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        string? kcLevel = ReadKcLevelFromRegistry();

        return kcLevel is null ? version : $"{version} {kcLevel}";
    }

    private static string? ReadProviderName(IntPtr hProv)
    {
        uint size = 0;
        if (!NativeMethods.CryptGetProvParam(
                hProv, NativeMethods.PP_NAME, null, ref size, 0)
            || size == 0)
        {
            return null;
        }

        var buffer = new StringBuilder((int)size);
        uint actualSize = size;

        if (!NativeMethods.CryptGetProvParam(
                hProv, NativeMethods.PP_NAME, buffer, ref actualSize, 0))
        {
            return null;
        }

        string name = buffer.ToString().TrimEnd('\0');

        return string.IsNullOrWhiteSpace(name) ? null : name;
    }

    private static string? ReadProviderVersion(IntPtr hProv)
    {
        bool hasBaseVersion = TryGetProviderVersion(hProv, out int major, out int minor);
        bool hasBuild = TryGetProviderBuild(hProv, out uint build);

        if (hasBaseVersion && hasBuild)
        {
            return $"{major}.{minor}.{build}";
        }

        if (hasBaseVersion)
        {
            return $"{major}.{minor}";
        }

        return hasBuild ? build.ToString() : null;
    }

    private static bool TryGetProviderVersion(IntPtr hProv, out int major, out int minor)
    {
        major = 0;
        minor = 0;

        byte[]? data = ReadRawProvParam(hProv, NativeMethods.PP_VERSION, out uint length);
        if (data is null || length < 2)
        {
            return false;
        }

        // Необычный формат PP_VERSION: 0x00000200 означает версию 2.0.
        major = data[1];
        minor = data[0];

        return major != 0 || minor != 0;
    }

    private static bool TryGetProviderBuild(IntPtr hProv, out uint build)
    {
        build = 0;

        byte[]? data = ReadRawProvParam(
            hProv, NativeMethods.PP_VERSION_EX, out uint length);

        if (data is null || length < sizeof(uint))
        {
            return false;
        }

        build = BitConverter.ToUInt32(data, 0);

        return build != 0;
    }

    private static byte[]? ReadRawProvParam(IntPtr hProv, uint param, out uint length)
    {
        length = 0;

        uint size = 0;
        if (!NativeMethods.CryptGetProvParamRaw(hProv, param, null, ref size, 0)
            || size == 0)
        {
            return null;
        }

        byte[] buffer = new byte[size];
        uint actualSize = size;

        if (!NativeMethods.CryptGetProvParamRaw(
                hProv, param, buffer, ref actualSize, 0))
        {
            return null;
        }

        if (actualSize > buffer.Length)
        {
            actualSize = (uint)buffer.Length;
        }

        if (actualSize < buffer.Length)
        {
            Array.Resize(ref buffer, (int)actualSize);
        }

        length = actualSize;
        return buffer;
    }

    private static string? ReadVersionFromRegistry()
    {
        string[] paths =
        {
            @"SOFTWARE\Wow6432Node\Crypto Pro\Settings",
            @"SOFTWARE\Crypto Pro\Settings"
        };

        foreach (string path in paths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key?.GetValue("Version") is string value
                    && !string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }
            catch (Exception)
            {
            }
        }

        return null;
    }

    private static string? ReadKcLevelFromRegistry()
    {
        string[] roots =
        {
            @"SOFTWARE\Wow6432Node\Crypto Pro\Cryptography\CurrentVersion",
            @"SOFTWARE\Crypto Pro\Cryptography\CurrentVersion"
        };

        foreach (string root in roots)
        {
            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(root);
                if (baseKey is null)
                {
                    continue;
                }

                foreach (string subKeyName in baseKey.GetSubKeyNames())
                {
                    using var subKey = baseKey.OpenSubKey(subKeyName);
                    object? value = subKey?.GetValue("KCLevel");

                    if (value is null)
                    {
                        continue;
                    }

                    int level;
                    try
                    {
                        level = Convert.ToInt32(value);
                    }
                    catch (Exception)
                    {
                        continue;
                    }

                    if (level > 0)
                    {
                        return $"KC{level}";
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        return null;
    }

    private static byte[] ComputeGostHash(byte[] data, uint algorithmId)
    {
        IntPtr hProv = IntPtr.Zero;
        IntPtr hHash = IntPtr.Zero;

        try
        {
            if (!NativeMethods.CryptAcquireContextW(
                    out hProv,
                    null,
                    NativeMethods.GOST_2012_256_PROVIDER,
                    NativeMethods.PROV_GOST_2012_256,
                    NativeMethods.CRYPT_VERIFYCONTEXT))
            {
                throw new CryptographicException(
                    $"Не удалось получить провайдер КриптоПро: {ErrorHelper.GetLastErrorMessage()}");
            }

            if (!NativeMethods.CryptCreateHash(hProv, algorithmId, IntPtr.Zero, 0, out hHash))
            {
                throw new CryptographicException(
                    $"Не удалось создать ГОСТ-хеш: {ErrorHelper.GetLastErrorMessage()}");
            }

            if (!NativeMethods.CryptHashData(hHash, data, (uint)data.Length, 0))
            {
                throw new CryptographicException(
                    $"Не удалось вычислить ГОСТ-хеш: {ErrorHelper.GetLastErrorMessage()}");
            }

            uint size = 0;
            if (!NativeMethods.CryptGetHashParam(
                    hHash, NativeMethods.HP_HASHVAL, null, ref size, 0))
            {
                throw new CryptographicException(
                    $"Не удалось получить размер ГОСТ-хеша: {ErrorHelper.GetLastErrorMessage()}");
            }

            byte[] hash = new byte[size];
            uint actualSize = size;

            if (!NativeMethods.CryptGetHashParam(
                    hHash, NativeMethods.HP_HASHVAL, hash, ref actualSize, 0))
            {
                throw new CryptographicException(
                    $"Не удалось получить ГОСТ-хеш: {ErrorHelper.GetLastErrorMessage()}");
            }

            if (actualSize != hash.Length)
            {
                Array.Resize(ref hash, (int)actualSize);
            }

            return hash;
        }
        finally
        {
            if (hHash != IntPtr.Zero)
            {
                NativeMethods.CryptDestroyHash(hHash);
            }

            if (hProv != IntPtr.Zero)
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
            }
        }
    }

    public static IntPtr CreateCertificateContext(byte[] certificateBytes)
    {
        IntPtr pCertContext = NativeMethods.CertCreateCertificateContext(
            NativeMethods.X509_ASN_ENCODING,
            certificateBytes,
            (uint)certificateBytes.Length);

        if (pCertContext == IntPtr.Zero)
        {
            throw new CryptographicException(
                $"Не удалось создать контекст сертификата: {ErrorHelper.GetLastErrorMessage()}");
        }

        return pCertContext;
    }

    public static void FreeCertificateContext(IntPtr pCertContext)
    {
        if (pCertContext != IntPtr.Zero)
        {
            NativeMethods.CertFreeCertificateContext(pCertContext);
        }
    }

    public static CertificateInfo GetCertificateInfo(byte[] certificateBytes)
    {
        try
        {
            using var certificate = new X509Certificate2(certificateBytes);
            string ownerName = certificate.GetNameInfo(X509NameType.SimpleName, false);

            if (string.IsNullOrWhiteSpace(ownerName))
            {
                ownerName = certificate.Subject;
            }

            return new CertificateInfo
            {
                OwnerName = ownerName,
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                SerialNumber = certificate.SerialNumber,
                Thumbprint = certificate.Thumbprint,
                KeyAlgorithm = FormatKeyAlgorithm(certificate),
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                FullText = certificate.ToString(true)
            };
        }
        catch (CryptographicException)
        {
            return new CertificateInfo
            {
                OwnerName = "Неизвестный сертификат",
                FullText = "Не удалось разобрать сертификат."
            };
        }
    }

    private static string FormatKeyAlgorithm(X509Certificate2 certificate)
    {
        string value = certificate.PublicKey.Oid.Value ?? string.Empty;
        string? friendlyName = certificate.PublicKey.Oid.FriendlyName;

        if (string.IsNullOrWhiteSpace(friendlyName))
        {
            return value;
        }

        return value.Length == 0 || friendlyName == value
            ? friendlyName
            : $"{friendlyName} ({value})";
    }

    public static string GetCertificateSubject(byte[] certificateBytes)
    {
        return GetCertificateInfo(certificateBytes).FullText;
    }

    public static void CloseSignature(IntPtr hCryptMsg)
    {
        if (hCryptMsg != IntPtr.Zero)
        {
            NativeMethods.CryptMsgClose(hCryptMsg);
        }
    }

    private static uint GetParamUInt32(IntPtr hCryptMsg, uint paramType)
    {
        uint size = sizeof(uint);
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));

        try
        {
            if (!NativeMethods.CryptMsgGetParam(hCryptMsg, paramType, 0, buffer, ref size))
            {
                throw new CryptographicException(
                    $"Не удалось получить параметр CMSG (0x{paramType:X}): {ErrorHelper.GetLastErrorMessage()}");
            }

            return (uint)Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static byte[] GetParamBytes(IntPtr hCryptMsg, uint paramType, uint index)
    {
        uint size = 0;

        if (!NativeMethods.CryptMsgGetParam(hCryptMsg, paramType, index, IntPtr.Zero, ref size))
        {
            throw new CryptographicException(
                $"Не удалось определить размер параметра CMSG (0x{paramType:X}): {ErrorHelper.GetLastErrorMessage()}");
        }

        if (size == 0)
        {
            return Array.Empty<byte>();
        }

        IntPtr buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            if (!NativeMethods.CryptMsgGetParam(hCryptMsg, paramType, index, buffer, ref size))
            {
                throw new CryptographicException(
                    $"Не удалось получить параметр CMSG (0x{paramType:X}): {ErrorHelper.GetLastErrorMessage()}");
            }

            byte[] result = new byte[size];
            Marshal.Copy(buffer, result, 0, (int)size);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertInfoHeader
    {
        internal uint dwVersion;
        internal NativeMethods.CRYPT_DATA_BLOB SerialNumber;
        internal CertificateAlgorithmIdentifier SignatureAlgorithm;
        internal NativeMethods.CRYPT_DATA_BLOB Issuer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertificateAlgorithmIdentifier
    {
        internal IntPtr pszObjId;
        internal NativeMethods.CRYPT_DATA_BLOB Parameters;
    }
}
