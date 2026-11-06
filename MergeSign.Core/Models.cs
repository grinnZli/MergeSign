namespace MergeSign.Core;

public sealed class SignerData
{
    public string SourceFilePath { get; init; } = string.Empty;

    public int Index { get; init; }
}

public sealed class CertificateInfo
{
    public string OwnerName { get; init; } = string.Empty;

    public string Subject { get; init; } = string.Empty;

    public string Issuer { get; init; } = string.Empty;

    public string SerialNumber { get; init; } = string.Empty;

    public string Thumbprint { get; init; } = string.Empty;

    public string KeyAlgorithm { get; init; } = string.Empty;

    public DateTime NotBefore { get; init; }

    public DateTime NotAfter { get; init; }

    public string FullText { get; init; } = string.Empty;
}
