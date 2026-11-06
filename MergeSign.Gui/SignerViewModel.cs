using System.ComponentModel;
using System.IO;

namespace MergeSign.Gui;

public enum BindingStatus
{
    NotChecked,
    Bound,
    NotBound
}

public sealed class SignerViewModel : INotifyPropertyChanged
{
    private bool _isChecked = true;
    private BindingStatus _bindingStatus = BindingStatus.NotChecked;
    private int _displayNumber;

    public string SourceFilePath { get; init; } = string.Empty;

    public int Index { get; init; }

    public int DisplayNumber
    {
        get => _displayNumber;
        set
        {
            if (_displayNumber == value)
            {
                return;
            }

            _displayNumber = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DisplayNumber)));
        }
    }

    public string OwnerName { get; init; } = "Неизвестный сертификат";

    public string Subject { get; init; } = "Не указан";

    public DateTime NotBefore { get; init; }

    public DateTime NotAfter { get; init; }

    public string Issuer { get; init; } = "Не указан";

    public string SerialNumber { get; init; } = "Не указан";

    public string Thumbprint { get; init; } = "Не указан";

    public string KeyAlgorithm { get; init; } = "Не указан";

    public string DetailedInfo { get; init; } = string.Empty;

    public string BindingDetails { get; set; } = string.Empty;

    public string SourceFileName => Path.GetFileName(SourceFilePath);

    public string ValidityText => NotAfter == default
        ? "Срок действия не определён"
        : $"Действителен с {NotBefore:dd.MM.yyyy} по {NotAfter:dd.MM.yyyy}";

    public string BindingStatusText => _bindingStatus switch
    {
        BindingStatus.Bound => "✅ Привязана к PDF",
        BindingStatus.NotBound => "❌ Не привязана",
        _ => "Не проверялась"
    };

    public bool IsChecked
    {
        get => _isChecked;
        set
        {
            if (_isChecked == value)
            {
                return;
            }

            _isChecked = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsChecked)));
        }
    }

    public BindingStatus BindingStatus
    {
        get => _bindingStatus;
        set
        {
            if (_bindingStatus == value)
            {
                return;
            }

            _bindingStatus = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(BindingStatus)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(BindingStatusText)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
