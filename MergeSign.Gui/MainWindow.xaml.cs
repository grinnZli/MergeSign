using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using MergeSign.Core;
using Microsoft.Win32;

namespace MergeSign.Gui;

public partial class MainWindow : Window
{
    private const double DetailsPanelWidth = 380;
    private const string ApplicationVersion = "1.0.0";
    private const string LicenseResourceName = "MergeSign.Gui.LICENSE";

    private readonly ObservableCollection<SignerViewModel> _signers = new();
    private bool _cryptoProAvailable = true;
    private bool _detailsPanelOpen;

    private string? CurrentPdfPath { get; set; }

    public MainWindow()
    {
        InitializeComponent();
        SignersListBox.ItemsSource = _signers;
        UpdateSummaryAndButtons();
        Loaded += MainWindow_Loaded;
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void AboutMenuItem_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            this,
            "MergeSign" + Environment.NewLine +
            $"Версия: {ApplicationVersion}" + Environment.NewLine +
            Environment.NewLine +
            "Утилита для объединения отсоединённых электронных подписей." +
            Environment.NewLine +
            Environment.NewLine +
            "Данное ПО распространяется под лицензией MIT. " +
            "Для работы требуется установленный КриптоПро CSP 5.0 R2 и выше.",
            "О программе",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void LicenseMenuItem_Click(object sender, RoutedEventArgs e)
    {
        string licenseText = ReadLicenseText();

        MessageBox.Show(
            this,
            licenseText,
            "Лицензия MIT",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void SecurityMenuItem_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            this,
            "Для безопасной работы используйте только актуальные версии " +
            "КриптоПро CSP. Не размещайте сторонние DLL в папке с программой.",
            "Проверка безопасности",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    private static string ReadLicenseText()
    {
        using Stream? stream = typeof(MainWindow).Assembly
            .GetManifestResourceStream(LicenseResourceName);

        if (stream is null)
        {
            return "Текст лицензии MIT недоступен.";
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var (providerName, providerVersion) =
            await Task.Run(CmsMerger.GetCryptoProDetails);

        _cryptoProAvailable = providerName is not null;

        if (_cryptoProAvailable)
        {
            ProviderStatusTextBlock.Text = string.IsNullOrWhiteSpace(providerVersion)
                ? $"Криптопровайдер: {providerName}"
                : $"Криптопровайдер: {providerName} (Версия: {providerVersion})";

            return;
        }

        UpdateSummaryAndButtons();
        ProviderStatusTextBlock.Text = "Криптопровайдер не найден!";
        StatusMessageTextBlock.Text = "КриптоПро CSP не обнаружен.";

        MessageBox.Show(
            this,
            "Внимание! На вашем компьютере не обнаружен КриптоПро CSP. " +
            "Без него невозможно проверить или создать ГОСТ-подпись. " +
            "Установите КриптоПро CSP для продолжения работы.",
            "КриптоПро CSP не найден",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    private async void CheckSignatureButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите файлы подписей",
            Filter = "Подписи (*.sig)|*.sig|Все файлы (*.*)|*.*",
            Multiselect = true
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        string[] filePaths = dialog.FileNames;
        StatusMessageTextBlock.Text = "Загрузка...";

        try
        {
            var (signers, errors) = await Task.Run(() =>
            {
                var result = new List<SignerViewModel>();
                var loadErrors = new List<string>();

                foreach (string filePath in filePaths)
                {
                    try
                    {
                        IntPtr hCryptMsg = CmsMerger.ReadSignature(filePath);

                        try
                        {
                            var signatures = CmsMerger.ExtractAllSignatures(hCryptMsg);

                            for (int i = 0; i < signatures.Count; i++)
                            {
                                CertificateInfo info = CmsMerger.GetCertificateInfo(
                                    signatures[i].CertificateBytes);

                                result.Add(new SignerViewModel
                                {
                                    SourceFilePath = filePath,
                                    Index = i,
                                    OwnerName = info.OwnerName,
                                    Subject = info.Subject,
                                    Issuer = info.Issuer,
                                    SerialNumber = info.SerialNumber,
                                    Thumbprint = info.Thumbprint,
                                    KeyAlgorithm = info.KeyAlgorithm,
                                    NotBefore = info.NotBefore,
                                    NotAfter = info.NotAfter,
                                    DetailedInfo = info.FullText,
                                    IsChecked = true
                                });
                            }
                        }
                        finally
                        {
                            CmsMerger.CloseSignature(hCryptMsg);
                        }
                    }
                    catch (Exception ex)
                    {
                        loadErrors.Add($"{Path.GetFileName(filePath)}: {ex.Message}");
                    }
                }

                return (Signers: result, Errors: loadErrors);
            });

            var existingThumbprints = new HashSet<string>(
                _signers
                    .Select(signer => signer.Thumbprint)
                    .Where(thumbprint => !string.IsNullOrWhiteSpace(thumbprint)),
                StringComparer.OrdinalIgnoreCase);

            int addedCount = 0;
            int duplicateCount = 0;

            foreach (SignerViewModel signer in signers)
            {
                string thumbprint = signer.Thumbprint?.Trim() ?? string.Empty;

                if (thumbprint.Length > 0 && !existingThumbprints.Add(thumbprint))
                {
                    duplicateCount++;
                    continue;
                }

                signer.DisplayNumber = _signers.Count + 1;
                _signers.Add(signer);
                addedCount++;
            }

            UpdateSummaryAndButtons();

            string status = duplicateCount > 0
                ? addedCount > 0
                    ? $"Подпись уже добавлена в список. Добавлено новых: {addedCount}."
                    : "Подпись уже добавлена в список."
                : $"Добавлено подписей: {addedCount}.";

            StatusMessageTextBlock.Text = errors.Count > 0
                ? $"{status} Ошибок загрузки: {errors.Count}."
                : status;

            if (errors.Count > 0)
            {
                MessageBox.Show(
                    this,
                    string.Join(Environment.NewLine, errors),
                    "Ошибки загрузки",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = ex.Message;

            MessageBox.Show(
                this,
                ex.Message,
                "Ошибка",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ClearSignaturesButton_Click(object sender, RoutedEventArgs e)
    {
        _signers.Clear();
        CurrentPdfPath = null;
        StatusMessageTextBlock.Text = "Список подписей очищен.";
        UpdateSummaryAndButtons();
    }

    private void SignerCheckBox_Click(object sender, RoutedEventArgs e)
    {
        UpdateSummaryAndButtons();
    }

    private void DetailsButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: SignerViewModel signer })
        {
            return;
        }

        SignersListBox.SelectedItem = signer;
        SignersListBox.ScrollIntoView(signer);
        ShowDetailsPanel();
    }

    private void SignersListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SignersListBox.SelectedItem is SignerViewModel)
        {
            ShowDetailsPanel();
        }
        else
        {
            HideDetailsPanel();
        }
    }

    private void CloseDetailsButton_Click(object sender, RoutedEventArgs e)
    {
        SignersListBox.SelectedItem = null;
    }

    private void CopyRawDetailsButton_Click(object sender, RoutedEventArgs e)
    {
        if (SignersListBox.SelectedItem is not SignerViewModel signer)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(signer.DetailedInfo))
        {
            StatusMessageTextBlock.Text = "Сырые данные сертификата отсутствуют.";
            return;
        }

        try
        {
            Clipboard.SetText(signer.DetailedInfo);
            StatusMessageTextBlock.Text =
                $"Скопированы данные сертификата подписи №{signer.DisplayNumber}.";
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = $"Не удалось скопировать: {ex.Message}";
        }
    }

    private void ShowDetailsPanel()
    {
        if (_detailsPanelOpen)
        {
            return;
        }

        _detailsPanelOpen = true;
        DetailsSplitter.Visibility = Visibility.Visible;
        DetailsPanel.Visibility = Visibility.Visible;

        var animation = new GridLengthAnimation
        {
            From = new GridLength(0),
            To = new GridLength(DetailsPanelWidth),
            Duration = TimeSpan.FromMilliseconds(220),
            FillBehavior = FillBehavior.Stop
        };

        animation.Completed += (_, _) =>
        {
            if (_detailsPanelOpen)
            {
                DetailsColumn.Width = new GridLength(DetailsPanelWidth);
            }
        };

        DetailsColumn.BeginAnimation(ColumnDefinition.WidthProperty, animation);
    }

    private void HideDetailsPanel()
    {
        if (!_detailsPanelOpen)
        {
            DetailsPanel.Visibility = Visibility.Collapsed;
            DetailsSplitter.Visibility = Visibility.Collapsed;
            DetailsColumn.Width = new GridLength(0);
            return;
        }

        _detailsPanelOpen = false;

        var animation = new GridLengthAnimation
        {
            From = new GridLength(DetailsColumn.ActualWidth),
            To = new GridLength(0),
            Duration = TimeSpan.FromMilliseconds(180),
            FillBehavior = FillBehavior.Stop
        };

        animation.Completed += (_, _) =>
        {
            if (_detailsPanelOpen)
            {
                return;
            }

            DetailsPanel.Visibility = Visibility.Collapsed;
            DetailsSplitter.Visibility = Visibility.Collapsed;
            DetailsColumn.Width = new GridLength(0);
        };

        DetailsColumn.BeginAnimation(ColumnDefinition.WidthProperty, animation);
    }

    private async void ExtractSignatureButton_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog
        {
            Title = "Выберите присоединённую подпись",
            Filter = "Присоединённые подписи (*.p7s;*.sig)|*.p7s;*.sig|Все файлы (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != true)
        {
            return;
        }

        string inputPath = openDialog.FileName;
        ExtractSignatureButton.IsEnabled = false;
        StatusMessageTextBlock.Text = "Извлечение вложенного содержимого...";

        try
        {
            byte[] content = await Task.Run(
                () => CmsMerger.ExtractEmbeddedContent(inputPath));

            bool isPdf = IsPdf(content);
            string extension = isPdf ? ".pdf" : ".sig";
            string baseName = Path.GetFileNameWithoutExtension(inputPath);

            var saveDialog = new SaveFileDialog
            {
                Title = "Сохранить извлечённое содержимое",
                Filter = isPdf
                    ? "PDF (*.pdf)|*.pdf|Все файлы (*.*)|*.*"
                    : "Все файлы (*.*)|*.*",
                DefaultExt = extension,
                AddExtension = true,
                InitialDirectory = Path.GetDirectoryName(inputPath) ?? string.Empty,
                FileName = $"detached_{baseName}{extension}"
            };

            if (saveDialog.ShowDialog(this) != true)
            {
                StatusMessageTextBlock.Text = "Извлечение отменено.";
                return;
            }

            await File.WriteAllBytesAsync(saveDialog.FileName, content);

            StatusMessageTextBlock.Text =
                $"Извлечено содержимое: {content.Length} байт.";

            MessageBox.Show(
                this,
                $"Вложенное содержимое извлечено:{Environment.NewLine}" +
                $"{saveDialog.FileName}{Environment.NewLine}" +
                $"Размер: {content.Length} байт.",
                "Извлечение подписи",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = ex.Message;

            MessageBox.Show(
                this,
                ex.Message,
                "Ошибка извлечения",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            UpdateSummaryAndButtons();
        }
    }

    private async void SplitSignatureButton_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog
        {
            Title = "Выберите файл подписи для разделения",
            Filter = "Подписи (*.sig)|*.sig|Все файлы (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != true)
        {
            return;
        }

        string inputPath = openDialog.FileName;
        SplitSignatureButton.IsEnabled = false;
        StatusMessageTextBlock.Text = "Чтение файла подписи...";

        try
        {
            int signatureCount = await Task.Run(
                () => CmsMerger.GetSignatureCount(inputPath));

            if (signatureCount <= 1)
            {
                MessageBox.Show(
                    this,
                    signatureCount == 0
                        ? "В выбранном файле нет подписей."
                        : "В выбранном файле только одна подпись — разделять нечего.",
                    "Разделение подписей",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                StatusMessageTextBlock.Text = "Разделение не требуется.";
                return;
            }

            string sourceBaseName = Path.GetFileNameWithoutExtension(inputPath);

            var saveDialog = new SaveFileDialog
            {
                Title = "Базовое имя для разделённых подписей",
                Filter = "Подписи (*.sig)|*.sig|Все файлы (*.*)|*.*",
                DefaultExt = ".sig",
                AddExtension = true,
                InitialDirectory = Path.GetDirectoryName(inputPath) ?? string.Empty,
                FileName = $"{sourceBaseName}_1.sig"
            };

            if (saveDialog.ShowDialog(this) != true)
            {
                StatusMessageTextBlock.Text = "Разделение отменено.";
                return;
            }

            string? directory = Path.GetDirectoryName(saveDialog.FileName);
            string chosenBaseName = Path.GetFileNameWithoutExtension(saveDialog.FileName);

            if (chosenBaseName.EndsWith("_1", StringComparison.Ordinal))
            {
                chosenBaseName = chosenBaseName[..^2];
            }

            if (string.IsNullOrWhiteSpace(chosenBaseName))
            {
                chosenBaseName = sourceBaseName;
            }

            string outputBasePath = Path.Combine(
                directory ?? string.Empty, chosenBaseName);

            StatusMessageTextBlock.Text =
                $"Разделение подписей ({signatureCount})...";

            var outputPaths = await Task.Run(
                () => CmsMerger.SplitSignatures(inputPath, outputBasePath));

            StatusMessageTextBlock.Text =
                $"Разделение завершено. Создано файлов: {outputPaths.Count}.";

            MessageBox.Show(
                this,
                $"Создано отдельных файлов подписи: {outputPaths.Count}." +
                $"{Environment.NewLine}{Environment.NewLine}" +
                string.Join(Environment.NewLine, outputPaths),
                "Разделение подписей",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = ex.Message;

            MessageBox.Show(
                this,
                ex.Message,
                "Ошибка разделения",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            UpdateSummaryAndButtons();
        }
    }

    private static bool IsPdf(byte[] content)
    {
        return content.Length >= 5
            && content[0] == 0x25
            && content[1] == 0x50
            && content[2] == 0x44
            && content[3] == 0x46
            && content[4] == 0x2D;
    }

    private async void CheckBindingButton_Click(object sender, RoutedEventArgs e)
    {
        if (_signers.Count == 0)
        {
            MessageBox.Show(
                this,
                "Сначала загрузите файлы .sig.",
                "Проверка привязки к PDF",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var signersToCheck = _signers.ToList();

        var dialog = new OpenFileDialog
        {
            Title = "Выберите подписанный файл",
            Filter = "Все файлы (*.*)|*.*|PDF (*.pdf)|*.pdf"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        string pdfPath = dialog.FileName;

        CheckBindingButton.IsEnabled = false;
        StatusMessageTextBlock.Text = "Проверка привязки...";

        try
        {
            var results = await Task.Run(() =>
            {
                var list = new List<(
                    SignerViewModel Signer,
                    BindingStatus Status,
                    string Details)>(signersToCheck.Count);

                byte[] documentHash = CmsMerger.ComputeDocumentHash(
                    pdfPath, CmsMerger.Gost2012_256Oid);

                foreach (SignerViewModel signer in signersToCheck)
                {
                    var details = new List<string>();
                    byte[]? messageDigest = null;

                    try
                    {
                        messageDigest = CmsMerger.GetMessageDigest(
                            signer.SourceFilePath, signer.Index);
                        details.Add(
                            $"messageDigest ({messageDigest.Length} байт): " +
                            Convert.ToHexString(messageDigest));
                    }
                    catch (Exception ex)
                    {
                        details.Add($"messageDigest: ошибка — {ex.Message}");
                    }

                    byte[]? computedHash = null;
                    try
                    {
                        IntPtr hCryptMsg = CmsMerger.ReadSignature(signer.SourceFilePath);

                        try
                        {
                            computedHash = CmsMerger.GetSignatureHash(
                                hCryptMsg, signer.Index);
                        }
                        finally
                        {
                            CmsMerger.CloseSignature(hCryptMsg);
                        }

                        details.Add(computedHash.Length == 0
                            ? "CMSG_COMPUTED_HASH: пусто"
                            : $"CMSG_COMPUTED_HASH ({computedHash.Length} байт): " +
                              Convert.ToHexString(computedHash));
                    }
                    catch (Exception ex)
                    {
                        details.Add($"CMSG_COMPUTED_HASH: ошибка — {ex.Message}");
                    }

                    details.Add(
                        $"хеш файла ({documentHash.Length} байт): " +
                        Convert.ToHexString(documentHash));

                    BindingStatus status;
                    byte[]? hashForComparison = messageDigest ?? computedHash;

                    if (hashForComparison is null)
                    {
                        status = BindingStatus.NotChecked;
                        details.Add("Сравнение невозможно: хеш подписи не извлечён.");
                    }
                    else if (hashForComparison.Length != documentHash.Length)
                    {
                        status = BindingStatus.NotChecked;
                        details.Add(
                            $"Длина хеша подписи ({hashForComparison.Length} байт) " +
                            $"не совпадает с длиной хеша файла ({documentHash.Length} байт).");

                        if (hashForComparison.Length == 64)
                        {
                            details.Add("Возможно, подпись использует ГОСТ 2012-512.");
                        }
                    }
                    else
                    {
                        bool matches = hashForComparison.AsSpan().SequenceEqual(documentHash);
                        status = matches ? BindingStatus.Bound : BindingStatus.NotBound;
                        details.Add(matches ? "Сравнение: совпадает." : "Сравнение: не совпадает.");
                    }

                    list.Add((signer, status, string.Join(Environment.NewLine, details)));
                }

                return list;
            });

            CurrentPdfPath = pdfPath;
            int bound = 0;

            foreach (var (signer, status, details) in results)
            {
                signer.BindingStatus = status;
                signer.BindingDetails = details;

                if (status == BindingStatus.Bound)
                {
                    bound++;
                }
            }

            StatusMessageTextBlock.Text =
                $"Проверка завершена: привязано {bound} из {results.Count}.";

            UpdateSummaryAndButtons();
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = ex.Message;

            MessageBox.Show(
                this,
                ex.Message,
                "Ошибка проверки",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            CheckBindingButton.IsEnabled = _signers.Count > 0;
        }
    }

    private async void MergeSignaturesButton_Click(object sender, RoutedEventArgs e)
    {
        if (CurrentPdfPath is null)
        {
            MessageBox.Show(
                this,
                "Сначала выберите PDF-файл кнопкой «Проверить привязку к PDF».",
                "Объединение подписей",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var selectedSigners = _signers.Where(signer => signer.IsChecked).ToList();
        if (selectedSigners.Count == 0)
        {
            MessageBox.Show(
                this,
                "Не выбрано ни одной подписи.",
                "Объединение подписей",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        string mergeBaseName = Path.GetFileNameWithoutExtension(CurrentPdfPath);

        var dialog = new SaveFileDialog
        {
            Title = "Сохранить объединённую подпись",
            Filter = "Подписи (*.sig)|*.sig|Все файлы (*.*)|*.*",
            DefaultExt = ".sig",
            AddExtension = true,
            InitialDirectory = Path.GetDirectoryName(CurrentPdfPath) ?? string.Empty,
            FileName = string.IsNullOrWhiteSpace(mergeBaseName)
                ? "merged.sig"
                : $"merge_{mergeBaseName}.sig"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var signersToMerge = selectedSigners
            .Select(signer => new SignerData
            {
                SourceFilePath = signer.SourceFilePath,
                Index = signer.Index
            })
            .ToList();

        string outputFilePath = dialog.FileName;

        MergeSignaturesButton.IsEnabled = false;
        StatusMessageTextBlock.Text = "Объединение...";

        try
        {
            int totalSigners = await Task.Run(() =>
            {
                CmsMerger.MergeSignatures(signersToMerge, outputFilePath);

                IntPtr hCryptMsg = CmsMerger.ReadSignature(outputFilePath);

                try
                {
                    return CmsMerger.GetSignerCount(hCryptMsg);
                }
                finally
                {
                    CmsMerger.CloseSignature(hCryptMsg);
                }
            });

            StatusMessageTextBlock.Text = "Объединение завершено.";
            UpdateSummaryAndButtons();

            MessageBox.Show(
                this,
                $"Объединено выбранных подписей: {selectedSigners.Count}." +
                $"{Environment.NewLine}Подписей в итоговом файле: {totalSigners}." +
                $"{Environment.NewLine}{outputFilePath}",
                "Объединение завершено",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusMessageTextBlock.Text = ex.Message;

            MessageBox.Show(
                this,
                ex.Message,
                "Ошибка объединения",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            UpdateSummaryAndButtons();
        }
    }

    private void UpdateSummaryAndButtons()
    {
        int loaded = _signers.Count;
        int selected = _signers.Count(signer => signer.IsChecked);
        string pdfName = CurrentPdfPath is null
            ? "не выбран"
            : Path.GetFileName(CurrentPdfPath);

        SummaryTextBlock.Text =
            $"Загружено подписей: {loaded}. " +
            $"Выбрано для объединения: {selected}. " +
            $"PDF-файл: {pdfName}";

        MergeSignaturesButton.IsEnabled =
            _cryptoProAvailable &&
            loaded > 0 && selected > 0 && CurrentPdfPath is not null;

        CheckBindingButton.IsEnabled = _cryptoProAvailable && loaded > 0;

        CheckSignatureButton.IsEnabled = _cryptoProAvailable;
        ExtractSignatureButton.IsEnabled = _cryptoProAvailable;
        SplitSignatureButton.IsEnabled = _cryptoProAvailable;
    }
}

internal sealed class GridLengthAnimation : AnimationTimeline
{
    public GridLength From { get; set; }

    public GridLength To { get; set; }

    public override Type TargetPropertyType => typeof(GridLength);

    protected override Freezable CreateInstanceCore()
    {
        return new GridLengthAnimation();
    }

    public override object GetCurrentValue(
        object defaultOriginValue,
        object defaultDestinationValue,
        AnimationClock animationClock)
    {
        double progress = animationClock.CurrentProgress ?? 0;
        double value = From.Value + (To.Value - From.Value) * progress;

        return new GridLength(value, GridUnitType.Pixel);
    }
}
