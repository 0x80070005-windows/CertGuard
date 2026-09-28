using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGuard.Security;

namespace CertGuard.Init;

/// <summary>
/// Инициализация CertGuard: подготовка каталогов, первичная генерация
/// сертификатов, проверка устройства при каждом запуске.
/// </summary>
public static class Initializer
{
    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    private const string CertFileName = "certificate.cer";
    private const string PfxFileName = "certguard.pfx";
    private const string DeviceFileName = "Device";

    // Кэш выбранного каталога (чтобы GetCertificateDir() был стабилен между вызовами)
    private static string? _resolvedCertDir;

    // Приватный сертификат текущей сессии
    private static X509Certificate2? _sessionCert;

    // ===================== Публичные свойства =====================

    /// <summary>
    /// Приватный сертификат текущей сессии. Null, если проверка не выполнялась
    /// или не удалась. Заполняется один раз в VerifyDeviceCertificate().
    /// </summary>
    public static X509Certificate2? SessionCertificate => _sessionCert;

    // ===================== Пути =====================

    public static string GetCertificateDir()
    {
        if (_resolvedCertDir != null)
            return _resolvedCertDir;

        if (IsWindows)
        {
            _resolvedCertDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CertGuard");
            return _resolvedCertDir;
        }

        const string systemDir = "/etc/certguard";
        if (TryEnsureDirectory(systemDir, out _))
        {
            _resolvedCertDir = systemDir;
            return _resolvedCertDir;
        }

        string userDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".config", "certguard");

        if (!TryEnsureDirectory(userDir, out string? err))
            throw new InvalidOperationException(
                $"Не удалось создать ни '{systemDir}', ни '{userDir}': {err}");

        Console.WriteLine($"⚠ /etc/certguard недоступен, используется {userDir}");
        _resolvedCertDir = userDir;
        return _resolvedCertDir;
    }

    private static bool TryEnsureDirectory(string path, out string? error)
    {
        error = null;
        try
        {
            if (!Directory.Exists(path))
                Directory.CreateDirectory(path);

            if (!OperatingSystem.IsWindows())
            {
                try
                {
                    File.SetUnixFileMode(path,
                        UnixFileMode.UserRead |
                        UnixFileMode.UserWrite |
                        UnixFileMode.UserExecute);
                }
                catch { /* best effort */ }
            }

            string probe = Path.Combine(path, ".probe_" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(probe, "ok");
            File.Delete(probe);

            return true;
        }
        catch (UnauthorizedAccessException ex) { error = ex.Message; return false; }
        catch (IOException ex) { error = ex.Message; return false; }
    }

    public static string GetSettingsFile()
        => Path.Combine(GetCertificateDir(), ".WPS_Setting");

    public static string GetPfxPath()
        => Path.Combine(GetCertificateDir(), PfxFileName);

    public static string GetDevicePathFile()
    {
        string folder = IsWindows ? @"C:\Temp\CertGuard\" : "/mnt/temp/";
        return Path.Combine(folder, DeviceFileName);
    }

    // ===================== Инициализация =====================

    public static void master_init()
    {
        try
        {
            string certDir = GetCertificateDir();
            Console.WriteLine($"Каталог сертификатов: {certDir}");

            EnsureTempFolder();

            string deviceTemp = GetDevicePathFile();
            if (!File.Exists(deviceTemp))
            {
                Console.Write("Введите директорию доверенного устройства " +
                              "(заканчивать на / или \\) - ");
                string? device = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(device))
                {
                    Console.WriteLine("Путь не может быть пустым.");
                    Environment.Exit(1);
                }
                File.WriteAllText(deviceTemp, device.Trim());
            }

            bool firstRun = !File.Exists(GetSettingsFile());
            if (firstRun)
            {
                InitializeFirstTime();
            }
            else
            {
                // Пароль спрашивается здесь один раз за весь процесс
                bool deviceOk = VerifyDeviceCertificate();
                if (deviceOk)
                {
                    Console.WriteLine("✓ Устройство подтверждено.");
                }
                else
                {
                    Console.WriteLine("⚠ ВНИМАНИЕ: Доверенное устройство не найдено.");
                    Console.WriteLine("  Можно использовать резервный мастер-ключ.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Критическая ошибка инициализации: {ex.Message}");
            Environment.Exit(1);
        }
    }

    private static void EnsureTempFolder()
    {
        string tempFolder = IsWindows ? @"C:\Temp\CertGuard\" : "/mnt/temp/";
        if (Directory.Exists(tempFolder))
            return;

        if (OperatingSystem.IsLinux())
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"sudo mkdir -p '{tempFolder}' && sudo chmod 0777 '{tempFolder}'\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var process = Process.Start(psi);
                process?.WaitForExit();

                if (process != null && process.ExitCode != 0)
                {
                    string err = process.StandardError.ReadToEnd();
                    Console.WriteLine($"⚠ Не удалось создать {tempFolder}: {err.Trim()}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠ Ошибка при создании {tempFolder}: {ex.Message}");
            }
        }
        else
        {
            Directory.CreateDirectory(tempFolder);
        }
    }

    // ===================== Первичная генерация =====================

    private static void InitializeFirstTime()
    {
        Console.WriteLine("=== Первый запуск — генерация сертификатов ===");
        Console.Write("Придумайте пароль для приватного ключа (PFX): ");
        string pfxPassword = ReadPassword();
        if (string.IsNullOrEmpty(pfxPassword))
        {
            Console.WriteLine("Пароль не может быть пустым.");
            Environment.Exit(1);
        }

        Console.Write("Повторите пароль: ");
        string pfxPassword2 = ReadPassword();
        if (pfxPassword != pfxPassword2)
        {
            Console.WriteLine("Пароли не совпадают.");
            Environment.Exit(1);
        }

        string devicePath = File.ReadAllText(GetDevicePathFile()).Trim();
        if (string.IsNullOrEmpty(devicePath))
        {
            Console.WriteLine("Путь к флешке пуст.");
            Environment.Exit(1);
        }

        if (!Directory.Exists(devicePath))
        {
            Console.WriteLine($"Каталог {devicePath} не найден. Создание...");
            try
            {
                Directory.CreateDirectory(devicePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не удалось создать каталог: {ex.Message}");
                Environment.Exit(1);
            }
        }

        string certDir = GetCertificateDir();

        var (publicCertPath, pfxPath, backupKeyHex) =
            CertificateGenerator.GenerateAndSave(devicePath, certDir, pfxPassword);

        byte[] backupBytes = Convert.FromHexString(backupKeyHex);
        byte[] backupHash = SHA512.HashData(backupBytes);
        CryptographicOperations.ZeroMemory(backupBytes);

        File.WriteAllText(GetSettingsFile(), Convert.ToHexString(backupHash));
        CryptographicOperations.ZeroMemory(backupHash);

        // Сразу загружаем сертификат в сессию, чтобы не спрашивать пароль второй раз
        try
        {
            var publicCert = CertificateService.LoadPublicCertificate(publicCertPath);
            var privateCert = CertificateService.LoadPrivateCertificate(pfxPath, pfxPassword);

            if (CertificateService.ThumbprintsMatch(publicCert, privateCert) &&
                CertificateService.VerifyChallengeResponse(publicCert, privateCert))
            {
                publicCert.Dispose();
                _sessionCert = privateCert;
                Console.WriteLine("✓ Сертификат загружен в сессию.");
            }
            else
            {
                publicCert.Dispose();
                privateCert.Dispose();
                Console.WriteLine("⚠ Не удалось проверить только что созданный сертификат.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠ Ошибка загрузки сертификата в сессию: {ex.Message}");
        }

        Console.WriteLine();
        Console.WriteLine("==================================================");
        Console.WriteLine("✓ СЕРТИФИКАТЫ УСПЕШНО СОЗДАНЫ!");
        Console.WriteLine("==================================================");
        Console.WriteLine($"📁 Публичный сертификат: {publicCertPath}");
        Console.WriteLine($"📁 Приватный ключ (PFX): {pfxPath}");
        Console.WriteLine($"📁 Файл настроек:        {GetSettingsFile()}");
        Console.WriteLine("==================================================");
        Console.WriteLine("⚠️  СОХРАНИТЕ РЕЗЕРВНЫЙ КЛЮЧ В НАДЁЖНОМ МЕСТЕ!");
        Console.WriteLine($"Резервный мастер-ключ: {backupKeyHex}");
        Console.WriteLine("==================================================");
    }

    // ===================== Проверка устройства =====================

    /// <summary>
    /// Загружает и проверяет сертификат. Пароль PFX запрашивается ровно один раз.
    /// При успехе результат кэшируется в <see cref="SessionCertificate"/>.
    /// </summary>
    public static bool VerifyDeviceCertificate()
    {
        // Если уже загружен — не спрашиваем повторно
        if (_sessionCert != null)
            return true;

        try
        {
            string devicePathFile = GetDevicePathFile();
            if (!File.Exists(devicePathFile))
                return false;

            string devicePath = File.ReadAllText(devicePathFile).Trim();
            if (string.IsNullOrEmpty(devicePath))
                return false;

            string certPath = Path.Combine(devicePath, CertFileName);
            if (!File.Exists(certPath))
                return false;

            string pfxPath = GetPfxPath();
            if (!File.Exists(pfxPath))
                return false;

            Console.Write("Введите пароль для приватного ключа: ");
            string pfxPassword = ReadPassword();
            if (string.IsNullOrEmpty(pfxPassword))
                return false;

            var publicCert = CertificateService.LoadPublicCertificate(certPath);
            var privateCert = CertificateService.LoadPrivateCertificate(pfxPath, pfxPassword);

            if (!CertificateService.ThumbprintsMatch(publicCert, privateCert))
            {
                publicCert.Dispose();
                privateCert.Dispose();
                return false;
            }

            if (!CertificateService.VerifyChallengeResponse(publicCert, privateCert))
            {
                publicCert.Dispose();
                privateCert.Dispose();
                return false;
            }

            publicCert.Dispose();

            // Кэшируем в сессию — пароль больше не понадобится
            _sessionCert?.Dispose();
            _sessionCert = privateCert;

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка проверки: {ex.Message}");
            return false;
        }
    }

    // ===================== Ввод пароля =====================

    public static string ReadPassword()
    {
        string password = "";
        ConsoleKeyInfo key;
        do
        {
            key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password = password.Remove(password.Length - 1);
                Console.Write("\b \b");
            }
            else if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            else if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password += key.KeyChar;
                Console.Write("*");
            }
        } while (true);
        return password;
    }
}