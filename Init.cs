using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGuard.Security;

namespace CertGuard.Init;

public static class Initializer
{
    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    private const string CertFileName = "certificate.cer";
    private const string PfxFileName = "certguard.pfx";
    private const string DeviceFileName = "Device";

    private static string? _resolvedCertDir;
    private static X509Certificate2? _sessionCert;

    public static X509Certificate2? SessionCertificate => _sessionCert;

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

    public static string GetPfxPath()
        => Path.Combine(GetCertificateDir(), PfxFileName);

    public static string GetDevicePathFile()
    {
        return Path.Combine(GetCertificateDir(), DeviceFileName);
    }

    public static void master_init()
    {
        try
        {
            string certDir = GetCertificateDir();
            Console.WriteLine($"Каталог сертификатов: {certDir}");

            // 🟢 ПРОВЕРКА СОСТОЯНИЯ
            bool pfxExists = File.Exists(GetPfxPath());
            bool deviceExists = File.Exists(GetDevicePathFile());

            // 1. Если нет приватного ключа — это либо первый запуск, либо катастрофа
            if (!pfxExists)
            {
                if (deviceExists)
                {
                    Console.WriteLine("⚠ Приватный ключ (PFX) не найден, но файл Device на месте.");
                }
                else
                {
                    Console.Write("Введите директорию доверенного устройства " +
                                  "(заканчивать на / или \\) - ");
                    string? device = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(device))
                    {
                        Console.WriteLine("Путь не может быть пустым.");
                        Environment.Exit(1);
                    }
                    File.WriteAllText(GetDevicePathFile(), device.Trim());
                }

                InitializeFirstTime();
                return; // После генерации выходим из метода
            }

            // 2. Если PFX есть, но нет файла Device — восстанавливаем настройки
            if (!deviceExists)
            {
                Console.WriteLine("⚠ Файл конфигурации устройства (Device) утерян.");
                Console.WriteLine("Приватный ключ (PFX) на месте. Требуется указать путь к флешке.");
                
                Console.Write("Введите директорию доверенного устройства " +
                              "(заканчивать на / или \\) - ");
                string? device = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(device))
                {
                    Console.WriteLine("Путь не может быть пустым.");
                    Environment.Exit(1);
                }
                File.WriteAllText(GetDevicePathFile(), device.Trim());
            }

            // 3. Всё на месте (или только что восстановили) — проверяем устройство
            bool deviceOk = VerifyDeviceCertificate();
            if (deviceOk)
            {
                Console.WriteLine("✓ Устройство подтверждено.");
            }
            else
            {
                Console.WriteLine("⚠ ВНИМАНИЕ: Доверенное устройство не найдено или сертификат не подходит.");
                Console.WriteLine("  Можно использовать резервный мастер-ключ или секретные вопросы.");
            }
        }
        catch (InvalidOperationException ex)
        {
            // Ловим ошибку из CertificateGenerator (защита от перезаписи)
            Console.WriteLine($"\n🛑 {ex.Message}\n");
            Environment.Exit(1);
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"\n🛑 {ex.Message}\n");
            Environment.Exit(1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Критическая ошибка инициализации: {ex.Message}");
            Environment.Exit(1);
        }
    }

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

        // Если на флешке остался старый certificate.cer, GenerateAndSave выдаст ошибку 
        // и мы не потеряем данные (защита от перезаписи).
        var (publicCertPath, pfxPath, backupKeyHex) =
            CertificateGenerator.GenerateAndSave(devicePath, certDir, pfxPassword);

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
        Console.WriteLine("==================================================");
        Console.WriteLine("⚠️  СОХРАНИТЕ РЕЗЕРВНЫЙ КЛЮЧ В НАДЁЖНОМ МЕСТЕ!");
        Console.WriteLine($"Резервный мастер-ключ: {backupKeyHex}");
        Console.WriteLine("==================================================");
    }

    public static bool VerifyDeviceCertificate()
    {
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
            {
                Console.WriteLine($"⚠ Файл {CertFileName} не найден по пути {certPath}");
                return false;
            }

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
                Console.WriteLine("⚠ Отпечатки сертификатов не совпадают (флешка от другого устройства?).");
                publicCert.Dispose();
                privateCert.Dispose();
                return false;
            }

            if (!CertificateService.VerifyChallengeResponse(publicCert, privateCert))
            {
                Console.WriteLine("⚠ Проверка цифровой подписи не удалась.");
                publicCert.Dispose();
                privateCert.Dispose();
                return false;
            }

            publicCert.Dispose();

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
