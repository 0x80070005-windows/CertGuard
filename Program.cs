using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGuard.Init;
using FileCrypto;

// ============================================================
//  Инициализация.
//  Здесь пароль PFX спрашивается ОДИН РАЗ за весь запуск.
//  После успешной проверки сертификат кладётся в
//  Initializer.SessionCertificate и больше не запрашивается.
// ============================================================
Initializer.master_init();

// Открытие .enc-файла двойным кликом / drag&drop
if (args.Length == 1 && File.Exists(args[0]) &&
    Path.GetExtension(args[0]).Equals(".enc", StringComparison.OrdinalIgnoreCase))
{
    HandleFileOpen(args[0]);
    return;
}

ShowMenu();

// ===================== Открытие .enc файла напрямую =====================

static void HandleFileOpen(string filePath)
{
    Console.WriteLine("------------------------------------------------");
    Console.WriteLine($"Обнаружен зашифрованный файл: {filePath}");
    Console.WriteLine("------------------------------------------------");

    X509Certificate2? cert = Initializer.SessionCertificate;

    if (cert == null)
    {
        HandleBackupDecrypt(filePath);
        Console.WriteLine("Нажмите Enter для выхода...");
        Console.ReadLine();
        return;
    }

    string? password = AskPasswordOrFail("Введите пароль для расшифровки: ");
    if (password == null) return;

    DoDecrypt(filePath, password, cert);
    Console.WriteLine("Нажмите Enter для выхода...");
    Console.ReadLine();
}

// ===================== Интерактивное меню =====================

static void ShowMenu()
{
    while (true)
    {
        Console.WriteLine("------------------------------------------------");
        Console.WriteLine("Добро пожаловать в CertGuard");
        Console.WriteLine("------------------------------------------------");
        Console.WriteLine("1 - Зашифровать файл");
        Console.WriteLine("2 - Дешифровать файл");
        Console.WriteLine("0 - Выход");
        Console.Write("Выберите действие: ");

        string? choice = Console.ReadLine();

        switch (choice)
        {
            case "1": EncryptFile(); break;
            case "2": DecryptFile(); break;
            case "0": return;
            default:
                Console.WriteLine("Неверный ввод, попробуйте снова.");
                break;
        }
    }
}

static void EncryptFile()
{
    X509Certificate2? cert = Initializer.SessionCertificate;
    if (cert == null)
    {
        Console.WriteLine("Шифрование недоступно: не удалось открыть приватный ключ.");
        return;
    }

    byte[]? backupKey = GetBackupKeyOrFail();
    if (backupKey == null) return;

    try
    {
        Console.Write("Введите путь к файлу для шифрования: ");
        string? inputFile = CleanPath(Console.ReadLine());
        if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
        {
            Console.WriteLine("Файл не найден.");
            return;
        }

        string? password = AskPasswordOrFail("Введите пароль для файла: ");
        if (password == null) return;

        string encryptedFile = inputFile + ".enc";

        Console.WriteLine("Идёт шифрование (Argon2id 64 MiB × 3 итерации)...");
        CryptoModule.Encrypt(inputFile, encryptedFile, password, cert, backupKey);
        Console.WriteLine($"✓ Файл зашифрован: {encryptedFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Ошибка шифрования: {ex.Message}");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(backupKey);
    }
}

static void DecryptFile()
{
    X509Certificate2? cert = Initializer.SessionCertificate;

    Console.Write("Введите путь к зашифрованному файлу (.enc): ");
    string? inputFile = CleanPath(Console.ReadLine());
    if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
    {
        Console.WriteLine("Файл не найден.");
        return;
    }

    if (!inputFile.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine("Файл должен иметь расширение .enc");
        return;
    }

    if (cert == null)
    {
        HandleBackupDecrypt(inputFile);
        return;
    }

    string? password = AskPasswordOrFail("Введите пароль для расшифровки: ");
    if (password == null) return;

    DoDecrypt(inputFile, password, cert);
}

// ===================== Резервный ключ =====================

static byte[]? GetBackupKeyOrFail()
{
    Console.Write("Введите резервный мастер-ключ (hex) или оставьте пустым для отмены: ");
    string? input = Console.ReadLine()?.Trim();

    if (string.IsNullOrEmpty(input))
    {
        Console.WriteLine("Отменено.");
        return null;
    }

    try
    {
        byte[] key = Convert.FromHexString(input);
        if (key.Length != 32)
        {
            Console.WriteLine("Ключ должен быть 64 шестнадцатеричных символа.");
            return null;
        }
        return key;
    }
    catch (FormatException)
    {
        Console.WriteLine("Некорректный hex-формат ключа.");
        return null;
    }
}

// ===================== Расшифровка через резервный ключ =====================

static void HandleBackupDecrypt(string inputFile)
{
    Console.WriteLine("Сертификат недоступен. Используется резервный мастер-ключ.");
    byte[]? backupKey = GetBackupKeyOrFail();
    if (backupKey == null) return;

    try
    {
        string outputFile = Path.ChangeExtension(inputFile, null);
        Console.WriteLine("Идёт расшифровка (резервный ключ)...");
        CryptoModule.DecryptWithBackupKey(inputFile, outputFile, backupKey);
        Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"ОШИБКА расшифровки: {ex.Message}");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(backupKey);
    }
}

// ===================== Вспомогательные =====================

static string? AskPasswordOrFail(string prompt)
{
    Console.Write(prompt);
    string? password = Initializer.ReadPassword();
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine("ОШИБКА: пароль не может быть пустым.");
        return null;
    }
    return password;
}

static void DoDecrypt(string filePath, string password, X509Certificate2 cert)
{
    string outputFile = Path.ChangeExtension(filePath, null);
    try
    {
        Console.WriteLine("Идёт расшифровка (Argon2id 64 MiB × 3 итерации)...");
        CryptoModule.Decrypt(filePath, outputFile, password, cert);
        Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"ОШИБКА расшифровки: {ex.Message}");
    }
}

static string? CleanPath(string? input)
{
    if (string.IsNullOrEmpty(input)) return input;
    input = input.Trim();
    if ((input.StartsWith("\"") && input.EndsWith("\"")) ||
        (input.StartsWith("'") && input.EndsWith("'")))
    {
        input = input.Substring(1, input.Length - 2);
    }
    return input;
}