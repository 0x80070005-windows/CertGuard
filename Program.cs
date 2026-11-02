using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGuard.Init;
using CertGuard.Security;
using FileCrypto;

// ============================================================
//  Инициализация.
//  Здесь пароль PFX спрашивается ОДИН РАЗ за весь запуск.
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

    // 1) Обычный путь: пароль + сертификат
    if (cert != null)
    {
        string? password = AskPasswordOrFail("Введите пароль для расшифровки: ");
        if (password == null) return;

        try
        {
            DoDecrypt(filePath, password, cert);
            Console.WriteLine("Нажмите Enter для выхода...");
            Console.ReadLine();
            return;
        }
        catch (Exception)
        {
            Console.WriteLine("Пароль неверный или сертификат не подходит.");
        }
    }

    // 2) Резервный путь: backupKey
    if (TryDecryptWithBackupKey(filePath))
    {
        Console.WriteLine("Нажмите Enter для выхода...");
        Console.ReadLine();
        return;
    }

    // 3) Восстановление по 3 вопросам
    if (TryDecryptWithRecovery(filePath))
    {
        Console.WriteLine("Нажмите Enter для выхода...");
        Console.ReadLine();
        return;
    }

    Console.WriteLine("Не удалось расшифровать файл.");
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

        Console.WriteLine("Ответьте на 3 вопроса восстановления:");
        string[] recoveryAnswers = RecoverySecrets.AskQuestions();

        string encryptedFile = inputFile + ".enc";

        Console.WriteLine("Идёт шифрование (Argon2id 64 MiB × 3 итерации)...");
        CryptoModule.Encrypt(inputFile, encryptedFile, password, cert, backupKey, recoveryAnswers);
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

    if (cert != null)
    {
        string? password = AskPasswordOrFail("Введите пароль для расшифровки: ");
        if (password == null) return;

        try
        {
            DoDecrypt(inputFile, password, cert);
            return;
        }
        catch (Exception)
        {
            Console.WriteLine("Пароль неверный или сертификат не подходит.");
        }
    }

    if (TryDecryptWithBackupKey(inputFile))
        return;

    TryDecryptWithRecovery(inputFile);
}

// ===================== Резервный ключ =====================

static byte[]? GetBackupKeyOrFail()
{
    Console.Write("Введите резервный мастер-ключ (32 байта / 64 hex символа): ");
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
            Console.WriteLine("Ключ должен быть 32 байта (64 hex символа).");
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

static bool TryDecryptWithBackupKey(string inputFile)
{
    Console.WriteLine("Пробуем расшифровать через backupKey...");
    byte[]? backupKey = GetBackupKeyOrFail();
    if (backupKey == null) return false;

    try
    {
        string outputFile = Path.ChangeExtension(inputFile, null);
        Console.WriteLine("Идёт расшифровка (backupKey)...");
        CryptoModule.DecryptWithBackupKey(inputFile, outputFile, backupKey);
        Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Не удалось расшифровать через backupKey: {ex.Message}");
        return false;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(backupKey);
    }
}

static bool TryDecryptWithRecovery(string inputFile)
{
    try
    {
        Console.WriteLine("Пытаемся восстановить доступ по 3 вопросам...");
        var recovery = RecoverySecrets.AskRecoveryData();

        // Сначала пробуем backupKey, если он был введён
        if (recovery.BackupKey != null)
        {
            try
            {
                string outputFile = Path.ChangeExtension(inputFile, null);
                Console.WriteLine("Идёт расшифровка через backupKey из восстановления...");
                CryptoModule.DecryptWithBackupKey(inputFile, outputFile, recovery.BackupKey);
                Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"backupKey из восстановления не подошёл: {ex.Message}");
            }
        }

        // Затем пробуем только 3 вопроса
        string outputFile2 = Path.ChangeExtension(inputFile, null);
        Console.WriteLine("Идёт расшифровка через 3 вопроса...");
        CryptoModule.DecryptWithRecovery(inputFile, outputFile2, recovery.Answers);
        Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile2}");
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Не удалось восстановить файл: {ex.Message}");
        return false;
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
    Console.WriteLine("Идёт расшифровка (Argon2id 64 MiB × 3 итерации)...");
    CryptoModule.Decrypt(filePath, outputFile, password, cert);
    Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
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
