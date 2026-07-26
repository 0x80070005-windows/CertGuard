using System;
using System.IO;
using System.Security.Cryptography;
using FileCrypto;
using CertGuard.Init;
using DeviceAuthentication1;

// Инициализация
Initializer.master_init();

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

    byte[]? masterKey = GetMasterKeyOrFail();
    if (masterKey == null)
        return;

    string? password = AskPasswordOrFail();
    if (password == null)
        return;

    DoDecrypt(filePath, password, masterKey);
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
            case "1":
                EncryptFile();
                break;
            case "2":
                DecryptFile();
                break;
            case "0":
                return;
            default:
                Console.WriteLine("Неверный ввод, попробуйте снова.");
                break;
        }
    }
}

static void EncryptFile()
{
    byte[]? masterKey = GetMasterKeyOrFail();
    if (masterKey == null)
        return;

    Console.Write("Введите путь к файлу для шифрования: ");
    string? inputFile = Console.ReadLine();
    inputFile = CleanPath(inputFile);

    if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
    {
        Console.WriteLine("Файл не найден.");
        return;
    }

    Console.Write("Введите пароль: ");
    string? password = ReadPassword();
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine("Пароль не может быть пустым.");
        return;
    }

    string encryptedFile = inputFile + ".enc";
    try
    {
        byte[] masterKeyHash = SHA256.HashData(masterKey);
        CryptoModule.Encrypt(inputFile, encryptedFile, password, masterKeyHash);
        Console.WriteLine($"✓ Файл зашифрован: {encryptedFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Ошибка шифрования: {ex.Message}");
    }
}

static void DecryptFile()
{
    byte[]? masterKey = GetMasterKeyOrFail();
    if (masterKey == null)
        return;

    Console.Write("Введите путь к зашифрованному файлу (.enc): ");
    string? inputFile = Console.ReadLine();
    inputFile = CleanPath(inputFile);

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

    string? password = AskPasswordOrFail();
    if (password == null)
        return;

    DoDecrypt(inputFile, password, masterKey);
}

// ===================== Общие вспомогательные методы =====================

static byte[]? GetMasterKeyOrFail()
{
    Console.WriteLine("Проверка устройства и получение мастер-ключа...");
    byte[]? masterKey = CertAutDevice.GetMasterKey();

    if (masterKey == null)
    {
        Console.WriteLine("Обычная проверка не удалась.");
        Console.Write("Введите резервный мастер-ключ (или оставьте пустым для выхода): ");
        string? backupKey = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(backupKey))
        {
            Console.WriteLine("Доступ запрещён.");
            return null;
        }

        try
        {
            byte[] backupBytes = Convert.FromHexString(backupKey);
            if (backupBytes.Length != 32)
                throw new FormatException("Ключ должен быть 64 шестнадцатеричных символа.");

            string expectedHash = File.ReadAllText(Initializer.GetSettingsFile()).Trim();
            byte[] hash = SHA512.HashData(backupBytes);
            string actualHash = Convert.ToHexString(hash);

            if (string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
            {
                Console.WriteLine("Резервный ключ верный. Доступ разрешён.");
                return backupBytes;
            }
            else
            {
                Console.WriteLine("Неверный резервный ключ.");
                return null;
            }
        }
        catch (FormatException)
        {
            Console.WriteLine("Некорректный формат ключа (должен быть в шестнадцатеричном виде).");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка проверки резервного ключа: {ex.Message}");
            return null;
        }
    }

    Console.WriteLine("✓ Устройство подтверждено.");
    return masterKey;
}

static string ReadPassword()
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

static string? AskPasswordOrFail()
{
    Console.Write("Введите пароль для расшифровки: ");
    string? password = ReadPassword();
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine("ОШИБКА: неверный пароль.");
        return null;
    }
    return password;
}

static void DoDecrypt(string filePath, string password, byte[] masterKey)
{
    string outputFile = Path.ChangeExtension(filePath, null);
    try
    {
        byte[] masterKeyHash = SHA256.HashData(masterKey);
        CryptoModule.Decrypt(filePath, outputFile, password, masterKeyHash);
        Console.WriteLine($"✓ Файл успешно расшифрован: {outputFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"ОШИБКА расшифровки: {ex.Message}");
    }
}

static string? CleanPath(string? input)
{
    if (string.IsNullOrEmpty(input))
        return input;

    input = input.Trim();

    if ((input.StartsWith("\"") && input.EndsWith("\"")) ||
        (input.StartsWith("'") && input.EndsWith("'")))
    {
        input = input.Substring(1, input.Length - 2);
    }

    return input;
}