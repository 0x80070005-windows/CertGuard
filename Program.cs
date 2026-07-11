using System;
using System.IO;
using FileCrypto;
using init;
using DeviceAuthentication1;   // ← пространство имён, где лежит CertAutDevice

init.init.master_init();

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

    if (!CheckDeviceOrFail())
        return;

    string? password = AskPasswordOrFail();
    if (password == null)
        return;

    DoDecrypt(filePath, password);

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
    // Если хотите проверять устройство и при шифровании – раскомментируйте:
    // if (!CheckDeviceOrFail()) return;

    Console.Write("Введите путь к файлу для шифрования: ");
    string? inputFile = Console.ReadLine();
    inputFile = CleanPath(inputFile);

    if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
    {
        Console.WriteLine("Файл не найден.");
        return;
    }

    Console.Write("Введите пароль: ");
    string? password = Console.ReadLine();
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine("Пароль не может быть пустым.");
        return;
    }

    string encryptedFile = inputFile + ".enc";
    try
    {
        CryptoModule.Encrypt(inputFile, encryptedFile, password);
        Console.WriteLine($"Файл зашифрован: {encryptedFile}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Ошибка шифрования: {ex.Message}");
    }
}

static void DecryptFile()
{
    if (!CheckDeviceOrFail())
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

    DoDecrypt(inputFile, password);
}

// ===================== Общие вспомогательные методы =====================

static bool CheckDeviceOrFail()
{
    Console.WriteLine("Проверка устройства подтверждения...");

    bool ok;
    try
    {
        // ИСПРАВЛЕНО: вызываем правильный метод CAD()
        ok = CertAutDevice.CAD();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"ОШИБКА проверки устройства: {ex.Message}");
        ok = false;
    }

    if (!ok)
    {
        Console.WriteLine("ДОСТУП ЗАПРЕЩЁН: устройство подтверждения не найдено или не прошло проверку.");
        return false;
    }

    Console.WriteLine("Устройство подтверждено.");
    return true;
}

static string? AskPasswordOrFail()
{
    Console.Write("Введите пароль для расшифровки: ");
    string? password = Console.ReadLine();

    //| password != "Treecode1
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine("ОШИБКА: неверный пароль.");
        return null;
    }

    return password;
}

static void DoDecrypt(string filePath, string password)
{
    string outputFile = Path.ChangeExtension(filePath, null);
    try
    {
        CryptoModule.Decrypt(filePath, outputFile, password);
        Console.WriteLine($"Файл успешно расшифрован: {outputFile}");
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