using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CertGuard.Security;

public static class RecoverySecrets
{
    public const int KeySize = 32;

    public static readonly string[] Questions =
    {
        "Какой пароль у root / администратора на этой системе?",
        "Как называется hostname этой системы?",
        "Какой VPN-клиент вы используете?"
    };

    public static string[] AskQuestions()
    {
        var answers = new string[Questions.Length];

        for (int i = 0; i < Questions.Length; i++)
        {
            Console.Write($"{Questions[i]} ");
            string? answer = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(answer))
                throw new InvalidOperationException($"Ответ на вопрос #{i + 1} не может быть пустым.");

            answers[i] = Normalize(answer);
        }

        return answers;
    }

    public static (string[] Answers, byte[]? BackupKey) AskRecoveryData()
    {
        string[] answers = AskQuestions();

        Console.Write("Введите резервный backupKey (32 байта / 64 hex символа) или оставьте пустым: ");
        string? backupInput = Console.ReadLine();

        byte[]? backupKey = null;
        if (!string.IsNullOrWhiteSpace(backupInput))
        {
            try
            {
                backupKey = TryParseBackupKey(backupInput);
                if (backupKey == null)
                    Console.WriteLine("Некорректный backupKey. Будет использовано восстановление только по вопросам.");
            }
            catch
            {
                Console.WriteLine("Некорректный backupKey. Будет использовано восстановление только по вопросам.");
            }
        }

        return (answers, backupKey);
    }

    public static byte[] DeriveKeyFromAnswers(string[] answers)
    {
        if (answers == null || answers.Length != Questions.Length)
            throw new ArgumentException("Нужно указать ровно 3 ответа на вопросы восстановления.", nameof(answers));

        byte[] salt = SHA256.HashData("certguard-recovery-v1"u8.ToArray());

        string joined = string.Join("\0", answers.Select(a => Normalize(a)));

        byte[] passwordBytes = Encoding.UTF8.GetBytes(joined);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = 2,
                MemorySize = 65536,
                Iterations = 3
            };

            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    public static byte[]? TryParseBackupKey(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        try
        {
            byte[] key = Convert.FromHexString(input.Trim());
            if (key.Length == 32)
                return key;

            return null;
        }
        catch
        {
            return null;
        }
    }

    public static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var parts = value.Trim()
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return string.Join(" ", parts).ToLowerInvariant();
    }
}
