using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CertGuard.Init;

namespace CreateSertificate
{
    public static class CS
    {
        private const int MasterKeySize = 32;
        private const int HalfKeySize = 16;
        private const int SaltSize = 16;
        private const int HmacSize = 32;

        private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static void Master_CS()
        {
            string settingsFile = Initializer.GetSettingsFile();
            string certDir = Initializer.GetCertificateDir();

            if (File.Exists(settingsFile))
            {
                Console.WriteLine("Ключи уже созданы. Пропускаем генерацию.");
                return;
            }

            if (!Directory.Exists(certDir))
                Directory.CreateDirectory(certDir);

            string devicePath;
            try
            {
                string deviceTempPath = IsWindows ? @"C:\Temp\CertGuard\Device" : "/mnt/temp/Device";

                if (!File.Exists(deviceTempPath))
                {
                    throw new Exception($"Файл {deviceTempPath} не найден!");
                }

                devicePath = File.ReadAllText(deviceTempPath).Trim();

                if (string.IsNullOrEmpty(devicePath))
                {
                    throw new Exception($"Файл {deviceTempPath} пуст! Напишите туда путь к флешке (например: /mnt/usb/)");
                }

                if (!devicePath.EndsWith("/") && !devicePath.EndsWith("\\"))
                {
                    throw new Exception($"Путь должен заканчиваться на / или \\. Получено: {devicePath}");
                }

                if (!Directory.Exists(devicePath))
                {
                    Console.WriteLine($"⚠ Каталог {devicePath} не найден. Попытка создать...");
                    try
                    {
                        Directory.CreateDirectory(devicePath);
                        Console.WriteLine($"✓ Каталог {devicePath} создан");
                    }
                    catch (Exception ex)
                    {
                        throw new Exception($"Не удалось создать каталог {devicePath}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Ошибка при работе с устройством: {ex.Message}");
            }

            byte[] masterKey = RandomNumberGenerator.GetBytes(MasterKeySize);
            string masterKeyHex = Convert.ToHexString(masterKey);

            byte[] part1 = new byte[HalfKeySize];
            byte[] part2 = new byte[HalfKeySize];
            Buffer.BlockCopy(masterKey, 0, part1, 0, HalfKeySize);
            Buffer.BlockCopy(masterKey, HalfKeySize, part2, 0, HalfKeySize);

            byte[] salt1 = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] salt2 = RandomNumberGenerator.GetBytes(SaltSize);

            byte[] hmac1 = ComputeHmac(part1, salt1);
            byte[] hmac2 = ComputeHmac(part2, salt2);

            string deviceCertPath = Path.Combine(devicePath, "certificate.cer");
            try
            {
                using (var fs = new FileStream(deviceCertPath, FileMode.Create))
                {
                    fs.Write(part1, 0, part1.Length);
                    fs.Write(salt1, 0, salt1.Length);
                    fs.Write(hmac1, 0, hmac1.Length);
                }
                Console.WriteLine($"✓ Часть 1 сертификата записана: {deviceCertPath}");
            }
            catch (Exception ex)
            {
                throw new Exception($"Не удалось записать сертификат на флешку ({deviceCertPath}): {ex.Message}");
            }

            string systemDir = IsWindows
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CertGuard")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                              ".local/share/nautilus/tags");

            string systemCertPath = Path.Combine(systemDir, "meta.dbnew");

            try
            {
                if (!Directory.Exists(systemDir))
                {
                    Console.WriteLine($"⚠ Каталог {systemDir} не найден. Создание...");
                    Directory.CreateDirectory(systemDir);
                    Console.WriteLine($"✓ Каталог {systemDir} создан");
                }

                using (var fs = new FileStream(systemCertPath, FileMode.Create))
                {
                    fs.Write(part2, 0, part2.Length);
                    fs.Write(salt2, 0, salt2.Length);
                    fs.Write(hmac2, 0, hmac2.Length);
                }
                Console.WriteLine($"✓ Часть 2 сертификата записана: {systemCertPath}");
            }
            catch (Exception ex)
            {
                throw new Exception($"Не удалось записать системный сертификат ({systemCertPath}): {ex.Message}");
            }

            byte[] hash = SHA512.HashData(masterKey);
            string finalHash = Convert.ToHexString(hash);
            try
            {
                File.WriteAllText(settingsFile, finalHash);
                Console.WriteLine($"✓ Эталонный хеш записан: {settingsFile}");
            }
            catch (Exception ex)
            {
                throw new Exception($"Не удалось записать {settingsFile}: {ex.Message}");
            }

            Console.WriteLine("==================================================");
            Console.WriteLine("✓ СЕРТИФИКАТЫ УСПЕШНО СОЗДАНЫ!");
            Console.WriteLine("==================================================");
            Console.WriteLine("📁 Файлы:");
            Console.WriteLine($"   Флешка:  {deviceCertPath}");
            Console.WriteLine($"   Система: {systemCertPath}");
            Console.WriteLine($"   Хеш:     {settingsFile}");
            Console.WriteLine("==================================================");
            Console.WriteLine("⚠️  СОХРАНИТЕ ЭТОТ КЛЮЧ В НАДЁЖНОМ МЕСТЕ!");
            Console.WriteLine($"Резервный мастер-ключ: {masterKeyHex}");
            Console.WriteLine("==================================================");
        }

        private static byte[] ComputeHmac(byte[] data, byte[] salt)
        {
            byte[] combined = new byte[data.Length + salt.Length];
            Buffer.BlockCopy(data, 0, combined, 0, data.Length);
            Buffer.BlockCopy(salt, 0, combined, data.Length, salt.Length);

            byte[] hmacKey = Encoding.UTF8.GetBytes("MySuperSecretHmacKeyForCertGuard");
            using (var hmac = new HMACSHA256(hmacKey))
            {
                return hmac.ComputeHash(combined);
            }
        }
    }
}