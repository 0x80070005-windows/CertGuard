using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CertGuard.Init;

namespace DeviceAuthentication1
{
    public static class CertAutDevice
    {
        private const int HalfKeySize = 16;
        private const int SaltSize = 16;
        private const int HmacSize = 32;
        private const int MasterKeySize = 32;

        private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static byte[]? GetMasterKey()
        {
            const string CertFileName = "certificate.cer";
            string SettingsFile = Initializer.GetSettingsFile();

            string DevicePathFile = IsWindows ? @"C:\Temp\CertGuard\Device" : "/mnt/temp/Device";
            string CertSystem = IsWindows
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                              "CertGuard", "meta.dbnew")
                : "/home/" + Environment.UserName + "/.local/share/nautilus/tags/meta.dbnew";

            try
            {
                // 1. Проверяем эталонный хеш
                if (!File.Exists(SettingsFile))
                    return null;
                string expectedHash = File.ReadAllText(SettingsFile).Trim();

                // 2. Читаем путь к устройству
                if (!File.Exists(DevicePathFile))
                    return null;
                string devicePath = File.ReadAllText(DevicePathFile).Trim();
                if (string.IsNullOrEmpty(devicePath))
                    return null;

                string deviceCertPath = Path.Combine(devicePath, CertFileName);
                if (!File.Exists(deviceCertPath))
                    return null;

                // 3. Читаем данные с флешки (часть1 + соль1 + HMAC1)
                byte[] deviceData = File.ReadAllBytes(deviceCertPath);
                if (deviceData.Length != HalfKeySize + SaltSize + HmacSize)
                    return null;

                byte[] part1 = new byte[HalfKeySize];
                byte[] salt1 = new byte[SaltSize];
                byte[] hmac1 = new byte[HmacSize];
                Buffer.BlockCopy(deviceData, 0, part1, 0, HalfKeySize);
                Buffer.BlockCopy(deviceData, HalfKeySize, salt1, 0, SaltSize);
                Buffer.BlockCopy(deviceData, HalfKeySize + SaltSize, hmac1, 0, HmacSize);

                // 4. Читаем системный файл (часть2 + соль2 + HMAC2)
                if (!File.Exists(CertSystem))
                    return null;
                byte[] systemData = File.ReadAllBytes(CertSystem);
                if (systemData.Length != HalfKeySize + SaltSize + HmacSize)
                    return null;

                byte[] part2 = new byte[HalfKeySize];
                byte[] salt2 = new byte[SaltSize];
                byte[] hmac2 = new byte[HmacSize];
                Buffer.BlockCopy(systemData, 0, part2, 0, HalfKeySize);
                Buffer.BlockCopy(systemData, HalfKeySize, salt2, 0, SaltSize);
                Buffer.BlockCopy(systemData, HalfKeySize + SaltSize, hmac2, 0, HmacSize);

                // 5. Проверяем целостность каждой части
                if (!VerifyHmac(part1, salt1, hmac1) || !VerifyHmac(part2, salt2, hmac2))
                    return null;

                // 6. Собираем мастер-ключ
                byte[] masterKey = new byte[MasterKeySize];
                Buffer.BlockCopy(part1, 0, masterKey, 0, HalfKeySize);
                Buffer.BlockCopy(part2, 0, masterKey, HalfKeySize, HalfKeySize);

                // 7. Проверяем по эталону
                byte[] hash = SHA512.HashData(masterKey);
                string actualHash = Convert.ToHexString(hash);
                if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                    return null;

                return masterKey;
            }
            catch
            {
                return null;
            }
        }

        private static bool VerifyHmac(byte[] data, byte[] salt, byte[] expectedHmac)
        {
            byte[] combined = new byte[data.Length + salt.Length];
            Buffer.BlockCopy(data, 0, combined, 0, data.Length);
            Buffer.BlockCopy(salt, 0, combined, data.Length, salt.Length);

            byte[] hmacKey = Encoding.UTF8.GetBytes("MySuperSecretHmacKeyForCertGuard");
            using (var hmac = new HMACSHA256(hmacKey))
            {
                byte[] computed = hmac.ComputeHash(combined);
                return computed.SequenceEqual(expectedHmac);
            }
        }
    }
}