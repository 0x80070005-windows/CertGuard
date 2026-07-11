using System.Security.Cryptography;
using System.Text;
using CertGuard.Services;

namespace DeviceAuthentication1
{
    public static class CertAutDevice
    {
        public static bool CAD()
        {
            const string DevicePathFile = "/mnt/temp/Device";
            const string CertFileName = "certificate.cer";
            const string CertSystem = "/home/kirill/.local/share/nautilus/tags/meta.dbnew";
            const string SettingsFile = ".WPS_Setting";

            try
            {
                // 1. Проверяем существование настроечного файла
                if (!File.Exists(SettingsFile))
                {
                    return false;
                }

                string expectedHash = File.ReadAllText(SettingsFile).Trim();
                //Console.WriteLine($"[ОТЛАДКА] Ожидаемый хеш (из .WPS_Setting): {expectedHash}");

                // 2. Читаем путь к устройству
                if (!File.Exists(DevicePathFile))
                {
                    //Console.WriteLine("[ОТЛАДКА] Файл пути устройства не найден: " + DevicePathFile);
                    return false;
                }

                string devicePath = File.ReadAllText(DevicePathFile).Trim();
                if (string.IsNullOrEmpty(devicePath))
                {
                    //Console.WriteLine("[ОТЛАДКА] Путь устройства пуст.");
                    return false;
                }
                //Console.WriteLine($"[ОТЛАДКА] Путь к устройству из {DevicePathFile}: {devicePath}");

                // 3. Формируем полный путь к сертификату устройства
                string deviceCertPath = Path.Combine(devicePath, CertFileName);
                //Console.WriteLine($"[ОТЛАДКА] Ожидаемый путь к сертификату устройства: {deviceCertPath}");

                if (!File.Exists(deviceCertPath))
                {
                    //Console.WriteLine("[ОТЛАДКА] Сертификат устройства не найден по пути: " + deviceCertPath);
                    return false;
                }

                string deviceCert = File.ReadAllText(deviceCertPath).Trim();
                //Console.WriteLine($"[ОТЛАДКА] Содержимое сертификата устройства: '{deviceCert}'");

                // 4. Читаем системный сертификат
                if (!File.Exists(CertSystem))
                {
                    //Console.WriteLine("[ОТЛАДКА] Системный сертификат не найден: " + CertSystem);
                    return false;
                }

                string systemCert = File.ReadAllText(CertSystem).Trim();
                //Console.WriteLine($"[ОТЛАДКА] Содержимое системного сертификата: '{systemCert}'");

                // 5. Вычисляем хеш от конкатенации
                string combined = deviceCert + systemCert;
                byte[] inputBytes = Encoding.UTF8.GetBytes(combined);
                byte[] hashBytes = SHA512.HashData(inputBytes);
                string actualHash = Convert.ToHexString(hashBytes);
                //Console.WriteLine($"[ОТЛАДКА] Вычисленный хеш: {actualHash}");

                // 6. Сравниваем
                bool result = string.Equals(actualHash, expectedHash, StringComparison.Ordinal);
                //Console.WriteLine($"[ОТЛАДКА] Результат сравнения: {result}");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ОШИБКА] {ex.Message}");
                return false;
            }
        }
    }
}

namespace CreateSertificate
{
    public static class CS
    {
        public static void Master_CS()
        {
            // Сбор системной информации (метод существует)
            CertGuard.Services.SystemInfoService.SaveAllSystemInfo();

            // Читаем файлы с информацией о системе
            string cpuinfo = File.ReadAllText("cpuinfo").Trim();
            string diskusage = File.ReadAllText("diskusage").Trim();
            string meminfo = File.ReadAllText("meminfo").Trim();

            // Формируем исходную строку и вычисляем SHA-512
            string stringForHashing = cpuinfo + diskusage + meminfo;
            byte[] inputBytes = Encoding.UTF8.GetBytes(stringForHashing);
            byte[] hashBytes = SHA512.HashData(inputBytes);
            string hashString = Convert.ToHexString(hashBytes);

            // Делим хеш пополам
            int halfLength = hashString.Length / 2;
            string firstPart = hashString.Substring(0, halfLength);
            string secondPart = hashString.Substring(halfLength);

            // Записываем первую часть в сертификат устройства
            string devicePath = File.ReadAllText("/mnt/temp/Device").Trim();
            string deviceCertPath = Path.Combine(devicePath, "certificate.cer");
            File.WriteAllText(deviceCertPath, firstPart.Trim());

            // Записываем вторую часть в системный сертификат
            string systemCertPath = "/home/kirill/.local/share/nautilus/tags/meta.dbnew";
            File.WriteAllText(systemCertPath, secondPart.Trim());

            // Хешируем объединённый хеш и записываем в .WPS_Setting
            byte[] hashBytes2 = SHA512.HashData(Encoding.UTF8.GetBytes(hashString));
            string finalHash = Convert.ToHexString(hashBytes2);
            File.WriteAllText(".WPS_Setting", finalHash.Trim());

            Console.WriteLine("[УСПЕХ] Сертификаты и ключ успешно созданы.");
        }
    }
}