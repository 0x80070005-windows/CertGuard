using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DeviceAuthentication1;
using CreateSertificate;

namespace CertGuard.Init
{
    public static class Initializer
    {
        private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        private static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static string GetCertificateDir()
        {
            string certDir = IsWindows
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CertGuard")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".CertGuard");

            return certDir;
        }

        public static string GetSettingsFile()
        {
            return Path.Combine(GetCertificateDir(), ".WPS_Setting");
        }

        public static void master_init()
        {
            try
            {
                string certDir = GetCertificateDir();
                if (!Directory.Exists(certDir))
                {
                    Directory.CreateDirectory(certDir);
                    Console.WriteLine($"Директория создана: {certDir}");
                }

                string FolderPath = IsWindows ? @"C:\Temp\CertGuard\" : @"/mnt/temp/";
                
                if (Directory.Exists(FolderPath))
                {
                    Console.WriteLine("Find folder = true");
                }
                else
                {
                    if (IsLinux)
                    {
                        var processInfo = new ProcessStartInfo
                        {
                            FileName = "/bin/bash",
                            Arguments = "-c \"sudo mkdir -p " + FolderPath + "\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using var process = Process.Start(processInfo);
                        process?.WaitForExit();
                    }
                    else if (IsWindows)
                    {
                        Directory.CreateDirectory(FolderPath);
                    }
                }

                string DeviceTemp = Path.Combine(FolderPath, "Device");
                
                if (File.Exists(DeviceTemp))
                {
                    Console.WriteLine("Find temp file = true");
                }
                else
                {
                    Console.Write("Введите директорию доверенного устройства (заканчивать на / или \\) - ");
                    string? device = Console.ReadLine();
                    File.WriteAllText(DeviceTemp, device);
                }

                if (!File.Exists(GetSettingsFile()))
                {
                    try
                    {
                        CreateSertificate.CS.Master_CS();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Ошибка создания сертификатов: {ex.Message}");
                        Console.WriteLine("Устройство не прошло проверку (ошибка записи на флешку или в системный каталог).");
                        Environment.Exit(1);
                    }
                }

                bool deviceOk = CertAutDevice.GetMasterKey() != null;
                if (deviceOk)
                {
                    Console.WriteLine("✓ Устройство подтверждено.");
                }
                else
                {
                    Console.WriteLine("⚠ ВНИМАНИЕ: Доверенное устройство не найдено.");
                    Console.WriteLine("  Вы сможете использовать программу с резервным ключом.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Критическая ошибка инициализации: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}