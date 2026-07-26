using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace CertGuard.Services
{
    public static class SystemInfoService
    {
        private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        private static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        private static string ExecuteCommand(string command)
        {
            ProcessStartInfo processInfo;

            if (IsLinux)
            {
                processInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else if (IsWindows)
            {
                processInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else
            {
                throw new PlatformNotSupportedException("Неподдерживаемая ОС");
            }

            using var process = Process.Start(processInfo);
            if (process == null)
                throw new InvalidOperationException("Не удалось запустить процесс.");

            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
                throw new Exception($"Команда завершилась с ошибкой (код {process.ExitCode}):\n{error}");

            return output;
        }

        public static void SaveCpuInfo()
        {
            string result;
            if (IsLinux)
                result = ExecuteCommand("cat /proc/cpuinfo");
            else if (IsWindows)
                result = ExecuteCommand("Get-WmiObject Win32_Processor | Format-List");
            else
                throw new PlatformNotSupportedException("Неподдерживаемая ОС");

            File.WriteAllText("cpuinfo", result);
        }

        public static void SaveMemInfo()
        {
            string result;
            if (IsLinux)
                result = ExecuteCommand("cat /proc/meminfo");
            else if (IsWindows)
                result = ExecuteCommand("Get-WmiObject Win32_PhysicalMemory | Format-List");
            else
                throw new PlatformNotSupportedException("Неподдерживаемая ОС");

            File.WriteAllText("meminfo", result);
        }

        public static void SaveDiskUsage()
        {
            string result;
            if (IsLinux)
                result = ExecuteCommand("df -h");
            else if (IsWindows)
                result = ExecuteCommand("Get-Volume | Format-List");
            else
                throw new PlatformNotSupportedException("Неподдерживаемая ОС");

            File.WriteAllText("diskusage", result);
        }

        public static void SaveAllSystemInfo()
        {
            SaveCpuInfo();
            SaveMemInfo();
            SaveDiskUsage();
        }
    }
}