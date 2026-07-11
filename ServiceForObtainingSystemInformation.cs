using System;
using System.Diagnostics;
using System.IO;

namespace CertGuard.Services
{
    public static class SystemInfoService
    {
        /// <summary>
        /// Выполняет bash-команду и возвращает stdout или бросает исключение при ошибке.
        /// </summary>
        private static string ExecuteBashCommand(string command)
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"{command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

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

        /// <summary>
        /// Сохраняет информацию о процессоре (из /proc/cpuinfo) в файл "cpuinfo" в текущей директории.
        /// </summary>
        public static void SaveCpuInfo()
        {
            string result = ExecuteBashCommand("cat /proc/cpuinfo");
            File.WriteAllText("cpuinfo", result);
            //Console.WriteLine("Информация о процессоре сохранена в cpuinfo");
        }

        /// <summary>
        /// Сохраняет информацию о памяти (из /proc/meminfo) в файл "meminfo" в текущей директории.
        /// </summary>
        public static void SaveMemInfo()
        {
            string result = ExecuteBashCommand("cat /proc/meminfo");
            File.WriteAllText("meminfo", result);
            //Console.WriteLine("Информация о памяти сохранена в meminfo");
        }

        /// <summary>
        /// Сохраняет информацию о дисках (вывод df) в файл "diskusage" в текущей директории.
        /// </summary>
        public static void SaveDiskUsage()
        {
            string result = ExecuteBashCommand("df -h");
            File.WriteAllText("diskusage", result);
           // Console.WriteLine("Информация о дисках сохранена в diskusage");
        }

        /// <summary>
        /// Сохраняет всю информацию (процессор, память, диски) одной командой.
        /// </summary>
        public static void SaveAllSystemInfo()
        {
            SaveCpuInfo();
            SaveMemInfo();
            SaveDiskUsage();
        }
    }
}