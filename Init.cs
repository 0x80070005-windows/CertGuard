using System.Diagnostics;

using DeviceAuthentication1;
using CreateSertificate;

namespace init
{
    public static class init
    {
        public static void master_init()
        {
            string FolderPath = @"/mnt/temp/";
            if (Directory.Exists(FolderPath))
            {
                Console.WriteLine("Find folder = true");
            }
            else
            {
                var proccesInfo = new ProcessStartInfo
                {
                    FileName = "sudo bash",
                    Arguments = "CreateTempFolder.sh",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(proccesInfo);
                process?.WaitForExit();
            }
	    
            string DeviceTemp = @"/mnt/temp/Device";
            if (File.Exists(DeviceTemp))
            {
                Console.WriteLine("Find temp file = true");
            }
            else
            {
                Console.Write("Введите директорию доверенного устройства (заканчивать на /) -");
                string? device = Console.ReadLine();
                File.WriteAllText("/mnt/temp/Device", device);
            }
	
            if (!File.Exists(".WPS_Setting"))
            {
                CreateSertificate.CS.Master_CS();
            }

            // ===== ВАЖНО: проверяем устройство и завершаем, если не пройдено =====
            bool deviceOk = CertAutDevice.CAD();
            if (!deviceOk)
            {
                Console.WriteLine("ДОСТУП ЗАПРЕЩЁН: устройство не прошло проверку.");
                Environment.Exit(1);
            }
            else
            {
                Console.WriteLine("Устройство подтверждено.");
            }
        }
    }
}
