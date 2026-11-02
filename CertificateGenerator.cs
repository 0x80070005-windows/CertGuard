using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertGuard.Security;

public static class CertificateGenerator
{
    public static (string publicCertPath, string pfxPath, string backupKeyHex)
        GenerateAndSave(string publicCertDir, string privateDir, string pfxPassword)
    {
        if (!Directory.Exists(publicCertDir))
            Directory.CreateDirectory(publicCertDir);

        if (!Directory.Exists(privateDir))
            Directory.CreateDirectory(privateDir);

        string publicCertPath = Path.Combine(publicCertDir, "certificate.cer");
        string pfxPath = Path.Combine(privateDir, "certguard.pfx");

        // ============================================================
        // 🛑 ГЛАВНЫЙ ПРЕДОХРАНИТЕЛЬ
        // Если файлы уже есть, мы НЕ перезаписываем их, а падаем с ошибкой.
        // ============================================================
        if (File.Exists(publicCertPath) || File.Exists(pfxPath))
        {
            throw new InvalidOperationException(
                "КРИТИЧЕСКАЯ ОШИБКА: Сертификаты уже существуют! " +
                "Программа остановлена, чтобы не уничтожить ваши ключи. " +
                "Если вы действительно хотите создать новую пару ключей, " +
                "удалите старые файлы вручную.");
        }

        using var rsa = RSA.Create(4096);

        var request = new CertificateRequest(
            "CN=CertGuard Device",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        // Теперь мы точно знаем, что файлов нет, и можем их создать
        File.WriteAllBytes(publicCertPath, cert.Export(X509ContentType.Cert));
        File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pfx, pfxPassword));

        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(pfxPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { /* best effort */ }
        }

        byte[] backupKey = RandomNumberGenerator.GetBytes(32);
        string backupKeyHex = Convert.ToHexString(backupKey);
        CryptographicOperations.ZeroMemory(backupKey);

        return (publicCertPath, pfxPath, backupKeyHex);
    }
}
