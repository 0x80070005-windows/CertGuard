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

        // Публичный сертификат — на флешку
        string publicCertPath = Path.Combine(publicCertDir, "certificate.cer");
        File.WriteAllBytes(publicCertPath, cert.Export(X509ContentType.Cert));

        // Приватный ключ — PFX в защищённую директорию
        string pfxPath = Path.Combine(privateDir, "certguard.pfx");
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

        // Резервный мастер-ключ (32 случайных байта)
        byte[] backupKey = RandomNumberGenerator.GetBytes(32);
        string backupKeyHex = Convert.ToHexString(backupKey);
        CryptographicOperations.ZeroMemory(backupKey);

        return (publicCertPath, pfxPath, backupKeyHex);
    }
}