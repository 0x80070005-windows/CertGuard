using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertGuard.Security;

public static class CertificateService
{
    private const int ChallengeSize = 32;

    public static X509Certificate2 LoadPublicCertificate(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Публичный сертификат не найден.", path);

        var cert = X509CertificateLoader.LoadCertificateFromFile(path);

        DateTime now = DateTime.Now;
        if (now < cert.NotBefore || now > cert.NotAfter)
        {
            cert.Dispose();
            throw new CryptographicException("Сертификат недействителен по сроку.");
        }

        return cert;
    }

    public static X509Certificate2 LoadPrivateCertificate(string pfxPath, string pfxPassword)
    {
        if (!File.Exists(pfxPath))
            throw new CryptographicException("Приватный сертификат (PFX) не найден.");

        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            pfxPath,
            pfxPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        if (!cert.HasPrivateKey)
        {
            cert.Dispose();
            throw new CryptographicException("В PFX отсутствует приватный ключ.");
        }

        return cert;
    }

    public static bool ThumbprintsMatch(X509Certificate2 a, X509Certificate2 b)
    {
        byte[] ta = Convert.FromHexString(a.Thumbprint);
        byte[] tb = Convert.FromHexString(b.Thumbprint);

        if (ta.Length != tb.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(ta, tb);
    }

    public static byte[] WrapKey(byte[] dek, X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey()
            ?? throw new CryptographicException("Сертификат не содержит RSA public key.");

        return rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] UnwrapKey(byte[] wrapped, X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPrivateKey()
            ?? throw new CryptographicException("Нет RSA private key.");

        return rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
    }

    public static bool VerifyChallengeResponse(
        X509Certificate2 publicCert,
        X509Certificate2 privateCert)
    {
        byte[] challenge = RandomNumberGenerator.GetBytes(ChallengeSize);

        byte[] signature;
        using (var rsaPriv = privateCert.GetRSAPrivateKey()
            ?? throw new CryptographicException("Нет RSA private key."))
        {
            signature = rsaPriv.SignData(
                challenge,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }

        using var rsaPub = publicCert.GetRSAPublicKey()
            ?? throw new CryptographicException("Сертификат не содержит RSA public key.");

        return rsaPub.VerifyData(
            challenge,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
    }
}