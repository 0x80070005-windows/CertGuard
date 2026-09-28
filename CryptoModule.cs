using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertGuard.Security;
using Konscious.Security.Cryptography;

namespace FileCrypto;

/// <summary>
/// Гибридная схема шифрования файлов:
///   DEK = random(32)
///   pwdKey = Argon2id(password, salt)
///   wrappedByCert = RSA-OAEP-SHA256(DEK, cert.PublicKey)
///   wrappedKeyEnc = AES-GCM(pwdKey, wrappedByCert)
///   backupCipher  = AES-GCM(backupKey, DEK)   // для резервного пути
///   чанки: AES-GCM(DEK, plaintext, AAD=header+index)
/// </summary>
public static class CryptoModule
{
    private const int KeySize = 32;
    private const int SaltSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int ChunkSize = 450 * 1024 * 1024;
    private const int BackupWrappedSize = KeySize;
    private const byte Version = 1;

    private static readonly byte[] Magic = "CGRD"u8.ToArray();

    // Argon2id — OWASP recommended
    private const int Argon2MemoryKiB = 65536;   // 64 MiB
    private const int Argon2Iterations = 3;
    private const int Argon2Parallelism = 4;

    // ===================== ENCRYPT =====================

    public static void Encrypt(
        string inputPath,
        string outputPath,
        string password,
        X509Certificate2 cert,
        byte[] backupKey)
    {
        if (cert is null)
            throw new ArgumentNullException(nameof(cert));

        if (backupKey is null || backupKey.Length != KeySize)
            throw new ArgumentException("Резервный ключ должен быть 32 байта.", nameof(backupKey));

        byte[] dek = RandomNumberGenerator.GetBytes(KeySize);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] noncePwd = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] pwdKey = DeriveKey(password, salt);

        try
        {
            // 1. Заворачиваем DEK публичным ключом сертификата
            byte[] wrappedByCert = CertificateService.WrapKey(dek, cert);

            // 2. Дополнительно шифруем это парольным ключом (AES-GCM)
            byte[] tagPwd = new byte[TagSize];
            byte[] wrappedKeyEnc = new byte[wrappedByCert.Length];

            try
            {
                using var aesPwd = new AesGcm(pwdKey, TagSize);
                aesPwd.Encrypt(noncePwd, wrappedByCert, wrappedKeyEnc, tagPwd);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrappedByCert);
            }

            // 3. Параллельно заворачиваем DEK резервным ключом
            byte[] backupNonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] backupTag = new byte[TagSize];
            byte[] backupCipher = new byte[BackupWrappedSize];

            using (var aesBackup = new AesGcm(backupKey, TagSize))
            {
                aesBackup.Encrypt(backupNonce, dek, backupCipher, backupTag);
            }

            byte[] baseNonce = RandomNumberGenerator.GetBytes(NonceSize);

            long totalSize = new FileInfo(inputPath).Length;
            ulong chunkCount = totalSize == 0
                ? 1
                : (ulong)((totalSize + ChunkSize - 1) / ChunkSize);

            byte[] header = BuildHeader(
                salt, noncePwd, tagPwd, wrappedKeyEnc,
                backupNonce, backupTag, backupCipher,
                baseNonce, chunkCount);

            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);

            output.Write(header);

            using var aes = new AesGcm(dek, TagSize);
            byte[] buffer = new byte[ChunkSize];
            ulong index = 0;
            int bytesRead;
            bool wroteAny = false;

            while ((bytesRead = ReadFull(input, buffer)) > 0)
            {
                wroteAny = true;
                EncryptChunk(aes, baseNonce, index, header,
                    buffer.AsSpan(0, bytesRead), output);
                index++;
            }

            if (!wroteAny)
                EncryptChunk(aes, baseNonce, 0, header,
                    ReadOnlySpan<byte>.Empty, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(pwdKey);
        }
    }

    // ===================== DECRYPT через сертификат =====================

    public static void Decrypt(
        string inputPath,
        string outputPath,
        string password,
        X509Certificate2 cert)
    {
        if (cert is null)
            throw new ArgumentNullException(nameof(cert));

        using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Header h = ReadHeader(input);

        byte[] pwdKey = DeriveKey(password, h.Salt);
        byte[] wrappedByCert = new byte[h.WrappedKeyEnc.Length];
        byte[] dek;

        try
        {
            try
            {
                using var aesPwd = new AesGcm(pwdKey, TagSize);
                aesPwd.Decrypt(h.NoncePwd, h.WrappedKeyEnc, h.TagPwd, wrappedByCert);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Неверный пароль.");
            }

            try
            {
                dek = CertificateService.UnwrapKey(wrappedByCert, cert);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Сертификат не подходит к этому файлу.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdKey);
            CryptographicOperations.ZeroMemory(wrappedByCert);
        }

        DecryptBody(input, outputPath, h, dek);
    }

    // ===================== DECRYPT через резервный ключ =====================

    public static void DecryptWithBackupKey(
        string inputPath,
        string outputPath,
        byte[] backupKey)
    {
        if (backupKey is null || backupKey.Length != KeySize)
            throw new ArgumentException("Резервный ключ должен быть 32 байта.", nameof(backupKey));

        using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Header h = ReadHeader(input);

        byte[] dek = new byte[BackupWrappedSize];

        try
        {
            using var aesBackup = new AesGcm(backupKey, TagSize);
            aesBackup.Decrypt(h.BackupNonce, h.BackupCipher, h.BackupTag, dek);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new CryptographicException("Неверный резервный ключ или файл повреждён.");
        }

        DecryptBody(input, outputPath, h, dek);
    }

    // ===================== Общая часть расшифровки =====================

    private static void DecryptBody(
        FileStream input,
        string outputPath,
        Header h,
        byte[] dek)
    {
        try
        {
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var aes = new AesGcm(dek, TagSize);

            byte[] lenBuf = new byte[4];
            byte[] tagBuf = new byte[TagSize];

            for (ulong i = 0; i < h.ChunkCount; i++)
            {
                ReadExact(input, lenBuf);
                int len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);

                if (len < 0 || len > ChunkSize)
                    throw new CryptographicException("Повреждённый формат файла.");

                ReadExact(input, tagBuf);

                byte[] ciphertext = new byte[len];
                ReadExact(input, ciphertext);

                byte[] nonce = MakeChunkNonce(h.BaseNonce, i);
                byte[] aad = BuildChunkAad(h.RawHeader, i);
                byte[] plaintext = new byte[len];

                try
                {
                    aes.Decrypt(nonce, ciphertext, tagBuf, plaintext, aad);
                }
                catch (CryptographicException)
                {
                    throw new CryptographicException(
                        $"Чанк #{i}: аутентификация не пройдена (файл повреждён или подменён).");
                }

                output.Write(plaintext);
            }

            if (input.Position != input.Length)
                throw new CryptographicException("В файле есть лишние данные после последнего чанка.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    // ===================== Заголовок =====================

    private sealed class Header
    {
        public byte[] RawHeader = null!;
        public byte[] Salt = null!;
        public byte[] NoncePwd = null!;
        public byte[] TagPwd = null!;
        public byte[] WrappedKeyEnc = null!;
        public byte[] BackupNonce = null!;
        public byte[] BackupTag = null!;
        public byte[] BackupCipher = null!;
        public byte[] BaseNonce = null!;
        public ulong ChunkCount;
    }

    private static byte[] BuildHeader(
        byte[] salt, byte[] noncePwd, byte[] tagPwd, byte[] wrappedKeyEnc,
        byte[] backupNonce, byte[] backupTag, byte[] backupCipher,
        byte[] baseNonce, ulong chunkCount)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(Magic);
            bw.Write(Version);
            bw.Write(salt);
            bw.Write(noncePwd);
            bw.Write(tagPwd);
            bw.Write(wrappedKeyEnc.Length);
            bw.Write(wrappedKeyEnc);
            bw.Write(backupNonce);
            bw.Write(backupTag);
            bw.Write(backupCipher);
            bw.Write(baseNonce);
            bw.Write(ChunkSize);
            bw.Write(chunkCount);
        }
        return ms.ToArray();
    }

    private static Header ReadHeader(FileStream input)
    {
        byte[] magic = new byte[4];
        ReadExact(input, magic);

        if (!CryptographicOperations.FixedTimeEquals(magic, Magic))
            throw new CryptographicException("Неверный формат файла (нет сигнатуры CGRD).");

        int versionByte = input.ReadByte();
        if (versionByte < 0)
            throw new CryptographicException("Неожиданный конец файла.");
        if ((byte)versionByte != Version)
            throw new CryptographicException($"Неподдерживаемая версия формата: {versionByte}.");

        var h = new Header();

        h.Salt = new byte[SaltSize];
        ReadExact(input, h.Salt);

        h.NoncePwd = new byte[NonceSize];
        ReadExact(input, h.NoncePwd);

        h.TagPwd = new byte[TagSize];
        ReadExact(input, h.TagPwd);

        byte[] lenBuf = new byte[4];
        ReadExact(input, lenBuf);
        int wrappedLen = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
        if (wrappedLen <= 0 || wrappedLen > 8192)
            throw new CryptographicException("Повреждён заголовок.");

        h.WrappedKeyEnc = new byte[wrappedLen];
        ReadExact(input, h.WrappedKeyEnc);

        h.BackupNonce = new byte[NonceSize];
        ReadExact(input, h.BackupNonce);

        h.BackupTag = new byte[TagSize];
        ReadExact(input, h.BackupTag);

        h.BackupCipher = new byte[BackupWrappedSize];
        ReadExact(input, h.BackupCipher);

        h.BaseNonce = new byte[NonceSize];
        ReadExact(input, h.BaseNonce);

        byte[] chunkSizeBuf = new byte[4];
        ReadExact(input, chunkSizeBuf);
        int chunkSize = BinaryPrimitives.ReadInt32LittleEndian(chunkSizeBuf);
        if (chunkSize <= 0 || chunkSize > ChunkSize)
            throw new CryptographicException("Повреждён размер чанка.");

        byte[] chunkCountBuf = new byte[8];
        ReadExact(input, chunkCountBuf);
        h.ChunkCount = BinaryPrimitives.ReadUInt64LittleEndian(chunkCountBuf);

        h.RawHeader = BuildHeader(
            h.Salt, h.NoncePwd, h.TagPwd, h.WrappedKeyEnc,
            h.BackupNonce, h.BackupTag, h.BackupCipher,
            h.BaseNonce, h.ChunkCount);

        return h;
    }

    // ===================== Вспомогательные =====================

    private static void EncryptChunk(
        AesGcm aes, byte[] baseNonce, ulong chunkIndex, byte[] header,
        ReadOnlySpan<byte> plaintext, FileStream output)
    {
        byte[] nonce = MakeChunkNonce(baseNonce, chunkIndex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        byte[] aad = BuildChunkAad(header, chunkIndex);

        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        Span<byte> lenBuf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, plaintext.Length);

        output.Write(lenBuf);
        output.Write(tag);
        output.Write(ciphertext);
    }

    private static byte[] BuildChunkAad(byte[] header, ulong chunkIndex)
    {
        byte[] aad = new byte[header.Length + 8];
        Buffer.BlockCopy(header, 0, aad, 0, header.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(aad.AsSpan(header.Length), chunkIndex);
        return aad;
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Argon2Parallelism,
                MemorySize = Argon2MemoryKiB,
                Iterations = Argon2Iterations
            };

            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] MakeChunkNonce(byte[] baseNonce, ulong chunkIndex)
    {
        byte[] nonce = (byte[])baseNonce.Clone();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(NonceSize - 8), chunkIndex);
        return nonce;
    }

    private static int ReadFull(FileStream fs, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = fs.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return totalRead;
    }

    private static void ReadExact(FileStream fs, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = fs.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read == 0)
                throw new CryptographicException("Неожиданный конец файла — файл повреждён.");
            totalRead += read;
        }
    }
}