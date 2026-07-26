using System;
using System.IO;
using System.Security.Cryptography;

namespace FileCrypto
{
    public static class CryptoModule
    {
        const int ChunkSize = 450 * 1024 * 1024;
        const int SaltSize = 32;
        const int NonceSize = 12;
        const int TagSize = 16;
        const int KeyHashSize = 32;

        public static void Encrypt(string inputPath, string outputPath, string password, byte[] masterKeyHash)
        {
            if (masterKeyHash.Length != KeyHashSize)
                throw new ArgumentException("Хеш мастер-ключа должен быть 32 байта");

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] baseNonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] key = DeriveKey(password, salt);

            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            // Пишем хеш мастер-ключа (32 байта)
            output.Write(masterKeyHash, 0, KeyHashSize);

            long totalSize = input.Length;
            ulong chunkCount = totalSize == 0 ? 1 : (ulong)((totalSize + ChunkSize - 1) / ChunkSize);

            output.Write(salt);
            output.Write(baseNonce);
            output.Write(BitConverter.GetBytes(chunkCount));

            byte[] buffer = new byte[ChunkSize];
            using var aesGcm = new AesGcm(key, TagSize);

            ulong index = 0;
            int bytesRead;
            bool wroteAny = false;

            while ((bytesRead = ReadFull(input, buffer)) > 0)
            {
                wroteAny = true;
                EncryptChunk(aesGcm, baseNonce, index, buffer.AsSpan(0, bytesRead), output);
                index++;
            }

            if (!wroteAny)
                EncryptChunk(aesGcm, baseNonce, 0, ReadOnlySpan<byte>.Empty, output);
        }

        static void EncryptChunk(AesGcm aesGcm, byte[] baseNonce, ulong chunkIndex,
                                  ReadOnlySpan<byte> plaintext, FileStream output)
        {
            byte[] nonce = MakeChunkNonce(baseNonce, chunkIndex);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];

            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            output.Write(BitConverter.GetBytes(plaintext.Length));
            output.Write(tag);
            output.Write(ciphertext);
        }

        public static void Decrypt(string inputPath, string outputPath, string password, byte[] expectedMasterKeyHash)
        {
            if (expectedMasterKeyHash.Length != KeyHashSize)
                throw new ArgumentException("Ожидаемый хеш мастер-ключа должен быть 32 байта");

            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);

            // Читаем сохранённый хеш мастер-ключа
            byte[] storedHash = new byte[KeyHashSize];
            ReadExact(input, storedHash);

            if (!storedHash.SequenceEqual(expectedMasterKeyHash))
                throw new CryptographicException("Мастер-ключ не соответствует файлу.");

            byte[] salt = new byte[SaltSize];
            byte[] baseNonce = new byte[NonceSize];
            byte[] chunkCountBytes = new byte[8];

            ReadExact(input, salt);
            ReadExact(input, baseNonce);
            ReadExact(input, chunkCountBytes);
            ulong chunkCount = BitConverter.ToUInt64(chunkCountBytes);

            byte[] key = DeriveKey(password, salt);
            using var aesGcm = new AesGcm(key, TagSize);

            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            byte[] lenBuf = new byte[4];
            byte[] tagBuf = new byte[TagSize];
            byte[] cipherBuf = new byte[ChunkSize];

            for (ulong i = 0; i < chunkCount; i++)
            {
                ReadExact(input, lenBuf);
                int len = BitConverter.ToInt32(lenBuf);

                if (len < 0 || len > ChunkSize)
                    throw new CryptographicException("Повреждённый формат файла.");

                ReadExact(input, tagBuf);

                Span<byte> cipherSpan = cipherBuf.AsSpan(0, len);
                ReadExact(input, cipherSpan);

                byte[] nonce = MakeChunkNonce(baseNonce, i);
                byte[] plaintext = new byte[len];

                aesGcm.Decrypt(nonce, cipherSpan, tagBuf, plaintext);

                output.Write(plaintext);
            }
        }

        static byte[] DeriveKey(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        }

        static byte[] MakeChunkNonce(byte[] baseNonce, ulong chunkIndex)
        {
            byte[] nonce = (byte[])baseNonce.Clone();
            byte[] counterBytes = BitConverter.GetBytes(chunkIndex);
            int offset = NonceSize - 8;
            if (offset < 0) offset = 0;
            Buffer.BlockCopy(counterBytes, 0, nonce, offset, Math.Min(8, NonceSize));
            return nonce;
        }

        static int ReadFull(FileStream fs, byte[] buffer)
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

        static void ReadExact(FileStream fs, byte[] buffer)
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

        static void ReadExact(FileStream fs, Span<byte> buffer)
        {
            int totalRead = 0;
            while (totalRead < buffer.Length)
            {
                int read = fs.Read(buffer.Slice(totalRead));
                if (read == 0)
                    throw new CryptographicException("Неожиданный конец файла — файл повреждён.");
                totalRead += read;
            }
        }
    }
}