using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;
using UnityEngine;

namespace Guinea.Core.DataHandler
{
    public static class Secure
    {
#if UNITY_EDITOR && GUINEA_DEVELOPMENT
        private static readonly bool s_debug = true;
#else
        private static readonly bool s_debug = false;
#endif  
        private static readonly PaddingMode s_paddingMode = PaddingMode.PKCS7;
        private static readonly int s_bufferSize = 10 * 1024; // * NOTE: Buffer Size for reading
        private static readonly string SymmetricSalt = "s"; //  !IMPORTANT:  Your salt here (please change this salt)
        #region Key Generator
        public class KeyPair
        {
            public string publicKey;
            public string privateKey;
        }

        public static KeyPair GenerateKeyPair(int size = 4096)
        {
            using (var rsa = new RSACryptoServiceProvider(size))
            {
                return new KeyPair { publicKey = rsa.ToXmlString(false), privateKey = rsa.ToXmlString(true) };
            }
        }
        #endregion

        #region Symmetric Data Encryption and Decryption
        
        #endregion

        #region Asymmetric Data Encryption and Decryption
        public static byte[] EncryptData(byte[] data, string publicKey)
        {
            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(publicKey);
                return provider.Encrypt(data, true);
            }
        }

        public static byte[] DecryptData(byte[] data, string privateKey)
        {
            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(privateKey);
                if (provider.PublicOnly)
                {
                    throw new Exception("The key provided is a public key and does not contain the private key elements required for decryption");
                }
                return provider.Decrypt(data, true);
            }
        }

        public static string EncryptString(string value, string publicKey)
        {
            return Convert.ToBase64String(EncryptData(Encoding.UTF8.GetBytes(value), publicKey));
        }

        public static string DecryptString(string value, string privateKey)
        {
            return Encoding.UTF8.GetString(DecryptData(Convert.FromBase64String(value), privateKey));
        }
        #endregion 

        #region HyBrid File Encryption and Description
        public static byte[] EncryptStringToBytes(string plainText, string publicKey)
        {
            byte[] un_encrypted = Encoding.UTF8.GetBytes(plainText);
            return EncryptBytesArray(un_encrypted, publicKey);
        }

        public static byte[] EncryptBytesArray(byte[] array, string publicKey)
        {
            using (var cypher = new AesManaged())
            {
                cypher.Padding = s_paddingMode;
                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                // Generate random key and IV for symmetric encryption
                var key = new byte[cypher.KeySize / 8];
                var iv = new byte[cypher.BlockSize / 8];

                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(key);
                rng.GetBytes(iv);

                // Encrypt the symmetric key and IV
                var buff = new byte[key.Length + iv.Length];
                Array.Copy(key, buff, key.Length);
                Array.Copy(iv, 0, buff, key.Length, iv.Length);
                buff = EncryptData(buff, publicKey);

                var buffLength = BitConverter.GetBytes(buff.Length);
                UnityEngine.Debug.Log($"Key:{ BitConverter.ToString(key)}");
                UnityEngine.Debug.Log($"IV:{ BitConverter.ToString(iv)}");
                // Logger.Log($"Data: {BitConverter.ToString(array)}");

                // Symmetric encrypt the data and write it to the file, along with the encrypted key and iv
                byte[] encrypted;
                int padding = cypher.BlockSize - (array.Length+buff.Length+2*sizeof(int)) % cypher.BlockSize;
                byte[] padding_length = BitConverter.GetBytes(padding);
                byte[] array_padding = new byte[array.Length + padding];
                // array.CopyTo(array_padding, 0);
                Array.Copy(array, array_padding, array.Length);
                using (var cypherKey = cypher.CreateEncryptor(key, iv))
                using (MemoryStream result = new MemoryStream())
                using (var cs = new CryptoStream(result, cypherKey, CryptoStreamMode.Write))
                using (MemoryStream input = new MemoryStream(array_padding)) //Todo: Check encode
                {
                    result.Write(buffLength, 0, buffLength.Length);
                    result.Write(buff, 0, buff.Length);
                    // Logger.LogIf(s_debug, $"Padding: {padding}");
                    result.Write(padding_length, 0, padding_length.Length);
                    input.CopyTo(cs, s_bufferSize);
                    // Logger.LogIf(s_debug, $"Original Length: {array.Length}");
                    cs.FlushFinalBlock();
                    encrypted = result.ToArray();
                    // Logger.LogIf(s_debug, $"Encrypted Length: {encrypted.Length}");
                    // Logger.LogIf(s_debug, $"Buff Length: {buff.Length}");
                    // Logger.LogIf(s_debug, $"A block Length: {cypher.BlockSize / 8}");
                    // Logger.Log($"Encrypted Data: {BitConverter.ToString(encrypted)}");
                }
                return encrypted;
            }
        }
     
        public static string DecryptStringFromBytes(byte[] cipherText, string privateKey)
        {
            byte[] un_encrypted = DecryptBytesFromBytes(cipherText, privateKey);
            return Encoding.UTF8.GetString(un_encrypted).Trim('\0');
        }

        public static byte[] DecryptBytesFromBytes(byte[] cipherText, string privateKey)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

            using (var cypher = new AesManaged())
            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                cypher.Padding = s_paddingMode;

                // Determine the length of the encrypted key and IV
                var buff = new byte[sizeof(int)];
                ms.Read(buff, 0, buff.Length);
                var buffLength = BitConverter.ToInt32(buff, 0);

                // Read the encrypted key and IV data from the file and decrypt using the asymmetric algorithm
                buff = new byte[buffLength];
                ms.Read(buff, 0, buff.Length);
                buff = DecryptData(buff, privateKey);
                byte[] padding_length = new byte[sizeof(int)];
                ms.Read(padding_length, 0, padding_length.Length);
                int padding = BitConverter.ToInt32(padding_length, 0);
                // Logger.LogIf(s_debug, $"Padding: {padding}");

                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                var key = new byte[cypher.KeySize / 8];
                var iv = new byte[cypher.BlockSize / 8];
                Array.Copy(buff, key, key.Length);
                Array.Copy(buff, key.Length, iv, 0, iv.Length);
                UnityEngine.Debug.Log($"Key:{ BitConverter.ToString(key)}");
                UnityEngine.Debug.Log($"IV:{ BitConverter.ToString(iv)}");

                // Decrypt the file data using the symmetric algorithm
                byte[] result = new byte[cipherText.Length - buffLength - sizeof(int) * 2];
                byte[] truncated = new byte[result.Length - padding];
                ms.Read(result, 0, result.Length);
                using (var cypherKey = cypher.CreateDecryptor(key, iv))
                using (MemoryStream ms_result = new MemoryStream())
                using (var cs = new CryptoStream(ms_result, cypherKey, CryptoStreamMode.Write))
                {
                    cs.Write(result, 0, result.Length);
                    cs.FlushFinalBlock();
                    byte[] raw = ms_result.ToArray();
                    Array.Copy(raw , truncated, Mathf.Min(truncated.Length, raw.Length));
                    return truncated;
                }
            }
        }
        #endregion

        #region Key Storage
        public static void WritePublicKey(string publicKeyFilePath, string publicKey)
        {
            File.WriteAllText(publicKeyFilePath, publicKey);
        }

        public static string ReadpublicKey(string publicKeyFilePath)
        {
            return File.ReadAllText(publicKeyFilePath);
        }

        public static string ReadPrivateKey(string privateKeyFilePath, string password)
        {
            var salt = Encoding.UTF8.GetBytes(SymmetricSalt);
            var cypherText = File.ReadAllBytes(privateKeyFilePath);

            using (var cypher = new AesManaged())
            {
                var pdb = new Rfc2898DeriveBytes(password, salt);
                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                var key = pdb.GetBytes(cypher.KeySize / 8);
                var iv = pdb.GetBytes(cypher.BlockSize / 8);

                using (var decryptor = cypher.CreateDecryptor(key, iv))
                using (var msDecrypt = new MemoryStream(cypherText))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    try
                    {
                        return srDecrypt.ReadToEnd();
                    }
                    catch (CryptographicException)
                    {
                        throw new Exception("ReadPrivateKey: Wrong password!!");
                    }
                }
            }
        }

        public static async Task<string> ReadPrivateKeyAsync(string privateKeyFilePath, string password, System.Threading.CancellationToken cancellationToken) //Todo: Implement in cancellationToken context
        {
            var salt = Encoding.UTF8.GetBytes(SymmetricSalt);
            var cypherText = File.ReadAllBytes(privateKeyFilePath); // TODO: Using asyncrhonous implementation

            using (var cypher = new AesManaged())
            {
                var pdb = new Rfc2898DeriveBytes(password, salt);
                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                var key = pdb.GetBytes(cypher.KeySize / 8);
                var iv = pdb.GetBytes(cypher.BlockSize / 8);

                using (var decryptor = cypher.CreateDecryptor(key, iv))
                using (var msDecrypt = new MemoryStream(cypherText))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    try
                    {
                        return await srDecrypt.ReadToEndAsync();
                    }
                    catch (CryptographicException)
                    {
                        throw new Exception("ReadPrivateKeyAsync: Wrong password!!");
                    }
                }
            }
        }
        public static void WritePrivateKey(string privateKeyFilePath, string privateKey, string password)
        {
            var salt = Encoding.UTF8.GetBytes(SymmetricSalt);
            using (var cypher = new AesManaged())
            {
                var pdb = new Rfc2898DeriveBytes(password, salt);

                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                var key = pdb.GetBytes(cypher.KeySize / 8);
                var iv = pdb.GetBytes(cypher.BlockSize / 8);

                // Logger.LogIf(s_debug, $"KEY: {Convert.ToBase64String(key)}");
                // Logger.LogIf(s_debug, $"IV: {Convert.ToBase64String(iv)}");

                using (var encryptor = cypher.CreateEncryptor(key, iv))
                using (var fsEncrypt = new FileStream(privateKeyFilePath, FileMode.Create))
                using (var csEncrypt = new CryptoStream(fsEncrypt, encryptor, CryptoStreamMode.Write))
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(privateKey);
                }
            }
        }
        
        public static async Task WritePrivateKeyAsync(string privateKeyFilePath, string privateKey, string password, System.Threading.CancellationToken cancellationToken) //Todo: Implement in cancellationToken context
        {
            var salt = Encoding.UTF8.GetBytes(SymmetricSalt);
            using (var cypher = new AesManaged())
            {
                var pdb = new Rfc2898DeriveBytes(password, salt);

                // Set cypher parameters
                cypher.BlockSize = cypher.LegalBlockSizes[0].MaxSize;
                cypher.KeySize = cypher.LegalKeySizes[0].MaxSize;

                var key = pdb.GetBytes(cypher.KeySize / 8);
                var iv = pdb.GetBytes(cypher.BlockSize / 8);

                // Logger.LogIf(s_debug, $"KEY: {Convert.ToBase64String(key)}");
                // Logger.LogIf(s_debug, $"IV: {Convert.ToBase64String(iv)}");

                using (var encryptor = cypher.CreateEncryptor(key, iv))
                using (var fsEncrypt = new FileStream(privateKeyFilePath, FileMode.Create))
                using (var csEncrypt = new CryptoStream(fsEncrypt, encryptor, CryptoStreamMode.Write))
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    await swEncrypt.WriteAsync(privateKey);
                }
            }
        }
        #endregion
    }
}