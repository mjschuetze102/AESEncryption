using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SymmetricKey
{
    /// <summary>
    /// Implements AES 128 Encryption
    /// Private key encryption
    ///   Fast and efficient algorithm
    ///  Key must remain a secret, and both parties require the key
    /// Uses Cipher Block Chaining (CBC) over Electronic CodeBook (ECB)
    ///   CBC: Block C depends not only on the outcome of Block B, but also Block A
    ///   i.e. if Block C == Block A, the outputs will still be different
    ///   ECB: Each Block with the same values, have the same encrypted output
    /// Uses a random initialization vector to xor with the first Block of data
    ///   This causes the same plaintext to output a different cipher text
    ///   Does not have to remain secret as it should only be used once
    /// This code is susceptible to Padding Oracle
    ///   Padding Oracle: https://www.youtube.com/watch?v=aH4DENMN_O4 @10:00
    ///     To mitigate, use Message Authentication Code (MAC)
    /// Written by Michael Schuetze on 3/14/2020.
    /// </summary>
    public class AESEncryption
    {
        private const int BLOCK_LENGTH = 128;
        private const int KEY_LENGTH = 128; // 192, 256

        private byte[] secKey;

        public AESEncryption()
        {
            // Only need to generate secret key once
            using (RNGCryptoServiceProvider secRand = new RNGCryptoServiceProvider())
            {
                secKey = new byte[KEY_LENGTH / 8];
                secRand.GetBytes(secKey);
            }
        }

        /// <summary>
        /// Encrypts a plaintext message
        /// </summary>
        /// <param name="plainText">Message to be encrypted</param>
        /// <returns>16 byte initialization vector concatenated to the front of the cipher text</returns>
        public byte[] Encode(string plainText)
        {
            // Need to generate initialization vector for every encoding
            byte[] iv = generateInitializationVector();

            // AES - Advanced Encryption Standard
            // CBC - Cipher Block Chaining
            // PKCS7 - Padding Standard to pad data up to a 255 byte (2040 bit) block
            //         1 byte missing: 0x01 is added
            //         2 byte missing: 0x0202 is added
            //         ...
            //         8 byte missing: 0x0808080808080808 is added
            using (SymmetricAlgorithm algorithm = Aes.Create())
            {
                algorithm.Key = secKey;
                algorithm.IV = iv;
                algorithm.Mode = CipherMode.CBC;
                algorithm.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    // Attach the initialization vector to the encoding so the decoding process has access to it
                    memoryStream.Write(iv);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    }
                    
                    return Encoding.ASCII.GetBytes(Convert.ToBase64String(memoryStream.ToArray()));
                }
            }
        }

        /// <summary>
        /// Decrypts an encoded message
        /// </summary>
        /// <param name="ivAndCipher">16 byte initialization vector concatenated to the front of the cipher text</param>
        /// <returns>String containing the original encrypted message</returns>
        public string Decode(byte[] ivAndCipher)
        {
            ivAndCipher = Convert.FromBase64String(Encoding.ASCII.GetString(ivAndCipher));

            // Remove initialization vector from the front of the cipher text
            byte[] iv = ivAndCipher.Take(BLOCK_LENGTH / 8).ToArray(); // Division converts bits to bytes
            byte[] cipherText = ivAndCipher.Skip(BLOCK_LENGTH / 8).ToArray();

            // AES - Advanced Encryption Standard
            // CBC - Cipher Block Chaining
            // PKCS7 - Padding Standard to pad data up to a 255 byte (2040 bit) block
            //         1 byte missing: 0x01 is added
            //         2 byte missing: 0x0202 is added
            //         ...
            //         8 byte missing: 0x0808080808080808 is added
            using (SymmetricAlgorithm algorithm = Aes.Create())
            {
                algorithm.Key = secKey;
                algorithm.IV = iv;
                algorithm.Mode = CipherMode.CBC;
                algorithm.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream(cipherText))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader streamReader = new StreamReader(cryptoStream))
                {
                    return streamReader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Generate Initialization Vector used in the first round of Encryption/Decryption
        /// </summary>
        /// <returns>Initialization vector of size 16 bytes (128 bits)</returns>
        private static byte[] generateInitializationVector()
        {
            using (RNGCryptoServiceProvider secRand = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[BLOCK_LENGTH / 8]; // Division converts bits to bytes
                secRand.GetBytes(iv);
                return iv;
            }
        }

        private static char[] hexArray = "0123456789ABCDEF".ToCharArray();
        private static string bytesToHex(byte[] bytes)
        {
            char[] hexChars = new char[bytes.Length * 3];
            for (int j = 0; j < bytes.Length; j++)
            {
                int v = bytes[j] & 0xFF;
                hexChars[j * 3] = hexArray[v >> 4];
                hexChars[j * 3 + 1] = hexArray[v & 0x0F];
                hexChars[j * 3 + 2] = ' ';
            }
            return new string(hexChars);
        }

        public static void Main(string[] args)
        {
            AESEncryption encryption = new AESEncryption();
            byte[] secKey = encryption.secKey;

            string plainText = "Hello World!";

            for (int rounds = 0; rounds < 3; rounds++)
            {
                byte[] encoded = encryption.Encode(plainText);
                string decoded = encryption.Decode(encoded);

                // Remove initialization vector from the front of the cipher text
                encoded = Convert.FromBase64String(Encoding.ASCII.GetString(encoded));
                byte[] iv = encoded.Take(BLOCK_LENGTH / 8).ToArray(); // Division converts bits to bytes
                byte[] cipherText = encoded.Skip(BLOCK_LENGTH / 8).ToArray();
                byte[] cipherTextB64 = Encoding.ASCII.GetBytes(Convert.ToBase64String(cipherText));

                Console.WriteLine("-------------------------------------------");
                Console.WriteLine("Init Vector: " + bytesToHex(iv));
                Console.WriteLine("Secret Key:  " + bytesToHex(secKey));
                Console.WriteLine("Encrypted:   " + bytesToHex(cipherText));
                Console.WriteLine("Decrypted:   " + bytesToHex(Encoding.UTF8.GetBytes(decoded)));
                Console.WriteLine("-------------------------------------------");
                Console.WriteLine("Plain Text:  " + plainText);
                Console.WriteLine("Encrypted:   " + Encoding.UTF8.GetString(cipherTextB64));
                Console.WriteLine("Decrypted:   " + decoded);
                Console.WriteLine("-------------------------------------------");
            }
            Console.ReadLine();
        }
    }
}