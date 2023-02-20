using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DataEncryption
{
    public class AsymmetricEncryptionDecryptionManager
    {
        public static string Encrypt(string data, RSAParameters rsaParameters)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.ImportParameters(rsaParameters);
                var byteData = Encoding.UTF8.GetBytes(data);
                var encryptedData = rsaCryptoServiceProvider.Encrypt(byteData, false);
                return Convert.ToBase64String(encryptedData);
            }
        }
        public static string Decrypt(string cipherText, RSAParameters rsaParameters)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                var cipherDataAsByte = Convert.FromBase64String(cipherText);
                rsaCryptoServiceProvider.ImportParameters(rsaParameters);
                var encryptedData = rsaCryptoServiceProvider.Decrypt(cipherDataAsByte, false);
                return Encoding.UTF8.GetString(encryptedData);
            }
        }
    }
}
