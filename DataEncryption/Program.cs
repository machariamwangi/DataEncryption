// See https://aka.ms/new-console-template for more information
using DataEncryption;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using Aes = System.Security.Cryptography.Aes;

Console.WriteLine("Hello, World!");

//var encryptedText = SymmetricEncryptionDecryptionManager.Encrypt("This is sample text.", key);
//Console.WriteLine(encryptedText);
//var decryptedText = SymmetricEncryptionDecryptionManager.Decrypt(encryptedText, key);
//Console.WriteLine(decryptedText);

var rsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);
var cipherText = AsymmetricEncryptionDecryptionManager.Encrypt("This is sample text.", rsaCryptoServiceProvider.ExportParameters(false));
Console.WriteLine(cipherText);
var plainText = AsymmetricEncryptionDecryptionManager.Decrypt(cipherText, rsaCryptoServiceProvider.ExportParameters(true));
Console.WriteLine(plainText);


//asymetric entription

//Generate a public/private key pair using the RSA algorithm
var rsa = new RSACryptoServiceProvider();
string publicKeyXML = rsa.ToXmlString(false);
string privateKeyXML = rsa.ToXmlString(true);

//use the public key to encrypt data.
byte[] data = Encoding.UTF8.GetBytes("Hello world!");
byte[] encryptedData = rsa.Encrypt(data, false);

//Then, to decrypt the data, you will need to use the private key.
byte[] decryptedData = rsa.Decrypt(encryptedData, false);
string message = Encoding.UTF8.GetString(decryptedData);
public class SymmetricEncryptionDecryptionManager
{
    public static string Encrypt(string data, string key)
    {
        byte[] initializationVector = Encoding.ASCII.GetBytes("abcede0123456789");
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initializationVector;
            var symmetricEncryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream as Stream, symmetricEncryptor, CryptoStreamMode.Write))
                {
                    using (var streamWriter = new StreamWriter(cryptoStream as Stream))
                    {
                        streamWriter.Write(data);
                    }
                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
        }
    }

    public static string Decrypt(string cipherText, string key)
    {
        byte[] initializationVector = Encoding.ASCII.GetBytes("abcede0123456789");
        byte[] buffer = Convert.FromBase64String(cipherText);
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = initializationVector;
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var memoryStream = new MemoryStream(buffer))
            {
                using (var cryptoStream = new CryptoStream(memoryStream as Stream,decryptor, CryptoStreamMode.Read))
                {
                    using (var streamReader = new StreamReader(cryptoStream as Stream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }
}