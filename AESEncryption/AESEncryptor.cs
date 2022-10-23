using System;  
using System.Text; 
using System.IO;  
using System.Security.Cryptography; 

// Sometimes AES and Rijndael get used interchangeably. For a more extensive description of what is the difference 
// between them I recommend reading through the wikipedia article on AES but to summarize it
// - Rijndael is the underlying algorithm and AES is just prescribing what parameters should be used. These are
// 
//     128 bits for the block and
//     128, 192 or 256 bits for the key.
// 
// Wrong, bad, just don’t …
// 
// I was hesitant to even put it here but we have to start somewhere. Below is an example of how NOT to do it.

public static class SymmetricEncryptor
{
    // don't use this

    static string password = "very strong password 123412;,[p;[; 172634812";

    public static byte[] EncryptString(string toEncrypt)
    {
        var key = GetKey(password);

        using (var aes = Aes.Create())
        using (var encryptor = aes.CreateEncryptor(key, key))
        {
            var plainText = Encoding.UTF8.GetBytes(toEncrypt);
            return encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
        }
    }

    public static string DecryptToString(byte[] encryptedData)
    {
        var key = GetKey(password);

        using (var aes = Aes.Create())
        using (var encryptor = aes.CreateDecryptor(key, key))
        {
            var decryptedBytes = encryptor
                .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }

    // converts password to 128 bit hash
    private static byte[] GetKey(string password)
    {
        var keyBytes = Encoding.UTF8.GetBytes(password);
        using (var md5 = MD5.Create())
        {
            return md5.ComputeHash(keyBytes);
        }
    }
}

//… and how you could then use it:

class Program
{
    static void Main(string[] args)
    {
        var textToEncrypt = "something you want to hide";
        Console.WriteLine("original text: {0}{1}{0}", Environment.NewLine, textToEncrypt);

        var encryptedData = SymmetricEncryptor.EncryptString(textToEncrypt);
        Console.WriteLine("encrypted data:{0}{1}{0}", Environment.NewLine, Convert.ToBase64String(encryptedData));

        var decryptedText = SymmetricEncryptor.DecryptToString(encryptedData);
        Console.WriteLine("decrypted text:{0}{1}{0}", Environment.NewLine, decryptedText);
    }
}