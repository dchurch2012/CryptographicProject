using System;
using System.Security.Cryptography;
using System.Text;

// In .NET (I used C#), there will be something like this:
public class RSACryptoApp
{
    // parameters from the python script (public key)
    private static readonly String EXP = "AQAB";
    private static readonly String MODULUS = "zf4LgceVPvjMLz/pp8exH58AeBrhjLe0k4FRmd59I0k4sH6oug6Z9RfY4FvEFcssBwH1cmWF5/Zen8xbRVRyUnzer6b6cKmlzHFYf0LlbovvYMkW5pdhRcTHK2ijByGtmVgU/CEKEQTy3elpU7ZsHE8D6T1M7L2gmGAxvgldUMRu4l8BPuRyht1a9dA9b6005atpdlkCSc3emXSfyBOBwNE0UicVTVncn9SBjP7bTBGgOKshYnYsqh4BD0I7AU3xdoAsZVWudECX/zVa7uUOk1ooVYjMEyfBngrEDXrmIkAlVruUuj/eWiYwT2vXqByQgDfDvat5IS4i3ywiHAWXUQ==";

    static string Header = "-------------------------------------------------------------";

            
    public static void Main(string[] args)
    {
        RsaEncryptWithPublicKey();
        RsaEncryptAndDecrypt();
    }
    
    public static void displayInformationalMessage()
    {
        string message = 
        "// Program RSACryptoApp\n" +
        "// Purpose:\n" +
        "// Demonstrate Creation of Public Key Components\n" +
        "// Specifically EXPONENT and MODULUS Components\n" +
        "// System.Security.Cryptography\n" +
        "// AND\n" +
        "// System.Security.Cryptography.X509Certificates\n" +
        "// Dot Net Encryption Libraries\n" +
        "// Basis of Encryption and Decryption is RSA Algorithm\n" +
        "// Original Plain Text is Displayed In it's Encrypted Format\n" +
        "// ALSO Performs:\n" +
        "// Demonstrate Encryption of plain text message\n" +
        "// ALSO Performs:\n" +
        "// Decryption of Encryped message using Private Key\n" +
        "// Demonstrate Encryption of plain text message\n" +
        "// Using RSA\n" +
        "// Libraries Used Are\n" +
        "// System.Security.Cryptography\n" +
        "// AND\n" +
        "// System.Security.Cryptography.X509Certificates\n" +
        "// Dot Net Encryption Libraries\n";
        
        Console.WriteLine(Header);
        Console.WriteLine(message);
        Console.WriteLine(Header);
    }

    // Use Convert.FromBase64String and Convert.ToBase64String instead.  
    // These functions are inverses.

    public static void RsaEncryptWithPublicKey()
    {
        String clearText = "Hello from .NET";

        displayInformationalMessage();

        Console.WriteLine(Header);
        Console.WriteLine("Demonstrating RSA Encryption Using Public Key");
        Console.WriteLine(Header);

        Console.WriteLine("Clear Text: " + clearText);
        Console.WriteLine(Header);

        Console.WriteLine(Header);
        Console.WriteLine("Plain Text: " + clearText);
        Console.WriteLine(Header);

        RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        csp.FromXmlString("<RSAKeyValue><Exponent>" + EXP + "</Exponent><Modulus>" + MODULUS + "</Modulus></RSAKeyValue>");
        
        try
        {
            // encrypting a string for testing purposes
            byte[] plainText = Encoding.ASCII.GetBytes(clearText);

            byte[] cipherText = csp.Encrypt(plainText, false);
            
            Console.WriteLine(Header);
            Console.WriteLine("Encrypted: " + Convert.ToBase64String(cipherText));
            Console.WriteLine(Header);
     }
        catch(Exception except)
        {
            Console.WriteLine(except.Message);
        }
    }
        
    public static void RsaEncryptAndDecrypt()
    {
        Console.WriteLine(Header);
        Console.WriteLine("Demonstrating RSA Encryption Using Public Key");
        Console.WriteLine(Header);

        string plainText = "Hello World";
        
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        string pubkey = rsa.ToXmlString(false);
        string prikey = rsa.ToXmlString(true);

        byte[] someThing = RSAEncrypt(Encoding.Unicode.GetBytes(plainText), pubkey);
        byte[] anotherThing = RSADecrypt(someThing, prikey);

        Console.WriteLine(Header);
        Console.WriteLine("Plain Text :");
        Console.WriteLine(plainText);
        Console.WriteLine(Header);

        Console.WriteLine(Header);
        Console.WriteLine("Encrypted Text :");
        Console.WriteLine(Convert.ToBase64String(someThing));
        Console.WriteLine(Header);
 
        Console.WriteLine(Header);
        Console.WriteLine("Demonstrating RSA Decryption Using Private Key");
        Console.WriteLine(Header);

        Console.WriteLine(Header);
        Console.WriteLine("Decrypted Text :");
        Console.WriteLine(Encoding.Unicode.GetString(anotherThing));
        Console.WriteLine(Header);

    }

    public static byte[] RSAEncrypt(byte[] plaintext, string destKey)
    {
        byte[] encryptedData;
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(destKey);
        encryptedData = rsa.Encrypt(plaintext, true);
        rsa.Dispose();
        
        return encryptedData;
    }

    public static byte[] RSADecrypt(byte[] ciphertext, string srcKey)
    {
        byte[] decryptedData;
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(srcKey);
        decryptedData = rsa.Decrypt(ciphertext, true);
        rsa.Dispose();
        return decryptedData;
    }

    public static void RSAEncryptionFromAPythonSample()
    {
        // Data Taken From a Python RSA Sample
        // parameters from the python script (public key)
        string EXP = "AQAB";
        string MODULUS = "zf4LgceVPvjMLz/pp8exH58AeBrhjLe0k4FRmd59I0k4sH6oug6Z9RfY4FvEFcssBwH1cmWF5/Zen8xbRVRyUnzer6b6cKmlzHFYf0LlbovvYMkW5pdhRcTHK2ijByGtmVgU/CEKEQTy3elpU7ZsHE8D6T1M7L2gmGAxvgldUMRu4l8BPuRyht1a9dA9b6005atpdlkCSc3emXSfyBOBwNE0UicVTVncn9SBjP7bTBGgOKshYnYsqh4BD0I7AU3xdoAsZVWudECX/zVa7uUOk1ooVYjMEyfBngrEDXrmIkAlVruUuj/eWiYwT2vXqByQgDfDvat5IS4i3ywiHAWXUQ==";

        String clearText = "Hello from .NET";

        Console.WriteLine("Plain Text: " + clearText);
        
        RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        csp.FromXmlString("<RSAKeyValue><Exponent>" + EXP + "</Exponent><Modulus>" + MODULUS + "</Modulus></RSAKeyValue>");

        // encrypting a string for testing purposes
        byte[] plainText = Encoding.ASCII.GetBytes(clearText);
        byte[] cipherText = csp.Encrypt(plainText, false);

        // Output:
        // Encrypted: F/agXpfSrs7HSXZz+jVq5no/xyQDXuOiVAG/MOY7WzSlp14vMOTM8TshFiWtegB3+2BZCMOEPLQFFFbxusuCFOYGGJ8yRaV7q985z/UDJVXvbX5ANYqrirobR+c868mY4V33loAt2ZFNXwr+Ubk11my1aJgHmoBem/6yPfoRd9GrZaSQnbJRSa3EDtP+8pXETkF9B98E7KvElrsRTLXEXSBygmeKsyENo5DDcARW+lVVsQuP8wUEGnth9SX4oG8i++gmQKkrv0ep6yFrn05xZJKgpOfRiTTo/Bkh7FxNP2wo7utzhtYkNnvtXaJPWAvqXg93KmNPqg1IsN4P1Swb8w==
        Console.WriteLine("Encrypted: " + Convert.ToBase64String(cipherText));
   }
}
