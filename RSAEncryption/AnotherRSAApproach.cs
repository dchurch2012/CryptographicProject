using System;
using System.Security.Cryptography;

namespace RSAKeys
{
    static class Program
    {
        static void Main()
        {
            const int KEY_SIZE = 2048;
            
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KEY_SIZE))
            {
                string publicKey = RSAKeysToPEM.GetPublicPEM(rsa);
                
                Console.WriteLine("Public Key : ");
                Console.WriteLine(publicKey);
                
                string privateKey = RSAKeysToPEM.GetPrivatePEM(rsa);
        
                Console.WriteLine("Private Key : ");
                Console.WriteLine(privateKey);
            }
        }
    }
}