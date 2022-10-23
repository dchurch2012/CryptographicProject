using System;
using System.Security.Cryptography;

namespace CreateAESKeys {
    class Program 
    {
        static void Main(string[] args) 
        {
            using (Aes myAes = Aes.Create()) 
            {
                Console.WriteLine("Generating AES key");
                Console.Write("Key: ");
                
                var key = Convert.ToBase64String(myAes.Key);
                Console.WriteLine(key);
                Console.Write("IV: ");
                
                var iV = Convert.ToBase64String(myAes.IV);
                Console.WriteLine(iV);
            }
        }
    }
}
