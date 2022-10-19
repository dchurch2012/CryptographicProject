using System;
using System.Security;
using System.Security.Cryptography;
using CSharp_easy_RSA_PEM;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace POCApplication
{
    class Program
    {
        //XML Formatted Strings
        private static string publicKeyStr = null;
        private static string privateKeyStr = null;
 
        //PEM Formatted Strings
        private static string publicKeyPEMStr = null;
        private static string privateKeyPEMStr = null;

        private static RSACryptoServiceProvider _cryptoServiceProvider = new RSACryptoServiceProvider();

        public static string plainText = null;
        public static string encryptedText = null;
        public static string decryptedText = null;
        
        static void Main(string[] args)
        {
            Console.WriteLine("generating Public and Private RSA Keys");
            generateKeys();
            
            plainText = getPlainText();
            string encryptedData = encryptDataRSAUsingPEMKeys(plainText, privateKeyPEMStr,publicKeyPEMStr);
 
            Console.WriteLine("Encrypted Text : " + encryptedData);
 
            string deCryptedD = decryptDataRSA(encryptedData, _cryptoServiceProvider);
        }
        
        public static int generateKeys()
        {
            publicKeyStr = Crypto.ExportPublicKeyToString(_cryptoServiceProvider);
            privateKeyStr = Crypto.ExportPrivateKeyToString(_cryptoServiceProvider);

            // Switch to UTF-8 Encoding From UTF-16 Encoding
            publicKeyStr = publicKeyStr.Replace("encoding=\"utf-16\"", "encoding=\"utf-8\"");
            privateKeyStr = privateKeyStr.Replace("encoding=\"utf-16\"", "encoding=\"utf-8\"");

            Console.WriteLine("#----------------------------------------------------------------------");
            Console.WriteLine("PUBLIC KEY :");
            Console.WriteLine(publicKeyStr);
            Console.WriteLine("#----------------------------------------------------------------------");

            Console.WriteLine("#----------------------------------------------------------------------");
            Console.WriteLine("PRIVATE KEY :");
            Console.WriteLine(privateKeyStr);
            Console.WriteLine("#----------------------------------------------------------------------");

            publicKeyPEMStr = Crypto.ExportPublicKeyToX509PEM(_cryptoServiceProvider);
            privateKeyPEMStr = Crypto.ExportPrivateKeyToRSAPEM(_cryptoServiceProvider);

            Console.WriteLine("#----------------------------------------------------------------------");
            Console.WriteLine("PUBLIC KEY PEM FORMAT:");
            Console.WriteLine(publicKeyPEMStr);
            Console.WriteLine("#----------------------------------------------------------------------");

            Console.WriteLine("#----------------------------------------------------------------------");
            Console.WriteLine("PRIVATE KEY PEM FORMAT:");
            Console.WriteLine(privateKeyPEMStr);
            Console.WriteLine("#----------------------------------------------------------------------");

            return 0;
        }

        public static string encryptDataRSAUsingPEMKeys(string Data, string loadedRSAPEM, string loadedX509PEM)
        {
            //============================================================================
            // Encrypt
            //============================================================================
            
            RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(loadedRSAPEM);
            RSACryptoServiceProvider publicX509key = Crypto.DecodeX509PublicKey(loadedX509PEM);

            Console.WriteLine("Using public key, encrypt \"" + Data + "\"..");
            
            encryptedText = Crypto.EncryptString(Data, publicX509key);
            Console.WriteLine("Encrypted: " + encryptedText);
            
            return encryptedText;
        }

        public static string decryptDataRSA(string enCryptedData, RSACryptoServiceProvider privateRSAkey)
        {
            //============================================================================
            // Decrypt
            //============================================================================
            Console.WriteLine("Using private key, decrypt..");
            
            decryptedText = Crypto.DecryptString(enCryptedData, privateRSAkey);
            Console.WriteLine("Decrypted: " + decryptedText );

            return decryptedText;
        }

        public static string getPlainText()
        {
            Console.WriteLine("Enter a String of Data : ");
            plainText = Console.ReadLine();

            return plainText;
        }
    }
}



