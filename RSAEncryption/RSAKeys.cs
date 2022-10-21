using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;  
using System.Text;  

namespace RSAEncryption
{
    static class Program
    {
        private static byte[] RSA_OID = 
            { 0x30, 0xD, 0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0 }; // Object ID for RSA
        
        // Corresponding ASN identification bytes
        const byte INTEGER = 0x2;
        const byte SEQUENCE = 0x30;
        const byte BIT_STRING = 0x3;
        const byte OCTET_STRING = 0x4;

        static void Main()
        {
            const int KEY_SIZE = 2048;
            
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KEY_SIZE))
            {
                //LoadKey() ;

                // Return Public Key ONLY
                RSAParameters RSAKeyInfo = rsa.ExportParameters(false);
                
                string RSAPEMPublicKey = ConvertPublicKey(RSAKeyInfo);
                
                Console.WriteLine("Public KEY : ");
                Console.WriteLine(RSAPEMPublicKey);
                
                // Return Public AND Private Key
                RSAKeyInfo = rsa.ExportParameters(true);
                
                string RSAPEMPrivateKey = ConvertPrivateKey(RSAKeyInfo);
                
                Console.WriteLine("Private KEY : ");
                Console.WriteLine(RSAPEMPrivateKey);
            }
        }
        
        private static string ConvertPublicKey(RSAParameters param)
        {
            List<byte> arrBinaryPublicKey = new List<byte>();

            arrBinaryPublicKey.InsertRange(0, param.Exponent);
            arrBinaryPublicKey.Insert(0, (byte)arrBinaryPublicKey.Count);
            arrBinaryPublicKey.Insert(0, INTEGER);

            arrBinaryPublicKey.InsertRange(0, param.Modulus);
            AppendLength(ref arrBinaryPublicKey, param.Modulus.Length);
            arrBinaryPublicKey.Insert(0, INTEGER);

            AppendLength(ref arrBinaryPublicKey, arrBinaryPublicKey.Count);
            arrBinaryPublicKey.Insert(0, SEQUENCE);

            arrBinaryPublicKey.Insert(0, 0x0); // Add NULL value

            AppendLength(ref arrBinaryPublicKey, arrBinaryPublicKey.Count);

            arrBinaryPublicKey.Insert(0, BIT_STRING);
            arrBinaryPublicKey.InsertRange(0, RSA_OID);

            AppendLength(ref arrBinaryPublicKey, arrBinaryPublicKey.Count);

            arrBinaryPublicKey.Insert(0, SEQUENCE);

            return System.Convert.ToBase64String(arrBinaryPublicKey.ToArray());
        }

        private static string ConvertPrivateKey(RSAParameters param)
        {
            List<byte> arrBinaryPrivateKey = new List<byte>();

            arrBinaryPrivateKey.InsertRange(0, param.InverseQ);
            AppendLength(ref arrBinaryPrivateKey, param.InverseQ.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.DQ);
            AppendLength(ref arrBinaryPrivateKey, param.DQ.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.DP);
            AppendLength(ref arrBinaryPrivateKey, param.DP.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.Q);
            AppendLength(ref arrBinaryPrivateKey, param.Q.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.P);
            AppendLength(ref arrBinaryPrivateKey, param.P.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.D);
            AppendLength(ref arrBinaryPrivateKey, param.D.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.Exponent);
            AppendLength(ref arrBinaryPrivateKey, param.Exponent.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.InsertRange(0, param.Modulus);
            AppendLength(ref arrBinaryPrivateKey, param.Modulus.Length);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            arrBinaryPrivateKey.Insert(0, 0x00);
            AppendLength(ref arrBinaryPrivateKey, 1);
            arrBinaryPrivateKey.Insert(0, INTEGER);

            AppendLength(ref arrBinaryPrivateKey, arrBinaryPrivateKey.Count);
            arrBinaryPrivateKey.Insert(0, SEQUENCE);

            return System.Convert.ToBase64String(arrBinaryPrivateKey.ToArray());
        }

        private static void AppendLength(ref List<byte> arrBinaryData, int nLen)
        {
            if (nLen <= byte.MaxValue)
            {
                arrBinaryData.Insert(0, Convert.ToByte(nLen));
                arrBinaryData.Insert(0, 0x81); //This byte means that the length fits in one byte
            }
            else
            {
                arrBinaryData.Insert(0, Convert.ToByte(nLen % (byte.MaxValue + 1)));
                arrBinaryData.Insert(0, Convert.ToByte(nLen / (byte.MaxValue + 1)));
                arrBinaryData.Insert(0, 0x82); //This byte means that the length fits in two byte
            }
        }

    }
}

  
