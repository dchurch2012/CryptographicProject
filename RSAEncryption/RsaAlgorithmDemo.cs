using System;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Serialization;

using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RSA_Algorithm
{

    public class RsaAlgorithmDemo 
    {
         public RsaAlgorithmDemo () 
         {
     
         }
  
        /// <summary>
        /// Demonstrates:
        ///     1. Creation of an X509Certificate2
        ///     2. Use of that Certificate to create an RSA Public/Private Key Pair
        ///     3. Displays the Public and Pricate Key pair in XML format
        /// </summary> 
        static void Main()
        {
            CertificateUtil certUtil = new CertificateUtil();
            certUtil.MakeRSAKeys();
        }
  
    }
    
    public class CertificateUtil
    {
        private X509Certificate2 cert = null;
        
        static RSACryptoServiceProvider rsa;
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public CertificateUtil()
        {

        }
        
        public CertificateUtil(String cn, HashAlgorithmName hashName)
        {
            // generate asymmetric key pair
            var ecdsa = ECDsa.Create(); 
            
            var req = new CertificateRequest("cn=foobar", ecdsa, HashAlgorithmName.SHA256);
            cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
        }
        
        public X509Certificate2 GetCertificate()
        {
            return cert;
        }
        
        public void RSACrypto()
        {
            rsa = new RSACryptoServiceProvider(2048);
            _privateKey = rsa.ExportParameters(true);
            _publicKey = rsa.ExportParameters(false);

        }
        
        public string GetPublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();
        }
        
        public string GetPrivateKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);
            return sw.ToString();
        }
        
        
        public X509Certificate2 MakeCert()
        {
            var ecdsa = ECDsa.Create(); // generate asymmetric key pair
            var req = new CertificateRequest("cn=foobar", ecdsa, HashAlgorithmName.SHA256);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

            // Create PFX (PKCS #12) with private key
            File.WriteAllBytes("D:\\Users\\dchurch\\Desktop\\mycert.pfx", cert.Export(X509ContentType.Pfx, "P@55w0rd"));

            // Create Base 64 encoded CER (public key only)
            File.WriteAllText("D:\\Users\\dchurch\\Desktop\\mycert.cer",
                "-----BEGIN CERTIFICATE-----\r\n"
                + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
                + "\r\n-----END CERTIFICATE-----");
                
            return cert;
        }
        
        public void MakeRSAKeys()
        {
            RSACrypto();
            string privateKey = null;
            string publicKey = null;
            
            publicKey = GetPublicKeyString();
            privateKey = GetPrivateKeyString();
            
            Console.WriteLine("---------------------------------------------------------------------------");
            Console.WriteLine("PUBLIC KEY");
            Console.WriteLine("---------------------------------------------------------------------------");
            
            Console.WriteLine("Public Key : " + publicKey);
            Console.WriteLine("---------------------------------------------------------------------------");
   
            Console.WriteLine("---------------------------------------------------------------------------");
            Console.WriteLine("PRIVATE KEY");
            Console.WriteLine("---------------------------------------------------------------------------");
            Console.WriteLine("Private Key : " + privateKey);
            Console.WriteLine("---------------------------------------------------------------------------");
         
        }

    }
   
}

