from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class CryptoLibrary:
    def __init__(rsa):
        self.rsa = rsa

        
    #-------------------------------------------------------------------------
    #   GENERATE CERTIFICATE PAIR
    #-------------------------------------------------------------------------
    def generateCertificatePair():
        print("Calling generateCertificatePair")

        new_key = RSA.generate(2048)

        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")

        print("Storing Private Key")
        
        fd = open("private_key.pem", "wb")
        fd.write(private_key)
        fd.close()

        print("Storing Public Key")
        
        fd = open("public_key.pem", "wb")
        fd.write(public_key)
        fd.close()

    #-------------------------------------------------------------------------
    #   ENCRYPT And DECRYPT DATA WITH CERTIFICATE
    #-------------------------------------------------------------------------
    def rsaEncryptDecrypt():
        print("Calling rsaEncryptDecrypt")
        
        message = b'CODE EVERYDAY TO GET BETTER'

        print("Plain Text : ");
        print(message);

        key = RSA.import_key(open('public_key.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        
        print("Encrypted Text : ");
        print(ciphertext)
        print("\n\n")

        key = RSA.import_key(open('private_key.pem').read())
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(ciphertext)
        
        print("Decrypted Text : ");
        print (plaintext.decode("utf-8"))

    #-------------------------------------------------------------------------
    #   GENERATE CERTIFICATE PAIR
    #-------------------------------------------------------------------------
    def generateCertificatePair2():
        new_key = RSA.generate(2048)

        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")

        fd = open("private_key.pem", "wb")
        fd.write(private_key)
        fd.close()

        fd = open("public_key.pem", "wb")
        fd.write(public_key)
        fd.close()

    #-------------------------------------------------------------------------
    #   ENCRYPT And DECRYPT DATA WITH CERTIFICATE
    #-------------------------------------------------------------------------
    def rsaEncryptDecrypt2():
        message = b'CODE EVERYDAY TO GET BETTER'

        key = RSA.import_key(open('public_key.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        print(ciphertext)
        print("\n\n")


        key = RSA.import_key(open('private_key.pem').read())
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(ciphertext)
        print (plaintext.decode("utf-8"))

    #-------------------------------------------------------------------------
    #   ENCRYPTION DEM
    #-------------------------------------------------------------------------
    def encryptionDemo():

        message = b"secret text"
        ciphertext = key.public_key().encrypt(message,
                            padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
            )
        )

        # If you receive the following error, make sure you are trying to encrypt bytes 
        # and not a String. b"somestring" represent bytes instead of a String.
        # 
        # TypeError: initializer for ctype 'unsigned char *' must be a bytes or list or tuple, not str

        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    #-------------------------------------------------------------------------
    #   PUBLIC PRIVATE KEYS DEMO
    #-------------------------------------------------------------------------
    def rsaPublicPrivateKey():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Storing Keys
        # 
        # To store the keys in a file, they first need to be serialized and then written to a file. 
        # To store the private key, we need to use the following.
        # 
        # private_key = ... # Placeholder - you generated this before

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open('private_key.pem', 'wb') as f:
            f.write(pem)

        # You can password protect the contents of this file using this top key serialization example.
        # To store the public key, we need to use a slightly modified version.

        # public_key = ... # Placeholder - you generated this before

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('public_key.pem', 'wb') as f:
            f.write(pem)

        # Remember that public and private keys are different so you will have to use these methods for each key.
        # Reading Keys
        # 
        # To get the keys out of the files, we need to read each file and then load them. 
        # To read the private key, use the following.

        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # If you store the key with a password, set password to what you used.
        # 
        # The variable private_key will now have the private key. 
        # To read the public key, we need to use a slightly modified version.


        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # The variable public_key will now have the public key.
        # Encrypting
        # 
        # Due to how asymmetric encryption algorithms like RSA work, encrypting with either one is fine, 
        # you just will need to use the other to decrypt. Applying a bit of logic to this can create some 
        # useful scenarios like signing and verification. For this example, I will assume that you keep both 
        # keys safe and don't release them since this example is only for local encryption (can be applied to 
        # wider though when keys are exchanged).

        # This means you can use either key but I will demonstrate using the public key to encrypt, 
        # this will mean anyone with the private key can decrypt the message.


        message = b'encrypt me!'
        public_key = ... # Use one of the methods above to get your public key

        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypting
        # 
        # Assuming that the public key was used to encrypt, we can use the private key to decrypt.
        # 
        # 
        # encrypted = ... # From before (could have been stored then read back here)
        # private_key = ... # Use one of the methods above to get your public key (matches the public_key)

        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsaDemonstration():
        #Demonstration
        #
        #To show this in action, here is a properly constructed example.

        # Generating a key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Storing the keys
        pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key.pem', 'wb') as f:
            f.write(pem)

        # Reading the keys back in (for demonstration purposes)
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Encrypting and decrypting
        message = b'encrypt me!'
        encrypted = public_key.encrypt(
            message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Checking the results
        original_message
        b'encrypt me!'
        message == original_message

    def rsaEncryptingAndDecrypting():
        # True
        # 
        # Encrypting and Decrypting Files
        # 
        # To encrypt and decrypt files, you will need to use read and write binary when opening files. 
        # You can simply substitute the values I previously used for message with the contents of a file. For example:

        f = open('test.txt', 'rb')
        message = f.read()
        f.close()

        # Using the variable message you can then encrypt it. 
        # To store, you can use the general Python method when encryption returns bytes.

        encrypted = 'data from encryption'
        f = open('test.encrypted', 'wb')
        f.write(encrypted)
        f.close()

        # Now to decrypt you can easily read the data from test.encrypted 
        # like the first bit of code in this section, decrypt it and 
        # then write it back out to test.txt using the second bit of code in this section.


        # I hardcoded the (N, E, D) parameters for a private key in python and exported the exponent and modulus 
        # to be used later for encryption.

        # custom base64 encoding
        def b64_enc(n, l):
            n = n.to_bytes(l, 'big')
            return base64.b64encode(n)

        # fixed a set of keys for testing purposes
        N = 26004126751443262055682011081007404548850063543219588539086190001742195632834884763548378850634989264309169823030784372770378521274048211537270851954737597964394738860810397764157069391719551179298507244962912383723776384386127059976543327113777072990654810746825378287761304202032439750301912045623786736128233730798303406858144431081065384988539277630625160727011582345942687126935423502995613920211095965452425548919926951203151483590222152446516520421379279591807660810550784744188433550335950652666201439521115515355539373928576162221297645781251953236644092963307595988040539993067709240004782161131243282208593
        E = 65537
        D = 844954574014654722486150458473919587206863455991060222377955072839922571984098861772377020041002939383041291761051853484512886782322743892284027026528735139923685801975918062144627908962369108081178131103781404720078456605432924519279933702927938064507063482999903002331319671303661755165294744970869186178561527578261522199503340027952798084625109041630166309505066404215223685733585467434168146932177924040219720383860880583466676764286302300281603021045351842170755190359364339936360197909582974922675680101321863304283607829144759777189360340512230537108705852116021758740440195445732631657876008160876867027543

        # construct pair of keys
        private_key = RSA.construct((N, E, D))
        public_key = private_key.publickey()

        # base64-encode parameters in big-endian format
        EXP = b64_enc(public_key.e, 3)
        MODULUS = b64_enc(public_key.n, 256)

        print('EXP:', EXP, 'MODULUS:', MODULUS)

        # Output:
        # EXP: b'AQAB' MODULUS: b'zf4LgceVPvjMLz/pp8exH58AeBrhjLe0k4FRmd59I0k4sH6oug6Z9RfY4FvEFcssBwH1cmWF5/Zen8xbRVRyUnzer6b6cKmlzHFYf0LlbovvYMkW5pdhRcTHK2ijByGtmVgU/CEKEQTy3elpU7ZsHE8D6T1M7L2gmGAxvgldUMRu4l8BPuRyht1a9dA9b6005atpdlkCSc3emXSfyBOBwNE0UicVTVncn9SBjP7bTBGgOKshYnYsqh4BD0I7AU3xdoAsZVWudECX/zVa7uUOk1ooVYjMEyfBngrEDXrmIkAlVruUuj/eWiYwT2vXqByQgDfDvat5IS4i3ywiHAWXUQ=='

        # In .NET (I used C#), there will be something like this:
        # 
        # using System;
        # using System.Security.Cryptography;
        # using System.Text;
        # 
        # public class RSACryptoApp
        # {
        #    $// parameters from the python script (public key)
        #    $private static readonly String EXP = "AQAB";
        #    $private static readonly String MODULUS = "zf4LgceVPvjMLz/pp8exH58AeBrhjLe0k4FRmd59I0k4sH6oug6Z9RfY4FvEFcssBwH1cmWF5/Zen8xbRVRyUnzer6b6cKmlzHFYf0LlbovvYMkW5pdhRcTHK2ijByGtmVgU/CEKEQTy3elpU7ZsHE8D6T1M7L2gmGAxvgldUMRu4l8BPuRyht1a9dA9b6005atpdlkCSc3emXSfyBOBwNE0UicVTVncn9SBjP7bTBGgOKshYnYsqh4BD0I7AU3xdoAsZVWudECX/zVa7uUOk1ooVYjMEyfBngrEDXrmIkAlVruUuj/eWiYwT2vXqByQgDfDvat5IS4i3ywiHAWXUQ==";
        # 
        #    $public static void Main(string[] args)
        #    ${
        #    $RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        #    $csp.FromXmlString("<RSAKeyValue><Exponent>" + EXP + "</Exponent><Modulus>" + MODULUS + "</Modulus></RSAKeyValue>");
        # 
        #    $// encrypting a string for testing purposes
        #    $byte[] plainText = Encoding.ASCII.GetBytes("Hello from .NET");
        #    $byte[] cipherText = csp.Encrypt(plainText, false);
        # 
        #    $Console.WriteLine("Encrypted: " + Convert.ToBase64String(cipherText));
        # 
        #    $// Output:
        #    $// Encrypted: F/agXpfSrs7HSXZz+jVq5no/xyQDXuOiVAG/MOY7WzSlp14vMOTM8TshFiWtegB3+2BZCMOEPLQFFFbxusuCFOYGGJ8yRaV7q985z/UDJVXvbX5ANYqrirobR+c868mY4V33loAt2ZFNXwr+Ubk11my1aJgHmoBem/6yPfoRd9GrZaSQnbJRSa3EDtP+8pXETkF9B98E7KvElrsRTLXEXSBygmeKsyENo5DDcARW+lVVsQuP8wUEGnth9SX4oG8i++gmQKkrv0ep6yFrn05xZJKgpOfRiTTo/Bkh7FxNP2wo7utzhtYkNnvtXaJPWAvqXg93KmNPqg1IsN4P1Swb8w==
        #    $}
        # }

        # Back to the python script:

        cipher = PKCS1_v1_5.new(private_key)

        random_generator = Random.new().read
        sentinel = random_generator(20)

        cipher_text = 'F/agXpfSrs7HSXZz+jVq5no/xyQDXuOiVAG/MOY7WzSlp14vMOTM8TshFiWtegB3+2BZCMOEPLQFFFbxusuCFOYGGJ8yRaV7q985z/UDJVXvbX5ANYqrirobR+c868mY4V33loAt2ZFNXwr+Ubk11my1aJgHmoBem/6yPfoRd9GrZaSQnbJRSa3EDtP+8pXETkF9B98E7KvElrsRTLXEXSBygmeKsyENo5DDcARW+lVVsQuP8wUEGnth9SX4oG8i++gmQKkrv0ep6yFrn05xZJKgpOfRiTTo/Bkh7FxNP2wo7utzhtYkNnvtXaJPWAvqXg93KmNPqg1IsN4P1Swb8w=='

        plain_text = cipher.decrypt(base64.b64decode(cipher_text.encode('ASCII')), sentinel)
        print('Decrypted:', plain_text.decode('ASCII'))

        # Output:
        # Decrypted: Hello from .NET


        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # With your key pair object, you will then be able to encode it in your desired format. 
        # We will use the PEM encoding for our key pair and produce the required 
        # bytes for our PEM encoded public and private keys. Take note of us passing 
        # the bytes for our private key password when calling private_key.private_bytes.


        private_key_pass = b"your-password"

        encrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
        )

        print(encrypted_pem_private_key.splitlines()[0])
        # b'-----BEGIN ENCRYPTED PRIVATE KEY-----'

        pem_public_key = private_key.public_key().public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(pem_public_key.splitlines()[0])
        # b'-----BEGIN PUBLIC KEY-----'

        # If you do not require an encrypted private key file, you can always pass no encryption for the key like so.


        unencrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        print(unencrypted_pem_private_key.splitlines()[0])
        # b'-----BEGIN RSA PRIVATE KEY-----'

        # With our PEM encoded public and private key bytes, we can generate them into strings 
        # if you wish to write to file or save them in another service.

        private_key_file = open("example-rsa.pem", "w")
        private_key_file.write(encrypted_pem_private_key.decode())
        private_key_file.close()

        public_key_file = open("example-rsa.pub", "w")
        public_key_file.write(pem_public_key.decode())
        public_key_file.close()

        # When we put all these pieces together, we get the following completed code example.

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        private_key_pass = b"your-password"

        encrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
        )

        pem_public_key = private_key.public_key().public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_key_file = open("example-rsa.pem", "w")
        private_key_file.write(encrypted_pem_private_key.decode())
        private_key_file.close()

        public_key_file = open("example-rsa.pub", "w")
        public_key_file.write(pem_public_key.decode())
        public_key_file.close()

    
    
    
    
    