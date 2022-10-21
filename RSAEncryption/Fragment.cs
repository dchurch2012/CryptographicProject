

Recently I need to save PublicKey and PrivateKey generated in my C# application to file, and works with it later. I use for this purpose such library as CSharp-easy-RSA-PEM.

It is very simple and quick solution, so I will recommend this library to other guys.

I use following code to get PublicKey as string (and save it to pem file in format Base64):

string publicKeyStr = Crypto.ExportPublicKeyToX509PEM(_cryptoServiceProvider);

it returns something like this:

-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxnBvS8cdsnAev2sRDRYWxznm1
QxZzaypfNXLvK7CDGk8TR7K+Pzsa+tpJfoyN/Z4B6xdlpsERo2Cu6AzolvrDLx5w
ZoI0kgdfaBMbUkdOB1m97zFYjKWoPeTskFzWZ3GHcQ3EXT0NJXXFXAskY45vEpbc
5qFgEhcPy3BMqHRibwIDAQAB
-----END PUBLIC KEY-----

And I use following code to get PrivateKey as string:

string privateKeyStr = Crypto.ExportPrivateKeyToRSAPEM(_cryptoServiceProvider);

it returns something like this:

-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCxnBvS8cdsnAev2sRDRYWxznm1QxZzaypfNXLvK7CDGk8TR7K+
Pzsa+tpJfoyN/Z4B6xdlpsERo2Cu6AzolvrDLx5wZoI0kgdfaBMbUkdOB1m97zFY
jKWoPeTskFzWZ3GHcQ3EXT0NJXXFXAskY45vEpbc5qFgEhcPy3BMqHRibwIDAQAB
AoGAAdwpqm7fxh0S3jOYpJULeQ45gL11dGX7Pp4CWHYzq1vQ14SDtFxYfnLWwGLz
499zvSoSHP1pvjPgz6lxy9Rw8dUxCgvh8VQydMQzaug2XD1tkmtcSWInwFKBAfQ7
rceleyD0aK8JHJiuzM1p+yIJ/ImGK0Zk2U/svqrdJrNR4EkCQQDo3d5iWcjd3OLD
38k1GALEuN17KNpJqLvJcIEJl0pcHtOiNnyy2MR/XUghDpuxwhrhudB/TvX4tuI0
MUeVo5fjAkEAw0D6m9jkwE5uuEYN/l/84rbQ79p2I7r5Sk6zbMyBOvgl6CDlJyxY
434DDm6XW7c55ALrnlratEW5HPiPxuHZBQJANnE4vtGy7nvn4Fd/mRQmAYwe695f
On1iefP9lxpx3huu6uvGN6IKPqS2alQZ/nMdCc0Be+IgC6fmNsGWtNtsdQJAJvB4
ikgxJqD9t8ZQ2CAwgM5Q0OTSlsGdIdKcOeB3DVmbxbV5vdw8RfJFjcVEbkgWRYDH
mKcp4rXc+wgfNFyqOQJATZ1I5ER8AZAn5JMMH9zK+6oFvhLUgKyWO18W+dbcFrBd
AzlTB+HHYEIyTmaDtXWAwgBvJNIHk4BbM1meCH4QnA==
-----END RSA PRIVATE KEY-----

Then you can use

RSACryptoServiceProvider publicX509key = Crypto.DecodeX509PublicKey(publicKeyStr);
RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(privateKeyStr);

to restore saved keys back to RSACryptoServiceProvider.

So, if someone need to resolve similar issue, you can just download this library, go to Solution Explorer -> (Right click on your project) -> Add -> Reference -> Overview in your Visual Studio to add this library in your project, and add using CSharp_easy_RSA_PEM; where you need it :)
Share
Follow
edited Jun 9, 2017 at 14:49
answered Jun 9, 2
