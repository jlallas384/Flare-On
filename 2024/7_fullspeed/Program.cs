using System.Net;
using System.Text;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.Text.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using SHA512 = System.Security.Cryptography.SHA512;

class EncStream {
    private ChaChaEngine ch = new ChaChaEngine();
    private NetworkStream stream;
    public EncStream(byte[] shared, NetworkStream stream) {
        this.stream = stream;
        using (SHA512 sha512 = SHA512.Create()) {
            byte[] bytes = SHA512.HashData(shared);
            KeyParameter key = new KeyParameter(bytes, 0, 32);
            ICipherParameters paramss = new ParametersWithIV(key, bytes, 32, 8);
            this.ch.Init(true, paramss);
        }
    }
    public String Send(String s) {
        byte[] bytes = new byte[s.Length + 1];
        ASCIIEncoding ascii = new ASCIIEncoding();
        ascii.GetBytes(s.ToCharArray(), 0, s.Length, bytes, 0);
        this.ch.ProcessBytes(bytes, 0, s.Length + 1, bytes, 0);
        this.stream.Write(bytes, 0, s.Length + 1);

        byte[] recv = new byte[1024];
        int sz = this.stream.Read(recv, 0, 1024);
        this.ch.ProcessBytes(recv, 0, sz, recv, 0);

        return ascii.GetString(recv, 0, sz - 1);
    }
}

class Program
{
    static void Main() {
        BigInteger q = new BigInteger("c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd", 16);
        BigInteger a = new BigInteger("a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f", 16);
        BigInteger b = new BigInteger("9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380", 16);
        FpCurve curve = new FpCurve(q, a, b);

        BigInteger x = new BigInteger("087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8", 16);
        BigInteger y = new BigInteger("127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182", 16);

        BigInteger xorKey = new BigInteger("133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337", 16);

        ECPoint point = curve.CreatePoint(x, y);

        BigInteger a1 = new BigInteger("0a6c559073da49754e9ad9846a72954745e4f2921213eccda4b1422e2fdd646fc7e28389c7c2e51a591e0147e2ebe7ae", 16).Xor(xorKey);
        BigInteger a2 = new BigInteger("264022daf8c7676a1b2720917b82999d42cd1878d31bc57b6db17b9705c7ff2404cbbf13cbdb8c096621634045293922", 16).Xor(xorKey);

        Console.WriteLine(a1);
        Console.WriteLine(a2);

        BigInteger a3 = new BigInteger("a0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c31", 16).Xor(xorKey);
        BigInteger a4 = new BigInteger("96a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dc", 16).Xor(xorKey);

        Console.WriteLine(a3);
        Console.WriteLine(a4);
        ECPoint otherPoint = curve.ValidatePoint(a1, a2);
        
        BigInteger keys = otherPoint.Multiply(new BigInteger("153712271226962757897869155910488792420")).Normalize().AffineXCoord.ToBigInteger();

        BigInteger streamm = new BigInteger("f272d54c31860f3fbd43da3ee32586dfd7c50cea1c4aa064c35a7f6e3ab0258441ac1585c36256dea83cac93007a0c3a29864f8e285ffa79c8eb43976d5b587f8f35e699547116fcb1d2cdbba979c989998c61490bce39da577011e0d76ec8eb0b8259331def13ee6d86723eac9f0428924ee7f8411d4c701b4d9e2b3793f6117dd30dacba2cae600b5f32cea193e0de63d709838bd6a7fd35edf0fc802b15186c7a1b1a475daf94ae40f6bb81afcedc4afb158a5128c28c91cd7a8857d12a661acaecaec8d27a7cf26a1727368535a44e2f3917ed09447ded797219c966ef3dd5705a3c32bdb1710ae3b87fe66669e0b4646fc416c399c3a4fe1edc0a3ec5827b84db5a79b81634e7c3afe528a4da15457b637815373d4edcac2159d056f5981f71c7ea1b5d8b1e5f06fc83b1def38c6f4e694e3706412eabf54e3b6f4d19e8ef46b04e399f2c8ece8417fa4008bc54e41ef701fee74e80e8dfb54b487f9b2e3a277fa289cf6cb8df986cdd387e342ac9f5286da11ca27840845ca68d1394be2a4d3d4d7c82e531b6dac62ef1ad8dc1f60b79265ed0deaa31ddd2d53aa9fd9343463810f3e2232406366b48415333d4b8ac336d4086efa0f15e6e590d1ec06f36", 16);

        byte[] bytess = streamm.ToByteArrayUnsigned();
        ChaChaEngine ch = new ChaChaEngine();
        using (SHA512 sha512 = SHA512.Create()) {
            byte[] bytes = SHA512.HashData(keys.ToByteArrayUnsigned());
            KeyParameter key = new KeyParameter(bytes, 0, 32);
            ICipherParameters paramss = new ParametersWithIV(key, bytes, 32, 8);
            ch.Init(true, paramss);
        } 

        ch.ProcessBytes(bytess, 0, bytess.Length, bytess, 0);
        ASCIIEncoding ascii = new ASCIIEncoding();
        Console.WriteLine(ascii.GetString(bytess, 0, bytess.Length));
        // SecureRandom g = SecureRandom.GetInstance("SHA256PRNG", true);

        // string ipAddress = "0.0.0.0";
        // int port = 31337;

        // // Create a TCP/IP socket
        // TcpListener server = new TcpListener(IPAddress.Parse(ipAddress), port);
        
        // // Start listening for incoming connections
        // server.Start();
        // Console.WriteLine($"Server listening on {ipAddress}:{port}");

        // while (true)
        // {
        //     // Wait for a connection
        //     Console.WriteLine("Waiting for a connection...");
        //     using (TcpClient client = server.AcceptTcpClient())
        //     {
        //         Console.WriteLine($"Connection from {client.Client.RemoteEndPoint}");


        //         // Get the stream to read data
        //         NetworkStream stream = client.GetStream();
        //         byte[] keya = new byte[48];
        //         byte[] keyb = new byte[48];


        //         stream.Read(keya, 0, 48);
        //         stream.Read(keyb, 0, 48);

        //         BigInteger mykey = new BigInteger(128, g);

        //         ECPoint mypoint = point.Multiply(mykey).Normalize();

        //         BigInteger keyx = mypoint.AffineXCoord.ToBigInteger().Xor(xorKey);
        //         BigInteger keyy = mypoint.AffineYCoord.ToBigInteger().Xor(xorKey);

        //         stream.Write(keyx.ToByteArrayUnsigned(), 0, 48);
        //         stream.Write(keyy.ToByteArrayUnsigned(), 0, 48);

        //         BigInteger ca = new BigInteger(1, keya, 0, 48, true);
        //         BigInteger cb = new BigInteger(1, keyb, 0, 48, true);

        //         ca = ca.Xor(xorKey);
        //         cb = cb.Xor(xorKey);

        //         ECPoint other = curve.ValidatePoint(ca, cb).Multiply(mykey).Normalize();

        //         Console.WriteLine(ca.ToString());
        //         Console.WriteLine(cb.ToString());

        //         Console.WriteLine(other.AffineXCoord.ToBigInteger().ToString());
        //         byte[] shared = other.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();

        //         EncStream s = new EncStream(shared, stream);
        //         Console.WriteLine(s.Send("verify"));
        //         Console.WriteLine(s.Send("ls"));
        //         Console.WriteLine(s.Send("cd|.."));
        //         Console.WriteLine(s.Send("ls"));
        //         Console.WriteLine(s.Send("cat|flag"));
        //     }
        // }
    }
}