using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace _3ds_crypto_client
{
    class Program
    {
        private static bool keep_log;
        public static Options opts = new Options();

        static void Main(string[] args)
        {
            Util.NewLogFile("3DS Crypto Client v1.0 - CaitSith2");
            var parser = new Parser();
            if (!parser.ParseArguments(args, opts))
            {
                Console.WriteLine(opts.GetUsage());
                return;
            }
            NetworkUtils.SetCryptoIPAddress(IPAddress.Parse(opts.InputIP));
            if (!NetworkUtils.TestCryptoServer())
            {
                return;
            }

            switch (opts.Mode)
            {
                case CryptoOperation.DecryptTitleKeys:
                    DecryptTitleKeys();
                    break;
                case CryptoOperation.EncryptTitleKeys:
                    EncryptTitleKeys();
                    break;
            }
            Util.CloseLogFile(true);
        }

        static void EncryptTitleKeys()
        {
            Util.Log("Encrypting Title keys");
            var titlekeys = File.ReadAllBytes(opts.InputFile);
            var numkeys = BitConverter.ToInt32(titlekeys, 0);
            for (var i = 0; i < numkeys; i++)
            {
                var titleID = new byte[8];
                var key = new byte[16];
                var keyIndex = BitConverter.ToInt32(titlekeys, 16 + (32*i));

                Array.Copy(titlekeys, 16 + (32*i) + 8, titleID, 0, 8);
                Array.Copy(titlekeys, 16 + (32*i) + 16, key, 0, 16);

                var sb = new StringBuilder();
                foreach (var b in titleID)
                    sb.Append(b.ToString("X2"));
                Util.Log($"Encrypting Title ID: {sb}");

                var enc = NetworkUtils.TryEncryptTitleKey(titleID, key, true, (NetworkUtils.TitleKeyType)keyIndex);
                if (enc == null)
                {
                    Util.Log("Title Key Encryption failed");
                    return;
                }
                enc.CopyTo(titlekeys,16+(32*i)+16);
            }
            File.WriteAllBytes(opts.OutputFile != "" ? opts.OutputFile : "encTitleKeys.bin", titlekeys);
            Util.Log("Title Key encryption completed successfully");
        }

        static void DecryptTitleKeys()
        {
            Util.Log("Decrypting Title keys");
            var titlekeys = File.ReadAllBytes(opts.InputFile);
            var numkeys = BitConverter.ToInt32(titlekeys, 0);
            for (var i = 0; i < numkeys; i++)
            {
                var titleID = new byte[8];
                var key = new byte[16];
                var keyIndex = BitConverter.ToInt32(titlekeys, 16 + (32 * i));

                Array.Copy(titlekeys, 16 + (32 * i) + 8, titleID, 0, 8);
                Array.Copy(titlekeys, 16 + (32 * i) + 16, key, 0, 16);

                var sb = new StringBuilder();
                foreach (var b in titleID)
                    sb.Append(b.ToString("X2"));
                Util.Log($"Decrypting Title ID: {sb}");

                var enc = NetworkUtils.TryDecryptTitleKey(titleID, key, true, (NetworkUtils.TitleKeyType)keyIndex);
                if (enc == null)
                {
                    Util.Log("Title Key Decryption failed");
                    return;
                }
                enc.CopyTo(titlekeys, 16 + (32 * i) + 16);
            }
            File.WriteAllBytes(opts.OutputFile != "" ? opts.OutputFile : "decTitleKeys.bin", titlekeys);
            Util.Log("Title Key decryption completed successfully");
        }
    }
}
