using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;

namespace _3ds_crypto_client
{
    internal class Program
    {
        public static string heading = new HeadingInfo("3DS Crypto Client", "v1.0");
        public static string copyright = new CopyrightInfo("CaitSith2", 2017);

        private static bool keep_log;
        public static Options opts = new Options();

        private static void Main(string[] args)
        {
            var parser = new Parser();
            if (!parser.ParseArguments(args, opts) || opts.help)
            {
                Console.WriteLine(opts.GetUsage());
                return;
            }

            opts = opts.GetSettings();
            Util.NewLogFile(heading,copyright);
            
            NetworkUtils.SetCryptoIPAddress(IPAddress.Parse(opts.InputIP));

            try
            {
                Util.Log($"Testing Crypto Server ({opts.InputIP})...");
                if (NetworkUtils.TestCryptoServer())
                {
                    switch (opts.Mode)
                    {
                        case CryptoOperation.DecryptTitleKeys:
                        case CryptoOperation.EncryptTitleKeys:
                            CryptTitleKeys(opts.Mode == CryptoOperation.EncryptTitleKeys);
                            break;
                        case CryptoOperation.EncryptBOSS:
                        case CryptoOperation.DecryptBOSS:
                        default:
                            Util.Log($"Operation {opts.Mode} not Implemented yet");
                            break;
                    }
                }
            }
            catch (Exception e)
            {
                Util.Log($"Operation {opts.Mode} failed due to an Exception: {e.Message}");
                if(opts.KeepLog == KeepLogSetting.ExceptionsOnly)
                    opts.KeepLog = KeepLogSetting.Always;
            }
            Util.CloseLogFile(opts.KeepLog == KeepLogSetting.Always);
        }

        private static void CryptTitleKeys(bool Encrypt)
        {
            var basefilename = Encrypt ? "decTitleKeys.bin" : "endTitleKeys.bin";
            var mode = Encrypt ? "En" : "De";
            Util.Log($"{mode}crypting Title keys");
            var outfilename = opts.OutputFile == "" ? basefilename : opts.OutputFile;
            var titlekeys = new TitleKeys(opts.InputFile);

            for (var i = 0; i < titlekeys.Entries.Count; i++)
            {
                var t = titlekeys.Entries[i];
                var sb = new StringBuilder();
                foreach (var b in t.TitleID)
                    sb.Append(b.ToString("X2"));
                Util.Log($"{mode}crypting Title ID: {sb}, (Key {i + 1} of {titlekeys.Entries.Count})");

                var enc = Encrypt
                    ? NetworkUtils.TryEncryptTitleKey(t.TitleID, t.Key, true, NetworkUtils.TitleKeyType.system)
                    : NetworkUtils.TryDecryptTitleKey(t.TitleID, t.Key, true, NetworkUtils.TitleKeyType.system);
                if (enc != null)
                {
                    t.Key = enc;
                    continue;
                }
                Util.Log($"Title Key {mode}cryption failed {NetworkUtils.GetExceptionString()}");
                return;
            }
            titlekeys.WriteFile(outfilename);
            Util.Log($"Title Key {mode.ToLower()}cryption completed successfully");
        }
    }

    internal class TitleKeys
    {
        public List<TitleKeyEntry> Entries = new List<TitleKeyEntry>();
        public byte[] Reserved;
        public TitleKeys(string filename)
        {
            using (var fs = File.OpenRead(filename))
            using (var br = new BinaryReader(fs))
            {
                var count = br.ReadUInt32();
                Reserved = br.ReadBytes(12);
                for (var i = 0; i < count; i++)
                {
                    var entry = new TitleKeyEntry
                    {
                        IndexTopBytes = br.ReadBytes(3),
                        Index = br.ReadByte(),
                        Reserved = br.ReadUInt32(),
                        TitleID = br.ReadBytes(8),
                        Key = br.ReadBytes(16)
                    };
                    if (entry.Index >= 6)
                        entry.Index = 0;
                    Entries.Add(entry);
                }
            }
        }

        public TitleKeys()
        {
            Reserved = new byte[12];
        }

        public void WriteFile(string filename)
        {
            using (var fs = File.OpenWrite(filename))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write(Entries.Count);
                bw.Write(0xFFFFFFFF);
                bw.Write(0xFFFFFFFF);
                bw.Write(0xFFFFFFFF);
                foreach (var t in Entries)
                {
                    bw.Write(t.IndexTopBytes);
                    bw.Write(t.Index);
                    bw.Write(0xFFFFFFFF);
                    bw.Write(t.TitleID);
                    bw.Write(t.Key);
                }
            }
        }

    }

    internal class TitleKeyEntry
    {
        public byte[] IndexTopBytes;
        public byte Index;
        public uint Reserved;
        public byte[] TitleID;
        public byte[] Key;
    }
}
