using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace _3ds_crypto_client
{
    public class NetworkUtils
    {
        public static IPAddress crypto_ip = new IPAddress(new byte[] { 192, 168, 1, 137 });
        public static int crypto_port = 8081;
        public static ProgressBar progress;
        public static byte[] download_data;
        public static long boss_size;
        public static SocketException sex;
        public static WebException wex;
        public static Exception ex;
        

        public static void SetCryptoIPAddress(IPAddress crypto_ip_arg = default(IPAddress))
        {
            if (crypto_ip_arg != default(IPAddress))
                crypto_ip = crypto_ip_arg;
        }

        private static void DownloadProgressCallback(object sender, DownloadProgressChangedEventArgs e)
        {
            progress.Report((double) e.BytesReceived/boss_size);
        }

        public static byte[] TryDownload(string file)
        {
            using (progress = new ProgressBar())
            {
                wex = null;
                try
                {
                    //Sometimes the server refuses to disclose the file size, so progress bar shows as 0% until complete.
                    //So, instead, lets extract the boss file size from the boss header.
                    var header = DownloadFirstBytes(file);
                    if (header == null || BitConverter.ToUInt64(header,0) != 0x0100010073736F62 ) return null;
                    boss_size = header[8] << 24 | header[9] << 16 | header[10] << 8 | header[11];
                   

                    var client = new WebClient();
                    client.DownloadProgressChanged += DownloadProgressCallback;
                    var dataTask = client.DownloadDataTaskAsync(file);
                    while (!dataTask.IsCompleted)
                    {
                        if (dataTask.IsFaulted) return null;
                        Thread.Sleep(20);
                    }
                    return dataTask.Result;
                }
                catch (WebException e)
                {
                    wex = e;
                    return null;
                }
            }
        }

        public static byte[] DownloadFirstBytes(string file)
        {
            wex = null;
            const int bytes = 0x400;
            try
            {
                var req = (HttpWebRequest) WebRequest.Create(file);
                req.AddRange(0, bytes - 1);

                using (var resp = req.GetResponse())
                using (var stream = resp.GetResponseStream())
                {
                    var buf = new byte[bytes];
                    var read = stream.Read(buf, 0, bytes);
                    Array.Resize(ref buf, read);
                    return buf;
                }
            }
            catch (WebException e)
            {
                wex = e;
                return null;
            }
        }

        private static byte[] DecryptData(byte[] metadata, byte[] data, int ofs)
        {
            byte[] dec = null;
            sex = null;
            ex = null;
            var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                sock.Connect(crypto_ip, crypto_port);
                sock.Send(metadata);

                var _bufsize = new byte[4];
                sock.Receive(_bufsize);

                var bufsize = BitConverter.ToInt32(_bufsize, 0);
                sock.ReceiveBufferSize = bufsize;
                sock.SendBufferSize = bufsize;

                dec = new byte[data.Length];
                data.CopyTo(dec, 0);
                using (progress = new ProgressBar())
                {
                    while (ofs < data.Length)
                    {
                        var buf = new byte[ofs + bufsize < data.Length ? bufsize : data.Length - ofs];
                        Array.Copy(data, ofs, buf, 0, buf.Length);
                        try
                        {
                            var s = sock.Send(buf);
                            var r = buf.Length;
                            while (r > 0)
                            {
                                var d = sock.Receive(buf);
                                r -= d;
                                Array.Copy(buf, 0, dec, ofs, d);
                                ofs += d;
                                Array.Resize(ref buf, r);
                                progress.Report((double)ofs / data.Length);
                            }
                        }
                        catch (SocketException e)
                        {
                            sex = e;
                            sock.Close();
                            return null;
                        }
                    }
                }

                sock.Send(BitConverter.GetBytes(0xDEADCAFE));
            }
            catch (Exception e)
            {
                ex = e;
                sock.Close();
            }

            return dec;
        }

        public enum CryptoMode
        {
            CBC_Enc,
            CBC_Dec,
            CTR_Enc,
            CTR_Dec,
            CCM_Enc,
            CCM_Dec
        }

        public enum PSPXI_AES
        {
            ClCertA = 0,
            UDS_WLAN,
            MiiQR,
            BOSS,
            Unknown,
            DownloadPlay,
            StreetPass,
            //Invalid = 7,
            Friends = 8,
            NFC
        }

        public static byte[] TryDecryptData(byte[] data, CryptoMode mode, PSPXI_AES pspxi, byte[] iv, int ofs = 0)
        {
            //return TryDecryptData(data, mode, (int) pspxi, iv, ofs);
            var metadata = new byte[1024];
            BitConverter.GetBytes(0xCAFEBABE).CopyTo(metadata, 0);
            BitConverter.GetBytes(data.Length - ofs).CopyTo(metadata, 4);
            BitConverter.GetBytes((int)pspxi).CopyTo(metadata, 8);
            BitConverter.GetBytes((int)mode).CopyTo(metadata, 0x0C);
            iv.CopyTo(metadata, 0x20);
            return DecryptData(metadata, data, ofs);
        }

        public static byte[] TryDecryptData(byte[] data, CryptoMode mode, int keyslot, byte[] iv, int ofs = 0, byte[] keyY = null)
        {
            var metadata = new byte[1024];
            BitConverter.GetBytes(0xCAFEBABE).CopyTo(metadata, 0);
            BitConverter.GetBytes(data.Length - ofs).CopyTo(metadata, 4);
            BitConverter.GetBytes((keyslot & 0x3F) | (keyY != null ? 0x40 : 0x00) | 0x80).CopyTo(metadata, 8);
            BitConverter.GetBytes((int) mode).CopyTo(metadata, 0x0C);
            keyY?.CopyTo(metadata, 0x10);
            iv.CopyTo(metadata, 0x20);
            return DecryptData(metadata, data, ofs);
        }

        public enum TitleKeyType
        {
            system,
            eshop,
            unknown1,
            unknwon2,
            unknown3,
            unknown4,
        }

        private static readonly byte[][] TitleKeyYs =
        {
            //Retail Keys
            new byte[] {0xD0, 0x7B, 0x33, 0x7F, 0x9C, 0xA4, 0x38, 0x59, 0x32, 0xA2, 0xE2, 0x57, 0x23, 0x23, 0x2E, 0xB9} , // 0 - eShop Titles
            new byte[] {0x0C, 0x76, 0x72, 0x30, 0xF0, 0x99, 0x8F, 0x1C, 0x46, 0x82, 0x82, 0x02, 0xFA, 0xAC, 0xBE, 0x4C} , // 1 - System Titles
            new byte[] {0xC4, 0x75, 0xCB, 0x3A, 0xB8, 0xC7, 0x88, 0xBB, 0x57, 0x5E, 0x12, 0xA1, 0x09, 0x07, 0xB8, 0xA4} , // 2
            new byte[] {0xE4, 0x86, 0xEE, 0xE3, 0xD0, 0xC0, 0x9C, 0x90, 0x2F, 0x66, 0x86, 0xD4, 0xC0, 0x6F, 0x64, 0x9F} , // 3
            new byte[] {0xED, 0x31, 0xBA, 0x9C, 0x04, 0xB0, 0x67, 0x50, 0x6C, 0x44, 0x97, 0xA3, 0x5B, 0x78, 0x04, 0xFC} , // 4
            new byte[] {0x5E, 0x66, 0x99, 0x8A, 0xB4, 0xE8, 0x93, 0x16, 0x06, 0x85, 0x0F, 0xD7, 0xA1, 0x6D, 0xD7, 0x55} , // 5

            //Development Keys
            new byte[]{0x55, 0xA3, 0xF8, 0x72, 0xBD, 0xC8, 0x0C, 0x55, 0x5A, 0x65, 0x43, 0x81, 0x13, 0x9E, 0x15, 0x3B} , // 0 - eShop Titles
            new byte[]{0x44, 0x34, 0xED, 0x14, 0x82, 0x0C, 0xA1, 0xEB, 0xAB, 0x82, 0xC1, 0x6E, 0x7B, 0xEF, 0x0C, 0x25} , // 1 - System Titles
            new byte[]{0xF6, 0x2E, 0x3F, 0x95, 0x8E, 0x28, 0xA2, 0x1F, 0x28, 0x9E, 0xEC, 0x71, 0xA8, 0x66, 0x29, 0xDC} , // 2
            new byte[]{0x2B, 0x49, 0xCB, 0x6F, 0x99, 0x98, 0xD9, 0xAD, 0x94, 0xF2, 0xED, 0xE7, 0xB5, 0xDA, 0x3E, 0x27} , // 3
            new byte[]{0x75, 0x05, 0x52, 0xBF, 0xAA, 0x1C, 0x04, 0x07, 0x55, 0xC8, 0xD5, 0x9A, 0x55, 0xF9, 0xAD, 0x1F} , // 4
            new byte[]{0xAA, 0xDA, 0x4C, 0xA8, 0xF6, 0xE5, 0xA9, 0x77, 0xE0, 0xA0, 0xF9, 0xE4, 0x76, 0xCF, 0x0D, 0x63} , // 5
        };

        public static byte[] TryDecryptTitleKey(byte[] titleID, byte[] key, bool Retail, TitleKeyType type)
        {
            var iv = new byte[16];
            titleID.CopyTo(iv, 0);
            return TryDecryptData(key, CryptoMode.CBC_Dec, 0x3D, iv, 0, TitleKeyYs[(int)type + (Retail ? 0 : 6)]);
        }

        public static byte[] TryEncryptTitleKey(byte[] titleID, byte[] key, bool Retail, TitleKeyType type)
        {
            var iv = new byte[16];
            titleID.CopyTo(iv, 0);
            return TryDecryptData(key, CryptoMode.CBC_Enc, 0x3D, iv, 0, TitleKeyYs[(int)type + (Retail ? 0 : 6)]);
        }

        public static byte[] TryDecryptBOSS(byte[] boss) // https://github.com/SciresM/3ds-crypto-server
        {
            var iv = new byte[0x10];
            Array.Copy(boss, 0x1C, iv, 0, 0xC);
            iv[0xF] = 1;

            var dec = TryDecryptData(boss, CryptoMode.CTR_Dec, PSPXI_AES.BOSS, iv, 0x28);
            if(dec == null)
                Util.Log(sex == null
                    ? $"Failed to decrypt BOSS file due to an exception: {ex}"
                    : $"Failed to decrypt BOSS file due to a socket exception: {sex}");
            return dec;
        }

        public static bool TestCryptoServer()
        {
            var iv = new byte[0x10];
            var keyY = new byte[0x10];
            var test_vector = new byte[] { 0xBC, 0xC4, 0x16, 0x2C, 0x2A, 0x06, 0x91, 0xEE, 0x47, 0x18, 0x86, 0xB8, 0xEB, 0x2F, 0xB5, 0x48 };
            
            try
            {
                var pingresult = new Ping().Send(crypto_ip, 2000).Status == IPStatus.Success;
                if (!pingresult)
                {
                    Util.Log("Crypto Server selftest failed due to server being offline.");
                    return false;
                }
                var dec = TryDecryptData(test_vector, CryptoMode.CBC_Dec, 0x2C, iv, 0, keyY);

                if (dec == null)
                {
                    Util.Log(sex == null
                        ? $"Crypto Server test failed due to an exception: {ex}"
                        : $"Crypto Server test failed due to Socket Exception: {sex}");
                    return false;
                }

                if (dec.All(t => t == 0) && dec.Length == 0x10)
                {
                    Util.Log("Crypto Server test succeeded!");
                    return true;
                }
                Util.Log(
                    "Crypto Server test failed due to incorrect output. Check that the server is configured properly.");
                return false;
            }
            catch (PingException pex)
            {
                Util.Log($"Crypto Server selftest failed due to ping exception: {pex.Message}, Inner Exception: {pex.InnerException.Message}");
                return false;
            }
            
        }
    }
}